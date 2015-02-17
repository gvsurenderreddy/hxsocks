#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 - 2015 v3aqb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import with_statement


__version__ = '0.0.1'

import sys
try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import errno
import socket
import threading
import time
import random
import select
import SocketServer
import struct
import hashlib
import logging
import encrypt
import os
import json
import urlparse
from collections import defaultdict, deque
from util import create_connection, parse_hostport
from dh import DH

default_method = 'rc4-md5'
users = {'user': 'pass'}


class KeyManager:
    userpkeys = defaultdict(deque)
    pkeyuser = {}
    pkeykey = {}
    pkeytime = {}

    @classmethod
    def create_key(cls, user, client_pkey):
        valid = 1
        if not valid:
            return 0, 0
        if len(cls.userpkeys[user]) > 3:
            cls.del_key(cls.userpkeys[user][0])
        dh = DH()
        shared_secret = dh.genKey(client_pkey)
        client_pkey = hashlib.md5(client_pkey).digest()
        cls.userpkeys[user].append(client_pkey)
        cls.pkeyuser[client_pkey] = user
        cls.pkeykey[client_pkey] = shared_secret
        cls.pkeytime[client_pkey] = time.time()
        return dh.getPubKey(), users[user]

    @classmethod
    def check_key(cls, pubk):
        if pubk not in cls.pkeykey:
            return 1
        if cls.pkeytime[pubk] < time.time() - 6 * 3600:
            cls.del_key(pubk)
            return 1

    @classmethod
    def del_key(cls, pkey):
        user = cls.pkeyuser[pkey]
        del cls.pkeyuser[pkey]
        del cls.pkeytime[pkey]
        del cls.pkeykey[pkey]
        cls.userpkeys[user].remove(pkey)


class HXSocksServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, serverinfo, RequestHandlerClass, bind_and_activate=True):
        self.serverinfo = serverinfo
        p = urlparse.urlparse(serverinfo)
        self.PSK = urlparse.parse_qs(p.query).get('PSK', [''])[0]
        self.method = urlparse.parse_qs(p.query).get('method', [''])[0] or default_method
        reverse = urlparse.parse_qs(p.query).get('reverse', [''])[0]
        self.reverse = parse_hostport(reverse) if reverse else None
        addrs = socket.getaddrinfo(p.hostname, p.port)
        if not addrs:
            raise ValueError('cant resolve listen address')
        self.address_family = addrs[0][0]
        server_address = (p.hostname, p.port)
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)

    def server_activate(self):
        self.socket.listen(self.request_queue_size)

    def get_request(self):
        connection = self.socket.accept()
        connection[0].settimeout(10)
        return connection


class HXSocksHandler(SocketServer.StreamRequestHandler):
    timeout = 10
    bufsize = 8192

    def handle(self):
        close = 0
        pskcipher = encrypt.Encryptor(self.server.PSK, self.server.method, servermode=0)
        while not close:
            cmd_len = 1 if pskcipher.decipher else pskcipher.iv_len + 1
            cmd = ord(pskcipher.decrypt(self.rfile.read(cmd_len)))
            if cmd == 0:  # client key exchange
                ts = pskcipher.decrypt(self.rfile.read(4))
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    return
                pklen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                client_pkey = pskcipher.decrypt(self.rfile.read(pklen))
                client_auth = pskcipher.decrypt(self.rfile.read(32))
                for user, passwd in users.items():
                    if hashlib.sha256(client_pkey + user.encode() + passwd.encode()).digest() == client_auth:
                        client = user
                        break
                else:
                    return logging.error('user not found, close socket')
                logging.info('client: %s is asking for a new key' % user)
                pkey, passwd = KeyManager.create_key(client, client_pkey)
                if pkey:
                    data = chr(0) + struct.pack('>H', len(pkey)) + pkey + hashlib.sha256(client_pkey + pkey + user.encode() + passwd.encode()).digest()
                    self.wfile.write(pskcipher.encrypt(data))
                else:
                    logging.error('client: %s create new key failed!' % user)
                    return
            elif cmd == 1:  # a connect request
                client_pkey = pskcipher.decrypt(self.rfile.read(16))
                rint = random.randint(64, 255)
                if KeyManager.check_key(client_pkey):
                    self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                    continue
                user = KeyManager.pkeyuser[client_pkey]
                cipher = encrypt.Encryptor(KeyManager.pkeykey[client_pkey], self.server.method, servermode=0)
                ts = cipher.decrypt(self.rfile.read(cipher.iv_len + 4))
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    return
                host_len = ord(cipher.decrypt(self.rfile.read(1)))
                hostport = cipher.decrypt(self.rfile.read(host_len))
                logging.info('CONNECT %s' % hostport)
                addr, port = parse_hostport(hostport)
                try:
                    remote = None
                    logging.info('server %s:%d request %s:%d from %s:%d' % (self.server.server_address[0], self.server.server_address[1],
                                 addr, port, self.client_address[0], self.client_address[1]))
                    data = b''
                    if self.server.reverse:
                        if select.select([self.connection], [], [], 0.0)[0]:
                            data = cipher.decrypt(self.connection.recv(self.bufsize))
                        remote = create_connection(self.server.reverse, timeout=1)
                        if data.startswith((b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'TRACE', b'OPTIONS', b'PATCH', b'CONNECT')) and b'HTTP/1' in data and b'\r\n' in data:
                            data = data.replace(b'\r\n', ('\r\nss-realip: %s:%s\r\nss-client: %s\r\n' % (self.client_address[0], self.client_address[1], user)).encode('latin1'), 1)
                        else:
                            a = 'CONNECT %s:%d HTTP/1.0\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, self.client_address[0], self.client_address[1], user)
                            remote.sendall(a.encode('latin1'))
                            remoterfile = remote.makefile('rb', 0)
                            d = remoterfile.readline()
                            while d not in (b'\r\n', b'\n', b'\r'):
                                if not d:
                                    raise IOError(0, 'remote closed')
                                d = remoterfile.readline()
                    if not remote:
                        remote = create_connection((addr, port), timeout=10)
                    remote.sendall(data)
                    self.wfile.write(pskcipher.encrypt(chr(0) + chr(rint)) + os.urandom(rint))
                    # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (IOError, OSError) as e:  # Connection refused
                    logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                    return
                self.forward_tcp(self.connection, remote, cipher, timeout=60)
                return
            else:
                close = 1

    def forward_tcp(self, local, remote, cipher, timeout=60):
        try:
            while 1:
                ins, _, _ = select.select([local, remote], [], [], timeout)
                if not ins:
                    break
                if local in ins:
                    data = local.recv(self.bufsize)
                    if not data:
                        break
                    remote.sendall(cipher.decrypt(data))
                if remote in ins:
                    data = remote.recv(self.bufsize)
                    if not data:
                        break
                    local.sendall(cipher.encrypt(data))
        except socket.timeout:
            pass
        except (OSError, IOError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            for sock in (remote, local):
                try:
                    sock.close()
                except (OSError, IOError):
                    pass


def start_servers(config):
    for serverinfo in config:
        try:
            logging.info('starting server: %s' % serverinfo)
            ssserver = HXSocksServer(serverinfo, HXSocksHandler)
            threading.Thread(target=ssserver.serve_forever).start()
        except Exception as e:
            logging.error('something wrong with config: %r' % e)


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    hello = 'hxsocks-server %s' % __version__
    if gevent:
        hello += ' with gevent %s' % gevent.__version__
    print(hello)
    print('by v3aqb')
    servers = ['hxp://0.0.0.0:90']
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'config.json')):
        global users
        d = json.loads(open(os.path.join(os.path.dirname(__file__), 'config.json')).read())
        users = d['users']
        servers = d['servers']
    for s in servers:
        logging.info('starting server: %s' % s)
        ssserver = HXSocksServer(s, HXSocksHandler)
        threading.Thread(target=ssserver.serve_forever).start()

if __name__ == '__main__':
    try:
        main()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        sys.exit(0)
