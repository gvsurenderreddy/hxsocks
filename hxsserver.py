#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
# Copyright (c) 2014 v3aqb
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


__version__ = '1.0.0'

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
import thread
import threading
import time
import random
import SocketServer
import struct
import binascii
import hashlib
import logging
import encrypt
import os
import urlparse
from collections import defaultdict, deque
from util import create_connection, parse_hostport
from dh import DH

method = 'rc4-md5'
users = {'user': 'pass'}


def hex2bytes(data):
    data = '0' * (len(data) % 2) + data
    return binascii.unhexlify(data)


def bytes2hex(data):
    return binascii.hexlify(data).decode()


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
        shared_secret = dh.genKey(bytes2hex(client_pkey))
        client_pkey = hashlib.md5(client_pkey).digest()
        cls.userpkeys[user].append(client_pkey)
        cls.pkeyuser[client_pkey] = user
        cls.pkeykey[client_pkey] = shared_secret
        cls.pkeytime[client_pkey] = time.time()
        return hex2bytes(dh.hexPub), users[user]

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
        while not close:
            cipher = encrypt.Encryptor(self.server.PSK, method, servermode=0)
            cmd = ord(cipher.decrypt(self.rfile.read(cipher.iv_len() + 1)))
            if cmd == 0:  # client key exchange
                ts = cipher.decrypt(self.rfile.read(4))
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    return
                pklen = struct.unpack('>H', cipher.decrypt(self.rfile.read(2)))[0]
                client_pkey = cipher.decrypt(self.rfile.read(pklen))
                client_auth = cipher.decrypt(self.rfile.read(32))
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
                    self.wfile.write(cipher.encrypt(data))
                else:
                    logging.error('client: %s create new key failed!' % user)
                    return
            elif cmd == 1:  # a connect request
                client_pkey = cipher.decrypt(self.rfile.read(16))
                if KeyManager.check_key(client_pkey):
                    rint = random.randint(64, 255)
                    self.wfile.write(cipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                    continue
                cipher = encrypt.Encryptor(KeyManager.pkeykey[client_pkey], method, servermode=0)
                ts = cipher.decrypt(self.rfile.read(cipher.iv_len() + 4))
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    return
                host_len = ord(cipher.decrypt(self.rfile.read(1)))
                hostport = cipher.decrypt(self.rfile.read(host_len))
                logging.info('CONNECT %s' % hostport)
                addr, port = parse_hostport(hostport)
                self.wfile.write(cipher.encrypt(chr(0)))
                try:
                    remote = None
                    logging.info('server %s:%d request %s:%d from %s:%d' % (self.server.server_address[0], self.server.server_address[1],
                                 addr, port, self.client_address[0], self.client_address[1]))
                    data = cipher.decrypt(self.connection.recv(self.bufsize))
                    if self.server.reverse:
                        remote = create_connection(self.server.reverse, timeout=1)
                        if data.startswith((b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'TRACE', b'OPTIONS', b'PATCH', b'CONNECT')) and b'HTTP/1' in data and b'\r\n' in data:
                            data = data.replace(b'\r\n', ('\r\nss-realip: %s:%s\r\nss-client: %s\r\n' % (self.client_address[0], self.client_address[1], self.server.key)).encode('latin1'), 1)
                        else:
                            a = 'CONNECT %s:%d HTTP/1.0\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, self.client_address[0], self.client_address[1], self.server.key)
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
                    # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (IOError, OSError) as e:  # Connection refused
                    logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                    return
                self.forward_tcp(self.connection, remote, cipher, timeout=60)
                return
            else:
                close = 1

    def forward_tcp(self, local, remote, cipher, timeout=60):
        def _io_copy(dest, source, timeout, cipher):
            try:
                dest.settimeout(timeout)
                source.settimeout(timeout)
                while 1:
                    data = source.recv(self.bufsize)
                    if not data:
                        break
                    dest.sendall(cipher(data))
            except socket.timeout:
                pass
            except (IOError, OSError) as e:
                if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                    raise
                if e.args[0] in (errno.EBADF,):
                    return
            finally:
                for sock in (dest, source):
                    try:
                        sock.close()
                    except (IOError, OSError):
                        pass
        thread.start_new_thread(_io_copy, (remote.dup(), local.dup(), timeout, cipher.decrypt))
        _io_copy(local, remote, timeout, cipher.encrypt)

    def finish(self):
        SocketServer.StreamRequestHandler.finish(self)


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

    ssserver = HXSocksServer('hxp://0.0.0.0:90', HXSocksHandler)
    ssserver.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        sys.exit(0)
