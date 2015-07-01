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

import os
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
import hmac
import logging
import encrypt
import io
import json
import urlparse
from collections import defaultdict, deque
from util import create_connection, parse_hostport, get_ip_address
from ecc import ECC
from encrypt import compare_digest

default_method = 'rc4-md5'
users = {'user': 'pass'}
salt = b'G\x91V\x14{\x00\xd9xr\x9d6\x99\x81GL\xe6c>\xa9\\\xd2\xc6\xe0:\x9c\x0b\xefK\xd4\x9ccU'
ctx = b'hxsocks'
mac_len = 16
server_cert = None


class KeyManager:
    userpkeys = defaultdict(deque)
    pkeyuser = {}
    pkeykey = {}
    pkeytime = {}

    @classmethod
    def create_key(cls, user, client_pkey, klen):
        if cls.notvalid(user, client_pkey):
            return 0, 0
        if len(cls.userpkeys[user]) > 3:
            cls.del_key(cls.userpkeys[user][0])
        dh = ECC(klen)
        shared_secret = dh.get_dh_key(client_pkey)
        client_pkey = hashlib.md5(client_pkey).digest()
        cls.userpkeys[user].append(client_pkey)
        cls.pkeyuser[client_pkey] = user
        cls.pkeykey[client_pkey] = shared_secret
        cls.pkeytime[client_pkey] = time.time()
        return dh.get_pub_key(), users[user]

    @classmethod
    def notvalid(cls, user, client_pkey):
        return hashlib.md5(client_pkey).digest() in cls.pkeyuser

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
        self.ss = bool(self.PSK) and urlparse.parse_qs(p.query).get('ss', ['1'])[0] == '1'
        reverse = urlparse.parse_qs(p.query).get('reverse', [''])[0]
        self.reverse = parse_hostport(reverse) if reverse else None
        addrs = socket.getaddrinfo(p.hostname, p.port)
        if not addrs:
            raise ValueError('cant resolve listen address')
        self.address_family = addrs[0][0]
        server_address = (p.hostname, p.port)
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)


class HXSocksHandler(SocketServer.StreamRequestHandler):
    timeout = 60
    bufsize = 32768

    def handle(self):
        pskcipher = encrypt.Encryptor(self.server.PSK, self.server.method, servermode=1)
        while True:
            bad_req = 0
            rint = random.randint(64, 255)
            cmd_len = 1 if pskcipher.decipher else pskcipher.iv_len + 1
            try:
                data = self.rfile.read(cmd_len)
            except:
                break
            self.connection.settimeout(self.timeout)
            cmd = ord(pskcipher.decrypt(data))
            if cmd == 10:  # client key exchange
                ts = pskcipher.decrypt(self.rfile.read(4))
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    bad_req |= 1
                pklen = ord(pskcipher.decrypt(self.rfile.read(1)))
                client_pkey = pskcipher.decrypt(self.rfile.read(pklen))
                client_auth = pskcipher.decrypt(self.rfile.read(32))
                for user, passwd in users.items():
                    h = hmac.new(passwd.encode(), ts + client_pkey + user.encode(), hashlib.sha256).digest()
                    if compare_digest(h, client_auth):
                        client = user
                        break
                else:
                    logging.error('user not found.')
                    bad_req |= 1
                pkey, passwd = KeyManager.create_key(client, client_pkey, pskcipher.key_len)
                if not bad_req and pkey:
                    logging.info('client: %s is asking for a new key' % user)
                    h = hmac.new(passwd.encode(), client_pkey + pkey + user.encode(), hashlib.sha256).digest()
                    scert = server_cert.get_pub_key()
                    r, s = server_cert.sign(h)
                    data = chr(0) + chr(len(pkey)) + pkey + h + chr(len(scert)) + scert + chr(len(r)) + r + s
                    self.wfile.write(pskcipher.encrypt(data))
                    continue
                else:
                    logging.error('client: %s create new key failed!' % user)
                    self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                    continue
            elif cmd == 11:  # a connect request
                client_pkey = pskcipher.decrypt(self.rfile.read(16))
                if KeyManager.check_key(client_pkey):
                    ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                    self.rfile.read(ctlen)
                    self.rfile.read(mac_len)
                    self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                    continue
                user = KeyManager.pkeyuser[client_pkey]
                cipher = encrypt.AEncryptor(KeyManager.pkeykey[client_pkey], self.server.method, salt, ctx, 1)
                ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                ct = self.rfile.read(ctlen)
                mac = self.rfile.read(mac_len)
                data = cipher.decrypt(ct, mac)
                buf = io.BytesIO(data)
                ts = buf.read(4)
                if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                    logging.error('bad timestamp, possible replay attrack')
                    self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                    continue
                passwd = users[user]
                host_len = ord(buf.read(1))
                hostport = buf.read(host_len)
                addr, port = parse_hostport(hostport)
                if self._request_is_loopback((addr, port)):
                    logging.info('server %d access localhost:%d denied. from %s:%d, %s' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1], user))
                    return self.wfile.write(pskcipher.encrypt(chr(2) + chr(rint)) + os.urandom(rint))
                try:
                    remote = None
                    logging.info('server %d request %s:%d from %s:%d, %s' % (self.server.server_address[1],
                                 addr, port, self.client_address[0], self.client_address[1], user))
                    data = buf.read()
                    if self.server.reverse:
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
                        remote.settimeout(10)
                    if not remote:
                        remote = create_connection((addr, port), timeout=10)
                    remote.sendall(data)
                    self.wfile.write(pskcipher.encrypt(chr(0) + chr(rint)) + os.urandom(rint))
                    # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (IOError, OSError) as e:  # Connection refused
                    logging.warning('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                    self.wfile.write(pskcipher.encrypt(chr(2) + chr(rint)) + os.urandom(rint))
                    continue
                if self.forward_tcp(self.connection, remote, cipher, pskcipher, timeout=60):
                    return
            elif cmd in (1, 3, 4):
                # A shadowsocks request
                if not self.server.ss:
                    logging.warning('shadowsocks not enabled for this server. port: %d' % self.server.server_address[1])
                    return
                if cmd == 1:
                    addr = socket.inet_ntoa(pskcipher.decrypt(self.rfile.read(4)))
                elif cmd == 3:
                    addr = pskcipher.decrypt(self.rfile.read(ord(pskcipher.decrypt(self.rfile.read(1)))))
                elif cmd == 4:
                    addr = socket.inet_ntop(socket.AF_INET6, pskcipher.decrypt(self.rfile.read(16)))
                port = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                if self._request_is_loopback((addr, port)):
                    logging.info('server %d access localhost:%d denied. from %s:%d' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1]))
                    return
                try:
                    remote = None
                    logging.info('server %d SS request %s:%d from %s:%d' % (self.server.server_address[1],
                                 addr, port, self.client_address[0], self.client_address[1]))
                    data = pskcipher.decrypt(self.connection.recv(self.bufsize))
                    if self.server.reverse:
                        remote = create_connection(self.server.reverse, timeout=1)
                        if data.startswith((b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'TRACE', b'OPTIONS', b'PATCH', b'CONNECT')) and b'HTTP/1' in data and b'\r\n' in data:
                            data = data.replace(b'\r\n', ('\r\nss-realip: %s:%s\r\nss-client: %s\r\n' % (self.client_address[0], self.client_address[1], self.server.PSK)).encode('latin1'), 1)
                        else:
                            a = 'CONNECT %s:%d HTTP/1.0\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, self.client_address[0], self.client_address[1], self.server.PSK)
                            remote.sendall(a.encode('latin1'))
                            remoterfile = remote.makefile('rb', 0)
                            d = remoterfile.readline()
                            while d not in (b'\r\n', b'\n', b'\r'):
                                if not d:
                                    raise IOError(0, 'remote closed')
                                d = remoterfile.readline()
                        remote.settimeout(10)
                    if not remote:
                        remote = create_connection((addr, port), timeout=10)
                    remote.sendall(data)
                    return self.ssforward_tcp(self.connection, remote, pskcipher, timeout=60)
                except (IOError, OSError) as e:  # Connection refused
                    logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                    return
            else:
                logging.warning('unknown cmd, bad encryption key?')
                break

    def forward_tcp(self, local, remote, cipher, pskcipher, timeout=60):
        readable = 1
        writeable = 1
        fds = [local, remote]
        try:
            while fds:
                ins, _, _ = select.select(fds, [], [], timeout)
                if not ins:
                    break
                if local in ins:
                    ctlen = self.rfile.read(2)
                    if not ctlen:
                        # client is no longer sending anything
                        fds.remove(local)
                        break
                    ctlen = struct.unpack('>H', pskcipher.decrypt(ctlen))[0]
                    if ctlen:
                        ct = self.rfile.read(ctlen)
                        mac = self.rfile.read(mac_len)
                        if ctlen < 512:
                            self.rfile.read(ord(pskcipher.decrypt(self.rfile.read(1))))
                        data = cipher.decrypt(ct, mac)
                        remote.sendall(data)
                    else:
                        # client is no longer sending anything, gracefully
                        remote.shutdown(socket.SHUT_WR)
                        self.rfile.read(ord(pskcipher.decrypt(self.rfile.read(1))))
                        fds.remove(local)
                        readable = 0
                if remote in ins:
                    data = remote.recv(self.bufsize)
                    if data:
                        ct, mac = cipher.encrypt(data)
                        data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
                        if len(ct) < 512:
                            rint = random.randint(64, 255)
                            data += pskcipher.encrypt(chr(rint)) + os.urandom(rint)
                        local.sendall(data)
                    else:
                        # remote no longer sending anything.
                        rint = random.randint(64, 255)
                        data = pskcipher.encrypt(b'\x00\x00' + chr(rint)) + os.urandom(rint)
                        local.sendall(data)
                        writeable = 0
                        fds.remove(remote)
        except socket.timeout:
            pass
        except (OSError, IOError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            try:
                remote.close()
            except (OSError, IOError):
                pass
        self.connection.settimeout(600)
        return readable + writeable

    def ssforward_tcp(self, local, remote, cipher, timeout=60):
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

    def _request_is_loopback(self, req):
        try:
            return get_ip_address(req[0]).is_loopback
        except Exception:
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
    global server_cert
    try:
        server_cert = ECC(from_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem'))
    except:
        logging.warning('server cert not found, creating...')
        server_cert = ECC(key_len=32)
        server_cert.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem'))

    servers = ['hxp://0.0.0.0:90']
    if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')):
        global users
        d = json.loads(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')).read())
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
