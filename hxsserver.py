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
import traceback
from collections import defaultdict, deque
from util import create_connection, parse_hostport, get_ip_address
from encrypt import compare_digest
from ecc import ECC

__version__ = '0.0.1'

DEFAULT_METHOD = 'rc4-md5'
DEFAULT_HASH = 'sha256'
SALT = b'G\x91V\x14{\x00\xd9xr\x9d6\x99\x81GL\xe6c>\xa9\\\xd2\xc6\xe0:\x9c\x0b\xefK\xd4\x9ccU'
CTX = b'hxsocks'

USER_PASS = {'user': 'pass'}
SERVER_CERT = None


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
        return dh.get_pub_key(), USER_PASS[user]

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

    def __init__(self, serverinfo, forward, RequestHandlerClass, bind_and_activate=True):
        self.serverinfo = serverinfo
        self.forward = set(forward)
        p = urlparse.urlparse(serverinfo)
        self.PSK = urlparse.parse_qs(p.query).get('PSK', [''])[0]
        self.method = urlparse.parse_qs(p.query).get('method', [DEFAULT_METHOD])[0]
        self.hash_algo = urlparse.parse_qs(p.query).get('hash', [DEFAULT_HASH])[0].upper()
        self.ss = self.PSK and urlparse.parse_qs(p.query).get('ss', ['1'])[0] == '1'
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
    bufsize = 8192

    def handle(self):
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            pskcipher = encrypt.Encryptor(self.server.PSK, self.server.method, servermode=1)
            while True:
                bad_req = 0
                rint = random.randint(64, 255)
                cmd_len = 1 if pskcipher.decipher else pskcipher.iv_len + 1
                try:
                    data = self.rfile.read(cmd_len)
                    self.connection.settimeout(self.timeout)
                    cmd = ord(pskcipher.decrypt(data))
                except Exception as e:
                    logging.error('cmd Exception: server %s %r from %s:%s' % (self.server.server_address[1], e, self.client_address[0], self.client_address[1]))
                    return
                if cmd == 10:  # client key exchange
                    ts = pskcipher.decrypt(self.rfile.read(4))
                    if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                        logging.error('bad timestamp. client_ip: %s' % self.client_address[0])
                        bad_req = 1
                    pklen = ord(pskcipher.decrypt(self.rfile.read(1)))
                    client_pkey = pskcipher.decrypt(self.rfile.read(pklen))
                    client_auth = pskcipher.decrypt(self.rfile.read(32))
                    pad_len = ord(pskcipher.decrypt(self.rfile.read(1)))
                    pskcipher.decrypt(self.rfile.read(pad_len))
                    if bad_req:
                        self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                        continue
                    client = None
                    for user, passwd in USER_PASS.items():
                        h = hmac.new(passwd.encode(), ts + client_pkey + user.encode(), hashlib.sha256).digest()
                        if compare_digest(h, client_auth):
                            client = user
                            break
                    else:
                        logging.error('user not found. client_ip: %s' % self.client_address[0])
                        self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                        continue
                    pkey, passwd = KeyManager.create_key(client, client_pkey, pskcipher.key_len)
                    if pkey:
                        logging.info('new key exchange. client: %s, ip: %s' % (client, self.client_address[0]))
                        h = hmac.new(passwd.encode(), client_pkey + pkey + client.encode(), hashlib.sha256).digest()
                        scert = SERVER_CERT.get_pub_key()
                        signature = SERVER_CERT.sign(h, self.server.hash_algo)
                        data = chr(0) + chr(len(pkey)) + pkey + h + chr(len(scert)) + scert + chr(len(signature)) + signature\
                            + chr(rint) + os.urandom(rint)
                        self.wfile.write(pskcipher.encrypt(data))
                        continue
                    else:
                        logging.error('Private_key already registered. client: %s, ip: %s' % (client, self.client_address[0]))
                        self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                        continue
                elif cmd == 11:  # a connect request
                    client_pkey = pskcipher.decrypt(self.rfile.read(16))
                    if KeyManager.check_key(client_pkey):
                        ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                        self.rfile.read(ctlen)
                        self.rfile.read(pskcipher.key_len)
                        self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                        continue
                    user = KeyManager.pkeyuser[client_pkey]
                    cipher = encrypt.AEncryptor(KeyManager.pkeykey[client_pkey], self.server.method, SALT, CTX, 1)
                    ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                    ct = self.rfile.read(ctlen)
                    mac = self.rfile.read(cipher.key_len)
                    data = cipher.decrypt(ct, mac)
                    buf = io.BytesIO(data)
                    ts = buf.read(4)
                    if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                        logging.error('bad timestamp, possible replay attrack')
                        self.wfile.write(pskcipher.encrypt(chr(1) + chr(rint)) + os.urandom(rint))
                        continue
                    passwd = USER_PASS[user]
                    host_len = ord(buf.read(1))
                    addr = buf.read(host_len)
                    port = struct.unpack('>H', buf.read(2))[0]
                    if self._request_is_loopback((addr, port)) and port not in self.server.forward:
                        logging.info('server %d access localhost:%d denied. from %s:%d, %s' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1], user))
                        return self.wfile.write(pskcipher.encrypt(chr(2) + chr(rint)) + os.urandom(rint))
                    try:
                        remote = None
                        logging.info('server %d request %s:%d from %s:%d, %s' % (self.server.server_address[1],
                                     addr, port, self.client_address[0], self.client_address[1], user))
                        if self.server.reverse:
                            remote = create_connection(self.server.reverse, timeout=1)
                            a = 'CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, addr, port, self.client_address[0], self.client_address[1], user)
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
                        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        self.wfile.write(pskcipher.encrypt(chr(0) + chr(rint)) + os.urandom(rint))
                        # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except (IOError, OSError) as e:  # Connection refused
                        logging.warning('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                        self.wfile.write(pskcipher.encrypt(chr(2) + chr(rint)) + os.urandom(rint))
                        continue
                    if self.forward_tcp(self.connection, remote, cipher, pskcipher, timeout=60):
                        return
                elif cmd & 15 in (1, 3, 4):
                    # A shadowsocks request
                    ota = cmd & 16
                    if not self.server.ss:
                        logging.warning('shadowsocks not enabled for this server. port: %d' % self.server.server_address[1])
                        return
                    if cmd & 15 == 1:
                        _addr = pskcipher.decrypt(self.rfile.read(4))
                        addr = socket.inet_ntoa(_addr)
                    elif cmd & 15 == 3:
                        _addr = addr = pskcipher.decrypt(self.rfile.read(ord(pskcipher.decrypt(self.rfile.read(1)))))
                    elif cmd & 15 == 4:
                        _addr = socket.AF_INET6, pskcipher.decrypt(self.rfile.read(16))
                        addr = socket.inet_ntop(_addr)
                    port = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                    # verify
                    if ota:
                        header = chr(cmd) + _addr + struct.pack('>H', port)
                        self._ota_chunk_idx = 0
                        rmac = pskcipher.decrypt(self.rfile.read(10))
                        key = pskcipher.decipher_iv + pskcipher.key
                        mac = hmac.new(key, header, hashlib.sha1).digest()[:10]
                        if not compare_digest(rmac, mac):
                            continue

                    if self._request_is_loopback((addr, port)) and port not in self.server.forward:
                        logging.info('server %d access localhost:%d denied. from %s:%d' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1]))
                        return
                    try:
                        remote = None
                        logging.info('server %d SS request %s:%d from %s:%d %s' % (self.server.server_address[1],
                                     addr, port, self.client_address[0], self.client_address[1], 'with ota' if ota else ''))
                        if self.server.reverse:
                            remote = create_connection(self.server.reverse, timeout=1)
                            a = 'CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, addr, port, self.client_address[0], self.client_address[1], self.server.PSK)
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
                        if ota:
                            return self.ssforward_tcp_ota(self.connection, remote, pskcipher, timeout=60)
                        return self.ssforward_tcp(self.connection, remote, pskcipher, timeout=60)
                    except (IOError, OSError) as e:  # Connection refused
                        logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                        return
                else:
                    logging.warning('unknown cmd %d, bad encryption key?' % cmd)
                    ins, _, _ = select.select([self.connection], [], [], 1)
                    while ins:
                        data = self.connection.recv(self.bufsize)
                        if not data:
                            break
                        ins, _, _ = select.select([self.connection], [], [], 1)
                    break
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())

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
                    ct_len = self.rfile.read(2)
                    if not ct_len:
                        # client closed
                        fds.remove(local)
                        remote.shutdown(socket.SHUT_WR)
                        break
                    ct_len = struct.unpack('>H', pskcipher.decrypt(ct_len))[0]
                    ct = self.rfile.read(ct_len)
                    mac = self.rfile.read(cipher.key_len)
                    data = cipher.decrypt(ct, mac)
                    data = data[1:0-ord(data[0])] if ord(data[0]) else data[1:]
                    if data:
                        remote.sendall(data)
                    else:
                        # client is no longer sending anything, gracefully
                        remote.shutdown(socket.SHUT_WR)
                        fds.remove(local)
                        readable = 0
                if remote in ins:
                    data = remote.recv(self.bufsize)
                    if data:
                        padding_len = random.randint(64, 255) if len(data) < 256 else 0
                        data = chr(padding_len) + data + b'\x00' * padding_len
                        ct, mac = cipher.encrypt(data)
                        data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
                        local.sendall(data)
                    else:
                        # remote no longer sending anything.
                        padding_len = random.randint(64, 255)
                        data = chr(padding_len) + b'\x00' * padding_len
                        ct, mac = cipher.encrypt(data)
                        data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
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
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
            raise e
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
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
            raise e
        finally:
            for sock in (remote, local):
                try:
                    sock.close()
                except (OSError, IOError):
                    pass

    def ssforward_tcp_ota(self, local, remote, cipher, timeout=60):
        try:
            while 1:
                ins, _, _ = select.select([local, remote], [], [], timeout)
                if not ins:
                    break
                if local in ins:
                    data_len = struct.unpack('>H', cipher.decrypt(self.rfile.read(2)))[0]
                    rmac = cipher.decrypt(self.rfile.read(10))
                    data = cipher.decrypt(self.rfile.read(data_len))
                    index = struct.pack('>I', self._ota_chunk_idx)
                    key = cipher.decipher_iv + index
                    mac = hmac.new(key, data, hashlib.sha1).digest()[:10]
                    if encrypt.compare_digest(rmac, mac):
                        self._ota_chunk_idx += 1
                        remote.sendall(data)
                    else:
                        logging.warning('OTA Failed')
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
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
            raise e
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


def start_servers(config, forward):
    for serverinfo in config:
        try:
            logging.info('starting server: %s' % serverinfo)
            ssserver = HXSocksServer(serverinfo, forward, HXSocksHandler)
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
    global SERVER_CERT
    try:
        SERVER_CERT = ECC(from_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem'))
    except:
        logging.warning('server cert not found, creating...')
        SERVER_CERT = ECC(key_len=32)
        SERVER_CERT.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem'))

    servers = ['hxp://0.0.0.0:90']
    if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')):
        global USER_PASS
        d = json.loads(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')).read())
        USER_PASS = d['users']
        servers = d['servers']
        forward = d.get('forward', [])
    for s in servers:
        logging.info('starting server: %s' % s)
        ssserver = HXSocksServer(s, forward, HXSocksHandler)
        threading.Thread(target=ssserver.serve_forever).start()

if __name__ == '__main__':
    try:
        main()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        sys.exit(0)
