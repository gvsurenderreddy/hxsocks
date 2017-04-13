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
import base64
from email.utils import formatdate
import hashlib
import hmac
import logging
import io
import json
import urlparse
import traceback
from collections import defaultdict, deque
from util import create_connection, get_ip_address
import encrypt
from encrypt import compare_digest
from ecc import ECC
from httputil import read_headers

__version__ = '0.0.1'

DEFAULT_METHOD = 'aes-128-cfb'
DEFAULT_HASH = 'sha256'
MAC_LEN = 16
CTX = b'hxsocks'

MAGIC_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

RESPONSE_HEADER = b'''\
HTTP/1.1 200 OK\r\n\
Server: {server}\r\n\
Date: {date}\r\n\
Content-Type: application/octet-stream\r\n\
Content-Length: {size}\r\n\
Connection: keep-alive\r\n\
Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform\r\n\
Pragma: no-cache\r\n\
\r\n'''

RESPONSE_HEADER_WS = b'''\
HTTP/1.1 101 Switching Protocols\r\n\
Server: {server}\r\n\
Date: {date}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n'
Sec-WebSocket-Accept: {ws_accept}\r\n\
\r\n'''

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

    @classmethod
    def get_user_by_pubkey(cls, pubkey):
        return cls.pkeyuser[pubkey]

    @classmethod
    def get_skey_by_pubkey(cls, pubkey):
        return cls.pkeykey[pubkey]


class HXSocksServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, serverinfo, forward, RequestHandlerClass, bind_and_activate=True):
        self.serverinfo = serverinfo
        self.forward = set(forward)
        p = urlparse.urlparse(serverinfo)
        if p.scheme == 'ss':
            self.PSK, self.method = p.password, p.username
        elif p.scheme == 'hxs':
            self.PSK = urlparse.parse_qs(p.query).get('PSK', [''])[0]
            self.method = urlparse.parse_qs(p.query).get('method', [DEFAULT_METHOD])[0]
        else:
            raise ValueError('bad serverinfo: {}'.format(self.serverinfo))

        q = urlparse.parse_qs(p.query)

        self.server = q.get('UA', ['nginx/1.2.2'])[0]
        self._http_obfs = False

        self.hash_algo = q.get('hash', [DEFAULT_HASH])[0].upper()
        self.ss = self.PSK and q.get('ss', ['1'])[0] == '1'

        addrs = socket.getaddrinfo(p.hostname, p.port)
        if not addrs:
            raise ValueError('cant resolve listen address')
        self.address_family = addrs[0][0]
        server_address = (p.hostname, p.port)
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)


class HXSocksHandler(SocketServer.StreamRequestHandler):
    timeout = 10
    bufsize = 1024 * 16

    def handle(self):
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            pskcipher = encrypt.Encryptor(self.server.PSK, self.server.method)
            self.connection.settimeout(self.timeout)
            data = self.rfile.read(4)
            if data in (b'GET ', b'POST'):
                self._http_obfs = True
                data += self.rfile.readline()
                header_data, headers = read_headers(self.rfile)
                # prep response
                d = {'date': formatdate(timeval=None, localtime=False, usegmt=True),
                     'server': self.server.server,
                     }
                if headers.get('Upgrade', '') == 'websocket':
                    sec_key = headers.get('Sec-WebSocket-Key', '')
                    d['ws_accept'] = base64.b64encode(hashlib.sha1(sec_key + MAGIC_GUID).digest())
                    response_header = RESPONSE_HEADER_WS.format(**d)
                else:
                    d['size'] = random.randint(128, 1024)
                    response_header = RESPONSE_HEADER.format(**d)
                # send response
                self.wfile.write(response_header)
                data = self.rfile.read(pskcipher.iv_len)
            else:
                self._http_obfs = False
                data += self.rfile.read(pskcipher.iv_len - 4)
            pskcipher.decrypt(data)
            while True:
                try:
                    data = self.rfile.read(1)
                    self.connection.settimeout(self.timeout)
                    cmd = ord(pskcipher.decrypt(data))
                except Exception as e:
                    logging.error('cmd Exception: server %s %r from %s:%s' % (self.server.server_address[1], e, self.client_address[0], self.client_address[1]))
                    break
                if cmd == 10:  # client key exchange
                    rint = random.randint(64, 255)
                    req_len = pskcipher.decrypt(self.rfile.read(2))
                    req_len = struct.unpack('>H', req_len)[0]
                    data = pskcipher.decrypt(self.rfile.read(req_len))
                    data = io.BytesIO(data)
                    ts = data.read(4)
                    if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                        # possible replay attack
                        logging.error('bad timestamp. client_ip: %s' % self.client_address[0])
                        break
                    pklen = ord(data.read(1))
                    client_pkey = data.read(pklen)
                    client_auth = data.read(32)

                    def _send(data):
                        data = struct.pack('>H', len(data)) + data
                        self.wfile.write(pskcipher.encrypt(data))

                    client = None
                    for user, passwd in USER_PASS.items():
                        h = hmac.new(passwd.encode(), ts + client_pkey + user.encode(), hashlib.sha256).digest()
                        if compare_digest(h, client_auth):
                            client = user
                            break
                    else:
                        logging.error('user not found. client_ip: %s' % self.client_address[0])
                        break
                    pkey, passwd = KeyManager.create_key(client, client_pkey, pskcipher.key_len)
                    if pkey:
                        logging.info('new key exchange. client: %s, ip: %s' % (client, self.client_address[0]))
                        h = hmac.new(passwd.encode(), client_pkey + pkey + client.encode(), hashlib.sha256).digest()
                        scert = SERVER_CERT.get_pub_key()
                        signature = SERVER_CERT.sign(h, self.server.hash_algo)
                        data = chr(0) + chr(len(pkey)) + chr(len(scert)) + chr(len(signature)) + pkey + h + scert + signature + os.urandom(rint)
                        _send(data)
                        continue
                    else:
                        logging.error('Private_key already registered. client: %s, ip: %s' % (client, self.client_address[0]))
                        # KeyManager.del_key(hashlib.md5(client_pkey).digest())
                        break
                elif cmd == 11:  # a connect request
                    client_pkey = pskcipher.decrypt(self.rfile.read(16))
                    rint = random.randint(64, 2048)

                    def _send(code, cipher):
                        if code == 1:
                            data = os.urandom(rint)
                            data = pskcipher.encrypt(struct.pack('>H', rint)) + data
                            self.wfile.write(data)
                        else:
                            ct = cipher.encrypt(chr(code) + os.urandom(rint-1))
                            data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
                            self.wfile.write(data)

                    if KeyManager.check_key(client_pkey):
                        logging.error('client key not exist or expired. client ip: %s' % self.client_address[0])
                        ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                        self.rfile.read(ctlen)
                        _send(1, None)
                        continue

                    user = KeyManager.get_user_by_pubkey(client_pkey)
                    cipher = encrypt.AEncryptor(KeyManager.get_skey_by_pubkey(client_pkey), self.server.method, CTX)
                    ctlen = struct.unpack('>H', pskcipher.decrypt(self.rfile.read(2)))[0]
                    ct = self.rfile.read(ctlen)
                    data = cipher.decrypt(ct)
                    buf = io.BytesIO(data)
                    ts = buf.read(4)
                    if abs(struct.unpack('>I', ts)[0] - time.time()) > 600:
                        logging.error('bad timestamp, possible replay attrack. client ip: %s' % self.client_address[0])
                        # KeyManager.del_key(client_pkey)
                        # _send(1, None)
                        break
                    host_len = ord(buf.read(1))
                    addr = buf.read(host_len)
                    port = struct.unpack('>H', buf.read(2))[0]
                    if self._request_is_loopback((addr, port)) and port not in self.server.forward:
                        logging.info('server %d access localhost:%d denied. from %s:%d, %s' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1], user))
                        _send(2, cipher)
                        continue
                    try:
                        logging.info('server %d request %s:%d from %s:%d, %s' % (self.server.server_address[1],
                                     addr, port, self.client_address[0], self.client_address[1], user))
                        remote = create_connection((addr, port), timeout=10)
                        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        _send(0, cipher)
                        # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except (IOError, OSError) as e:  # Connection refused
                        logging.warning('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                        _send(2, cipher)
                        continue
                    if self.forward_tcp(self.connection, remote, cipher, pskcipher, timeout=60):
                        break
                    self.connection.settimeout(60)
                    logging.debug('hxsocks connect reusable, except next connection')
                elif cmd in (1, 3, 4, 17, 19, 20):
                    # A shadowsocks request
                    if not self.server.ss:
                        logging.warning('shadowsocks not enabled for this server. port: %d' % self.server.server_address[1])
                        break
                    ota = cmd & 16
                    if cmd & 15 == 1:
                        _addr = pskcipher.decrypt(self.rfile.read(4))
                        addr = socket.inet_ntoa(_addr)
                    elif cmd & 15 == 3:
                        _addr = pskcipher.decrypt(self.rfile.read(1))
                        addr = pskcipher.decrypt(self.rfile.read(ord(_addr)))
                        _addr += addr
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
                            logging.error("OTA Failed!!")
                            break

                    if self._request_is_loopback((addr, port)) and port not in self.server.forward:
                        logging.info('server %d access localhost:%d denied. from %s:%d' % (self.server.server_address[1], port, self.client_address[0], self.client_address[1]))
                        break
                    try:
                        remote = None
                        logging.info('server %d SS request %s:%d from %s:%d %s' % (self.server.server_address[1],
                                     addr, port, self.client_address[0], self.client_address[1], 'with ota' if ota else ''))
                        remote = create_connection((addr, port), timeout=10)
                        if ota:
                            return self.ssforward_tcp_ota(self.connection, remote, pskcipher, timeout=60)
                        return self.ssforward_tcp(self.connection, remote, pskcipher, timeout=60)
                    except (IOError, OSError) as e:  # Connection refused
                        logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                        return
                else:
                    logging.warning('unknown cmd %d, bad encryption key?' % cmd)
                    break
            ins, _, _ = select.select([self.connection], [], [], 1)
            while ins:
                data = self.connection.recv(self.bufsize)
                if not data:
                    break
                ins, _, _ = select.select([self.connection], [], [], 1)
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())

    def forward_tcp(self, local, remote, cipher, pskcipher, timeout=60):
        readable = 1
        writeable = 1
        fds = [local, remote]
        total_send = 0
        try:
            while fds:
                if len(fds) < 2:
                    timeout = 10
                ins, _, _ = select.select(fds, [], [], timeout)
                if not ins:
                    logging.debug('timed out')
                    break
                if local in ins:
                    ct_len = self.rfile.read(2)
                    if not ct_len:
                        logging.debug('client closed')
                        fds.remove(local)
                        remote.shutdown(socket.SHUT_WR)
                        break
                    ct_len = struct.unpack('>H', pskcipher.decrypt(ct_len))[0]
                    ct = self.rfile.read(ct_len)
                    data = cipher.decrypt(ct)
                    pad_len = ord(data[0])
                    cmd = ord(data[-1])
                    if 0 < pad_len < 8:
                        # fake chunk, drop
                        # TODO: respond fake chunk if pad_len == 1, could cause trouble
                        pass
                    else:
                        data = data[1:0-pad_len] if pad_len else data[1:]
                        if data:
                            remote.sendall(data)
                        else:
                            logging.debug('client close, gracefully')
                            if cmd:
                                remote.close()
                            else:
                                remote.shutdown(socket.SHUT_WR)
                            fds.remove(local)
                            readable = 0

                if remote in ins:
                    data = remote.recv(self.bufsize)
                    if not data:
                        writeable = 0
                        fds.remove(remote)
                        if total_send < 8196 and random.random() < 0.5:
                            _data = chr(2) + b'\x00' * random.randint(1024, 8196)
                            ct = cipher.encrypt(_data)
                            _data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
                            local.sendall(_data)
                    total_send += len(data)
                    padding_len = random.randint(8, 255)
                    data = chr(padding_len) + data + b'\x00' * padding_len
                    ct = cipher.encrypt(data)
                    data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
                    local.sendall(data)
        except socket.timeout:
            pass
        except (OSError, IOError) as e:
            if e.args[0] in (errno.EBADF,):
                return
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
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
            if e.args[0] in (errno.EBADF,):
                return
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
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
            if e.args[0] in (errno.EBADF,):
                return
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc())
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
    logging.basicConfig(level=logging.INFO,
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

    servers = ['hxs://0.0.0.0:9000']
    forward = []
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
