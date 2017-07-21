#!/usr/bin/env python

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

from collections import OrderedDict, defaultdict
import time
import random
import re
import socket
try:
    from ipaddr import IPAddress as ip_address
except ImportError:
    from ipaddress import ip_address as ip_address


def getaddrinfo(host, port=None, family=0, socktype=0, proto=0, flags=0):
    """return (family, socktype, proto, canonname, sockaddr)
       >>> socket.getaddrinfo("www.python.org", 80, 0, 0, socket.SOL_TCP)
       [(2, 1, 6, '', ('82.94.164.162', 80)),
        (10, 1, 6, '', ('2001:888:2000:d::a2', 80, 0, 0))]"""
    return socket.getaddrinfo(host, port, family, socktype, proto, flags)


def read_response_line(fp):
    line = fp.readline()
    if not line.startswith(b'HTTP'):
        raise IOError(0, 'bad response line: %r' % line)
    version, _, status = line.strip().partition(b' ')
    status, _, reason = status.partition(b' ')
    status = int(status)
    return line, version, status, reason


def read_header_data(fp):
    header_data = []
    while True:
        line = fp.readline()
        header_data.append(line)
        if line in (b'\r\n', b'\n', b'\r'):  # header ends with a empty line
            break
        if not line:
            raise IOError(0, 'remote socket closed')
    return b''.join(header_data)


def create_connection(address, timeout=object(), proxy=None, source_address=None):
    # proxy: http proxy only, using CONNECT method ('ip/hostname', port)
    if proxy:
        soc = _create_connection(proxy, timeout=timeout, source_address=source_address)
        s = ['CONNECT %s:%s HTTP/1.1\r\n' % (address[0], address[1]), ]
        s.append('Host: %s:%s\r\n\r\n' % (address[0], address[1]))
        soc.sendall(''.join(s).encode())
        remoterfile = soc.makefile('rb', 0)
        line, version, status, reason = read_response_line(remoterfile)
        if status != 200:
            raise IOError(0, 'create tunnel via %s failed!' % proxy)
        read_header_data(remoterfile)
        return soc
    return _create_connection(address, timeout=timeout, source_address=source_address)


def _create_connection(address, timeout=object(), source_address=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.
    """

    host, port = address
    err = None
    for res in getaddrinfo(host, port):
        af, socktype, proto, canonname, sa = res
        sock = None
        if af == 10:
            continue
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not object():
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


def get_ip_address(host):
    try:
        return ip_address(host)
    except:
        try:
            return ip_address(getaddrinfo(host)[0][4][1])
        except:
            return ip_address('0.0.0.0')


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


class iv_store(object):

    def __init__(self, maxlen, timeout):
        self.maxlen = maxlen
        self.timeout = timeout
        self.store = OrderedDict()
        self.last_time_used = time.time()

    def add(self, item):
        self.last_time_used = time.time()
        if random.random() < 0.01:
            self._clean()
        if item in self:
            raise ValueError("iv reused")
        self.store[item] = self.last_time_used
        while len(self.store) > self.maxlen:
            self.store.popitem()

    def __contains__(self, item):
        if random.random() < 0.01:
            self._clean()
        self.last_time_used = time.time()
        try:
            if self.store[item] < time.time() - self.timeout:
                while True:
                    a, _ = self.store.popitem()
                    if a == item:
                        break
                return False
            else:
                return True
        except KeyError:
            return False

    def _clean(self):
        garbage = []
        for k in self.store:
            if self.store[k] < time.time() - self.timeout:
                garbage.append(k)
            else:
                break
        for k in garbage:
            del self.store[k]

    def __str__(self):
        return str([k for k in self.store])

    def __repr__(self):
        return str([k for k in self.store])


class iv_checker(object):
    # check reused iv, removing out-dated data automatically

    def __init__(self, maxlen, timeout):
        self.timeout = timeout * 10
        self.store = defaultdict(lambda: iv_store(maxlen, timeout * 2))

    def check(self, key, iv):
        if random.random() < 0.01:
            self._clean()
        self.store[key].add(iv)

    def _clean(self):
        garbage = []
        for k, v in self.store.items():
            if v.last_time_used < time.time() - self.timeout:
                garbage.append(k)
        for k in garbage:
            del self.store[k]


if __name__ == "__main__":
    t = socket.getaddrinfo('www.baidu.com', 80)
    r = getaddrinfo('www.baidu.com')
    print(t)
    print(r)
    print(r[0][4][0])
