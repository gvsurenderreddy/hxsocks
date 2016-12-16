#!/usr/bin/env python
# coding: UTF-8
#
import sys
import io
try:
    from http.client import HTTPMessage
    import email
except ImportError:
    from httplib import HTTPMessage


def read_response_line(fp):
    line = fp.readline()
    if not line.startswith(b'HTTP'):
        raise IOError(0, 'bad response line: %r' % line)
    version, _, status = line.strip().partition(b' ')
    status, _, reason = status.partition(b' ')
    status = int(status)
    return line, version, status, reason


def read_request_line(fp):
    line = fp.readline()
    if not line.startswith(b'HTTP'):
        raise IOError(0, 'bad response line: %r' % line)
    command, _, uri = line.strip().partition(b' ')
    uri, _, version = uri.partition(b' ')
    return line, command, uri, version


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


def read_headers(fp):
    header_data = read_header_data(fp)
    headers = parse_headers(header_data)
    return header_data, headers


def parse_headers(data):
    if sys.version_info > (3, 0):
        return email.parser.Parser(_class=HTTPMessage).parsestr(data.decode('iso-8859-1'))
    else:
        fp = io.StringIO(data.decode('iso-8859-1'))
        return HTTPMessage(fp, 0)
