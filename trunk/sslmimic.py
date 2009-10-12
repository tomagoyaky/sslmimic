#!/usr/bin/python
#
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
SSLMimic. A simple SSL enabled HTTP debugging proxy.

This proxy will generate detailed timing information for HTTP transactions.
It can produce detailed binary logs, or dump debugging information to STDOUT.

SSLMimic also supports debugging SSL protected applications.
"""

__author__ = 'naustin@google.com (Nick Austin)'
__version__ = '$Id:$'

import socket
import os
import sys
import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
import math
import select
import time
import logging
import decimal
import sre
import signal
import getopt
import ssl_proxy_log
#import mx.TextTools
import tempfile

import OpenSSL

##
## (TODO: naustin) Include first to last timing (Throughput)
##

class SSLFile2(socket._fileobject):
  """
  Subclass of sockets _fileobject class that adds support for SSL readline.

  Use this in place of socket.makefile.

  See socket._fileobject for use instructions.
  """
  def read(self, size=-1):
    """
    Same as socket._fileobject.read
    """
    data = self._rbuf
    if size < 0:
      # Read until EOF
      buffers = []
      if data:
        buffers.append(data)
      self._rbuf = ""
      if self._rbufsize <= 1:
        recv_size = self.default_bufsize
      else:
        recv_size = self._rbufsize
      while True:
        data = self._sock.recv(recv_size)
        if not data:
          break
        buffers.append(data)
      return "".join(buffers)
    else:
      # Read until size bytes or EOF seen, whichever comes first
      buf_len = len(data)
      if buf_len >= size:
        self._rbuf = data[size:]
        return data[:size]
      buffers = []
      if data:
        buffers.append(data)
      self._rbuf = ""
      while True:
        left = size - buf_len
        recv_size = max(self._rbufsize, left)
        try:
          data = self._sock.recv(recv_size)
        except OpenSSL.SSL.ZeroReturnError:
          data = ''
        except OpenSSL.SSL.SysCallError:
          data = ''
        if not data:
          break
        buffers.append(data)
        n = len(data)
        if n >= left:
          self._rbuf = data[left:]
          buffers[-1] = data[:left]
          break
        buf_len += n
      return "".join(buffers)

class ProxyServer(BaseHTTPServer.HTTPServer):
  """
  ProxyServer class that defines a new StartSSL function.
  """
  def __init__(self, server_address, HandlerClass):
    BaseHTTPServer.HTTPServer.__init__(self, server_address, HandlerClass)
    #SocketServer.BaseServer.__init__(self, server_address, HandlerClass)
    self.socket = socket.socket(self.address_family, self.socket_type)
    self.server_bind()
    self.server_activate()

  def StartSSL(self):
    context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    #self.socket = OpenSSL.SSL.Connection(context,
    #    socket.socket(self.address_family, self.socket_type))
    self.socket = OpenSSL.tsafe.Connection(context,
        socket.socket(self.address_family, self.socket_type))

class ProxyRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
  """
  Main request handling class.

  All of the heavy lifiting is done in this class.
  """
  interactive = False
  display_filter = None
  dump_payload = None
  log = logging

  # False here means don't spoof
  spoof_ssl_config = {'DEFAULT': True, 'secure.example.com:443': False}

  ssl_redirect_table = {}
  http_redirect_table = {}
  log_file = None
  cert = None

  def setup(self):
    self.connection = self.request
    self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
    self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

  def SetErrorState(self, request_log, error_num, error_name):
    self.send_error(error_num, error_name)
    request_log.TimeStop('total')
    request_log.SetValue('response_code', error_num)
    request_log.SetValue('response_disposition', error_name)
    request_log.WriteLog(self.log_file)

  def fetch2(self, request, responsefd, datafd = None):

    # FIXME: We should plot number of packets

    fetch_logging = logging.getLogger('fetch2')
    fetch_logging.debug('In fetch2')
    request_log = ssl_proxy_log.Log()
    request_log.SetValue('request_time', decimal.Decimal(repr(time.time())))
    request_log.TimeStart('total')
    RSIZE = 65535
    #RSIZE = 4000000
    outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    outbound_request = request.GetOutboundRequest()
    target_host = request.GetTargetHost()
    request_log.SetValue('request', request)
    request_log.SetValue('client', self.client_address)

    fetch_logging.debug('URI: %s' % request.GetURI())
    fetch_logging.debug('TargetHost: %s:%s' % target_host)

    if request.GetMethod() == 'POST':
      headers = request.GetHeaders()
      if 'content-length' in headers:
        content_length = int(headers['content-length'])
        request_log.SetValue('client_content-length', content_length)
      else:
        content_length = None

    fetch_logging.debug('Starting DNS resolution')
    request_log.TimeStart('dns')
    try:
      target_ip = socket.gethostbyname(target_host[0])
    except socket.gaierror, e:
      request_log.TimeStop('dns')
      self.SetErrorState(request_log, 503, 'DNS error: %s' % e)
      return request_log
    request_log.TimeStop('dns')
    request_log.SetValue('target_ip', target_ip)
    fetch_logging.debug('Completed DNS resolution')

    fetch_logging.debug('Starting connect')
    try:
      request_log.SetValue('pid', os.getpid())
      request_log.SetValue('connect_begin', time.time())
      request_log.TimeStart('connect')
      outbound_connection.connect((target_ip, target_host[1]))
      request_log.TimeStop('connect')
      request_log.SetValue('connect_end', time.time())
    except socket.error, e:
      request_log.TimeStop('connect')
      request_log.SetValue('connect_end', time.time())
      self.SetErrorState(request_log, 503, \
                         'Service Unavailable: Socket error: %s' % e)
      return request_log
    fetch_logging.debug('Connect completed')


    # If this is an SSL request, do the SSL handshake and replace the
    # connection variables
    if request.IsSSL():
      fetch_logging.debug('This IS an SSL request')
      context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
      context.set_info_callback(InfoCall)
      https_connection = OpenSSL.SSL.Connection(context, outbound_connection)
      https_connection.set_connect_state()
      request_log.TimeStart('ssl_handshake')
      https_connection.do_handshake()
      request_log.TimeStop('ssl_handshake')
      https_connection.state_string()

      outbound_connection = https_connection
      #outbound_connection_file = socket._fileobject(outbound_connection, 'rb')
      outbound_connection_file = SSLFile2(outbound_connection)

    else:
      fetch_logging.debug('This is NOT an SSL request')
      outbound_connection_file = outbound_connection.makefile('rb')


    fetch_logging.debug('Sending request to server')
    try:
      outbound_connection.sendall(outbound_request)
    except socket.error, e:
      self.SetErrorState(request_log, 503, \
                         'Service Unavailable: Socket error: %s' % e)
      return request_log
    fetch_logging.debug('Completed sending request to server')

    # If we have a content_length, and an incoming postfd, send post data:
    if datafd and content_length:
      fetch_logging.debug('Starting post with content_length')
      request_log.TimeStart('post_cycle')

      iterations_req = int(math.ceil(float(content_length) / RSIZE))
      last_itr = content_length % RSIZE
      for itr in xrange(1, iterations_req + 1):
        if itr == iterations_req and last_itr > 0:
          post_block = datafd.read(last_itr)
        else:
          post_block = datafd.read(RSIZE)
        outbound_connection.sendall(post_block)
      request_log.TimeStop('post_cycle')
      fetch_logging.debug('Completed post')

    # If we only have an incoming postfd, then look for a EOF for the end.
    elif datafd:
      fetch_logging.debug('Starting post withOUT content_length')
      request_log.TimeStart('post_cycle')
      post_block = datafd.read(RSIZE)
      post_block_len = len(post_block)
      # Once you read nothing, you know that the connection is over.
      while len(post_block) > 0:
        outbound_connection.sendall(post_block)
        post_block = datafd.read(RSIZE)
        post_block_len += len(post_block)
      request_log.TimeStop('post_cycle')
      request_log.SetValue('client_content-length', post_block_len)
      fetch_logging.debug('Completed post')

    fetch_logging.debug('selecting on server connection')
    request_log.TimeStart('headers')
    request_log.TimeStart('first_byte')
    select.select([outbound_connection], [], [])
    request_log.TimeStop('first_byte')
    fetch_logging.debug('select completed')

    fetch_logging.debug('Calling readline on server connection')
    http_response = outbound_connection_file.readline()
    request_log.SetValue('inbound_headers_size', len(http_response))
    fetch_logging.debug('Readline on server connection completed')

    if len(http_response) == 0:
      self.SetErrorState(request_log, 503, \
                         'Service Unavailable: No response from server')
      return request_log

    if not http_response.startswith('HTTP'):
      self.SetErrorState(request_log, 503, \
                         'Service Unavailable: Server response does'
                         ' not start with HTTP')
      return request_log

    # Take second argument (numeric response) and add that to the log obj
    request_log.SetValue('response_code', http_response.split(' ')[1])
    request_log.SetValue('raw_response', http_response)

    fetch_logging.debug('Starting header collection')
    header_count = 0
    while header_count < 100:
      fetch_logging.debug('Calling readline on server connection')
      header_line = outbound_connection_file.readline()
      fetch_logging.debug('Readline on server connection completed: %s' %
        len(header_line))
      header_count += 1
      request_log.SetValue('inbound_headers_size',
          request_log.GetValue('inbound_headers_size') + len(http_response))
      if header_line.lower().startswith('connection'):
        http_response = http_response + 'Proxy-connection: Close\r\n'
        continue
      #XXX: This is for the cache-control test.
      #XXX: This should be replaced with nice header rewrite code.
      elif header_line.lower().startswith('cache-control'):
        #http_response = http_response + 'Cache-Control: public; max-age=72000\r\n'
        #http_response = http_response + 'Expires: Tue, 18 Jan 2018 00:00:00 GMT\r\n'
        pass
        continue
      http_response = http_response + header_line
      if header_line == '\r\n':
        break
      if header_line == '\n' or header_line == '\r':
        self.SetErrorState(request_log, 503, \
                           'Service Unavailable: Servers headers'
                           ' may not end in \\r\\n')
        return request_log

    request_log.SetValue('number_inbound_headers', header_count)
    request_log.SetValue('raw_response', http_response)

    if header_count >= 100:
      self.SetErrorState(request_log, 503, \
                         'Service Unavailable: > then 100 headers' \
                         ' returned from server')
      return request_log
    request_log.TimeStop('headers')
    fetch_logging.debug('Finished header collection')

    response_lines = http_response.split('\r\n')

    request_log.TimeStart('body')
    inbound_content_len = None
    for line in response_lines:
      if line.lower().startswith('content-length'):
        inbound_content_len = int(line.split(':')[1])
        request_log.SetValue('server_content_len', inbound_content_len)

    complete_payload = []

    if inbound_content_len:
      fetch_logging.debug('Starting read with server_content_len: %s'
          % inbound_content_len)
      iterations_req = int(math.ceil(float(inbound_content_len) / RSIZE))
      last_itr = inbound_content_len % RSIZE
      responsefd.write(http_response)
      for itr in xrange(1, iterations_req + 1):
        if itr == iterations_req and last_itr > 0:
          http_response = outbound_connection_file.read(last_itr)
          # Dump payload to stdout if so configured
          if self.dump_payload:
            complete_payload.append(http_response)
        else:
          try:
            http_response = outbound_connection_file.read(RSIZE)
          except OpenSSL.SSL.SysCallError, error:
            fetch_logging.debug('exception: %s' % error)
        try:
          responsefd.write(http_response)
        except socket.error, e:
          fetch_logging.info('%s: Socket error: %s' % (self.client_address, e))
          request_log.SetValue('response_disposition', 'Socket error: %s' % e)
          request_log.TimeStop('total')
          request_log.WriteLog(self.log_file)
          return request_log

    else:
      fetch_logging.debug('Starting read without server_content_len')
      request_log.SetValue('server_content_len', 0)

      while len(http_response) > 0:
        try:
          responsefd.write(http_response)
        except socket.error, e:
          fetch_logging.info('%s: Socket error: %s' % (self.client_address, e))
          request_log.SetValue('response_disposition',
                               'Client Socket error: %s' % e)
          request_log.WriteLog(self.log_file)
          return request_log
        try:
          http_response = outbound_connection_file.read(RSIZE)
          fetch_logging.debug('Read %s bytes' % len(http_response))
          # Dump payload to stdout if so configured
          if self.dump_payload:
            complete_payload.append(http_response)
        except OpenSSL.SSL.ZeroReturnError, error:
          fetch_logging.debug('exception: %s' % error)
          http_response = ''
        request_log.SetValue('server_content_len',
            request_log.GetValue('server_content_len') + len(http_response))

    if self.dump_payload:
      request_log.SetValue('server_payload', ''.join(complete_payload))
    request_log.SetValue('response_disposition', 'Success')
    request_log.TimeStop('body')
    request_log.TimeStop('total')
    request_log.WriteLog(self.log_file)
    return request_log
    # End of fetch2

  def BypassSSL(self, request, connection, timeout=10):
    """ This function connects the sever and client, passing through
    all data untouched.
    """
    RSIZE = 8192
    request_log = ssl_proxy_log.Log()
    request_log.SetValue('request', request)
    request_log.SetValue('request_time', decimal.Decimal(repr(time.time())))
    request_log.SetValue('client', self.client_address)

    fetch_logging = logging.getLogger('BypassSSL')

    fetch_logging.debug('Entering BypassSSL')
    target_host = request.GetTargetHost()
    fetch_logging.debug('target_host: %s:%s' % target_host)

    request_log.TimeStart('total')

    fetch_logging.debug('Starting DNS resolution')
    request_log.TimeStart('dns')
    try:
      target_ip = socket.gethostbyname(target_host[0])
    except socket.gaierror, e:
      request_log.TimeStop('dns')
      self.SetErrorState(request_log, 503, 'DNS error: %s' % e)
      return request_log

    request_log.TimeStop('dns')
    request_log.SetValue('target_ip', target_ip)
    fetch_logging.debug('Completed DNS resolution')

    outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outbound_connection.settimeout(timeout)

    client_id = connection.getpeername()

    fetch_logging.debug('Starting connect')
    try:
      request_log.SetValue('connect_begin', time.time())
      request_log.TimeStart('connect')
      outbound_connection.connect((target_ip, target_host[1]))
      request_log.TimeStop('connect')
      request_log.SetValue('connect_end', time.time())
    except socket.error, e:
      fetch_logging.debug('Connection to %s:%s failed: %s' % (target_host[0],
        target_host[1], e))
      request_log.TimeStop('connect')
      self.SetErrorState(request_log, 500, 'Connection Failed: %s' % e)
      return request_log

    # Once we've managed to open a connection to the target endpoint, tell
    # the client we're ready for more data.
    fetch_logging.debug('Sending HTTP 200 OK to client')
    connection.sendall('HTTP/1.0 200 OK Connected\r\n\r\n')

    request_log.SetValue('client_content-length', 0)
    request_log.SetValue('server_content-length', 0)


    client_data_len = 0
    server_data_len = 0

    request_log.TimeStart('body')
    while True:
      ready = select.select([outbound_connection, connection], [],
          [outbound_connection, connection])

      if ready[2]:
        fetch_logging.debug('Exception reported from select on: %s' %
            ready[2][0])
        request_log.TimeStop('body')
        request_log.TimeStop('total')
        request_log.SetValue('response_code', None)
        request_log.SetValue('response_disposition',
            'exceptional condition from select')
        request_log.WriteLog(self.log_file)

        outbound_connection.close()
        return request_log

      for i in ready[0]:
        # For every socket that has data waiting, read data into buffer, and
        # dump on other socket.
        data = i.recv(RSIZE)
        if i == outbound_connection:
          target = connection
          host = target_host
          server_data_len += len(data)
        else:
          target = outbound_connection
          host = client_id
          client_data_len += len(data)

        if not data:
          # This is in the event of a zero byte read (ie connection closed)
          fetch_logging.debug('End of data on: %s:%s' % host)
          outbound_connection.close()
          request_log.TimeStop('body')
          request_log.TimeStop('total')
          request_log.SetValue('client_content-length', client_data_len)
          request_log.SetValue('server_content-length', server_data_len)
          request_log.SetValue('response_disposition', 'Success')
          return request_log

        # Send data from source -> target after it is ready to recv
        select.select([], [target], [])
        target.sendall(data)

  def SpoofSSL(self, request, connection):
    """ This Function starts an SSL connection to the client, and updates
    rfile, wfile, and connection with the new SSL targets.
    """
    self.log.debug('Entering SpoofSSL')
    target_host = request.GetTargetHost()

    self.log.debug('target_host: %s:%s' % target_host)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)

    if not self.cert:
      raise ValueError, 'self.cert not defined: Can not spoof SSL without cert'

    context.use_privatekey_file(self.cert)
    context.use_certificate_file(self.cert)

    self.log.debug('SSL context built')
    self.log.debug('Sending HTTP 200 OK to client')

    connection.sendall('HTTP/1.0 200 OK Connected\r\n\r\n')

    ssl_connection = OpenSSL.SSL.Connection(context, connection)
    ssl_connection.set_accept_state()
    self.log.debug('Select(ing) on connection socket')
    select.select([connection], [], [])
    self.log.debug('SSL calling do_handshake()')
    ssl_connection.do_handshake()
    self.log.debug('SSL do_handshake() completed')

    ssl_connection.state_string()

    self.log.debug('Building SSL fileobjects')
    new_connection_write = socket._fileobject(ssl_connection, 'w')
    new_connection_read = socket._fileobject(ssl_connection, 'r')
    new_connection = socket._fileobject(ssl_connection)
    self.log.debug('Done building SSL fileobjects')

    self.connection = ssl_connection
    self.wfile = new_connection_write
    self.rfile = new_connection_read

    return True

  def do_POST(self):
    """
    Function called by HTTPServer. (Need one of these for each of the HTTP
    verbs.
    """
    orig_request = ssl_proxy_log.Request(self.path, 'POST', self.headers,
        self.log, self.http_redirect_table, self.ssl_redirect_table)
    self.log.debug('do_POST called: %s' % self.path)
    request_log = self.fetch2(orig_request, self.wfile, self.rfile)

    if not request_log:
      return

    if self.display_filter:
      if not self.display_filter.search(self.path):
        return

    if self.interactive:
      self.Log(request_log)

  def HeadGet(self, method):
    """
    This function is called for both the HEAD and GET verbs.
    """
    self.log.debug('HeadGet called: %s' % self.path)
    orig_request = ssl_proxy_log.Request(self.path, method, self.headers,
        self.log, self.http_redirect_table, self.ssl_redirect_table)
    self.log.debug('orig_request built, calling fetch2')

    request_log = self.fetch2(orig_request, self.wfile)

    if not request_log:
      return

    if self.display_filter:
      if not self.display_filter.search(self.path):
        return

    if self.interactive:
      self.Log(request_log)

    #log.SetValue('url', self.path)
    #self.Log(log)

  def do_GET(self):
    """
    Function called by HTTPServer. (Need one of these for each of the HTTP
    verbs.
    """
    self.log.debug('do_GET called')
    self.HeadGet('GET')

  def do_HEAD(self):
    """
    Function called by HTTPServer. (Need one of these for each of the HTTP
    verbs.
    """
    self.log.debug('do_HEAD called')
    self.HeadGet('HEAD')

  def SSLSpoofCheck(self, host):
    spoof = None
    if self.spoof_ssl_config.has_key(self.path):
      spoof = self.spoof_ssl_config[self.path]
    else:
      for i in self.spoof_ssl_config:
        if sre.search(i, self.path):
          self.log.debug('SSLSpoofCheck %s matched %s' % (i, host))
          spoof = self.spoof_ssl_config[i]
          break

    if spoof == None:
      self.log.debug('SSLSpoofCheck no matches, using DEFAULT')
      spoof = self.spoof_ssl_config['DEFAULT']

    self.log.debug('SSLSpoofCheck for %s: %s' % (host, spoof))
    return spoof

  def do_CONNECT(self):
    """
    Function called by HTTPServer. (Need one of these for each of the HTTP
    verbs.

    This function has all of the special case logic for MIMing SSL connections.

    If we're supposed to be MIMing a connection we do the following:
      1) Tell the client that they are connected to the target.
      2) Perform SSL negotiation. (Client will get SSL warning at this point)
      3) Read client request that would have been sent to the real server.
      4) Build new request and call the appropriate method (HEAD, GET, etc).
    """
    self.log.debug('do_CONNECT called')
    pre_ssl_request = ssl_proxy_log.Request(self.path, 'CONNECT', self.headers,
        self.log, self.http_redirect_table, self.ssl_redirect_table)

    spoof = self.SSLSpoofCheck(self.path)

    if not spoof:
      request_log = self.BypassSSL(pre_ssl_request, self.connection)

      if not request_log:
        return

      if self.interactive:
        self.Log(request_log)

      return

    ssl_response = self.SpoofSSL(pre_ssl_request, self.connection)
    self.log.debug('do_CONNECT: Host to connect to: %s' % self.path)

    # Now that the Client thinks they are talking to the server, redo the
    # request processing as if we are the target server.
    self.raw_requestline = self.rfile.readline()
    if not self.raw_requestline:
      self.close_connection = 1
      return False

    if not self.parse_request(): # An error code has been sent, just exit
      return False

    mname = 'do_' + self.command

    if not hasattr(self, mname):
      self.send_error(501, "Unsupported method (%r)" % self.command)
      return False

    method = getattr(self, mname)

    # Build a new path for an HTTPS operation, and call the correct method
    target_host = pre_ssl_request.GetTargetHost()
    self.path = 'https://%s:%s%s' % (target_host[0], target_host[1], self.path)

    if not hasattr(self, mname):
      self.send_error(501, "Unsupported method (%r)" % self.command)
      return

    self.log.debug('do_CONNECT: New SSL path: %s' % self.path)

    method = getattr(self, mname)
    method()

  def Log(self, times):
    """
    Used to dump log info during interactive request.

    Args:
      times (ssl_proxy_request.Log obj)

    Returns:
      None. (Dumps info to stdout).
    """

    print '--'
    print times.PrettyPrintLog()

    return

def InfoCall(connection, functionno, rc):
  """Callback for SSL handshake messages """

  ssl_logging = logging.getLogger('SSL_InfoCall')

  ssl_logging.debug('In InfoCall')
  ssl_logging.debug('State         : %s' % connection.state_string())
  ssl_logging.debug('Fuction Number: %s' % functionno)
  ssl_logging.debug('Return Code   : %s' % rc)
  return 0

def ProxyDaemon(log_file = '/var/log/ssl_proxy_access.log',
         HandlerClass = ProxyRequestHandler,
         ServerClass = ProxyServer, protocol="HTTP/1.0",
         thread = True, interactive = False, port = 1443,
         spoof_ssl_config = { 'DEFAULT': True },
         display_filter = None, cert = None, dump_payload = False,
         http_redirect_table = {}, ssl_redirect_table = {}, log = logging):
  sys.setcheckinterval(10)
  server_address = ('0.0.0.0', port)
  HandlerClass.protocol_version = protocol
  HandlerClass.cert = cert
  HandlerClass.spoof_ssl_config = spoof_ssl_config
  HandlerClass.log = log

  # Example for http_redirect_table:
  # http_redirect_table == {'https://host.example.com:443/(foo/.*)':
  #                         'http://otherhost.example.com:7433/\1'}
  # This will match URLs like https://host.example.com:443/foo/bar
  # And rewrite them as       http://otherhost.example.com:7433/foo/bar
  # Before making connections.
  HandlerClass.http_redirect_table = http_redirect_table

  # Example for ssl_redirect_table:
  # ssl_redirect_table == {('orig.example.com', 443): 
  #                        ('new_dest.example.com', 443)}
  HandlerClass.ssl_redirect_table = ssl_redirect_table

  HandlerClass.dump_payload = dump_payload

  if interactive:
    HandlerClass.interactive = True
    HandlerClass.display_filter = display_filter
    log_fh = None
  else:
    try:
      log_fh = open(log_file, 'a')
    except:
      log.fatal('Could not open access log: %s' % log_file)
      sys.exit(os.EX_CANTCREAT)
    HandlerClass.log_file = log_fh
    HandlerClass.interactive = False


  if thread:
    reusable_socketserver = SocketServer.ThreadingTCPServer
  else:
    reusable_socketserver = SocketServer.TCPServer

  reusable_socketserver.allow_reuse_address = True
  reusable_socketserver.daemon_threads = True

  try:
    httpd = reusable_socketserver(server_address, HandlerClass)
  except socket.error:
    log.exception('Could not bind to %s:%s' % server_address)
    sys.exit(os.EX_OSERR)
  sa = httpd.socket.getsockname()
  log.info('Listening on %s port %s ...' % (sa[0] , sa[1]))

  # Need to get the logfile closed before the shutdown happens.
  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    log.info('Shutting down from keyboard...')
    if log_fh:
      log_fh.close()
  except:
    if log_fh:
      log_fh.close()
    log.exception('Exception after serve_forever')
    raise

def createDaemon(stderr_fd = None):
  """Detach a process from the controlling terminal and run it in the
  background as a daemon.
  """

  UMASK = 0
  WORKDIR = "/"
  MAXFD = 1024

  # The standard I/O file descriptors are redirected to /dev/null by default.
  if (hasattr(os, 'devnull')):
    REDIRECT_TO = os.devnull
  else:
    REDIRECT_TO = '/dev/null'

  try:
    pid = os.fork()
  except OSError, e:
    raise Exception, "%s [%d]" % (e.strerror, e.errno)

  if (pid == 0):       # The first child.
    os.setsid()

    try:
      pid = os.fork()        # Fork a second child.
    except OSError, e:
      raise Exception, "%s [%d]" % (e.strerror, e.errno)

    if (pid == 0):    # The second child.
      os.chdir(WORKDIR)
      os.umask(UMASK)
    else:
      os._exit(0)    # Exit parent (the first child) of the second child.
  else:
    os._exit(0)       # Exit parent of the first child.

  import resource              # Resource usage information.
  maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
  if (maxfd == resource.RLIM_INFINITY):
    maxfd = MAXFD

  # Iterate through and close all file descriptors.
  for fd in xrange(0, maxfd):
    if fd == stderr_fd:
      continue
    try:
      os.close(fd)
    except OSError:   # ERROR, fd wasn't open to begin with (ignored)
      pass

  if stderr_fd:
    os.dup2(stderr_fd, 0)
  else:
    os.open(REDIRECT_TO, os.O_RDWR)      # standard input (0)

  # Duplicate standard input to standard output and standard error.
  os.dup2(0, 1)                        # standard output (1)
  os.dup2(0, 2)                        # standard error (2)

  return 0

def LogDeath(signum, frame):
  logging.info('Caught fatal signal: %s, Shutting down' % signum)
  logging.debug('Frame: %s' % frame)
  sys.exit(0)

def CreateStarCert(filename, log = logging):
  """
  This function will produce a "*" cert which is valid for one day.
  """
  temp1 = tempfile.mkstemp(prefix = 'ssl_proxy')
  temp2 = tempfile.mkstemp(prefix = 'ssl_proxy')

  cert_fields = { "C": "US", "ST": "**INSECURE CONNECTION**",
                  "L": "**INSECURE CONNECTION**",
                  "O": "**INSECURE CONNECTION**",
                  "OU": "**INSECURE CONNECTION**",
                  "CN": "*" }

  cert_valid_days = 1

  cert_string = '/C=%(C)s/ST=%(ST)s/L=%(L)s/O=%(O)s/OU=%(OU)s/CN=%(CN)s' % \
                cert_fields

  openssl_command = 'openssl req -newkey rsa:1024 -keyout "%s" -nodes ' \
  '-x509  -days 365 -out "%s" -subj "%s" -set_serial 0 -days %s ' \
  '-batch' % (temp1[1], temp2[1], cert_string, cert_valid_days)

  find_openssl = os.system('which openssl > /dev/null')

  if not find_openssl == 0:
    log.error('Could not find openssl. (Used "which openssl" to search)')
    raise OSError, 'Command "which openssl" returned: %s' % find_openssl

  log.info('Running command: %s' % openssl_command)
  openssl_status = os.system(openssl_command)
  if not openssl_status == 0:
    raise OSError, 'Attempt to run openssl returned: %s' % openssl_status

  # Extract the keys into strings.
  key = os.read(temp1[0], 2048)
  cert = os.read(temp2[0], 2048)

  os.close(temp1[0])
  os.close(temp2[0])

  os.unlink(temp1[1])
  os.unlink(temp2[1])

  new_cert = open(filename, 'wb')
  new_cert.write('%s\n%s' % (key, cert))

  new_cert.close()

  log.info('Successfully created %s' % filename)
  return True

def main():
  def Usage(Asked = False):
    if Asked:
      target = sys.stdout
    else:
      target = sys.stderr
    target.write('Usage: %s [hdnsvli] [c <cert.pem>] [u <match regex>] [p <port>]\n' % sys.argv[0])
    target.write('SSL MIM Proxy\nVersion: %s\n' % __version__)
    target.write('  h (help)       : This message\n')
    target.write('  v (version)    : Print version number then exit\n')
    target.write('  d (debug)      : Log verbose debug messages\n')
    target.write('  n (nodaemon)   : Do not detach from controlling terminal\n')
    target.write('  b (daemon)     : Detach from controlling terminal\n')
    target.write('  c (cert)       : Cert to use when spoofing SSL connect\n')
    target.write('  p (port)       : Port to listen to requests on\n')
    target.write('  s (nothread)   : Do not use threads (slow)\n')
    target.write('    (access_log) : Path to access log\n')
    target.write('    (app_log)    : Path to application log\n')
    target.write('    (spoof)      : regex of hosts to MIM SSL connects\n')
    target.write('    (nospoof)    : regex of hosts to bypass MIM SSL connects\n')
    target.write('    (httpspoof)  : rewrite rule for http connections\n')
    target.write('    (sslspoof)   : rewrite rule for https connections\n')
    target.write('  i (interactive): Run as a forground debugger\n')
    target.write('  l (payload)    : Dump payload for matched URLs (Only in interactive mode)\n')
    target.write('  L (all-payload): Dump ALL payload (Only in interactive mode)\n')
    target.write('  (dont_create_missing_cert) : Dont create missing certs\n')
    target.write('  u (url)        : Only display urls matched by regex (Only '
        'in interactive mode)\n\n')

  #errors.catch_errors()
  signal.signal(signal.SIGTERM, LogDeath)
  signal.signal(signal.SIGHUP, LogDeath)
  APP_LOG = '/var/log/ssl_proxy.log'
  ACCESS_LOG = '/var/log/ssl_proxy_access.log'

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hvVdnilsp:c:b:u:", ["help",
       "debug", "nodaemon", "port=", "version", "interactive", "thread",
       "nothread", "url=", "daemon", "cert=", "payload", "spoof=", "nospoof=",
       "httpspoof=", "sslspoof=", "access_log=", "app_log=",
       "dont_create_missing_cert"])
  except getopt.GetoptError:
    sys.stderr.write('FATAL: Problem with option processing. Exiting\n')
    Usage()
    sys.exit(os.EX_USAGE)

  # This extracts the first element from each of the ops tuples.
  # (ie ops = [('foo', ''), ('-port', '443'), ('-v', '')] ->
  # switches = ['foo', '-port', '-v']
  switches = map(lambda x: x[0], opts)

  daemon = True
  debug = False
  interactive = False
  target_port = 1443
  thread = True
  display_filter = None
  dump_payload = False
  create_missing_cert = True

  # Controls which hosts will be MIMed. Can use regular expressions.
  spoof_ssl_config = {'DEFAULT': True}
  http_redirect_table = {}
  ssl_redirect_table = {}

  cert = 'star.pem'

  for o, a in opts:
    if o in ("-v", "-V", "--version"):
      print __version__
      sys.exit(0)
    if o in ("-d", "--debug"):
      debug = True
    if o in ("-b", "--daemon"):
      daemon = True
    if o in ("-n", "--nodaemon"):
      daemon = False
    if o in ("-h", "--help"):
      Usage(True)
      sys.exit(0)
    if o in ("-p", "--port"):
      target_port = int(a)
    if o in ("-c", "--cert"):
      cert = os.path.abspath(a)
    if o in ("-l", "--payload"):
      dump_payload = True
    if o in ("-i", "--interactive"):
      daemon = False
      if not 'thread' in switches:
        thread = False
      else:
        thread = True
      interactive = True
      thread = True
    if o in ("--spoof"):
      spoof_ssl_config[a] = True
    if o in ("--nospoof"):
      spoof_ssl_config[a] = False
    if o in ("--thread"):
      thread = True
    if o in ("-s", "--nothread"):
      thread = False
    if o in ("-u", "--url"):
      display_filter = sre.compile(a)
    if o in ("--httpspoof"):
      vals = a.split('=>')
      http_redirect_table[vals[0]] = vals[1]
    if o in ("--sslspoof"):
      vals = a.split('=>')
      ssl_redirect_table[vals[0].split(':')] = vals[1].split(':')
    if o in ("--app_log"):
      APP_LOG = os.path.abspath(a)
    if o in ("--access_log"):
      ACCESS_LOG = os.path.abspath(a)
    if o in ("-dont_create_missing_cert", "--dont_create_missing_cert"):
      create_missing_cert = False

  if len(opts) == 0:
    Usage(False)
    sys.stderr.write('FATAL: You need to pass at least one argument\n')
    sys.exit(os.EX_USAGE)

  if not interactive:
    try:
      app_log = open(APP_LOG, 'a')
    except IOError:
      sys.stderr.write('FATAL: Can not open application log: %s. Exiting\n' %
          APP_LOG)
      sys.exit(os.EX_CANTCREAT)

  if daemon:
    sys.stderr.write('Daemonizing...\n')
    createDaemon(app_log.fileno())

  global logger
  logger = logging.getLogger('ssl_proxy')

  handler_stderr = logging.StreamHandler()
  logging_format = '%(asctime)s %(levelname)s %(message)s'
  formatter = logging.Formatter(logging_format)
  handler_stderr.setFormatter(formatter)

  if not debug:
    logger.setLevel(logging.INFO)
  else:
    logger.setLevel(logging.DEBUG)

  if not daemon:
    logger.addHandler(handler_stderr)
  else:
    handler_file = logging.FileHandler(APP_LOG)
    handler_file.setFormatter(formatter)
    logger.addHandler(handler_file)

  if not os.path.exists(cert):
    if create_missing_cert:
      logger.warning('Cert file: %s does not exist, will create' % cert)
      CreateStarCert(cert, logger)
    else:
      logger.fatal('Cert file: %s does not exist, exiting' % cert)
      sys.exit(os.EX_CONFIG)

  logger.debug('Application Log: %s' % APP_LOG)
  logger.debug('Access Log: %s' % ACCESS_LOG)

  logger.info('Now starting proxy')

  ProxyDaemon(port = target_port, thread = thread, cert = cert,
      interactive = interactive, display_filter = display_filter,
      spoof_ssl_config = spoof_ssl_config, log_file = ACCESS_LOG,
      dump_payload = dump_payload, http_redirect_table = http_redirect_table,
      ssl_redirect_table = ssl_redirect_table, log = logger)

if __name__ == '__main__':
  main()
