#!/usr/bin/python2.4
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
This file contains the Log and Request classes.

The Log class holds all of the diagnostic data relating to each request.
The Request class contains all of the necessary data to track and translate
  each request.
"""

__author__ = 'naustin@google.com (Nick Austin)'

import logging
import time
import decimal
import sre
import md5
import gzip
import StringIO
import pickle

class Log:
  CLASS_VERSION = 1
  def __init__(self):
    self.VERSION = self.CLASS_VERSION
    self.times = { 'btime': time.time(), '__outstanding__': {}}
    self.log = { 'times': self.times, 'response_disposition': '__MISSING__' }
    self.no_error = False

  def __getitem__(self, key):
    if key in self.times['__outstanding__']:
      if self.no_error:
        return 0
      raise KeyError, 'This value was never stopped'
    try:
      return self.times[key]
    except KeyError:
      if self.no_error:
        return 0
      raise

  def __iter__(self):
    self.iter = 0
    return self

  def next(self):
    def step():
      self.iter += 1
      if self.iter > len(self.times):
        raise StopIteration
      return self.times.items()[self.iter - 1]

    value = step()

    if value[0] == '__outstanding__':
      value = step()
    return value

  def __getstate__(self):
    return self.VERSION, self.times, self.log

  def __setstate__(self, state):
    if state[0] > self.CLASS_VERSION:
      raise ValueError, 'Wrong version of Log class: %s' % state[0]

    self.VERSION, self.times, self.log = state

    if not self.times.has_key('__outstanding__'):
      self.times['__outstanding__'] = {}
    self.no_error = False

  def TimeStart(self, operation, timet = None):
    self.times['__outstanding__'][operation] = operation
    if not timet:
      timet = decimal.Decimal(repr(time.time()))
    if self.times.has_key(operation):
      raise ValueError, 'Attempt to start existing counter'
    self.times[operation] = timet
    return True

  def TimeStop(self, operation, timet = None):
    if not timet:
      timet = decimal.Decimal(repr(time.time()))
    if not self.times.has_key(operation):
      raise ValueError, 'Attempt to stop nonexistent counter'
    self.times[operation] = timet - self.times[operation]
    assert self.times[operation] > 0
    del self.times['__outstanding__'][operation]
    return True

  def SetValue(self, key, value):
    self.log[key] = value
    return True

  def __genpickle(self):
    dumps = pickle.dumps(self, True)
    return dumps

  def GzipDecompress(self, compressed_data):
    gzip_data = StringIO.StringIO()
    gzip_data.write(compressed_data)
    gzip_data.seek(0)
    gzip_file = gzip.GzipFile(fileobj = gzip_data)
    output = gzip_file.read()
    return output

  def _PayloadIsCompressed(self, response):
    if response and 'content-encoding: gzip' in response.lower():
      return True
    else:
      return False

  def PrintTimes(self):
    if self['total']:
      entry_out = {}
      for i in ('dns', 'connect', 'ssl_handshake', 'first_byte',
          'headers', 'body'):
        if self.times.has_key(i):
          try:
            entry_out[i] = str(self[i])[:6]
          except KeyError:
            entry_out[i] = 'Err'
        else:
          entry_out[i] = 'NA'

      output = 'Duration: %s (DNS: %s, Connect: %s, SSL Handshake: %s, ' \
        'First Byte: %s, Headers: %s Body: %s)' % \
          (self['total'], entry_out['dns'], entry_out['connect'],
              entry_out['ssl_handshake'], entry_out['first_byte'],
              entry_out['headers'], entry_out['body'])

      return output
    else:
      return ''

  def PrettyPrintLog(self):
    delimiter = '\n'
    output = []
    if not self.log.has_key('request'):
      return ''

    request = self.GetValue('request')
    outbound_request = request.GetOutboundRequest().strip()

    method = request.GetMethod()

    # The amount of time this request took, and the orig URL
    request_time = self.GetValue('request_time')
    time_format = '%Y/%m/%d %H:%M:%S' + '.%s' % \
        str(request_time - int(request_time))[2:7]
    request_time_out = time.strftime(time_format, time.localtime(request_time))

    output.append('[%s]: %s' % (request_time_out, request.GetURI()))
    output.append(outbound_request + '\r\n')
    response_disposition = self.GetValue('response_disposition')
    if response_disposition != 'Success':
      output.append('response_disposition: %s' % response_disposition)
      output.append(self.PrintTimes())
      return delimiter.join(output)

    if self.log.has_key('raw_response'):
      response = self.GetValue('raw_response').strip()
      output.append(response + '\r\n')
    else:
      response = None
      if method == 'CONNECT':
        output.append('(This connection was not spoofed)')
      else:
        output.append('(No response from server)')

    if self.log.has_key('server_payload'):
      ascii_set = "".join([(" ",chr(x))[x < 127]
          for x in range(128)]) + " " * 128

      server_payload = self.GetValue('server_payload')
      if self._PayloadIsCompressed(response):
        output.append('(decompressed gzip data)')
        server_payload = self.GzipDecompress(server_payload)

      if server_payload.translate(ascii_set) == server_payload:
        output.append(server_payload)
      else:
        output.append('(%s byte(s) of non-printable 8bit data not shown)' %
            len(server_payload))
    else:
      output.append('(Payload not recorded)')

    output.append(self.PrintTimes())
    return delimiter.join(output)

  def VerifySig(self):
    if not self.log.has_key('md5'):
      raise ValueError, 'This class has no md5 recorded'
    old_md5 = self.log.has_key('md5')
    new_md5 = self.GenerateSig(False)

  def GenerateSig(self, record = True):
    old_md5 = None
    hash = md5.new()
    if self.log.has_key('md5'):
      old_md5 = self.log['md5']
      del self.log['md5']
    hash.update(self.__genpickle())
    new_md5 = hash.hexdigest()
    if record:
      self.log['md5'] = new_md5
    elif old_md5:
      self.log['md5'] = old_md5

    return new_md5

  def GetValue(self, key):
    return self.log[key]

  def WriteLog(self, log_file):
    if not log_file:
      return False
    old_fp = self.log['request'].headers.fp
    self.log['request'].headers.fp = None

    # We need to log in atomic blocks.
    pickle = self.__genpickle()
    log_file.write(pickle)
    log_file.flush()
    del pickle

    self.log['request'].headers.fp = old_fp

class Request:
  CLASS_VERSION = 1
  def __init__(self, url, method, headers, log = logging,
      http_redirect_table = {}, ssl_redirect_table = {}):
    self.VERSION = self.CLASS_VERSION
    self.url = url
    self.method = method
    self.headers = headers
    self.log = log

    self.ssl_redirect_table = ssl_redirect_table
    self.http_redirect_table = http_redirect_table

    # This will define spoof_url
    self._ProcessRedirects()

    self.relative_path = self._ProcessRelativePath(self.url)
    self.spoof_relative_path = self._ProcessRelativePath(self.spoof_url)

    # Remove any connection headers, and add our own
    self.headers['Connection'] = 'Close'

    self.Spoofing(True)

  def __getstate__(self):
    return self.VERSION, self.url, self.method, self.headers, \
           self.ssl_redirect_table, self.http_redirect_table, \
           self.spoofing

  def __setstate__(self, state):
    if type(state) == dict:
      print 'Directly adding __dict__ for legacy support'
      self.__dict__ = state
      self.VERSION = self.CLASS_VERSION
      for i in ('ssl_redirect_table', 'http_redirect_table'):
        if not self.__dict__.has_key(i):
          self.__dict__[i] = None
      self._ProcessRedirects()
      self.Spoofing(False)
      return

    if state[0] > self.CLASS_VERSION:
      raise ValueError, 'Wrong version of Request class: %s' % state[0]

    self.VERSION, self.url, self.method, self.headers, \
    self.ssl_redirect_table, self.http_redirect_table, self.spoofing = state

    # Logging objects can not be pickled
    self.log = logging

    # We need to run these to recalc other state info.
    self._ProcessRedirects()

    self.relative_path = self._ProcessRelativePath(self.url)
    self.spoof_relative_path = self._ProcessRelativePath(self.spoof_url)

    self.Spoofing(self.spoofing)
    return

  def _ProcessRelativePath(self, path):
    # Split full url on '/'s, take everything after the 3rd slash
    # (After the http://host/) and put the '/'es back in.
    # prepend a leading slash to the resulting string.
    return '/' + '/'.join(path.split('/')[3:])

  def _ProcessRedirects(self):
    self.log.debug('Entering _ProcessRedirects')
    newurl = None
    for target in self.http_redirect_table:
      match = sre.search(target, self.url)
      if match:
        self.log.debug('Matched %s on %s' % (target, self.url))
        newurl = match.expand(self.http_redirect_table[target])
        self.log.debug('  expanded %s to %s' %
            (self.http_redirect_table[target], newurl))
        break

    if not newurl:
      self.log.debug('No matches on %s' % self.url)
      self.spoof_url = self.url
    else:
      self.spoof_url = newurl

  def Spoofing(self, enabled = None):
    if not enabled:
      # This should never fail, since it should be set during __init__
      return self.spoofing

    if enabled:
      self.spoofing = True
      self.live_url = self.spoof_url
      self.live_relative_path = self.spoof_relative_path
    else:
      self.spoofing = False
      self.live_url = self.url
      self.live_relative_path = self.relative_path
    return self.spoofing

  def GetURI(self):
    return self.live_url

  def GetMethod(self):
    return self.method

  def GetRelativePath(self):
    return self.live_relative_path

  def GetOutboundRequest(self):
    if self.method in ['POST', 'GET', 'HEAD']:
      del self.headers['proxy-connection']
      del self.headers['keep-alive']

      headers_target = ''

      for header in self.headers:
        headers_target = '%s%s: %s\r\n' % (headers_target,
            header, self.headers[header].strip())

      outbound_request = '%s %s HTTP/1.0\r\n%s\r\n' % \
          (self.method, self.live_relative_path, headers_target)
      return outbound_request

    elif self.method == 'CONNECT':
      return 'CONNECT %s:%s' % self.GetTargetHost()
      pass

  def GetHeaders(self):
    return self.headers

  def IsSSL(self):
    if self.live_url[:5].upper() == 'HTTPS':
      return True
    else:
      return False

  def GetTargetHost(self):
    if self.method in ['POST', 'GET', 'HEAD']:
      target_host = self.live_url.split('://')[1].split('/')[0]
    elif self.method == 'CONNECT':
      target_host = self.live_url

    if ':' in target_host:
      target_host_split = target_host.split(':')
      target_host = target_host_split[0]
      target_port = int(target_host_split[1])
    else:
      if self.IsSSL():
        target_port = 443
      else:
        target_port = 80

    # Allow transparent redirects.
    if self.spoofing and \
    self.ssl_redirect_table.has_key((target_host, target_port)):
      target_host, target_port = self.ssl_redirect_table[(target_host,
          target_port)]

    return (target_host, target_port)

def main(argv):
  pass

if __name__ == '__main__':
  main()
