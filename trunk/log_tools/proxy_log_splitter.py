#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc.
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

"""One-line documentation for proxy_log_splitter module.

A detailed description of proxy_log_splitter.
"""

__author__ = 'naustin@google.com (Nick Austin)'

__version__ = '$Id:$'


import logging
import time
import proxy_log_tools
import ssl_proxy_log
import getopt
import sys
import os
import dbm
#from ssl_proxy_log import *

def LogSplitter(file, log = logging, dup_detection = True,
    target_format = 'ssl_proxy_access_%Y%m%d.log'):
  log.info('Starting extraction from %s' % file)
  current_record = 0
  host_stats = {}
  target_files = {}
  log_extractor = proxy_log_tools.LogExtractor(file = file,
      produce_stats = 10000, max_records = None, log = log)

  for i in log_extractor:
    request_time = i.GetValue('request_time')
    target = time.strftime(target_format, time.localtime(request_time))
    if not target_files.has_key(target):
      index_file = '%s.%s' % (target, '.index')
      #XXX: Index files
      #if os.path.exists(target):
      #  if not os.path.exists(index_file):
      #    log.warning('Index file missing: %s' % index_file)
      #    try:
      #      dbm.open(index_file)
      #try:
      #  stat =  os.stat(target)
      log.info('Creating: %s' % target)
      target_files[target] = open(target, 'a')

    new_log = ssl_proxy_log.Log()

    new_log.__setstate__(i.__getstate__())
    new_log.WriteLog(target_files[target])

  for log_file in target_files:
    target_files[log_file].close()

def main():

  def Usage(Asked = False):
    if Asked:
      target = sys.stdout
    else:
      target = sys.stderr
    target.write('Usage: %s [hqviofd]\n' % sys.argv[0])
    target.write('Proxy Log Splitter\nVersion: %s\n' % __version__)
    target.write('  h (help)    : This message\n')
    target.write('  v (version) : Print version number then exit\n')
    target.write('  q (quite)   : Log fewer messages\n')
    target.write('  i (input)   : Log file to process\n')
    target.write('  o (output)  : Directory to write output\n')
    target.write('  f (format)  : Format for filenames (name_%Y%m%d)\n')
    target.write('  d (dups-ok) : Disable expensive duplication detection\n\n')
    target.write('Example: %s -i ssl_proxy_access_hyd.log -o '
      '/var/data/logs/hyd/ -f ssl_proxy_access_hyd_%%Y%%m%%d.log\n\n' %
      sys.argv[0])

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hvVqi:o:f:d", ["help", "quite",
       "input=", "output=", "format=", "version", "dups-ok"])
  except getopt.GetoptError:
    sys.stderr.write('FATAL: Problem with option processing. Exiting\n')
    Usage()
    sys.exit(2)

  quite = False
  #source_file = '/var/data/logs/ssl_proxy_access.log'
  #dest_dir = '/var/data/logs/out/'
  source_file = None
  dest_dir = None
  dest_format = None
  dup_detection = True

  for o, a in opts:
    if o in ("-v", "-V", "--version"):
      print __version__
      sys.exit(0)
    if o in ("-q", "--quite"):
      quite = True
    if o in ("-n", "--nodaemon"):
      daemon = False
    if o in ("-h", "--help"):
      Usage(True)
      sys.exit(0)
    if o in ("-i", "--input"):
      source_file = a
    if o in ("-o", "--output"):
      dest_dir = a
    if o in ("-f", "--format"):
      dest_format = a
    if o in ("-d", "--dups-ok"):
      dup_detection = False

  if not source_file:
    sys.stderr.write('FATAL: Log file to process not specified\n\n')
    Usage()
    sys.exit(2)

  if not dest_dir:
    sys.stderr.write('FATAL: Directory to write output not specified\n\n')
    Usage()
    sys.exit(2)

  if not dest_format:
    dest_format = '%s_%s' % (source_file.split('/')[-1], '%Y%m%d')

  logger = logging.getLogger('proxy_log_splitter')

  handler_stderr = logging.StreamHandler()
  logging_format = '%(asctime)s %(levelname)s %(message)s'
  formatter = logging.Formatter(logging_format)
  handler_stderr.setFormatter(formatter)

  if quite:
    logger.setLevel(logging.ERROR)
  else:
    logger.setLevel(logging.DEBUG)

  logger.addHandler(handler_stderr)

  LogSplitter(file = source_file,
      target_format = '%s/%s' % (dest_dir, dest_format),
      dup_detection = dup_detection, log = logger)


if __name__ == '__main__':
  main()
