#!/usr/bin/python
#
# Copyright 2006 Google Inc. All Rights Reserved.

"""One-line documentation for proxy_log_decoder module.

A detailed description of proxy_log_decoder.
"""

__author__ = 'naustin@google.com (Nick Austin)'
__version__ = '$Id$'

import os
import logging
import cPickle
import sys
import time
import mx.TextTools
import gzip
import StringIO
import getopt
import proxy_log_tools

def Dump(target_log, log = logging):
  log_extractor = proxy_log_tools.LogExtractor(file = target_log,
      produce_stats = 10000)
  log.info('Starting extraction from %s' % target_log)

  current_record = 0
  for i in log_extractor:
    current_record += 1
    print "--"
    try:
      print i.PrettyPrintLog()
    except KeyError:
      log.warning('KeyError at record %s' % current_record)
      pass

  log.info('Saw %s records' % current_record)

  del log_extractor
  return

def main():
  def Usage(Asked = False):
    if Asked:
      target = sys.stdout
    else:
      target = sys.stderr
    target.write('Usage: %s [h] log_to_process\n' % sys.argv[0])
    target.write('Proxy Log Dumper\nVersion: %s\n' % __version__)
    target.write('  h (help)       : This message\n\n')
    return

  def ValidateFile(file):
    if not os.path.isfile(file):
      log.fatal('%s does not seem to be a file' % target_log_file)
      sys.exit(66)

    if not os.access(file, os.R_OK):
      log.fatal('No read access to %s' % target_log_file)
      sys.exit(66)

    return True

  log = logging.getLogger('proxy_log_dumper')
  handler_stderr = logging.StreamHandler()
  logging_format = '%(asctime)s %(levelname)s %(message)s'
  formatter = logging.Formatter(logging_format)
  handler_stderr.setFormatter(formatter)

  log.addHandler(handler_stderr)
  log.setLevel(logging.DEBUG)

  try:
    opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
  except getopt.GetoptError:
    sys.stderr.write('FATAL: Problem with option processing. Exiting\n')
    Usage()
    sys.exit(2)

  for opt in opts:
    if opt in ("h", "--help", "-help"):
      self.Usage(True)

  if len(sys.argv) < 2:
    target_log_file = None
  else:
    target_log_file = sys.argv[1]

  if not args:
    log.fatal('FATAL: You must specify the log file to process')
    sys.exit(64)

  for i in args:
    ValidateFile(i)

  #Dump('/var/log/ssl_proxy_access.log', log = log)
  for i in args:
    Dump(i, log = log)

if __name__ == '__main__':
  main()
