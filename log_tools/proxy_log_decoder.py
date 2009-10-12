#!/usr/bin/python2.2
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


"""One-line documentation for proxy_log_decoder module.

A detailed description of proxy_log_decoder.
"""

__author__ = 'naustin@google.com (Nick Austin)'

import cPickle
import logging
import sys
import time
import StatsEngine
import proxy_log_tools
#from proxy_log_tools import *
#from ssl_server import *

def Scrape(target_log = '/var/log/ssl_proxy_access.log', max_records = None):
  logging.basicConfig(level=logging.INFO,
                      format='%(asctime)s %(levelname)s %(message)s')

  logging.info('Starting extraction from %s' % target_log)
  current_record = 0
  host_stats = {}
  log_extractor = proxy_log_tools.LogExtractor(file = target_log,
      produce_stats = 10000, max_records = max_records)

  start_time = time.time()
  for a in log_extractor:
    a.no_error = True
    current_record += 1

    request = a.GetValue('request')
    uri = request.GetURI()
    hostname = request.GetTargetHost()
    relative_path = request.GetRelativePath()
    handler = relative_path.split('?')[0]

    try:
      status = a.GetValue('response_disposition')
    except KeyError:
      print uri
      print a.__dict__
      sys.exit(1)

    if status == 'Success':
      #print uri
      connect_begin = a.GetValue('request_time')
      connect_time = a['connect']

      #if a['total'] > 3:
      #  print '%s %s %s %s %s %s %s' % (a.GetValue('request_time'), a['dns'],
      #      a['connect'], a['ssl_handshake'], a['first_byte'], a['headers'],
      #      a['total'])

      #print '%s %s' % (connect_begin, connect_time)

      continue
      # Dump all data re this stat.
      if '/example/test_url' in handler:
        print '%s %s %s %s %s %s %s %s' % (a.GetValue('request_time'),
            handler, a['dns'], a['connect'], a['ssl_handshake'],
            a['first_byte'], a['headers'], a['total'])

      # Skip all stat generation

      if not host_stats.has_key((hostname, handler)):
        host_stats[(hostname, handler)] = {}
        for stat in a:
          host_stats[(hostname, handler)][stat[0]] = \
            StatsEngine.StatsEngine(hostname)

        #for stat in ('connect_time', 'total_time', 'dns_time', '')
        #host_stats[(hostname, handler)] = StatsEngine.StatsEngine(hostname)

      for stat in a:
        try:
          host_stats[(hostname, handler)][stat[0]].AddDataPoint(stat[1])
        except KeyError:
          host_stats[(hostname, handler)][stat[0]] = \
            StatsEngine.StatsEngine(hostname)

    #print '%s %s' % (a['total'], uri)
  logging.info('Saw %s records' % current_record)

  del log_extractor

  return

  for hostname in host_stats:
    #print hostname
    #if 'prodz.google.com' in hostname[0][0]:
    if '/example/test_url' in hostname[1]:
      print hostname
      stats = host_stats[hostname]['total'].ReturnStats()
      for stat in host_stats[hostname]:
        stats = host_stats[hostname][stat].ReturnStats()
        print '%s %s %s: %s %s %s %s' % (hostname[0][0], hostname[1], stat,
          stats['count'], stats['mean'], stats['stddev'], stats['max'])

def main():
  #import hotshot
  #p = hotshot.Profile("ssl_proxy_log.prof")
  #p.runcall(Scrape, '/var/log/ssl_proxy_access.log', 50000)
  #Scrape('/dev/stdin')
  Scrape('/var/log/ssl_proxy_access.log')

if __name__ == '__main__':
  main()
