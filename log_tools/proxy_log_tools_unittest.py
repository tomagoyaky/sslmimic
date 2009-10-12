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


"""Unittest for proxy_log_tools module"""

__author__ = 'naustin@google.com (Nick Austin)'

from google3.testing.pybase import googletest
from google3.pyglib import flags

import unittest
import sys
import logging
import os
import tempfile
import proxy_log_tools

class ProxyLogTest(unittest.TestCase):
  test_srcdir = './'
  def setUp(self):
    self.simple_server_log = os.path.join(self.test_srcdir,
        'testdata/ssl_server.log')
    self.simple_server_log_index = os.path.join(self.test_srcdir,
        'testdata/ssl_server.log.index')

    logger = logging.getLogger('test')
    handler_stderr = logging.StreamHandler()
    logging_format = '%(asctime)s %(levelname)s %(message)s'
    handler_stderr.setFormatter(logging.Formatter(logging_format))
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler_stderr)

    self.log = logger

  def open(self, file, index = None):

    if index:
      require_index = True
    else:
      require_index = False

    test_logextractor = proxy_log_tools.LogExtractor(
        file = file, require_index = require_index,
        index_file = index, log = self.log )

    return test_logextractor

  def test_open(self):

    test_logextractor = self.open(self.simple_server_log)

    self.assertTrue(isinstance(test_logextractor,
                               proxy_log_tools.LogExtractor),
                    "LogExtractor failed to open: %s" % self.simple_server_log)

  def test_index_creation(self):

    temp_index = tempfile.mktemp()

    test_logextractor = self.open(self.simple_server_log, temp_index)

    self.assertTrue(isinstance(test_logextractor,
                               proxy_log_tools.LogExtractor),
                    "LogExtractor failed to open: %s with new index" %
                    self.simple_server_log)

    self.assertTrue(os.path.exists(temp_index),
                    "LogExtractor failed to create a new index file after "
                    "using require_index = True")

    del test_logextractor

    os.remove(temp_index)

  def test_index_len(self):

    test_logextractor = self.open(self.simple_server_log,
                                  self.simple_server_log_index)

    self.assertEqual(len(test_logextractor), 2)

  def test_log_entry(self):

    test_logextractor = self.open(self.simple_server_log)

    log_list = {}

    for i in test_logextractor:
      log_list[i.GenerateSig()] = i

    self.verify_log_data_1(log_list)

  def verify_log_data_1(self, log_list):
    self.assertTrue(log_list.has_key('a18122a3716e53d4b156bc8a721e0c6a'))
    self.assertTrue(log_list.has_key('2ca50a7e0abda6495157e1dab2c519e1'))

if __name__ == '__main__':
  unittest.main()
