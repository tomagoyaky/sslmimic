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

__author__ = 'naustin@gmail.com (Nick Austin)'
__version__ = '$Id$'

import logging
import cPickle
import time
import decimal
import ssl_proxy_log
import os
import bsddb.dbshelve
import pickle
import md5

class LogExtractor:
  """ Class that will provide access to log files created by
      the sslmimic.py (SSL Man In the Middle Proxy).

      Args:
        file         : (str) Path to log file to be accessed.
        index_file   : (str) (opt) Path to index file.
        log          : (obj) Logging object that provides info,
                             debug, etc methods to be called
                             with debug messages.
        produce_stats: (int) Produces status message every time
                             this many records have been seen. Set
                             this to None to supress status messages.
        max_records  : (int) Don't process more then this many records.
        require_index: (bol) If this is set to true, then an index file is
                             opened/created for this log file. Index
                             files are used for duplicate supression when
                             adding to log files.

      Returns:
        An iterator that will return ssl_proxy_log.Log objects.

      Example:
        import proxy_log_tools
        import logging

        logger = logging.getLogger('test')
        logger.setLevel(logging.DEBUG)

        log_itr = proxy_log_tools.LogExtractor(file = \
          '/path/to/ssl_proxy_access.log', log = logging,
          produce_stats = 10000, require_index=True)

        for log in log_itr:
          print log.GetValue('response_disposition')
  """
  INDEX_FILE_VERSION = 1
  def __init__(self, file, log = logging, produce_stats = None,
      max_records = None, index_file = None, require_index = False):

    self.current_record = 0
    self.current_record_position = 0
    self.stats = produce_stats
    self.log = log
    self.start_time = time.time()
    self.max_records = max_records
    self.require_index = require_index
    self.open_dbs = {}
    self.file = file
    self.index_file = index_file
    self.file_handle = None

    if not os.path.exists(file):
      raise ValueError, 'File: %s does not exist' % file

    if require_index and not index_file:
      raise ValueError, 'require_index set, but index_file is not.'

    if index_file:
      self.index = self.OpenIndex(file, self.index_file)
      if not self.index:
        self.log.info('Index file %s for: %s failed, (re)creating' %
                      (self.index_file, file))
        self.CreateIndex(file, self.index_file)
        self.index = self.OpenIndex(file, self.index_file)
      else:
        self.log.debug('Opened index %s' % self.index_file)

    else:
      self.index = None

    if self.index == None and require_index:
      raise ValueError, 'require_index set, but index is unavailable'

    file_handle = open(file, 'r')
    self.file_handle = file_handle

  def __del__(self):
    self.log.debug('Cleaning up, closing all DBs')

    # CloseIndex changes open_dbs dict, so we can't just itr over it
    open_dbs = self.open_dbs.keys()
    for i in open_dbs:
      self.CloseIndex(i)

    if self.file_handle:
      self.file_handle.close()

    return True

  def Reset(self):
    """ Move iterator back to beginning of open log file

        Args:
          None

        Returns:
          True
    """
    self.current_record = 0
    self.current_record_position = 0
    self.start_time = time.time()
    self.file_handle.seek(0)
    return True

  def __iter__(self):
    return self

  def RecordPosition(self):
    """ Return the bytewise offset for the beginning of the last
        decoded record.

        Args:
          None

        Returns:
          (int): Position of beginning of last read record.
    """
    return self.current_record_position

  def __len__(self):
    if not self.index == None:
      return self.index['META_DATA']['count']
    else:
      raise ValueError, 'len() function requires use of Index'

  def next(self):
    self.current_record += 1
    self.current_record_position = self.file_handle.tell()
    record = False

    if self.max_records:
      if self.current_record > self.max_records:
        raise StopIteration

    try:
      record = cPickle.load(self.file_handle)
    except EOFError:
      raise StopIteration
    except AttributeError:
      self.next()
    except cPickle.UnpicklingError:
      self.log.warning('Failure at record: %s Offset: %s' %
          (self.current_record, self.file_handle.tell()))
      #raise #XXX
      record = self.FindNextPickle()
    except:
      self.log.warning('Unknown failure at record: %s Offset: %s' %
          (self.current_record, self.file_handle.tell()))
      raise

    if record == False:
      self.log.warning('Unset record at: %s Offset: %s' %
          (self.current_record, self.file_handle.tell()))

    if self.stats:
      if self.current_record % self.stats == 0 and self.current_record != 0:
        time_to_now = time.time() - self.start_time
        recsec = self.stats / time_to_now
        self.start_time = time.time()
        self.log.info('Current record: %s req/sec: %s' %
            (self.current_record, recsec))
    return record

  def __GenHash(self, filename):
      """ Generates an md5sum for the passed filename.

          Args:
            filename: (str) Path to file to be hashed.

          Returns:
            (str) hex digest of md5sum for file passed, or
            None on error.
      """

      blocksize = 8192
      hash_depth = 4398046511104

      try:
        __hashfile_handle = open(filename, 'r')
      except (OSError, IOError), error:
        raise('FATAL: Hash of file failed!: %s' % error)

      hashobject = md5.new()
      hashfile_block = __hashfile_handle.read(blocksize)
      current_depth = blocksize

      while len(hashfile_block) > 0 and current_depth <= hash_depth:
        hashobject.update(hashfile_block)
        hashfile_block = __hashfile_handle.read(blocksize)
        current_depth = current_depth + blocksize

      hash = hashobject.hexdigest()
      __hashfile_handle.close
      return hash

  def CloseIndex(self, index_file):
    if self.open_dbs.has_key(index_file):
      index = self.open_dbs[index_file]
      self.log.debug('Closing index file: %s' % index_file)
      index.close()
      del index
      del self.open_dbs[index_file]
      return True
    else:
      self.log.debug('Attempt to close non-opened index: %s' % index_file)
      return False

  def CreateIndex(self, file, index_file = None):
    if not index_file:
      index_file = '%s.index' % file

    if not os.path.exists(file):
      self.log.warn('Log file: %s Does not exits' % file)
      return False

    try:
      index = bsddb.dbshelve.open(index_file, 'c')
    except bsddb.error, e:
      self.log.error('Failed to create index file: %s, %s' % (index_file, e))
      return False

    self.open_dbs[index_file] = index
    log_ext = LogExtractor(file, produce_stats = 10000)

    self.log.debug('Now creating index file: %s' % index_file)
    meta_data = { 'version': self.INDEX_FILE_VERSION }

    seq = 0
    seq_index = []
    for i in log_ext:
      pos = log_ext.RecordPosition()
      sig = i.GenerateSig()
      index[sig] = pos
      seq_index.append(sig)
      seq += 1

    index['sequence'] = seq_index
    meta_data['target_size'] = os.stat(file).st_size
    meta_data['target_hash'] = self.__GenHash(file)
    meta_data['count'] = seq

    index['META_DATA'] = meta_data

    del log_ext
    self.CloseIndex(index_file)
    return True

  def OpenIndex(self, file, index_file = None):
    if not index_file:
      index_file = '%s/%s.index' % (os.path.abspath(file), file)

    if not os.path.exists(index_file):
      self.log.warn('Index file: %s Does not exist' % index_file)
      return False

    if not os.path.exists(file):
      self.log.warn('Log file: %s Does not exits' % file)
      return False

    try:
      index = bsddb.dbshelve.open(index_file, 'r')
    except bsddb.error, e:
      self.log.warn('Index file: %s can not be opened: %s' % index_file, e)
      return False

    self.open_dbs[index_file] = index

    # Who knows what kind of crazy DBs will be passed to this script? These
    # checks make sure that the index file is what we expected.
    try:
      meta_data = index['META_DATA']
    except KeyError:
      self.log.warn('Index file: %s Not correct format, '
                     'META_DATA_VERSION key missing' % index_file)
      self.CloseIndex(index_file)
      return False

    # We want to deal with changing index versions
    if meta_data['version'] != self.INDEX_FILE_VERSION:
      self.log.warn('Index file: %s VERSION key: %s != %s' % (index_file,
        meta_data['version'], self.INDEX_FILE_VERSION))
      self.CloseIndex(index_file)
      return False

    real_file_hash = self.__GenHash(file)
    real_file_size = os.stat(file).st_size

    target_file_hash = meta_data['target_hash']
    target_file_size = meta_data['target_size']

    if not real_file_hash == target_file_hash:
      self.log.warn('Index and log file mismatch %s != %s' % (real_file_hash,
        target_file_hash))
      self.CloseIndex(index_file)
      return False

    if not real_file_size == target_file_size:
      self.log.warn('Index and log file size mismatch %s != %s' %
          (real_file_size, target_file_size))
      self.CloseIndex(index_file)
      return False

    return index

  def FindNextPickle(self):
    search_start = self.file_handle.tell()
    DEPTH = 655350
    for i in xrange(1, DEPTH):
      self.file_handle.seek(search_start + i)
      try:
        a = cPickle.load(self.file_handle)
      except cPickle.UnpicklingError:
        continue
      except:
        continue

      self.log.warning('Found next pickle at offset: +%s' % i)
      return a

    self.log.error('FATAL: Could not find next pickle in %s' % DEPTH)
    raise LookupError, 'Is your logfile corrupt?'

def main(argv):
  pass

if __name__ == '__main__':
  main()
