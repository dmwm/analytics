#!/usr/bin/env python
from Analytics.LogReader import LogAnalyser
from Analytics.IPInfo import IPResolver
from Analytics.CMSWEB import *
import sys, os, os.path, gc

gc.DEBUG_STATS = 1
gc.set_threshold(256*1024)

# Check command line arguments.
if len(sys.argv) < 3:
  print >> sys.stderr, "usage: %s SUMMARY-DIR LOG-DIR..." % sys.argv[0]
  sys.exit(1)

if not os.path.exists(sys.argv[1]) or not os.access(sys.argv[1], os.W_OK):
  print >> sys.stderr, "%s: no such directory" % sys.argv[1]
  sys.exit(1)

# Remaining sys.argv are directories to look for monthly log archive
# zip files. For any given month there are several log archives, one
# per host. We determine which monthly stats files require updating
# by comparing the time stamps of the zip and the stats file; when
# we update a stats file, we record the archive file time stamp.
#
# When updating the stats file, we rely on the server rotating logs
# on UTC date change, and generate the stats for this time period.
# In other words, we assume access_log file per day to report, and
# do not use the dates from the HTTP logs themselves, as they are in
# local time and subject to daylight savings variations.
LogAnalyser(sys.argv[1], RXLOG, cmsweb_parser, IPResolver(maxtime = 15)).scan_dirs(sys.argv[2:])
