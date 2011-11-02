"""Utilities for analysing CMSWEB server logs."""

######################################################################
# IMPORTANT IMPLEMENTATION NOTE 1
#
# The log pattern matching, which produces the initial statistics,
# consumes by far the most resources in this module. Python is an
# expedient but relatively poor choice for this task, partly because
# it wastes time creating many unnecessary intermediate objects,
# partly because it is unable to natively parallel process this task
# which naturally is very parallelisable: every line can be analysed
# independently.
#
# The exact construction of this module was derived from a large
# number of attempts to get python execute the task efficiently, and
# utilising all possible CPU cores on the system. The present best
# choice is python multiprocessing, but be warned the exact code is
# extremely delicate and is based on significant experimentation on
# observed but undocumented python behaviour. Long term the generic
# log pattern matching part should be re-implemented as a natively
# threaded C/C++ extension module; it probably would accelerate the
# task by factor of ten or more and eliminate many current flaws.
#
# The following properties are important when working with this code.
#
# Firstly, minimum possible amount of data should be passed between
# the multiprocessing processes. This package passes into log parser
# processes only the _names_ of the files to parse, and out the
# combined statistics for one log file at a time - roughly one day on
# one host.  In addition during parsing sets of IP addresses are
# passed from time to time to the resolver. All these processes exit
# after one month's worth of logs has been processed.
#
# Reducing the data transmission is important for two reasons. The
# first is performance: passing data over multiprocessing queues is
# _very_ expensive. The second is that once data is passed through a
# queue, python's ability to garbage collect that data appears to be
# almost zero, even if the data is clearly fully out of scope and no
# longer referenced. It appears the only truly effective method for
# collecting the queued garbage is to... exit processes often enough.
#
# Because of above issues, in an analysis of several months of log
# data it is important to keep the virtual size of the parent process
# at minimum as children will inherit everything on fork. This means
# the parent process can _not_ collect the statistics results
# itself. This complicates optimisation of analysing lots of logs
# because it's hard to share any state - the state at the time of
# forking processes must be kept at minimum, and sending significant
# state over queues is too expensive.
#
# In addition multiprocessing complicates signal handling and requires
# careful handling of programming errors, e.g. unplanned KeyErrors.
# For example hitting Ctrl-C on interactively running log analyser
# almost certainly will not interrupt all the running processes. It is
# very likely problems will result in unterminated processes left
# forever hanging, possibly even in the background. The present code
# does its best to get the program always terminate, but significant
# flaws still very likely remain. Unfortunately it seems that a
# "killall -9 python" is a fairly regularly needed cure.

######################################################################
# IMPORTANT IMPLEMENTATION NOTE 2:
#
# The LogAnalyser creates up to number of cores minus one but always
# minimum of two log reader processes. If the system has more than two
# cores, this 'minus one' is there to use the remaining CPU for
# results aggregation and DNS resolution. It is common for the
# aggregator and name resolver (named, kernel, etc.) combined to
# utilise 90-95% of one core.
#
# Related to the above, the analyser can create approximately 1 MB/s
# stable DNS traffic while performing reverse mapping of IP addresses
# to domain names. Some ADSL providers appear to rate limit DNS
# traffic, resulting in significant number of DNS RCODE REFUSED
# answers. For best results run analysis on unthrottled systems.
#
# Majority of this DNS traffic is caused by 'wild host' mapping.  The
# origin of the 'wild host' mapping is that a substantial fraction of
# IP addresses have no PTR reverse mapping to name, making it harder
# to determine the source domains at required accuracy.  When the
# domain name cannot be located in any other way, the ipinfo module
# performs 'wild host' scan in nearby IP address space.  This improves
# analytics accuracy but increases DNS traffic approximately ten-fold;
# run time is not usually affected at all. This tradeoff benefits CMS
# web analytics, but if you use this in a different environment you
# might want to consider turning off the proximity searches.

######################################################################
__all__ = ["StatsKey", "StatsQuant", "StatsByteTiming",
           "StatsData", "LogAnalyser"]

import os, re, sys
from Analytics.Debug import debug
from Analytics.IPInfo import IPResolver
from multiprocessing import Process, Queue, cpu_count
from time import time, strftime, gmtime, sleep
from gzip import open as gzopen
from cStringIO import StringIO
from threading import Thread
from calendar import timegm
from zipfile import ZipFile
from copy import deepcopy
from Queue import Empty
from glob import iglob
from math import sqrt
from stat import *

def log_line_split(file):
  """Generator to read a log file breaking it to lines. This is vastly
  more efficient than 'for line in file' on a zip file."""
  pos = 0
  linebuf = ''
  while True:
    nl = linebuf.find('\n', pos)
    if nl >= 0:
      yield linebuf[pos:nl+1]
      pos = nl+1
    else:
      next = file.read(1048576)
      linebuf = linebuf[pos:] + next
      if linebuf == '': break
      pos = 0

def log_file_parse(rx, zippath, logfile):
  """Generator to break each line in `logfile` inside zip file `zippath`
  into the regular expression match groups of `rx`."""
  zf = ZipFile(zippath, "r")
  for line in log_line_split(zf.open(logfile)):
    m = rx.match(line)
    if not m:
      print zippath, logfile, "not matched:", line
    else:
      yield m.groups()

class StatsKey(tuple):
  """Access statistics key.

  The key is a tuple of fields in the following orer, assigned
  whatever strings the log classifier chose:
    - service: service label;
    - instance: service instance, e.g. database instance;
    - subclass: service subclass, e.g. version or web vs. data service;
    - api: service specific api call, usually some portion of the sub-url;
  """
  def __new__(cls, service = "", instance = "", subclass = "", api = ""):
    """Constructor, initialises key fields with data."""
    if isinstance(service, tuple): # somehow multiprocessing queue does this
      service, instance, subclass, api = service
    return super(StatsKey, cls).__new__(cls, (service, instance, subclass, api))

  @property
  def service(self):
    """Returns the service component of the key tuple."""
    return self[0]

  @property
  def instance(self):
    """Returns the instance component of the key tuple."""
    return self[1]

  @property
  def subclass(self):
    """Returns the subclass component of the key tuple."""
    return self[2]

  @property
  def api(self):
    """Returns the api component of the key tuple."""
    return self[3]

class StatsQuant:
  """Statistics quantity.

  For a given metric *t* the following values are stored:
    - num: total number of events;
    - min: min(t);
    - max: max(t);
    - sum: sum(t);
    - sum2: sum(t^2).

  In addition the following computed read-only properties are available:
    - avg: sum(t) / num
    - rms: sqrt(sum(t^2) / num - avg(t)^2).
  """
  def __init__(self, num = 0., min = 0., max = 0., sum = 0., sum2 = 0.):
    """Constructor, initialises value fields with data."""
    self.num = num
    self.min = min
    self.max = max
    self.sum = sum
    self.sum2 = sum2

  @property
  def avg(self):
    if self.num:
      return self.sum / self.num
    else:
      return 0.

  @property
  def rms(self):
    if self.num:
      try:
        return sqrt(self.sum2 / self.num - self.avg ** 2)
      except ValueError, e:
        # Numerical errors which occur with narrow distribution.  In
        # practice the term under sqrt() frequently becomes -0, or very
        # close to it within numerical precision. Suppress to zero.
        # print >> sys.stderr, "*** RMS error (%s), s=%.17f s2=%.17f" \
        #   " num=%.17f avg=%.17f term=%.17f" % (str(e), self.sum, self.sum2,
        #    self.num, self.avg, self.sum2 / self.num - self.avg ** 2)
        return 0.
    else:
      return 0.

  def _tuple(self):
    return (self.num, self.min, self.max, self.sum, self.sum2)

  def __repr__(self):
    """Produce somewhat human-friendly representation of the value."""
    return repr(self._tuple())

  def __add__(self, other):
    """Add two quantities."""
    return StatsQuant(num = self.num + other.num,
                      min = min(self.min, other.min),
                      max = max(self.max, other.max),
                      sum = self.sum + other.sum,
                      sum2 = self.sum2 + other.sum2)

  def __iadd__(self, other):
    """Merge statistics from another quantity to this one."""
    self.num += other.num
    self.min = min(self.min, other.min)
    self.max = max(self.max, other.max)
    self.sum += other.sum
    self.sum2 += other.sum2
    return self

  def tick(self, val):
    """Tick the value by adding one request's statistics to it

    @param val -- the amount to add.
    @return self.
    """
    self.num += 1
    self.min = min(self.min, val)
    self.max = max(self.max, val)
    self.sum += val
    self.sum2 += val * val
    return self

class StatsByteTiming:
  """Combined `StatsQuant` statistics for data served and response time."""
  def __init__(self, bytes = None, timing = None):
    self.bytes = bytes or StatsQuant()
    self.timing = timing or StatsQuant()

  def __repr__(self):
    return repr((self.bytes, self.timing))

  def __iadd__(self, other):
    return StatsByteTiming(bytes = self.bytes + other.bytes,
                           timing = self.timing + other.timing)

  def __add__(self, other):
    self.bytes += other.bytes
    self.timing += other.timing
    return self

  def tick(self, bytes, time):
    self.bytes.tick(bytes)
    self.timing.tick(time)
    return self

class StatsData:
  """Access statistics value.

  The value stored for each `StatsKey`, containing:
    - total: `StatsByteTiming` for all requests;
    - methods: `StatsByteTiming` by http method;
    - codes: `StatsByteTiming` by http return code;
    - users: `StatsByteTiming` by user names;
    - browsers: `StatsByteTiming` by browser;
    - ips: `StatsByteTiming` by client ip addreses;
    - hosts: `StatsByteTiming` by host names;
    - domains: `StatsByteTiming` by domain names;
    - countries: `StatsByteTiming` by two-letter country codes;
    - locations: `StatsByteTiming` by country, region and city.
  """
  def __init__(self,
               total = None,
               methods = None,
               codes = None,
               users = None,
               browsers = None,
               ips = None,
               hosts = None,
               domains = None,
               countries = None,
               locations = None):
    """Constructor, initialises value fields with data."""
    self.total = total or StatsByteTiming()
    self.methods = methods or {}
    self.codes = codes or {}
    self.users = users or {}
    self.browsers = browsers or {}
    self.ips = ips or {}
    self.hosts = hosts or {}
    self.domains = domains or {}
    self.countries = countries or {}
    self.locations = locations or {}

  def _tuple(self):
    return (self.total.timing, self.total.bytes,
            len(self.methods), len(self.codes),
            len(self.users), len(self.browsers),
            len(self.ips), len(self.hosts), len(self.domains),
            len(self.countries), len(self.locations))

  def __repr__(self):
    """Produce somewhat human-friendly representation of the value."""
    return ("<StatsData TIMING %s; BYTES %s; NUSR %d; NMTH %d; NCOD %d; NBRW %d;"
            " NIP %d; NHOST %d; NDOM %d; NCC %d; NLOC %d>" % self._tuple())

  def __add__(self, other):
    """Add two stats counters."""
    dicts = (({}, self.methods, other.methods),
             ({}, self.codes, other.codes),
             ({}, self.users, other.users),
             ({}, self.browsers, other.browsers),
             ({}, self.ips, other.ips),
             ({}, self.hosts, other.hosts),
             ({}, self.domains, other.domains),
             ({}, self.countries, other.countries),
             ({}, self.locations, other.locations))

    for d, mine, othr in dicts:
      for c in mine, othr:
        for k, v in c.iteritems():
          if k not in d:
            d[k] = StatsByteTiming()
          d[k] += v

    return StatsData(total = self.total + other.total,
                     methods = dicts[0][0],
                     codes = dicts[1][0],
                     users = dicts[2][0],
                     browsers = dicts[3][0],
                     ips = dicts[4][0],
                     hosts = dicts[5][0],
                     domains = dicts[6][0],
                     countries = dicts[7][0],
                     locations = dicts[8][0])

  def __iadd__(self, other):
    """Merge statistics from another value counter to this one."""
    for mine, othr in ((self.methods, other.methods),
                       (self.codes, other.codes),
                       (self.users, other.users),
                       (self.browsers, other.browsers),
                       (self.ips, other.ips),
                       (self.hosts, other.hosts),
                       (self.domains, other.domains),
                       (self.countries, other.countries),
                       (self.locations, other.locations)):
      for k, v in othr.iteritems():
        if k not in mine:
          mine[k] = StatsByteTiming()
        mine[k] += v

    self.total += other.total
    return self

  def tick(self, bytes, time, method, code, user, browser, ip,
           host, domain, country, location):
    """Tick the value by adding one request's statistics to it.

    @param bytes -- number of bytes served.
    @param time -- time in millisecond spent to serve the request.
    @param method -- request method.
    @param code -- request http return code.
    @param user -- user name of the client.
    @param browser -- browser of the client.
    @param ip -- ip address of the client.
    @param host -- host name of the client.
    @param domain -- domain name of the client.
    @param country -- country of the client.
    @param location -- location of the client.
    @return self.
    """
    self.total.tick(bytes, time)
    for c, key in ((self.methods, method),
                   (self.codes, code),
                   (self.users, user),
                   (self.browsers, browser),
                   (self.ips, ip),
                   (self.hosts, host),
                   (self.domains, domain),
                   (self.countries, country),
                   (self.locations, location)):
      if key:
        if key not in c:
          c[key] = StatsByteTiming()
        c[key].tick(bytes, time)
    return self

class LogResolver(Thread):
  """Separate utility thread spawned for running IP address resolution
  on the background while log scanning is going on.

  Log scanning processes send their lists of new IP addresses to this
  thread every once in a while. The IP address resolution therefore
  happens on the background while logs are being processed. Note that
  depending on number of unique IP addresses in the logs, the origin
  of the addresses, the DNS configuration and network performance,
  this thread alone can utilise a significant fraction of a CPU core.

  Since address resolution is asynchronous, this thread should be told
  to quit before querying `IPResolver` for the final results. This
  ensures all addresses have been submitted to the resolver and have
  been resolved before retrieving the results.

  This thread must run in the same multiprocessing process which will
  retrieve the final results from `IPResolver`. The results are not
  sent anywhere, they should be retrieved from the resolver itself.
  """
  def __init__(self, ip2i, queue):
    """Constructor. Initialise with `IPResolver` instance `ip2i` and
    multiprocessing `Queue` instance `queue`. The log scanners should
    send sets of string-format IP addresses to this queue. The final
    results will be available from `ip2i.query()` at the end."""
    Thread.__init__(self)
    self.ip2i = ip2i
    self.queue = queue

  def run(self):
    """Run the resolver thread.

    Alternately waits up to 0.5 s for new addresses to show up on the
    input queue, then spends up to 5 seconds to process DNS resolution
    tasks.

    `None` should be sent to the input queue once all other addresses
    have been sent to complete the resolution.  This causes the thread
    to wait for the resolution to complete entirely, then to exit.

    Note the results are not returned. The thread owner should query
    the `IPResolver` instance for the results."""
    while True:
      try:
        task = self.queue.get(True, 0.5)
        if task == None:
          self.ip2i.wait()
          return

        self.ip2i.submit(task)

      except Empty:
        self.ip2i.process(5)

class LogParser(Process):
  """Internal utility process spawned to parse log files concurrently in
  multiple separate process.

  The sole purpose of this class is to push log parsing into separate
  processes using python multiprocessing such that parsing can utilise
  fully all available CPU cores. Each `LogParser` process pulls files
  to parse off a shared task queue to parse, and invokes the parser on
  them.

  Each parse invocation is expected to produce a preliminary analytics
  result, which is pushed back to another queue to a `LogAggregator`
  for merging into final results. The parsers are expected to stream
  lists of new IP addresses regularly to `LogResolver` so IP address
  resolution completes largely while parsing takes place.

  Once the process receives `None` in the task queue it outputs `None`
  on the result queue and exits. The owner of this class should insert
  as many `None` objects into the task queue as there are processes
  running, and join processes when it receives `None` objects in the
  output queue. The results are complete when all the processes have
  been joined.

  Please see the implementation note at the beginning of this file
  for important information on technical design of this class.
  """
  def __init__(self, id, rx, parser, queue, qresult, *args):
    Process.__init__(self)
    self.id = id
    self.rx = rx
    self.parser = parser
    self.queue = queue
    self.qresult = qresult
    self.args = args

  def run(self):
    try:
      while True:
        task = self.queue.get()
        if task == None:
          return

        debug("LOGREADER", 1, "#%d processing %s", self.id, " ".join(task))
        stats = self.parser(log_file_parse(self.rx, *task), *self.args)
        self.qresult.put((self.id, stats))

    finally:
      # Send result objects.
      self.qresult.put((self.id, None))

class LogAggregator(Process):
  """Internal utility process spawned to aggregate stats results.

  This process collects all the partial statistics from log parsers
  and produced final aggregated statistic, which it then writes out.
  The process exits when all the input log files have been processed;
  see the implementation notes at the beginning for an explanation.

  The statistics are stored broken down by `StatsKey`. Each server
  access is counted against exactly one `StatsKey`, so statistics for
  different keys are disjoint and can be combined freely. The response
  time average and standard deviation can be re-calculated for
  arbitrary key combinations.

  The stats summaries are saved in plan text, json and yaml formats.
  """

  def __init__(self, analyser, lim, logs, statfile, dbfile, mystamp):
    Process.__init__(self)
    self.lim = lim
    self.logs = logs
    self.statfile = statfile
    self.dbfile = dbfile
    self.mystamp = mystamp
    self.ip2i = analyser.ip2i
    self.time_format = analyser.time_format
    self.time_unit = analyser.time_unit
    self.rx = analyser.rx
    self.parser = analyser.parser
    self.qresolver = Queue()
    self.resolver = LogResolver(self.ip2i, self.qresolver)

  def run(self):
    # Out of date, (re)generate the statistics. Resolve IP addresses.
    stats = self._parse()

    # Resolve IP addresses and close resolver.
    self._resolve(stats)

    # Produce summary.
    timebins, svckeys = self._summarise(stats)

    # Create stats directory for detailed results.
    statdir = self.statfile.replace(".txt", "")
    if not os.path.exists(statdir + "-yml"):
      os.mkdir(statdir + "-yml")
    if not os.path.exists(statdir + "-json"):
      os.mkdir(statdir + "-json")

    # Save the summary.
    self._save_text(timebins, svckeys, stats, statdir)
    self._save_yaml(timebins, svckeys, stats, statdir)
    self._save_json(timebins, svckeys, stats, statdir)

    # Update database stamp.
    open(self.dbfile, "w").write(self.mystamp)

    # Report resolver statistics.
    debug("LOGREADER", 1, "resolver stats:")
    resstat = self.ip2i.statistics()
    for key in sorted(resstat.keys()):
      status, name = key
      debug("LOGREADER", 1, " %7d %s (%s)", resstat[key], name, status)

  def _parse(self):
    # Start resolver.
    self.resolver.start()

    # Build prototype stats result, with a bin for every time unit.
    stats = dict((strftime(self.time_format, gmtime(t)), {})
                 for t in xrange(self.lim[0], self.lim[1], self.time_unit))

    # Parse and resolve logs.
    qtasks = Queue()
    qresult = Queue()
    nproc = max(2, cpu_count()-1)
    xprocs = xrange(nproc)
    procs = [LogParser(cpu, self.rx, self.parser, qtasks, qresult,
                       self.qresolver, self.lim[0], self.lim[1],
                       self.time_format)
             for cpu in xprocs]

    map(lambda log: qtasks.put((log[6], log[2])), self.logs)
    map(lambda i: qtasks.put(None), xprocs)
    map(lambda p: p.start(), procs)

    # Wait for results.
    while nproc:
      procid, result = qresult.get()
      if result == None:
        nproc -= 1
        procs[procid].join()
        debug("LOGREADER", 1, "joined process #%d, %d still running",
              procid, nproc)
        continue

      nsvcs = 0
      for timebin, data in result.iteritems():
        assert timebin in stats, "Unexpected %s result" % timebin
        for sk, sd in data.iteritems():
          if sk not in stats[timebin]:
            stats[timebin][sk] = StatsData()
          stats[timebin][sk] += sd
          nsvcs += 1
      debug("LOGREADER", 1,
            "merged stats from process #%d, %d stats in %d timebins: %s",
            procid, nsvcs, len(result), " ".join(sorted(result.keys())))

    return stats

  def _resolve(self, stats):
    debug("LOGREADER", 1, "received all results, resolving addresses")
    addrs = set()
    for daydata in stats.values():
      for stat in daydata.values():
        addrs.update(ip for ip in stat.ips.keys())

    self.qresolver.put(addrs)
    self.qresolver.put(None)
    self.resolver.join()
    self.resolver = None
    self.qresolver = None
    ipcache = self.ip2i.query()

    debug("LOGREADER", 1, "remapping ip addresses to detailed info")
    for daydata in stats.values():
      for stat in daydata.values():
        for ip, v in stat.ips.iteritems():
          ipi = ipcache[ip]
          for m, val in ((stat.hosts, ipi.hostname),
                         (stat.domains, ipi.domain),
                         (stat.countries,
                          ipi.geoip.country or ipi.asn.country),
                         (stat.locations,
                          ", ".join(x for x in
                                    (ipi.geoip.country,
                                     ipi.geoip.region,
                                     ipi.geoip.city)
                                    if x != None))):
            if val not in m:
              m[val] = StatsByteTiming()
            m[val] += v

  def _summarise(self, stats):
    debug("LOGREADER", 1, "producing global summaries")
    timebins = sorted(set(stats.keys())) + ["TOTAL"]
    svcs = set(s.service for data in stats.values() for s in data.keys())
    svckeys = [StatsKey(x) for x in ["ALL"] + sorted(svcs)]

    for tb in timebins:
      for svc in svckeys:
        if tb not in stats:
	  stats[tb] = {}
	if svc not in stats[tb]:
	  stats[tb][svc] = StatsData()

    allkey = StatsKey("ALL")
    for timebin, data in stats.iteritems():
      for s, v in data.iteritems():
	svckey = StatsKey(s.service)
        if timebin != "TOTAL" and s.service != "ALL" and svckey != s:
	  if s not in stats["TOTAL"]:
            stats["TOTAL"][s] = StatsData()
	  stats["TOTAL"][s] += v
	  stats["TOTAL"][allkey] += v
	  stats["TOTAL"][svckey] += v
	  stats[timebin][allkey] += v
	  stats[timebin][svckey] += v

    return timebins, svckeys

  def _save_text(self, timebins, svckeys, stats, statdir):
    debug("LOGREADER", 1, "saving text summary")

    def underline(svc, line):
      return "  " + svc.service + line[len(svc.service):]

    def format(v):
      return ((" %10d" + " %10.1f" * 8 + " %7d" * 9) %
              (v.total.timing.num,
               v.total.timing.avg, v.total.timing.rms,
               v.total.timing.min, v.total.timing.max,
               v.total.bytes.avg, v.total.bytes.rms,
               v.total.bytes.min, v.total.bytes.max,
               len(v.methods), len(v.codes),
               len(v.users), len(v.browsers),
               len(v.ips), len(v.hosts), len(v.domains),
               len(v.countries), len(v.locations)))

    result = StringIO()
    titles1 = ("#request",
               "dt avg", "dt rms", "dt min", "dt max",
               "out avg", "out rms", "out min", "out max")
    titles2 = ("#method", "#code", "#user", "#brwser",
               "#ip", "#host", "#domain",
               "#c'ntry", "#loc'n")
    line = "_" * (11 * len(titles1) + 8 * len(titles2) - 2)

    result.write(" " * 11)
    result.writelines(underline(svc, line) for svc in svckeys)
    result.write("\n")
    result.write("%-10s" % "Date")
    result.writelines((" %10s" * len(titles1) + " %7s" * len(titles2))
                      % (titles1 + titles2) for svc in svckeys)
    result.write("\n")

    # Now add stats per service for each time bin.
    for timebin in timebins:
      result.write("%-10s" % timebin)
      result.writelines(format(stats[timebin][svc]) for svc in svckeys)
      result.write("\n")

    # Write it out.
    open(self.statfile, "w").write(result.getvalue())

  def _save_yaml(self, timebins, svckeys, stats, statdir):
    debug("LOGREADER", 1, "saving yaml summary")

    def pad(n, s):
      padding = " " * n
      return padding + s.rstrip().replace("\n", "\n" + padding) + "\n"

    def maxcnt(timebin, svc):
      if timebin == "TOTAL" and svc.service == "ALL":
        return 50
      elif timebin == "TOTAL" or svc.service == "ALL":
        return 25
      else:
        return 10

    def slice(vals, nmax):
      items = sorted(vals.items(), reverse=True, key=lambda kv: kv[1].timing.num)
      if nmax < 0 or len(items) <= nmax+1:
	return items

      result = items[0:nmax]
      tail = items[nmax:]
      k = "%d others" % len(tail)
      v = sum((kv[1] for kv in tail), StatsByteTiming())
      result.append((k, v))
      return result

    def format_quant(q):
      return ("{ tot: %.1f, avg: %.1f, rms: %.1f, min: %.1f, max: %.1f }"
              % (q.sum, q.avg, q.rms, q.min, q.max))

    def format_list(vals, nmax):
      return "".join("- %s:\n"
                     "    nr of requests: %d\n"
                     "    response time:  %s\n"
                     "    kilobytes out:  %s\n" %
                     ((k == "-" and "(Unidentified)" or k),
                      v.timing.num,
                      format_quant(v.timing),
                      format_quant(v.bytes))
                     for k, v in slice(vals, nmax))

    def format_svc(s):
      return ("service:        %s\n"
              "instance:       %s\n"
              "subclass:       %s\n"
              "api:            %s\n"
              % s)

    def format_val(v, nmax):
      return ("nr of requests: %d\n"
              "response time:  %s\n"
              "kilobytes out:  %s\n"
              "http methods:\n%s"
              "http codes:\n%s"
              "users:\n%s"
              "browsers:\n%s"
              "ip addresses:\n%s"
              "hostnames:\n%s"
              "domains:\n%s"
              "countries:\n%s"
              "locations:\n%s" %
              (v.total.timing.num,
               format_quant(v.total.timing),
               format_quant(v.total.bytes),
               pad(2, format_list(v.methods, nmax)),
               pad(2, format_list(v.codes, nmax)),
               pad(2, format_list(v.users, nmax)),
               pad(2, format_list(v.browsers, nmax)),
               pad(2, format_list(v.ips, nmax)),
               pad(2, format_list(v.hosts, nmax)),
               pad(2, format_list(v.domains, nmax)),
               pad(2, format_list(v.countries, nmax)),
               pad(2, format_list(v.locations, nmax))))

    # Output overall summary for each time bin.
    result = gzopen("%s-yml/summary.yml.gz" % statdir, "wb", 9)
    result.write("---\n")
    for timebin in timebins:
      result.write("%s:\n" % timebin)
      result.writelines("  - %s:\n%s" %
                        (svc.service,
                         pad(6, format_val(stats[timebin][svc],
                                           maxcnt(timebin, svc))))
                        for svc in svckeys
                        if stats[timebin][svc].total.timing.num != 0)
    result.close()

    # Output per-timebin detailed files, including one for "TOTAL".
    for timebin in timebins:
      result = gzopen("%s-yml/%s.yml.gz" % (statdir, timebin), "wb", 9)
      result.write("---\n")
      result.write("%s:\n" % timebin)
      for svc in svckeys:
        if stats[timebin][svc].total.timing.num != 0:
          result.write("  - %s:\n"
                       "    - total:\n" %
                       svc.service)
          result.write(pad(8, format_val(stats[timebin][svc],
                                         maxcnt(timebin, svc))))

          items = sorted(((s, v) for s, v in stats[timebin].iteritems()
                          if s.service == svc.service and s not in svckeys),
                         key = lambda sv: sv[1].total.timing.sum,
                         reverse = True)
          result.write("    - services by time:\n")
          result.writelines("      - %d:\n%s%s" %
                            (n,
                             pad(10, format_svc(sv[0])),
                             pad(10, format_val(sv[1], 7)))
                            for n, sv in zip(xrange(len(items)), items))

          items = sorted(((s, v) for s, v in stats[timebin].iteritems()
                          if s.service == svc.service and s not in svckeys),
                         key = lambda sv: sv[1].total.bytes.sum,
                         reverse = True)

          result.write("    - services by output:\n")
          result.writelines("      - %d:\n%s%s" %
                            (n,
                             pad(10, format_svc(sv[0])),
                             pad(10, format_val(sv[1], 7)))
                            for n, sv in zip(xrange(len(items)), items))
      result.close()

  def _save_json(self, timebins, svckeys, stats, statdir):
    debug("LOGREADER", 1, "saving json summary")
    strings = {}

    def maxcnt(timebin, svc):
      if timebin == "TOTAL" and svc.service == "ALL":
        return 50
      elif timebin == "TOTAL" or svc.service == "ALL":
        return 25
      else:
        return 10

    def mkstr(s):
      if s in strings:
        return strings[s]
      else:
        id = len(strings)
        strings[s] = id
        return id

    def slice(vals, nmax):
      items = sorted(vals.items(), reverse=True, key=lambda kv: kv[1].timing.num)
      if nmax < 0 or len(items) <= nmax+1:
	return items

      result = items[0:nmax]
      tail = items[nmax:]
      k = "%d others" % len(tail)
      v = sum((kv[1] for kv in tail), StatsByteTiming())
      result.append((k, v))
      return result

    def format_quant(q):
      return ('[%.3f,%.3f,%.3f,%.3f,%.3f]'
              % (q.num, q.sum, q.sum2, q.min, q.max))

    def format_list(vals, nmax, pad):
      return (",\n" + pad).join('[%d,%d,%s,%s]' %
                                (mkstr(k == "-" and "(Unidentified)" or k),
			         v.timing.num,
			         format_quant(v.timing),
			         format_quant(v.bytes))
		                for k, v in slice(vals, nmax))

    def format_svc(s):
      return '%d,%d,%d,%d' % (mkstr(s.service), mkstr(s.instance),
                              mkstr(s.subclass), mkstr(s.api))

    def format_columns():
      return ('"nreq","total","hmethod","hcode","user","browser"'
	      ',"ip","host","domain","country","location"')

    def format_val(v, nmax, pad):
      lpad = pad + " "
      return (('%d,[%s,%s]' + (',\n' + pad + '[%s]') * 9) %
              (v.total.timing.num,
               format_quant(v.total.timing),
	       format_quant(v.total.bytes),
               format_list(v.methods, nmax, lpad),
	       format_list(v.codes, nmax, lpad),
	       format_list(v.users, nmax, lpad),
	       format_list(v.browsers, nmax, lpad),
	       format_list(v.ips, nmax, lpad),
	       format_list(v.hosts, nmax, lpad),
	       format_list(v.domains, nmax, lpad),
	       format_list(v.countries, nmax, lpad),
               format_list(v.locations, nmax, lpad)))

    # Output overall summary for each time bin.
    strings = {}
    result = open("%s-json/summary.txt" % statdir, "wb")
    result.write('{"data":[\n')
    for timebin in timebins:
      result.write('{"bin":"%s","items":[\n' % timebin)
      result.write(',\n'.join
		   ('[%d,%s]' %
		    (mkstr(svc.service),
		     format_val(stats[timebin][svc],
				maxcnt(timebin, svc),
				" "))
                    for svc in svckeys
                    if stats[timebin][svc].total.timing.num != 0))
      result.write(']}')
      if timebin != timebins[-1]:
        result.write(",")
      result.write('\n')
    result.write('],"columns":["service",%s],"strings":[\n' % format_columns())
    result.write(',\n'.join
		 ('"%s"' % s for id, s in
	          sorted(zip(strings.values(), strings.keys()))))
    result.write("]}\n")
    result.close()

    # Output per-timebin detailed files, including one for "TOTAL".
    for timebin in timebins:
      strings = {}
      result = open("%s-json/%s.txt" % (statdir, timebin), "wb")
      result.write('{"data":[\n')
      result.write('{"bin":"%s","items":[\n' % timebin)
      skeys = [s for s in svckeys if stats[timebin][s].total.timing.num != 0]
      for svc in skeys:
        result.write('[%d,%s,[\n'
		     % (mkstr(svc.service),
			format_val(stats[timebin][svc], maxcnt(timebin, svc), " ")))

        items = sorted(((s, v) for s, v in stats[timebin].iteritems()
                        if s.service == svc.service and s not in svckeys),
                       key = lambda sv: sv[1].total.timing.num,
                       reverse = True)

        result.write(',\n'.join
		     ("  [%s,%s]" %
		      (format_svc(s), format_val(v, maxcnt(timebin, s), "   "))
                      for s, v in items))
        result.write(" ]]")
        if svc != skeys[-1]:
          result.write(",")
        result.write("\n")
      result.write(']}],"columns":["service",%s,"detail"],"strings":[\n' % format_columns())
      result.write(',\n'.join
                   ('"%s"' % s for id, s in
	            sorted(zip(strings.values(), strings.keys()))))
      result.write("]}\n")
      result.close()

# FIXME: for arbitrary time binning:
#  The time bin is a string, "YYYYMMDDTHH00" for hour bins, "YYYYWW"
#  for week bins, and "YYYYMMDD" for day bins.
#    - YYYY: four-digit year;
#    - MM: two-digit month, 1 .. 12;
#    - DD: two-digit day of month, 1 .. 31;
#    - HH: two-digit hour, 0 .. 23;
#    - WW: two-digit ISO week number, 1 .. 53, or empty string.

class LogAnalyser:
  """Log analysis manager object.

  The `LogAnalyser` coordinates the analysis of web server log files.
  It maintains a directory of server access analytics, using some set
  of input directories and a log matcher: regexp + classifier.

  The analyser processes files named 'access_log_yyyymmdd.txt' in any
  'access_log_yyyymm.zip' files contained in the input directories.
  There can be several zip and log files for any one month and day.
  All the logs are processed together, allowing easy aggregation of
  results to combined analytics across multiple servers.

  The analyser processes logs in monthly groups and produces daily and
  monthly summaries. For each month it collects list of applicable log
  files. It is assumed the logs were automatically rotated daily and
  the log file name matches the log entry dates reasonably well. The
  analyser includes log files for one day before and after the month
  in case the logs are slightly (less than a day) out of order.

  The logs are split into lines and matched against the given regular
  expression, and the results fed to the provided custom classifier
  function which builds the actual server access statistics. This is
  done in parallel, using all the CPU cores on the system.

  The analyser updates three file sets in the target directory with
  the results: a simple fixed column-width format top-level summary
  text file per month, and two per-month directories for YAML and JSON
  files with more complete details. The latter include one summary file
  with overall results for each day and monthly total (but less detail),
  and a file per day plus one for monthly total with complete details.

  The summaries include `StatsData` information keyed by `StatsKey`.
  The final lists written to output are truncated to top 50/25/10
  (plus one "N others") depending on context.

  The analyser maintains a state file for each month, recording which
  log files were used to produce the result. The results are refreshed
  automatically, month by month, if the input files selected for the
  results differ from those used for previous results. However if the
  file ".frozen-yyyymmm" exists, the results for that month are not
  updated even if the logs have changed. This allows logs of previous
  months to be moved to tape earlier (to avoid having to keep the
  one-day-before-month log file on disk).
  """
  def __init__(self, statedir, rx, parser, ip2i = None):
    """Constructor, initialise log analyser.

    @param statedir -- Directory for maintaining analytics results.

    @param rx -- Regular expression used to split input log files.
    All the lines in input log files must match this expression;
    lines which do not match will generate a warning.

    @param parser -- Classifier which consumes the `rx` match tuples.

    @param ip2i -- A `IPResolver` instance for resolving IP addresses.
    If None, the analyser instantiates an `IPResolver` with default
    argument list.
    """
    self.statedir = statedir
    self.ip2i = ip2i or IPResolver()
    self.time_format = "%Y-%m-%d" # time_format argument
    self.time_unit = 86400        # time_unit argument
    self.horizon = 1              # horizon argument
    self.rx = rx
    self.parser = parser

  def scan_dirs(self, dirs):
    """Scan input directories and update analytics results.

    @param dirs -- Iterable of directories which contain log archives.

    @return No return value. Updates analytics in state directory.
    """
    self.ip2i.reset_statistics()

    # Locate monthly log archives and peek inside for log files.
    months = {}
    all_logs = []
    for dir in dirs:
      for zip_path in iglob("%s/access_log_*.zip" % dir):
        st = os.stat(zip_path)
        m = re.match(r".*/access_log_((\d{4})(\d\d))\.zip$", zip_path)

        if not m:
          continue

        # Determine month date properties
        if m.group(1) not in months:
          year = nextyear = int(m.group(2))
          month = nextmonth = int(m.group(3))
          if month == 12:
            nextyear = year + 1
            nextmonth = 1
          else:
            nextmonth = month + 1

          # FIXME: use miscutils.timeseries() for arbitrary time units.
          month_start = timegm((year, month, 1, 0, 0, 0, 0, -1, -1))
          month_end = timegm((nextyear, nextmonth, 1, 0, 0, 0, 0, -1, -1))
          prev_day = month_start - self.time_unit * self.horizon
          next_day = month_end + self.time_unit * self.horizon
          months[m.group(1)] = (month_start, month_end,
                                strftime("%Y%m%d", gmtime(prev_day)),
                                strftime("%Y%m%d", gmtime(next_day)))

        zfile = ZipFile(zip_path, "r")
        for fi in zfile.infolist():
          n = re.match(r"access_log_(\d+)(?:\.txt)?$", fi.filename)
          if n:
            all_logs.append((m.group(1), n.group(1),
                             fi.filename, fi.file_size, fi.CRC,
                             "%04d%02d%02dZ%02d%02d%02d" % fi.date_time,
                             zip_path, st[ST_SIZE], st[ST_MTIME]))

    # For each month build a list of log files to consider as input.
    # For any one month, we take files for one previous and one next
    # day to handle slightly out of order logging.
    monthly_logs = {}
    for month, lim in months.iteritems():
      logs = [l for l in all_logs if l[1] >= lim[2] and l[1] < lim[3]]
      monthly_logs[month] = sorted(logs)

    # Decide which months need to be reprocessed. For each month build
    # a list of log files we used for that months results, and compare
    # to the list we have saved (if any). Reprocess the month if the
    # the two lists aren't identical and the month isn't frozen.
    for month in sorted(months.keys(), reverse=True):
      lim = months[month]
      logs = monthly_logs[month]

      statfile = "%s/stats-%s.txt" % (self.statedir, month)
      dbfile = "%s/stats-%s.db" % (self.statedir, month)
      dbfrozen = "%s/.frozen-%s" % (self.statedir, month)
      mystamp = "".join("%s %s %s %s %s\n" %
                        (f[4], f[3], f[5], f[2], f[6])
                        for f in logs)

      try:
        oldstamp = os.access(statfile, os.R_OK) and open(dbfile).read()
      except EnvironmentError:
        oldstamp = None

      if mystamp != oldstamp and not os.path.exists(dbfrozen):
        agg = LogAggregator(self, lim, logs, statfile, dbfile, mystamp)
        agg.start()
        agg.join()
