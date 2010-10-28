import os, os.path, re
from Analytics.LogReader import *
from Analytics.Debug import debug
from traceback import print_exc
from time import strftime, gmtime
from calendar import timegm
from zipfile import ZipFile

__all__ = ["RXLOG", "BROWSER2NAME", "URI2SVC", "cmsweb_parser", "expand"]

"""Cache of browser to name mappings."""
_browsermap = {}

"""Cache of recently seen IP addreses."""
_seenip = set()

"""Map month abbreviations to numeric value, with January == 1."""
MONTH = { "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12 }

"""Regular expression for cmsweb front-end server log files.

The log parsing spends much time in regexp matching, so avoid costly
constructs in this regexp, especially unnecessary backtracking and
match groups. This is the reason RXLOG does not attempt to match
'HTTP/n.m' at the end of the request line: attempting to match all
attack and malformed requests would more than double the log parsing
time. Hence the suffix is matched manually in cmsweb_parser."""
RXLOG = re.compile(r"^\[(\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d) ([-+]\d{4})\]"
                   r" \S+ (\S+) \"([A-Z]+) (.*)\" (\d+)"
                   r" \[data: (?:\d+|-) in (\d+) out (?:\d+|-) body (\d+) us \]"
                   r" \[auth: \S+ \S+ \"([^\"]*)\" .* \]"
                   r" \[ref: \".*?\" \"(.*)\" \]$")

"""Series of mappings from user agent idents to version. Match the
browser ident against these regular expressions in the list order.
When a match is found, perform re.sub with the version argument to
translate the full version to an abberviated more useful one."""
BROWSER2NAME = [
  (re.compile(r"(Netcraft Web Server Survey|Netvibes)"), r"\1"),
  (re.compile(r"(http://[^;\)]+)"), r"Bot \1"),

  (re.compile(r"(visDQMUpload) .*python/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"((?:WM|Prod)Agent) .*Revision: (\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"(WMCore\.\S+)/(\S+)"), r"\1 \2"),
  (re.compile(r"(PhEDEx-WebApp|dls-client)/(\S+)"), r"\1 \2"),
  (re.compile(r"(Python)(?:-urllib?)/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"(Android \d+\.\d+)"), r"\1"),
  (re.compile(r"(Chrome|Opera|Java|LWP::Simple|Lynx"
              r"|Wget|curl|w3m|WWW-Mechanize)/(\d+\.\d+)"), r"\1 \2"),

  (re.compile(r"(iPhone);.*Version/(\d\.\d).* (Safari)/"), r"\1 \3 \2"),
  (re.compile(r"Version/(\d\.\d).* (Safari)/"), r"\2 \1"),
  (re.compile(r"(Safari)/(\d+\.\d+)"), r"\1 \2"),

  (re.compile(r"(SeaMonkey|Iceweasel|Epiphany"
              r"|Camino|Konqueror)/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"(Firefox)(?:-.*)?/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"(Konqueror|AppleWebKit)/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"(MSIE \d+\.\d+)"), r"\1"),
  (re.compile(r"(Mozilla)/(\d+\.\d+)"), r"\1 \2"),

  (re.compile(r"(ELinks|ZmEu)"), r"\1"),
  (re.compile(r"(libwww-perl|lwp-\w+)/(\d+\.\d+)"), r"\1 \2"),
  (re.compile(r"^-$"), r"(Incognito?)") ]

"""Series of mappings of URIs to a tuple usable for `ServiceKey`:
service, instance, subclass, api. The first entry of each tuple is the
regular expression to match against the URI argument.

The remaining tuple elements are either:
- `None` to use default value for that parameter.
- A literal string to use always as the value.
- Number N to use match group N for the value.
- Tuple ('choose', N, (REGEXP, STR)...) which returns the first
  literal string STR for which the REGEXP matches URI's match group N.
- Tuple ('rewrite', N, (REGEXP, SUBST)...) which returns URI's match
  group N rewritten through re.sub on all REGEXP, SUBST pairs.

The first regexp to match the URI will be used to map the URI to a
`ServiceKey`. The regexps should be ordered by frequency of match.
The vast majority of the log parsing is spent in the regexp matches
so it's important to avoid costly constructs, especially with lots
of backtracking and unnecessary match groups.
"""
URI2SVC = [
  (re.compile(r"(/dqm)(/[^/]+)($|/[^?&]*)"),
   1, 2,
   ('choose', 3,
    (re.compile(r"^/plotfairy"), "plots"),
    (re.compile(r"^"), "app")),
   ('rewrite', 3,
    (re.compile(r"^(/plotfairy/[^/]+).*"), r"\1"),
    (re.compile(r"^(/(?:extjs|yui|static|data/[^/]+))/.*"), r"\1/*"),
    (re.compile(r"^(/session/)[^/]+($|/)"), r"\1*\2"))),

  (re.compile(r"(/phedex/datasvc)(/(?:docs?|app|static))($|/[^?&]*)"),
   1, None, 2,
   ('rewrite', 3,
    (re.compile(r"^/[^/]+\.[a-z]+$"), r"/*.*"),
    (re.compile(r"^(/(?:yui|css|js|images))/.*"), r"/yui-css-js-imgs/*"))),

  (re.compile(r"(/phedex/datasvc)(?:(/+[^/]+)(/[^/]+)($|/[^?&]*)?)"),
   1, 3, 2, 4),

  (re.compile(r"(/phedex)(/graphs)($|/[^?&]*)"),
   1, None, 2, 3),

  (re.compile(r"(/phedex)(/([^/.]+))?($|/[^?&]*)"),
   1, 2, "other",
   ('rewrite', 4,
    (re.compile(r"^/[^/]+\.[a-z]+$"), "/*.*"))),

  (re.compile(r"((/(?:base|conddb|crabconf|prod-?mon|prodrequest"
              r"|das|dbs_discovery|filemover|sitedb|T0Mon))"
              r"(?:[-a-z0-9_]*))($|/[^?&]*)"),
   ('rewrite', 2, (re.compile(r"/prod[-a-z]+"), "/prodtools")),
   1, None,
   ('rewrite', 3,
    (re.compile(r"/YUI/.*"), r"/YUI/*"),
    (re.compile(r"/[^/]+\.root$"), r"/*.root"),
    (re.compile(r"/(?:js|css|imgs?|images)/[^/]+\.[a-z]+$"), r"/js-css-img/*.*"))),

  (re.compile(r"((/overview)(?:[-a-z0-9_]*))($|/[^?&]*)"),
   2, 1,
   ('choose', 3,
    (re.compile(r"^/plotfairy"), "plots"),
    (re.compile(r"^"), "app")),
   ('rewrite', 3,
    (re.compile(r"^(/plotfairy/[^/]+).*"), r"\1"),
    (re.compile(r"^(/(extjs|yui|static))/.*"), r"\1/*"),
    (re.compile(r"^(/session/)[^/]+($|/)"), r"\1*\2"))),

  (re.compile(r"(/(?:$|(?:favicon|index|robots)\.[a-z]+$|img/|css/))"),
   "static-content", None, None, 1),

  (re.compile(r"((?:HTTP|[a-z]+[.:]|//?(?:admin|mysql|sql|pma|[a-z.]*w00t)|"
              r"/\?|.*/php|.*\.php|.*/(?:cgi-bin|soap)).*)"),
   "attacks", None, None,
   ('rewrite', 1,
    (re.compile(r"(/phpMyAdmin)-[-0-9a-z.]+"), r"\1-*"))) ]

def expand(m, how, default = ""):
  """Expand match `m` as `how`, using `default` value if the values is
  unresolved. See `URI2SVC` for documentation on possible forms of
  `how`."""
  if how == None:
    return default
  elif isinstance(how, int):
    return m.group(how) or default
  elif isinstance(how, str):
    return m.expand(how)
  elif how[0] == 'choose':
    s = m.group(how[1])
    for pat, res in how[2:]:
      if re.match(pat, s):
        s = res
        break
    return s or default
  elif how[0] == 'rewrite':
    s = m.group(how[1])
    for pat, res in how[2:]:
      s = re.sub(pat, res, s)
    return s or default
  else:
    assert False, "mapping not understood: '%s'" % repr(how)

def cmsweb_parser(rows, qresolver, start_time, end_time, time_format):
  """Classify log entries to higher-level info

  Processes log entries from `rows`. Rows with time outside the range
  from start_time to end_time are discarded. The rest are accumulated
  to results: a dictionary of timebin to dictionary of `StatsKey` to
  `StatsData`.

  URIs are mapped to `StatsKey` using `URI2SVC`. The user agent
  strings are mapped to more comprehensible ones using `BROWSER2NAME`.
  The log row's time is mapped to timebin using `time_format`.

  @param rows -- iterable yielding `RXLOG` match groups.
  @param qresolver -- queue for IP address resolution requests.
  @param start_time -- beginning of reporting period.
  @param end_time -- end of reporting period.
  @param time_format -- `strftime` string format for the reporting time bins.

  @return Dictionary of results, as described above.
  """
  # Parse the files, accumulating stats results.
  global _browsermap, _seenip # share across calls within one process
  newip = set()
  stats = {}

  # Read log entries.
  for row in rows:
    (date, tz, ip, method, uri, code, bytes, usecs, user, browser) = row

    # Request new IPs to be resolved on background.
    if ip not in _seenip:
      _seenip.add(ip)
      newip.add(ip)
      if len(newip) >= 50:
        qresolver.put(newip)
        newip = set()

    # Remove trailing " HTTP/n.m" from the URI. Some attacks make
    # malformed requests without the required HTTP/n.m part. Making
    # RXLOG match it optionally significantly slows down log pattern
    # matching, so handle it manually here.
    uriend = len(uri)
    if uriend > 9 and uri.find(" HTTP/", uriend-9, uriend-3) >= 0:
      uriend -= 9

    # Resolve log time.
    #
    # The strptime() version is twice as slow, so do it by hand.
    # strptime() also doesn't do +nnnn timezones, so we have to do
    # that part ourselves. Verify the UTC time is in the window we
    # want to report on.
    #
    # t = timegm(strptime(date, "%d/%b/%Y:%H:%M:%S")) \
    #     - (int(tz[0:3]) * 3600 + int(tz[3:5]) * 60)
    t = timegm((int(date[7:11]), MONTH[date[3:6]], int(date[0:2]),
                int(date[12:14]), int(date[15:17]), int(date[18:20]),
                0, 0, -1)) - (int(tz[0:3]) * 3600 + int(tz[3:5]) * 60)

    # Check the entry is in selected time window. We get sent logs
    # for an extended period before and after the actual period to
    # handle moderately out of order logs.
    if t < start_time or t >= end_time:
      continue

    # Resolve user agent into a more useful browser name/version.
    if browser not in _browsermap:
      newname = browser
      for rx, subst in BROWSER2NAME:
        m = rx.search(browser)
        if m: newname = m.expand(subst); break
      _browsermap[browser] = newname
      debug("CMSWEB", 2, "new browser %s from %s", newname, browser)
    browser = _browsermap[browser]

    # Map URI to service, instance, subclass and API call.
    key = None
    for rx, nsvc, ninst, nclass, napi in URI2SVC:
      m = rx.match(uri, 0, uriend)
      if m:
        key = StatsKey(service = expand(m, nsvc, "Other"),
                       instance = expand(m, ninst, "N/A"),
                       subclass = expand(m, nclass, "N/A"),
                       api = expand(m, napi))
        break

    if key == None:
      key = StatsKey(service = "other", instance = "N/A", subclass = "N/A",
                     api = re.sub(r"\?.*", "", uri[:uriend]))

    # Tick the stats.
    timebin = strftime(time_format, gmtime(t))
    if timebin not in stats:
      stats[timebin] = {}

    if key not in stats[timebin]:
      stats[timebin][key] = StatsData()

    stats[timebin][key].tick(float(bytes) / 1024,
                             float(usecs) * 1e-3,
                             method, code, user, browser, ip,
                             None, None, None, None)

  # Submit remaining IP addresses for query.
  if newip:
    qresolver.put(newip)

  # Return the stats.
  return stats

######################################################################
if __name__ == "__main__":
  import sys, os, os.path
  from Analytics.IPInfo import IPResolver
  from Analytics.LogReader import LogAnalyser
  debug["*"] = 1

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
  LogAnalyser(sys.argv[1], RXLOG, cmsweb_parser, IPResolver(maxtime = 15))\
    .scan_dirs(sys.argv[2:])
