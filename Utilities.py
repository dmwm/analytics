"""Miscellaneous utilities."""

import re, time, calendar, logging

"""Regular expression to split words and numbers, for `natkey`."""
RE_DIGIT_SEQ = re.compile(r'([-+]?\d+)')

"""Regular expression to detect thousand parts, for `thousands`."""
RE_THOUSANDS = re.compile(r'(\d)(\d{3}($|\D))')

"""Regular expression to split off trailing decimal part, for `thousands`."""
RE_DECIMAL = re.compile(r'^(.*?)(\.[^.]*)?$')

######################################################################
def thousands(s):
  """Format numbers nicely, with thousand separators."""
  prefix, suffix = RE_DECIMAL.match(s).groups()
  while True:
    r = re.sub(RE_THOUSANDS, r"\1'\2", prefix)
    if r == prefix:
      return r + (suffix or "")
    else:
      prefix = r
  return prefix + (suffix or "")

######################################################################
def natkey(s):
  """Convert string to alternating tokens of non-numeric words and
  numbers as python (big) integer type.

  Use this as a key function to python's built-in sort to sort strings
  into natural sort order. It returns a list, which when used as a
  sort key automatically sorts `s` so that numeric parts are compared
  numerically and non-numeric parts alphabetically.

  Only integral numeric parts are recognised. Leading -/+ sign in
  front of a numeric part is assumed to be part of the number.

  @return A list with alternating strings and python numbers.
  """
  list = re.split(RE_DIGIT_SEQ, s)
  return [ ((i % 2 == 0 and (list[i],)) or (int(list[i]),))[0]
	   for i in xrange(0, len(list)) ]

def natsorted(list):
  """Sort an iterable into natural sort order.

  Breaks each string into alternating series of non-numeric words and
  numbers (integers only).  The strings are then sorted by sorting the
  non-numeric parts alphabetically and the numeric parts numerically.

  @return The input list in sorted order.
  """
  return sorted(list, key = natkey)

######################################################################
def timeseries(span, start, end):
  """Generate a time series from `start` to `end` in units of `span`.

  Generates (LOW, HIGH) tuples where each tuple defines a half-open
  interval [LOW, HIGH).  The HIGH of one tuple will be the LOW of the
  following one. All generated intervals are in UTC time units. Except
  for the hourly spans, all intervals are from midnight to midnight.
  The spans for weeks, months and years are from first midnight of the
  corresponding one calendar week/month/year to the first midnight of
  the next one.

  The `span` may be the string "hour", "day", "week" or "month".
  - "hour" generates hour intervals.
  - "day" generates day intervals.
  - "week" generates ISO week intervals (from Mondays).
  - "month" generates calendar month intervals from first of month.
  - "year" generates calendar year intervals from first of January.

  The time series starts from the beginning of the interval `start`
  falls into, and ends in an interval that contains `end`.  If `start`
  equals to `end`, then generates a single interval tuple containing
  `start` and `end`.

  For example requesting for the week interval where start and end
  equal the current UTC time, the result is one time interval where
  LOW is the beginning of the week and HIGH is the beginning of the
  next week.

  @return This is a generator, so there's no return value as such.
  """
  if span == 'hour':
    # Convert first time to UTC hour, then make a series of hours.
    low = int(start / 3600)
    high = max(low+1, int((end+3599) / 3600))
    for t in xrange(low, high):
      yield (t*3600, (t+1)*3600)
  elif span == 'day':
    # Convert first time to UTC day at 00:00, then make a series of days.
    low = int(start / 86400)
    high = max(low+1, int((end+86399) / 86400))
    for t in xrange(low, high):
      yield (t*86400, (t+1)*86400)
  elif span == 'week':
    # Convert first time to previous Monday.  Then make a
    # time series of weeks until we pass the end date.
    low = int(start/86400) - time.gmtime(start).tm_wday
    high = max(low+1, int((end+86399) / 86400))
    for t in xrange(low, high, 7):
      yield (t*86400, (t+7)*86400)
  elif span == 'month':
    # Create a time series for each first of the month.
    limit = int((end+86399)/86400)*86400
    t = time.gmtime(start)
    year = t.tm_year
    month = t.tm_mon
    day = calendar.timegm((year, month, 1, 0, 0, 0, 0, 0, 0))
    while True:
      low = day
      month += 1
      if month > 12:
	month = 1
	year += 1
      day = calendar.timegm((year, month, 1, 0, 0, 0, 0, 0, 0))
      yield (low, day)
      if day >= limit:
	break
  elif span == 'year':
    # Create a series of the first of January of each year.
    limit = int((end+86399)/86400)*86400
    t = time.gmtime(start)
    year = t.tm_year
    day = calendar.timegm((year, 1, 1, 0, 0, 0, 0, 0, 0))
    while True:
      low = day
      year += 1
      day = calendar.timegm((year, 1, 1, 0, 0, 0, 0, 0, 0))
      yield (low, day)
      if day >= limit:
	break

def timenumfmt(span, timeval):
  """Format `timeval` in numerical string format as unit of `span`:
  "hour", "day", "week", "month" or "year"."""
  if span == 'hour': return time.strftime('%Y%m%dZ%H00', time.gmtime(int(timeval)))
  elif span == 'day': return time.strftime('%Y%m%d', time.gmtime(int(timeval)))
  elif span == 'week': return time.strftime('%Y%V', time.gmtime(int(timeval)))
  elif span == 'month': return time.strftime('%Y%m', time.gmtime(int(timeval)))
  elif span == 'year': return time.strftime('%Y', time.gmtime(int(timeval)))

def sizevalue(val):
  """Convert a storage size into a numeric value (as bytes).  Storage
  sizes are a floating point number optionally followed by a letter
  "k", "M", "G", "T", "P" or "E" for kilo-, mega-, giga-, tera-,
  peta- and exabytes, respectively.  A raw number is accepted as
  well, returned as such, i.e. as bytes."""
  m = re.match(r'^([-+\d.Ee]+)([kMGTPE])$', val)
  if m:
    scale = { 'k': 2**10, 'M': 2**20, 'G': 2**30, 'T': 2**40, 'P': 2**50, 'E': 2**60 }
    return float(m.group(1)) * scale[m.group(2)]
  else:
    return float(val)

if __name__ == "__main__":
  print thousands("1000.1")
  print thousands("1000.1234")
  print natsorted(["A100", "A-10", "A+2", "B30", "B3A3", "B2A10", "B2A9" ])
  print natkey("A_30_C+45x10.1")

  def showtimes(span, start, end):
    print span, start, end, "=>", \
        [(timenumfmt(span, low), timenumfmt(span, high))
         for low, high in timeseries(span, start, end)]

  now = time.time()
  print "Now is %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))
  for span in 'hour', 'day', 'week', 'month', 'year':
    showtimes(span, now, now)
  showtimes('hour', now, now+86400)
  showtimes('day', now, now+10*86400)
  showtimes('week', now, now+35*86400)

  for val in "1", "1G", "123k":
    print val, "=", sizevalue(val)

