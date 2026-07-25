# -*- coding: utf-8 -*-

#
# Crypto-licensing -- Cryptographically signed licensing, w/ Cryptocurrency payments
#
# Copyright (c) 2022, Dominion Research & Development Corp.
#
# Crypto-licensing is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.  It is also available under alternative (eg. Commercial)
# licenses, at your option.  See the LICENSE file at the top of the source tree.
#
# It is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#

import calendar
import datetime
import fnmatch
import functools
import types
import getpass
import glob
import logging
import math
import os
import re
import sys
import time
import traceback

from functools		import wraps

import pytz_deprecation_shim as pytz
try:
    from tzlocal	import get_localzone
except ImportError:
    def get_localzone( _root='/' ):
        """No tzlocal; support basic Linux systems with a TZ variable or an /etc/timezone file"""
        # /etc/timezone, ... file?
        for tzbase in ( 'etc/timezone',			# Debian, Ubuntu, ...
                        'etc/sysconfig/clock' ): 	# RedHat, ...
            tzpath		= os.path.join( _root, tzbase )
            if os.path.exists( tzpath ):
                with open( tzpath, 'rb' ) as tzfile:
                    tzname	= tzfile.read().decode().strip()
                if '#' in tzname:
                    # eg. 'Somewhere/Special # The Special Zone'
                    tzname	= tzname.split( '#', 1 )[0].strip()
                if ' ' in tzname:
                    # eg. 'America/Dawson Creek'.  Not really correct, but we'll handle it
                    tzname	= tzname.replace( ' ', '_' )
                return pytz.timezone( tzname )

        raise pytz.UnknownTimeZoneError( 'Can not find any timezone configuration' )


from numbers		import Number

from urllib.parse	import urlencode, unquote       # noqa: F401
from urllib.request	import urlopen, Request		# noqa: F401

try:
    import pathlib					# noqa: F401
except ImportError:
    import pathlib2 as pathlib				# noqa: F401

# Use secrets.token_bytes for random number generation; supply for Python <3.6
try:
    from secrets	import token_bytes, DEFAULT_ENTROPY
except ImportError:
    # Directly from https://github.com/python/cpython/blob/3.10/Lib/secrets.py
    from random		import SystemRandom as _sysrand

    DEFAULT_ENTROPY = 32  # number of bytes to return by default

    # Python 3 <3.6 support; fall back to os.urandom
    _randbytes = getattr( _sysrand, 'randbytes', os.urandom )

    def token_bytes(nbytes=None):
        """Return a random byte string containing *nbytes* bytes.

        If *nbytes* is ``None`` or not supplied, a reasonable
        default is used.

        >>> token_bytes(16)  #doctest:+SKIP
        b'\\xebr\\x17D*t\\xae\\xd4\\xe3S\\xb6\\xe2\\xebP1\\x8b'
        """
        if nbytes is None:
            nbytes = DEFAULT_ENTROPY
        return _randbytes(nbytes)


type_str_base			= str
type_num_base			= Number

unicode				= str


def is_mapping( thing ):
    """See if the thing implements the Mapping protocol."""
    return hasattr( thing, 'keys' ) and hasattr( thing, '__getitem__' )


def is_listlike( thing ):
    """Something like a list or tuple; indexable, but not a string or a class (some may have
    __getitem__, eg. cpppo.state, based on a dict).

    """
    return not isinstance( thing, (type_str_base,type) ) and hasattr( thing, '__getitem__' )


__author__                      = "Perry Kundert"
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2022 Dominion R&D Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
Miscellaneous functionality used by various other modules.
"""


#
# Logging related tooling
#
def change_function( function, **kwds ):
    """Change a function with one or more changed co_... attributes, eg.:

            change_function( func, co_filename="new/file/path.py" )

    will change the func's co_filename to the specified string.

    The types.CodeType constructor differs between Python 2 and 3; see
    type help(types.CodeType) at the interpreter prompt for information:

    Python2:
        code(argcount,                nlocals, stacksize, flags, codestring,
         |        constants, names, varnames, filename, name, firstlineno,
         |        lnotab[, freevars[, cellvars]])

    Python3:
        code(argcount, kwonlyargcount, nlocals, stacksize, flags, codestring,
         |        constants, names, varnames, filename, name, firstlineno,
         |        lnotab[, freevars[, cellvars]])


    """
    if hasattr( function.__code__, 'replace' ):
        function.__code__	= function.__code__.replace( **kwds )
        return

    # Enumerate all the __code__ attributes in the same order; types.CodeTypes doesn't accept
    # keyword args, only positional.  This must be updated if new releases of Python have additional
    # parameters, but should be backward-compatible (the positional ordering should be consistent
    # for any parameters in use by a version)
    attrs			= [ "co_argcount",
                                    "co_posonlyargcount",
                                    "co_kwonlyargcount",
                                    "co_nlocals",
                                    "co_stacksize",
                                    "co_flags",
                                    "co_code",
                                    "co_consts",
                                    "co_names",
                                    "co_varnames",
                                    "co_filename",
                                    "co_name",
                                    "co_qualname",
                                    "co_firstlineno",
                                    "co_lnotab",
                                    "co_exceptiontable",
                                    "co_freevars",
                                    "co_cellvars", ]

    assert all( k in attrs and hasattr( function.__code__, k ) for k in kwds ), \
        "Invalid function keyword(s) supplied: %s" % ( ", ".join( kwds ))

    # Alter the desired function attributes w/ any supplied keywaords, and update the function's
    # __code__.  Deduces what positional args are required by which attrs exist in this function's
    # code object
    modi_args			= [
        kwds.get( a, getattr( function.__code__, a ))
        for a in attrs
        if hasattr( function.__code__, a )
    ]
    modi_code			= types.CodeType( *modi_args )
    modi_func			= types.FunctionType( modi_code, function.__globals__ )
    function.__code__		= modi_func.__code__


#
# Add some new custom logging levels with minimal functionality.
# We've tried to be consistent w/ cpppo's logging levels.
#

#      .FATAL 		       == 50
#      .ERROR 		       == 40
#      .WARNING 	       == 30
logging.NORMAL			= logging.INFO+5        # 25
logging.DETAIL			= logging.INFO+3        # 23
#      .INFO    	       == 20
#      .DEBUG    	       == 10
logging.TRACE			= logging.NOTSET+5      # 5
#      .NOTSET    	       == 0

logging.addLevelName( logging.NORMAL,	'NORMAL' )
logging.addLevelName( logging.DETAIL,	'DETAIL' )
logging.addLevelName( logging.TRACE,	'TRACE' )

# We'll use functools.partialmethod (Python 3.4+) if available for creating custom named log
# functions for the new levels. For older Python 3 versions (<3.4), we fall back to manually
# defining the methods and fixing their co_filename to match logging._srcfile.
if hasattr( functools, 'partialmethod' ):
    logging.Logger.normal		= functools.partialmethod( logging.Logger.log, logging.NORMAL )
    logging.Logger.detail		= functools.partialmethod( logging.Logger.log, logging.DETAIL )
    logging.Logger.trace		= functools.partialmethod( logging.Logger.log, logging.TRACE )
else:
    def __normal( self, msg, *args, **kwargs ):
        if self.isEnabledFor( logging.NORMAL ):
            self._log( logging.NORMAL, msg, args, **kwargs )

    def __detail( self, msg, *args, **kwargs ):
        if self.isEnabledFor( logging.DETAIL ):
            self._log( logging.DETAIL, msg, args, **kwargs )

    def __trace( self, msg, *args, **kwargs ):
        if self.isEnabledFor( logging.TRACE ):
            self._log( logging.TRACE, msg, args, **kwargs )

    change_function( __normal, co_filename=logging._srcfile )
    change_function( __detail, co_filename=logging._srcfile )
    change_function( __trace, co_filename=logging._srcfile )

    logging.Logger.normal		= __normal
    logging.Logger.detail		= __detail
    logging.Logger.trace		= __trace

    '''
    import traceback
    _logging_Logger_findCaller = logging.Logger.findCaller
    def __findCaller( self, *args, **kwds ):
        print( "{_srcfile} vs: ".format( _srcfile=logging._srcfile ) + ''.join( traceback.format_stack() ))
        return _logging_Logger_findCaller( self, *args, **kwds )
    logging.Logger.findCaller		= __findCaller
    '''

logging.normal			= functools.partial( logging.log, logging.NORMAL )
logging.detail			= functools.partial( logging.log, logging.DETAIL )
logging.trace			= functools.partial( logging.log, logging.TRACE )

log				= logging.getLogger( "misc" )

log_cfg				= {
    "level":	logging.NORMAL,
    "datefmt":	'%Y-%m-%d %H:%M:%S',
    #"format":	'%(asctime)s.%(msecs).03d %(threadName)10.10s %(name)-16.16s %(levelname)-8.8s %(funcName)-10.10s %(message)s',
    #"format":	'%(asctime)s %(levelname)-8.8s %(name)-16.16s %(filename)-16.16s %(lineno)-5d %(message)s',
    "format":	'%(asctime)s %(levelname)-8.8s %(name)-10.10s %(funcName)-10.10s %(message)s',
    #"format":	'%(asctime)s %(levelname)-8.8s %(name)-16.16s %(message)s',
}

log_levelmap 			= {
    -3: logging.FATAL,
    -2: logging.ERROR,
    -1: logging.WARNING,
    0: logging.NORMAL,
    1: logging.DETAIL,
    2: logging.INFO,
    3: logging.DEBUG,
    4: logging.TRACE,
}


def log_level( adjust ):
    """Return a logging level corresponding to the +'ve/-'ve adjustment"""
    return log_levelmap[
        max(
            min(
                adjust,
                max( log_levelmap.keys() )
            ),
            min( log_levelmap.keys() )
        )
    ]


def log_args( func ):
    """Decorator for logging function args, kwds"""
    @wraps( func )
    def wrapper( *args, **kwds ):
        print('args - ', args)
        print('kwds - ', kwds)
        return func(*args, **kwds)
    return wrapper


#
# misc.timer
#
# Select platform appropriate timer function (time.time for Python 3)
#
if sys.platform == 'win32' and sys.version_info[0:2] < (3,8):
    # On Windows (before Python 3.8), the best timer is time.clock
    timer			= time.clock
else:
    # On most other platforms the best timer is time.time
    timer			= time.time


def memoize( maxsize=None, maxage=None, log_at=None ):
    """A very simple memoization wrapper based on (immutable) args only, for simplicity.  Any
    keyword arguments must be immaterial to the successful outcome, eg. timeout, selection of
    providers, etc..

    Only successful (non-Exception) outcomes are cached!

    Keeps track of the age (in seconds) and usage (count) of each entry, updating them on each call.
    When an entry exceeds maxage, it is purged.  If the memo dict exceeds maxsize entries, 10% are
    purged.

    Optionally logs when we memoize something, at level log_at.
    """
    def decorator( func ):
        @wraps( func )
        def wrapper( *args, **kwds ):
            now			= timer()
            # A 0 hits count is our sentinel indicating args not memo-ized
            last,hits		= wrapper._stat.get( args, (now,0) )
            if not hits or ( maxage and ( now - last > maxage )):
                entry = wrapper._memo[args] = func( *args, **kwds )
                if log_at and log.isEnabledFor( log_at ):
                    if hits:
                        log.log( log_at, "{} Refreshed {!r} == {!r}".format( wrapper.__name__, args, entry ))
                    else:
                        log.log( log_at, "{} Memoizing {!r} == {!r}".format( wrapper.__name__, args, entry ))
            else:
                entry		= wrapper._memo[args]
                #log.detail( "{} Remembers {!r} == {!r}".format( wrapper.__name__, args, entry ))
            hits	       += 1
            wrapper._stat[args] = (now,hits)

            if maxsize and len( wrapper._memo ) > maxsize:
                # Prune size, by ranking each entry by hits/age.  Something w/:
                #
                #   2 hits 10 seconds old > 1 hits 6 seconds old > 3 hits 20 seconds old
                #
                # Sort w/ the highest rated keys first, so we can just eject all those after 9/10ths of
                # maxsize.
                rating		= sorted(
                    (
                        (hits / ( now - last + 1 ), key)		# Avoids hits/0
                        for key,(last,hits) in wrapper._stat.items()
                    ),
                    reverse	= True,
                )
                for rtg,key in rating[maxsize * 9 // 10:]:
                    # log.detail( "{} Ejecting  {!r} == {!r} w/ rating {:7.2f}, stats: {}".format(
                    #     wrapper.__name__, key, wrapper._memo[key], rtg, wrapper._stat[key] ))
                    del wrapper._stat[key]
                    del wrapper._memo[key]
            return entry

        wrapper._memo	= dict()		# { args: entry, ... }
        wrapper._stat	= dict()		# { args: (<timestamp>, <count>), ... }

        def stats( predicate=None, now=None ):
            if now is None:
                now		= timer()
            cnt,age,avg		= 0,0,0
            for key,(last,hits) in wrapper._stat.items():
                if not predicate or predicate( *key ):
                    cnt	       += 1
                    age	       += now-last
                    avg	       += hits
            return cnt,age/(cnt or 1),avg/(cnt or 1)
        wrapper.stats		= stats
        return wrapper
    return decorator


#
# Duration -- parse/format human-readable durations, eg. 1w2d3h4m5.678s
#
class Duration( datetime.timedelta ):
    """The definition of a year is imprecise; we choose compatibility w/ the simplest 365.25 days/yr.
    An actual year is about 365.242196 days =~= 31,556,925.7344 seconds.  The official "leap year"
    calculation yields (365 + 1/4 - 1/100 + 1/400) * 86,400 == 31,556,952 seconds/yr.  We're
    typically dealing with human-scale time periods with this data structure, so use the simpler
    definition of a year, to avoid seemingly-random remainders when years are involved.

    Is a dateetime.timedelta, so works well with built-in datetime +/- timedelta functionality.

    """
    YR 				= 31557600
    WK				=   604800
    DY				=    86400
    HR				=     3600
    MN				=       60

    @classmethod
    def _format( cls, delta, detail=False ):
        if detail:
            def abbrev( amount, label ):
                return "{a} {l}{s} ".format( a=amount, l=label, s='' if amount == 1 else 's' )
        else:
            def abbrev( amount, label ):
                return "{a}{l}".format( a=amount, l=label[0] )
        seconds			= delta.days * cls.DY + delta.seconds
        microseconds		= delta.microseconds
        result			= ''

        years			= seconds // cls.YR
        if years:
            result             += abbrev( years, 'year' )
        y_secs			= seconds % cls.YR

        weeks			= y_secs // cls.WK
        if weeks:
            result             += abbrev( weeks, 'week' )
        w_secs			= y_secs % cls.WK

        days			= w_secs // cls.DY
        if days:
            result             += abbrev( days, 'day' )
        d_secs			= w_secs % cls.DY

        hours			= d_secs // cls.HR
        if hours:
            result             += abbrev( hours, 'hour' )
        h_secs			= d_secs % cls.HR

        minutes			= h_secs // cls.MN
        if minutes:
            result             += abbrev( minutes, 'minute' )

        s			= h_secs % cls.MN
        is_us			= microseconds  % 1000 > 0
        is_ms			= microseconds // 1000 > 0
        if is_ms and ( s > 0 or is_us ):
            # s+us or both ms and us resolution; default to fractional
            result	       += "{s}.{us:0>6}".format( us=microseconds, s=s ).rstrip( '0' ) + 's'
        elif microseconds > 0 or s > 0:
            # s or sub-seconds remain; auto-scale to s/ms/us; the finest precision w/ data.
            if s:
                result         += "{s}s".format( s=s )
            if is_us:
                result         += "{us}us".format( us=microseconds )
            elif is_ms:
                result         += "{ms}ms".format( ms=microseconds // 1000 )
        elif microseconds == 0 and seconds == 0:
            # A zero duration
            result	       += "0s"
        else:
            # A non-empty duration w/ no remaining seconds output above; nothing left to do
            pass
        return result

    DURSPEC_RE			= re.compile(
        flags=re.IGNORECASE | re.VERBOSE,
        pattern=r"""
            ^
            (?:\s*(?P<y>\d+)\s*y((((ea)?r)s?)?)?)? # y|yr|yrs|year|years
            (?:\s*(?P<w>\d+)\s*w((((ee)?k)s?)?)?)?
            (?:\s*(?P<d>\d+)\s*d((((a )?y)s?)?)?)?
            (?:\s*(?P<h>\d+)\s*h((((ou)?r)s?)?)?)?
            (?:\s*(?P<m>\d+)\s*m((in(ute)?)s?)?)?  # m|min|minute|mins|minutes
            (?:
              (?:\s* # seconds mantissa (optional) + fraction (required)
                (?P<s_man>\d+)?
                [.,](?P<s_fra>\d+)\s*             s((ec(ond)?)s?)?
              )?
            | (?:
                (?:\s*(?P<s> \d+)\s*              s((ec(ond)?)s?)?)?
                (?:\s*(?P<ms>\d+)\s*(m|(milli))   s((ec(ond)?)s?)?)?
                (?:\s*(?P<us>\d+)\s*(u|μ|(micro)) s((ec(ond)?)s?)?)?
                (?:\s*(?P<ns>\d+)\s*(n|(nano))    s((ec(ond)?)s?)?)?
              )
            )
            \s*
            $
        """ )

    @classmethod
    def _parse( cls, durspec ):
        """Parses a duration specifier, returning the matching timedelta"""
        durmatch		= cls.DURSPEC_RE.match( durspec )
        if not durmatch:
            raise RuntimeError("Invalid duration specification: {durspec}".format( durspec=durspec ))
        seconds			= (
            int( durmatch.group( 's' ) or durmatch.group( 's_man' ) or 0 )
            + cls.MN * int( durmatch.group( 'm' ) or '0' )
            + cls.HR * int( durmatch.group( 'h' ) or '0' )
            + cls.DY * int( durmatch.group( 'd' ) or '0' )
            + cls.WK * int( durmatch.group( 'w' ) or '0' )
            + cls.YR * int( durmatch.group( 'y' ) or '0' )
        )
        microseconds		= (
            int( "{:0<6}".format( durmatch.group( 's_fra' ) or '0' ))
            + int( durmatch.group( 'ms' ) or '0' )  * 1000
            + int( durmatch.group( 'us' ) or '0' )
            + int( durmatch.group( 'ns' ) or '0' ) // 1000
        )
        return datetime.timedelta( seconds=seconds, microseconds=microseconds )

    def __new__( cls, value = None ):
        """Construct a Duration from something convertible into a datetime.timedelta.

        """
        if isinstance( value, type_str_base ):
            value		= cls._parse( value )
        if isinstance( value, (int,float) ):
            value		= datetime.timedelta( seconds=value )
        assert isinstance( value, datetime.timedelta ), \
            "Cannot construct a Duration from a {value!r}".format( value=value )
        # The value is (now) a datetime.timedelta; copy it's internals.
        self			= datetime.timedelta.__new__(
            cls,
            days	= value.days,
            seconds	= value.seconds,
            microseconds= value.microseconds
        )
        # self._days		= value.days
        # self._seconds		= value.seconds
        # self._microseconds	= value.microseconds
        # self._hashcode		= -1
        return self

    def __str__( self ):
        return self._format( self )

    def __repr__( self ):
        return self._format( self, detail=True )

    def __float__( self ):
        return self.total_seconds()

    def __int__( self ):
        return int( float( self ))

    def __add__( self, rhs ):
        """Convert any int/float/str, etc. to a Duration/timedelta, and add it to the current
        timedelta

        """
        if not isinstance( rhs, Duration):
            rhs			= Duration( rhs )
        return Duration( super( Duration, self ).__add__( rhs ))

    def __sub__( self, rhs ):
        if not isinstance( rhs, Duration):
            rhs			= Duration( rhs )
        return Duration( super( Duration, self ).__sub__( rhs ))


def parse_seconds( seconds ):
    """Convert an <int>, <float>, "<float>", "[HHH]:MM[:SS[.sss]]", "1m30s" or a Duration to a float number of seconds.

    """
    if isinstance( seconds, datetime.timedelta ):       # <timedelta>, <Duration>
        return seconds.total_seconds()
    try:						# '1.23'
        return float( seconds )
    except ValueError:
        pass
    try:						# 'HHH:MM[:SS[.sss]]'
        return math.fsum(
            map(
                lambda p: p[0] * p[1],
                zip(
                    [ 60*60, 60, 1 ],
                    map(
                        lambda i: float( i or 0 ),
                        parse_seconds.HHMMSS_RE.search( seconds ).groups()
                    )
                )
            )
        )
    except Exception:					# '1m30s'
        pass
    return Duration( seconds ).total_seconds()
parse_seconds.HHMMSS_PAT	= r'(\d*):(\d{2})(?::(\d{2}(?:\.\d+)?))?'  # noqa: E305
parse_seconds.HHMMSS_RE		= re.compile(
    flags=re.IGNORECASE | re.VERBOSE, pattern=parse_seconds.HHMMSS_PAT )


#
# Some simpler datetime and duration handling functionality.
#
# NOTE: Does *not* support the ambiguous timezone abbreviations! (eg. MST/MDT instead of Canada/Mountain)
#
def parse_datetime( time, zone=None ):
    """Interpret the time string "2019/01/20 10:00" as a naive local time, in the specified time zone,
    eg. "Canada/Mountain" (default: "UTC").  Returns the datetime; default time zone: UTC.  If a
    timezone name follows the datetime, use it instead of zone/'UTC'.

    """
    tz			= pytz.timezone( zone or 'UTC' )
    # First, see if we can split out datetime and a specific timezone.  If not, just try
    # patterns against the supplied time string, unmodified, and default tz to zone/UTC.
    dtzmatch		= parse_datetime.DATETIME_RE.match( time )
    if dtzmatch:
        time		= dtzmatch.group( 'dt' )
        zone		= dtzmatch.group( 'tz' )
        if zone:
            tz		= pytz.timezone( str( zone ))

    # Then, try parsing some time formats w/ timezone data, and convert to the designated timezone
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
    ]:
        try:
            return datetime.datetime.strptime( time, fmt ).astimezone( tz )
        except Exception:
            pass

    # Next, try parsing some naive datetimes, and then localize them to their designated timezone
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]:
        try:
            return tz.localize( datetime.datetime.strptime( time, fmt ))
        except Exception:
            pass
    raise RuntimeError("Couldn't parse datetime from {time!r} w/ time zone {tz!r}".format(
        time=time, tz=tz ))
parse_datetime.DATETIME_PAT	= r"""
        # YYYY-MM-DDTHH:MM:SS.sss+ZZ:ZZ
        (?P<dt>[0-9-]+([ T][0-9:\.\+\-]+)?)
        # Optionally, whitespace followed by a Blah[/Blah] Timezone name, eg. Canada/Mountain
        (?:\s+
          (?P<tz>[a-z_-]+(/[a-z_-]*)*)
        )?
    """							# noqa: E305
parse_datetime.DATETIME_RE	= re.compile(
    flags	= re.IGNORECASE | re.VERBOSE,
    pattern	= r"""
        ^
        \s*
        {pattern}
        \s*
        $
    """.format( pattern=parse_datetime.DATETIME_PAT ))


#
# Config file handling
#
# Define the default paths used for configuration files, etc.
CONFIG_BASE			= 'crypto-licensing'
CONFIG_FILE			= CONFIG_BASE+'.cfg'    # Default application configuration file


class Timestamp( datetime.datetime ):
    """A simple Timestamp that can be specified from a Timestamp or datetime.datetime, and is always
    local to a specific timezone, and formats simply and deterministically.

    """
    UTC				= pytz.UTC
    LOC				= get_localzone()       # from environment TZ, /etc/timezone, etc.

    _precision			= 3			# How many default sub-second digits
    _epsilon			= 10 ** -_precision     # How small a difference to consider ==
    _fmt			= '%Y-%m-%d %H:%M:%S'   # 2014-04-01 10:11:12

    def __str__( self ):
        return self.render()

    def __repr__( self ):
        return '<%s =~= %.6f>' % ( self, self.timestamp() )

    def __new__( cls, *args, **kwds ):
        """Since datetime.datetime is immutable, we must use __new__ and return one."""
        kargs			= dict( zip(
            ('year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond', 'tzinfo' ), args ))
        assert len( kargs ) == len( args ), \
            "Too many args provided"
        kdup			= set( kargs ).intersection( kwds )
        assert not kdup, \
            "Duplicate positional and keyword args provided: {kdup!r}".format( kdup=kdup )
        kwds.update( kargs )

        # A Timestamp is *always* specific to a timezone; default is UTC.
        if kwds.get( 'tzinfo' ) is None:
            kwds['tzinfo']	= cls.UTC
        if set( kwds ) == set( 'tzinfo' ):
            # From current time
            kwds['year']	= timer()
        if set( kwds ) == {'year', 'tzinfo'} and isinstance( kwds['year'], (int,float) ):
            # From a single numeric timestamp
            kwds['year']	= datetime.datetime.fromtimestamp( kwds['year'], tz=kwds['tzinfo'] )
        if set( kwds ) == {'year', 'tzinfo'} and isinstance( kwds['year'], datetime.datetime ):
            # From a datetime.datetime, possibly converted into another timezone.
            dt			= kwds.pop( 'year' ).astimezone( kwds['tzinfo'] )
            kwds['year']	= dt.year
            kwds['month']	= dt.month
            kwds['day']		= dt.day
            kwds['hour']	= dt.hour
            kwds['minute']	= dt.minute
            kwds['second']	= dt.second
            kwds['microsecond']	= dt.microsecond
        # Finally, from a partial/complete date/time specification
        assert set( kwds ).issuperset( {'year', 'month', 'day'} ), \
            "Timestamp must specify at least y/m/d"
        return datetime.datetime.__new__( cls, **kwds )

    def render( self, tzinfo=None, ms=True, tzdetail=None ):
        """Render the time in the specified zone (default: local), optionally with milliseconds
        (default: True).

        If the resultant timezone is not UTC, include the timezone full name in the output by
        default.  Thus, the output is always deterministic (only UTC times may every be output
        without timezone information).

        If tzdetail is supplied, if bool/str and Truthy, always include full timezone name; if
        Falsey, include abbreviation (warning: NOT parsable, because abbreviations are
        non-deterministic!).  If int and Truthy, always include full numeric timezone offset; if
        Falsey; only with non-UTC timezones.

        """
        subsecond		= self._precision if ms is True else int( ms ) if ms else 0
        assert 0 <= subsecond <= 6, \
            "Invalid sub-second precision; must be 0-6 digits"
        value			= round( self.timestamp(), subsecond ) if subsecond else self.timestamp()
        tz			= tzinfo or self.LOC    # default to local timezone
        dt			= super( Timestamp, self ).astimezone( tz )
        result			= dt.strftime( self._fmt )
        if subsecond:
            result	       += ( '%.*f' % ( subsecond, value ))[-subsecond-1:]
        if tz is not self.UTC or tzdetail is not None:
            if isinstance( tzdetail, (bool, type_str_base, type(None)) ):
                if tzdetail is None or bool( tzdetail ):
                    # full zone name if tzdetail is bool/str and Truthy (default)
                    try:
                        result += " " + dt.tzinfo.key
                    except AttributeError:
                        result += " " + dt.tzinfo.zone
                else:
                    # Warning: result not parse-able, b/c TZ abbreviations are wildly non-deterministic
                    result       += dt.strftime(' %Z' )   # default abbreviation for non-UTC (only if tzdetail=='')
            elif isinstance( tzdetail, (int, float) ):
                if bool( tzdetail ):
                    result       += dt.strftime( '%z' )   # otherwise, append numeric tz offset (only if tzdetail==1)

        return result

    def __float__( self ):
        return self.timestamp()

    def __int__( self ):
        return int( self.timestamp() )

    def timestamp( self ):
        """Exists in Python 3.3+.  Convert a timezone-aware datetime to a UNIX timestamp.  You'd
        think strftime( "%s.%f" )?  You'd be wrong; a timezone-aware datetime should always
        strftime to the same (correct) UNIX timestamp via its "%s" format, but this also doesn't
        work.

        Convert the time to a UTC time tuple, then use calendar.timegm to take a UTC time tuple and
        compute the UNIX timestamp.

        """
        try:
            return super( Timestamp, self ).timestamp()
        except AttributeError:
            return calendar.timegm( self.utctimetuple() ) + self.microsecond / 1000000

    # Comparisons.  Always equivalent to lexicographically, in UTC to 3 decimal places.  However,
    # we'll compare numerically, to avoid having to render/compare strings; if the <self>.value is
    # within _precision (default: 3) / _epsilon (default: 0.001) of <rhs>.value, it is considered
    # equal.  Some datetime implementations may not have .timestamp(), so we provide a fallback.
    def __lt__( self, rhs ):
        assert isinstance( rhs, (Timestamp, datetime.datetime) ), \
            "Expected Timestamp/datetime, got: {!r}".format( rhs )
        try:
            rhs_ts		= rhs.timestamp()
        except AttributeError:
            rhs_ts		= calendar.timegm( rhs.utctimetuple() ) + rhs.microsecond / 1000000
        return self.timestamp() + self._epsilon/2 < rhs_ts

    def __gt__( self, rhs ):
        assert isinstance( rhs, (Timestamp, datetime.datetime) ), \
            "Expected Timestamp/datetime, got: {!r}".format( rhs )
        try:
            rhs_ts		= rhs.timestamp()
        except AttributeError:
            rhs_ts		= calendar.timegm( rhs.utctimetuple() ) + rhs.microsecond / 1000000
        return self.timestamp() - self._epsilon/2 > rhs_ts

    def __le__( self, rhs ):
        return not self.__gt__( rhs )

    def __ge__( self, rhs ):
        return not self.__lt__( rhs )

    def __eq__( self, rhs ):
        return not self.__ne__( rhs )

    def __ne__( self, rhs ):
        return self.__lt__( rhs ) or self.__gt__( rhs )

    # Add/subtract Duration or numeric seconds.  +/- 0 is a noop/copy.  A Timestamp /
    # datetime.datetime is immutable, so cannot implement __i{add/sub}__.  Converts to timedelta,
    # and uses underlying __{add,sub}__.
    def __add__( self, rhs ):
        """Convert any int/float/str, etc. to a Duration/timedelta, and add it to the current
        Timestamp, retaining its timezone preference.

        """
        if not isinstance( rhs, Duration):
            rhs			= Duration( rhs )
        if rhs.total_seconds():
            return Timestamp( super( Timestamp, self ).__add__( rhs ), tzinfo=self.tzinfo )
        return self

    def __sub__( self, rhs ):
        """Convert any int/float/str, etc. to a Duration/timedelta, and subtract it from the current
        Timestamp, retaining its timezone preference.  If another Timestamp/datetime.datetime is
        supplied, return the difference as a Duration instead.

        """
        if isinstance( rhs, datetime.datetime ):
            # Subtracting datetimes; result is a Duration; from existing __sub__ --> timedelta
            return Duration( super( Timestamp, self ).__sub__( rhs ))
        # Subtracting something else; must be convertible by Duration into a timedelta
        rhs			= Duration( rhs )
        if rhs.total_seconds():
            return Timestamp( super( Timestamp, self ).__sub__( rhs ), tzinfo=self.tzinfo )
        return self


def config_paths( filename, extra=None ):
    """Yield the configuration search paths in *reverse* order of precedence (furthest or most
    general eg. /etc/..., to nearest or most specific, eg. ./...).

    This is the order that is required by configparser; settings configured in "later" files
    override those in "earlier" ones.

    For other purposes (eg. loading complete files), the order is likely reversed!  The caller must
    do this manually.

    By default, the "current" directory '.' will be used last, in the absence of any specific
    'extra' directories.  For example, when searching for things, the current directory (most
    specific) might be searched first, then most general directories.  However, for writing/saving
    things, the most general writable directory might be used, and then (finally) the 'extra' or
    current directory if that's the only writable place.  The reason we don't *always* use '.' if
    other 'extra' directories are provided, is to allow the caller to *avoid* searching/writing
    in/to the current directory!  Include '.' somewhere in 'extras' if this is appropriate.

    The set of default search PATHS functions can be globally altered by assigning a new list of
    f(<filename>) to config_paths.PATHS, which produce a path containing the target <filename>.

    """
    for pf in config_paths.PATHS:						# any default dirs...
        yield pf( filename )							# from least to most specific
    for e in ( [ '.' ] if extra is None else extra ):				# any extra dirs...
        yield os.path.join( e, filename )					# default . unless []; relative to current working dir (most specific)


config_paths.PATHS		= [
    lambda fn: os.path.join( os.getenv( 'APPDATA', os.sep + 'etc' ), fn ),      # global app data dir, eg. /etc/ (most general)
    lambda fn: os.path.join( os.path.expanduser( '~' ), '.'+CONFIG_BASE, fn ),  # user dir, ~username/.crypto-licensing/name
    lambda fn: os.path.join( os.path.expanduser( '~' ), '.' + fn ),		# user dir, ~username/.name
]


ConfigNotFoundError		= FileNotFoundError


class ConfigFoundError( KeyError ):
    pass


def config_open( name, mode=None, extra=None, skip=None, reverse=None, overwrite=None, **kwds ):
    """Find and open all glob-matched file name(s) found on the standard or provided configuration
    file paths (plus any extra), for reading in most specific to most general order (or in 'reverse'
    for writing).  Yield the open file(s), or raise a ConfigNotFoundError (a FileNotFoundError)
    if no matching file(s) at all were found, to be somewhat consistent with a raw open() call.

    If an absolute path is provided, only it (or those matching any glob pattern provided) are
    traversed; otherwise, we search the config_paths + extras.

    We traverse these in reverse order by default for "reading" mode: nearest and most specific, to
    furthest and most general, and any matching file(s) in ascending sorted order; specify
    reverse=False to obtain the files in the most general/distant configuration first.  The default
    for 'reverse' is True for writing ('w' or 'a') modes, False for reading modes.  Since we
    normally attempt to open any available file first, we'll generally only be writing a new file;
    putting it by default in the most generic writable place by default makes sense.

    By default, we assume the matching target file(s) are UTF-8/ASCII text files, and default to
    open in 'r' mode.

    A 'skip' glob pattern or predicate function taking a single name and returning True/False may be
    supplied.  By default, skips files w/ a trailing "~".

    When reading and writing to *existing* files, skip and the glob pattern matching is supported.
    When creating *new* files, of course skip (fnmatch) and glob patterns must be avoided (because
    they only interact with already existing files).  So, avoid using any globbing characters "*?[]"
    in the filename, or it will be impossible to create a file.

    Writing to existing files will (by default) raise a ConfigFoundError, unless overwrite=True.

    """
    mode			= mode.lower() if mode else 'r'
    is_writing			= 'w' in mode or 'a' in mode
    is_globbing			= glob.has_magic( name )
    assert not is_globbing or not is_writing, \
        "Cannot use file name \"globbing\" while writing to {}".format( name )
    if overwrite is None:
        overwrite		= False
    if reverse is None:
        reverse			= False if is_writing else True
    if skip in (None, True):  # By default, skips any filename ending in "~"; prevents writing such a file unless skip=False
        skip			= "*~"
    if isinstance( skip, type_str_base ):
        filtered		= lambda names: (n for n in names if not fnmatch.fnmatch( n, skip ))  # noqa: E731
    elif hasattr( skip, '__call__' ):
        filtered		= lambda names: (n for n in names if not skip( n ))  # noqa: E731
    elif skip is False:
        filtered		= lambda names: names  # noqa: E731
    else:
        raise AssertionError( "Invalid skip={!r} provided".format( skip ))
    # If an absolute or ~[user] path is provided, ignore config search paths and extras; otherwise,
    # forward/reverse search for the name relative to the config_paths + extra.
    name			= os.path.expanduser( name )
    if os.path.isabs( name ):
        search			= [ name ]
        if extra:
            log.warning( "Ignoring specified extra search paths: {extra}".format( extra=', '.join( extra )))
    else:
        search			= list( config_paths( name, extra=extra ))
        if reverse:
            search.reverse()
    log.debug( "config_open {}ing paths: {}".format( 'Writ' if is_writing else 'Read', ', '.join( search )))
    for fn in search:
        log.trace( "config_open search {fn!r}{globbing}".format(
            fn=fn, globbing=" w/ globbing" if is_globbing else "" ))
        for gn in sorted( filtered( glob.iglob( fn ) if is_globbing else [ fn ] )):
            if is_writing and ( not overwrite ) and os.path.exists( gn ):
                log.info( "config_open refuse {fn!r} in mode {mode!r}; will not overwrite existing file".format(
                    fn=fn, mode=mode ))
                raise ConfigFoundError( gn )
            try:
                f		= open( gn, mode=mode or 'r', **kwds )
            except Exception as exc:
                # The file couldn't be opened (eg. permissions, bad open args/kwds)
                log.debug( "config_open failed {fn!r} in mode {mode!r} w/ {kwds}: {exc}".format(
                    fn=fn, mode=mode, kwds=', '.join( '{}={!r}'.format( k, v ) for k,v in kwds.items() ),
                    exc=''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))
                pass
            else:
                log.info( "config_open opened {fn!r} in mode {mode!r}".format(
                    fn=f.name, mode=mode ))
                yield f


def deduce_name( basename=None, extension=None, filename=None, package=None, default=None ):
    """If no basename, use filename  .../<basename>.py, or package <basename>.submodule.

    An absolute path 'basename' will remain unchanged.  If no extension is present, the supplied
    'extension' will be appended.

    """
    if not ( basename or ( filename or package )):
        assert default, \
            "Cannot deduce basename without either filename (__file__) or package (__package__), or default"
        return default
    if basename is None:
        if filename:
            basename		= os.path.basename( filename )		# eg. '/a/b/c/d.py' --> 'd.py'
            basename,_		= os.path.splitext( basename )		# up to last '.' in filename (the extension)
        else:
            basename		= package
            if '.' in basename:
                basename	= basename[:basename.find( '.' )]       # up to first '.' in package name
    name			= basename
    if extension and not os.path.splitext( name )[1]:
        # No identifiable extension on root; this safely ignores path components containing '.'
        if extension[0] != '.':
            name	       += '.'
        name		       += extension
    return name


def config_open_deduced( basename=None, extension=None, filename=None, package=None, **kwds ):
    """Find any glob-matched configuration file(s), optionally deducing the basename from the provided
    __file__ filename or __package__ package name, returning the open file or raising a ConfigNotFoundError
    (a FileNotFoundError).

    If writing, will default to not overwrite an existing file; will raise a ConfigFoundError instead.
    """
    name			= deduce_name(
        basename	= basename,
        extension	= extension,
        filename	= filename,
        package		= package,
    )
    log.info( "Opening {} w/ {}".format( name, kwds ))
    for f in config_open( name, **kwds ):
        yield f


def input_secure( prompt, secret=True, file=None ):
    """When getting secure (optionally secret) input from standard input, we don't want to use getpass, which
    attempts to read from /dev/tty.

    """
    if ( file or sys.stdin ).isatty():
        # From TTY; provide prompts, and do not echo secret input
        if secret:
            return getpass.getpass( prompt, stream=file )
        elif file:
            # Coming from some file; no prompt, read a line from the file source
            return file.readline()
        else:
            return input( prompt )
    else:
        # Not a TTY; don't litter pipeline output with prompts
        if file:
            return file.readline()
        return input()


def gray( p ):
    #grayscale			= '''$@B%8&WM#*oahkbdpqwmZO0QLCJUYXzcvunxrjft/\|()1{}[]?-_+~<>i!lI;:,"^`'.'''
    grayscale			= '''$EFLlv!;,.'''
    return grayscale[-1 - max( 0, min( len( grayscale )-1, int( p * len( grayscale ))))]
