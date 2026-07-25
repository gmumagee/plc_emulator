# -*- coding: utf-8 -*-

import datetime
import json
import logging
import pytest
import random
import time

try:
    from functools	import lru_cache
except ImportError:
    lru_cache			= None

from .misc		import (
    parse_datetime, parse_seconds, Timestamp, Duration, memoize, timer, gray, pytz
)

log				= logging.getLogger( "misc_test" )


def test_Duration():
    d			= Duration( "1m33s123ms" )
    assert str( d ) == "1m33.123s"
    assert repr( d ) == "1 minute 33.123s"
    assert repr( d+60 ) == "2 minutes 33.123s"
    assert repr( d+123456789 ) == "3 years 47 weeks 4 days 3 hours 34 minutes 42.123s"
    assert str( d+123456789 ) == "3y47w4d3h34m42.123s"


def test_Timestamp_smoke( monkeypatch ):
    monkeypatch.setattr( Timestamp, 'LOC', pytz.timezone( "Canada/Mountain" ))
    dt			= parse_datetime( "2021-01-01 00:00:00.1 UTC" )
    ts_dt		= Timestamp( dt )
    assert str( ts_dt ) == "2020-12-31 17:00:00.100 Canada/Mountain"


def test_Timestamp( monkeypatch ):
    monkeypatch.setattr( Timestamp, 'LOC', pytz.timezone( "Canada/Mountain" ))

    dt			= parse_datetime( "2021-01-01 00:00:00.1 Canada/Pacific" )
    assert isinstance( dt, datetime.datetime )

    ts_dt		= Timestamp( dt )
    assert isinstance( ts_dt, Timestamp )
    assert isinstance( ts_dt, datetime.datetime )
    assert ts_dt.timestamp() == 1609488000.1

    ts_int		= Timestamp( 0 )
    assert isinstance( ts_int, Timestamp )
    assert isinstance( ts_int, datetime.datetime )
    assert ts_int.timestamp() == 0

    assert float( ts_dt ) == float( Timestamp( datetime.datetime(
        year=2021, month=1, day=1, hour=8, minute=0, second=0, microsecond=100000, tzinfo=pytz.UTC
    )))

    assert str( ts_dt ) == "2021-01-01 01:00:00.100 Canada/Mountain"

    assert str( ts_dt + "1m1.33s" ) == "2021-01-01 01:01:01.430 Canada/Mountain"
    assert str( ts_dt - "1m1s330ms" ) == "2021-01-01 00:58:58.770 Canada/Mountain"

    assert str( ts_dt +  61.33 ) == "2021-01-01 01:01:01.430 Canada/Mountain"
    assert str( ts_dt -  61.33 ) == "2021-01-01 00:58:58.770 Canada/Mountain"

    assert parse_seconds(      "01.33" ) ==  1.33       # as a simple float
    # [HHH]:MM[:SS[.sss]] time specs default to MM, then H:MM, and only with sufficient segments, then to H:MM:SS
    assert parse_seconds(     ":01" ) == 60.0
    assert parse_seconds(    "0:01" ) == 60.0
    assert parse_seconds(   "01:01" ) == 3660.0		# as a HH:MM time tuple
    assert parse_seconds( "0:01:01.33" ) == 61.33
    assert str( ts_dt + parse_seconds( "0:01:01.33" )) == "2021-01-01 01:01:01.430 Canada/Mountain"
    assert str( ts_dt - parse_seconds( "61.33" )) == "2021-01-01 00:58:58.770 Canada/Mountain"
    assert str( ts_dt - parse_seconds( "1m1s330000us" )) == "2021-01-01 00:58:58.770 Canada/Mountain"

    assert ts_dt.timestamp() == 1609488000.1
    assert ( ts_dt + "1ms" ).timestamp() == 1609488000.101
    assert ( ts_dt - "1ms" ).timestamp() == 1609488000.099
    assert str( ts_dt + "1ms" ) == "2021-01-01 01:00:00.101 Canada/Mountain"
    assert str( ts_dt - "1ms" ) == "2021-01-01 01:00:00.099 Canada/Mountain"

    assert ( ts_dt + "1us" ).timestamp() == 1609488000.100001
    assert ( ts_dt - "1us" ).timestamp() == 1609488000.099999

    # Solidly beyond _precision (comparisons are +/- (10 ** _precision) / 2)
    ts_dt_p1ms		= ts_dt + "1ms"
    ts_dt_m1ms		= ts_dt - "1ms"

    # Round to w/in _precision
    ts_dt_p499us	= ts_dt + "499us"
    ts_dt_m499us	= ts_dt - "499us"

    # Rounds beyond _precision
    ts_dt_p501us	= ts_dt + "501us"
    ts_dt_m501us	= ts_dt - "501us"

    assert( ts_dt_p1ms    >    ts_dt )
    assert( ts_dt_p1ms    >       dt )
    assert( ts_dt_p1ms    !=   ts_dt )
    assert( ts_dt_p1ms    !=      dt )
    assert( ts_dt_p1ms    >=   ts_dt )
    assert( ts_dt_p1ms    >=      dt )
    assert( ts_dt_m1ms    <    ts_dt )
    assert( ts_dt_m1ms    <       dt )
    assert( ts_dt_m1ms    <=   ts_dt )
    assert( ts_dt_m1ms    <=      dt )
    assert( ts_dt_p499us  ==   ts_dt )
    assert( ts_dt_p499us  ==      dt )
    assert( ts_dt_p501us  !=   ts_dt )
    assert( ts_dt_p501us  !=      dt )
    assert( ts_dt_p499us  >=   ts_dt )
    assert( ts_dt_p499us  >=      dt )
    assert( ts_dt_m499us  ==   ts_dt )
    assert( ts_dt_m499us  ==      dt )
    assert( ts_dt_m501us  !=   ts_dt )
    assert( ts_dt_m501us  !=      dt )
    assert( ts_dt_m499us  <=   ts_dt )
    assert( ts_dt_m499us  <=      dt )
    assert( ts_dt         <    ts_dt_p1ms )
    assert( ts_dt         <=   ts_dt_p1ms )
    assert( ts_dt         >    ts_dt_m1ms )
    assert( ts_dt         >=   ts_dt_m1ms )
    assert( ts_dt         ==   ts_dt_p499us )
    assert( ts_dt         >=   ts_dt_p499us )
    assert( ts_dt         <=   ts_dt_p499us )
    assert( ts_dt         ==   ts_dt_m499us )
    assert( ts_dt         >=   ts_dt_m499us )
    assert( ts_dt         <=   ts_dt_m499us )


memoize_count		= 1000000


def test_memoize_speed_raw():
    def adder_raw( a, b ):
        return a + b + ( adder_raw( a//2, b//2 ) if a or b else 0 )

    beg			= timer()
    val_raw		= sum( adder_raw( i * 23 % 100, i * 19 % 100 ) for i in range( memoize_count ))
    dur			= timer() - beg
    log.normal( "val_raw: {:7.3f}s:  {}".format( dur, val_raw ))


def test_memoize_speed_memoize():
    @memoize(maxsize=1000)
    def adder_mem( a, b ):
        return a + b + ( adder_mem( a//2, b//2 ) if a or b else 0 )

    beg			= timer()
    val_mem		= sum( adder_mem( i * 23 % 100, i * 19 % 100 ) for i in range( memoize_count ))
    dur			= timer() - beg
    log.normal( "val_mem: {:7.3f}s:  {}".format( dur, val_mem ))


@pytest.mark.skipif( not lru_cache, reason="@functools.lru_cache" )
def test_memoize_speed_lru_cache():
    @lru_cache(maxsize=1000)
    def adder_lru( a, b ):
        return a + b + ( adder_lru( a//2, b//2 ) if a or b else 0 )

    beg			= timer()
    val_lru		= sum( adder_lru( i * 23 % 100, i * 19 % 100 ) for i in range( memoize_count ))
    dur			= timer() - beg
    log.normal( "val_lru: {:7.3f}s:  {}".format( dur, val_lru ))


def test_memoize():
    assert ''.join( gray( n/100 ) for n in range( 101 )) \
        == "..........,,,,,,,,,,;;;;;;;;;;!!!!!!!!!!vvvvvvvvvvllllllllllLLLLLLLLLLFFFFFFFFFFEEEEEEEEEE$$$$$$$$$$$"

    # random.random() returns values in [0.0,1.0) -- so we will never see the 'hi' value
    count			= 1000
    duration			= 10.0
    lo,hi			= 0, 10
    cells			= hi * hi
    mid				= hi // 2
    big,sml			= hi * 3 / 4, hi * 1 / 4

    def one():
        return int( random.triangular( lo, hi, big ))

    def two():
        return int( random.triangular( lo, hi, sml ))

    @memoize()
    def unlimited( x, y, keyword=None ):
        return (x,y)

    # max 1/2 remembered, due to size.  A higher proportion of these should end up in the most-used
    # quadrant, because they are ejected based on a metric where less old + more probed entries are
    # preserved with higher probability.
    @memoize( maxsize=50 )
    def maxsizing( x, y, keyword=None ):
        return (x,y)

    @memoize( maxage=duration / 2 )     # about 1/2 remembered, due to time
    def maxageing( x, y, keyword=None ):
        return (x,y)
    print( "maxageing: {} ".format( ', '.join( dir( maxageing ))))

    beg				= timer()
    for i in range( count ):
        x			= one()  # Tends mostly high
        y 			= two()  # Tends mostly low
        assert unlimited( x, y, keyword=i ) == (x,y)
        assert maxsizing( x, y, keyword=i ) == (x,y)
        assert maxageing( x, y, keyword=i ) == (x,y)
        now			= timer()
        elapsed			= now - beg
        target			= i * duration / count
        if elapsed < target:
            #print( "Sleeping {!r} - {!r} == {!r}".format( target, elapsed, target - elapsed ))
            time.sleep( target - elapsed )

    # 0,0 is lower left
    def ll( x, y ):
        return x <  mid and y <  mid

    def lr( x, y ):
        return x >= mid and y <  mid

    def ul( x, y ):
        return x <  mid and y >= mid

    def ur( x, y ):
        return x >= mid and y >= mid

    # unlimited: No memoizations discarded; 1,000 random probes in 10 x 10 array; 0-4 lo, 5-9 hi.
    stats			= {}
    now				= timer()
    for func in [ unlimited, maxsizing, maxageing ]:
        for quad in [ ll, lr, ul, ur ]:
            stats[func.__name__ + '_' + quad.__name__] = func.stats( quad, now=now )
        print( "{}  {:^30}   {:^30}".format( func.__name__, 'Hits', 'Age (s.)' ))
        for numeric in (True, False):
            print( "    +{}+    +{}+".format( '-' * 30, '-' * 30 ))
            for y in range( hi ):
                ages		= ''
                used		= ''
                for x in range( hi ):
                    try:
                        last,hits = func._stat[(x,y)]
                        age	= now - last
                        ages   += "{:^3.1f}".format( age/duration ) if numeric else " {} ".format( gray( age/duration ))
                        # if no memoizations purged and all probed equally, each cell should see count / cells hits.  However, random.triangular
                        # produces peaks of 3x expected at highest, 0 at edges.
                        exp	= count / cells
                        used   += "{:^3}".format( hits if numeric else gray( hits / exp / 3 ))  # eg hits == 12 vs. exp == 10 --> 20% above midpoint --> 0.6
                    except KeyError:
                        ages   += ' ' * 3
                        used   += ' ' * 3
                print( "    |{}|    |{}|".format( used, ages ))
            print( "    +{}+    +{}+".format( '-' * 30, '-' * 30 ))
    print( json.dumps( stats, indent=4 ))
