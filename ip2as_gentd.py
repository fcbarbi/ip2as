"""
ip2as_gentd.py
Generate Traffic Data file for testing ip2as traffic analyzer
"""
#
# Author: fcbarbi at gmail.com
# Update: July 2014
#
# Usage: python ip2as_gentd
# Generates file <FILENAME> where each record has the structure: "datetime,ip-src,ip-dest,dataload"
#

DATE = '11/04/2014'
FILENAME = '_20141104_in.txt'
HOURS = 1  # between 1 and 24, generated data always starts at 0:0:0 AM

import random
import numpy as np
from numpy.random import randn
import matplotlib.pyplot as plt
from ipaddr import IPNetwork
from ipaddr import IPAddress

from ip2as_functions import *
# from ip2as_functions import isIPv4
# from ip2as_functions import LoadCidrTable
# from ip2as_functions import LoadRirTable
# from ip2as_functions import local_asn
# from ip2as_functions import ournets4
# from ip2as_functions import ournets6

# external networks
c4,c6 = {},{}
nm = [0,32,0,128]
(c4,c6,nm) = LoadCidrTable( c4,c6,nm )
(c4,c6,nm) = LoadCidrTable( c4,c6,nm )
(c4,c6,nm) = LoadRirTable( c4,c6,nm )
(c4,c6,nm) = LoadRirTable( c4,c6,nm )
other4 = [str(c4[cidr][0][0]) for cidr in c4]
other6 = [str(c6[cidr][0][0]) for cidr in c6]

# add RESERVED networks
# other4.append('169.254.0.0/16')
# other4.append('224.0.0.0/4')
# other4.append('192.0.2.0/24')
# other4.append('192.88.99.0/24')
# other4.append('192.168.0.0/16')
# other4.append('198.18/15')
# other4.append('198.51.100.0/24')
# other4.append('203.0.113.0/24')
# other4.append('224.0.0.0/4')
# other4.append('233.252.0.0/24')
# other4.append('240.0.0.0/4')

# add some INTERNATIONAL networks
other4.append('194.6.252.0/24');
other4.append('194.88.226.0/23');
other4.append('194.99.67.0/24');
other4.append('194.113.27.0/24');
other4.append('194.126.152.0/23');
other4.append('194.33.11.0/24');
other4.append('194.49.17.0/24');
other4.append('194.55.104.0/23');
other4.append('194.63.152.0/22');
other4.append('194.79.36.0/22');
other6.append('2001:1900:2212::/48'); # from http://bgp.he.net/AS3356#_prefixes6
other6.append('2001:1900:221d::/48');

# other4  = ['189.2.0.0/15','200.9.199.0/24','177.32.0.0/14','186.233.84.0/22','177.86.248.0/22',\
#           '186.250.44/22','201.44/15','201.56/15','201.64/15','201.72/15','201.90/16','186.244/14',\
#           '187.12/14','187.40/14','187.76/14','187.124/14','189.12/15','200.140/16','200.142.64/19',\
#           '200.152.192/19','200.160.224/19','200.163/16','200.180/16']
# other6 = ['2804:d40::/28','2804:14c::/31','2801:9e::/32','2001:12f8::/48']

def draw(a,b):
    """ draw an integer value between a and b
    """
    #return int(random.uniform(a,b))
    return random.randint(a,b)

def drawN( mu=30,se=10,hi=60,lo=0 ):
    """ draw() from a normal censored distribution
    :param mu: mean
    :param se: standard error
    :param hi: highest allowed value
    :param lo: lowest
    :return: float
    """
    bDraw = True
    while bDraw:
        d = random.normalvariate(mu, se)
        if lo <= d <= hi:
            bDraw = False
    return int( d )

def DrawAnIP( cidr ):
    """ generates a random IP address from the given CIDR
    DrawAnIP('17/7')
    DrawAnIP('187.18.48/20')
    DrawAnIP('2001:12c8::/32')
    """

    if isIPv4(cidr):

        cidr = cidr.split('/')
        try:
            mask = int(cidr[1])
            if mask<0 or mask>32:
                mask = 32
        except:
            mask = 32
        byte = cidr[0].split('.')

        try:
         byte0 = byte[0]
        except:
         byte0 = '0'

        try:
         byte1 = byte[1]
        except:
         byte1 = '0'

        try:
         byte2 = byte[2]
        except:
         byte2 = '0'

        try:
         byte3 = byte[3]
        except:
         byte3 = '0'

        anip = '0.0.0.0'
        if mask<=8:
            anip = '%s.%s.%s.%s' % ( byte0, draw(1, 254), draw(1, 254), draw(1, 254)  )
        if mask>8 and mask<=16:
            anip = '%s.%s.%s.%s' % ( byte0, byte1, draw(1, 254), draw(1, 254)  )
        if mask>16 and mask<=24:
            anip = '%s.%s.%s.%s' % ( byte0, byte1, byte2, draw(1, 254)  )

    else:

        cidr = cidr.split('/')
        byte = cidr[0].split('::')
        anip = '%s::%s' % ( byte[0], draw(1, 254)  )

    return anip

def GenTestData( iHours,sDate,sFileName ):

    # profile of traffic load during the day staring at 0h up to 23h
    TrafficProfile = [1,2,1,2,2,3,3,4,5,6,8,10,9,8,6,7,9,6,5,5,4,3,2,1]

    FILESIZE = iHours*60*60 # number of lines in file (should be a multiple of 60*60)
    MINMTU = 20         # minimum MTU (in bytes)
    MAXMTU = 1500       # ipv6 bears more but we dont distinguish the IP packets
    MINPERSEC = 1       # min num of packets per second at low traffic ie. when peakFactor==1
    SEP = ','

    # fix filezize to be no longer than one day of simulated data
    if FILESIZE<0 | FILESIZE>24*60*60:
        FILESIZE = 24*60*60

    if MINPERSEC < 1:
        MINPERSEC = 1

    if not 1<=iHours<=24:
        iHours = 1

    f = open( sFileName, 'w')
    for tt in xrange( FILESIZE ):  # range(1,FILESIZE):

        hh = tt/(60*60)
        mm = (tt - hh*60*60)/60
        ss = tt - hh*60*60 - mm*60

        # simulate traffic profile during the day
        peakFactor = TrafficProfile[hh]

        # generate a random number of records during the same second window (ss0=ss)
        ss0=np.nan # ss0 is an aux var to recall the second we are in
        for ttsec in xrange( int(MINPERSEC*peakFactor) ): #draw(1, MAXPERSEC*peakFactor)+1):
            if ss0==ss:
                millisec = draw(millisec,60) #draw( ,,,millisec )
            else:
                millisec = draw(0, 10) #draw(0,10,0)
            #datetime = sDate+' %d:%d:%d.%d' % ( hh,mm,ss,millisec ) #;print datetime
            datetime = sDate+' %d:%d:%d' % ( hh,mm,ss ) #;print datetime
            ss0=ss

            if draw(0,5) in (4,5):  # dar 0-3 generates an ipv4 packet, from 4-5 it is an ipv6
              if draw(0,1)==0:  # incoming traffic
                ipsrc  = DrawAnIP( other6[draw(0,len(other6)-1)] )
                ipdest = DrawAnIP( ournets6[draw(0,len(ournets6)-1)] )
              else:  # outgoing traffic
                ipsrc  = DrawAnIP( ournets6[draw(0,len(ournets6)-1)] )
                ipdest = DrawAnIP( other6[draw(0,len(other6)-1)] )
            else:
              if draw(0,1)==0:
                ipsrc  = DrawAnIP( other4[draw(0,len(other4)-1)] )
                ipdest = DrawAnIP( ournets4[draw(0,len(ournets4)-1)] )
              else:
                ipsrc  = DrawAnIP( ournets4[draw(0,len(ournets4)-1)] )
                ipdest = DrawAnIP( other4[draw(0,len(other4)-1)] )

            rec = datetime + SEP + ipsrc + SEP + ipdest + SEP + str(draw(MINMTU, MAXMTU)) #;print rec
            #recx = rec + SEP + asnsrc + SEP + asndest + SEP + entsrc + SEP + entdest

            f.write(rec+'\n')
            #fx.write(recx+'\n')

    f.close()
    print 'simulated data file generated'

if __name__=="__main__":
    GenTestData( HOURS, DATE, FILENAME )





