
# ip2as_functions.py
# Functions for project ip2asn
#
# Author: fcbarbi at gmail.com
# update July 2014
#
# boolean = isIPv4( sIp )
#  Long = HashKey( sCidr )
# ( sCidrout,iMask ) = validCidr( sCidr )
# ( sCidr,iAsn ) = LookupIp( sIp, table, net_masks )
# ( sCidr,iAsn ) = getCidrAsn( sIp, cidr_table, net_masks, local_resources )
# ( cidr4_table, cidr6_table, net_masks ) = LoadCidrTable( cidr4_table, cidr6_table, net_masks, filename=CIDR_file, bDebug=False ):
# ( cidr4_table, cidr6_table, net_masks ) = LoadRirTable( cidr4_table, cidr6_table, net_masks, filename=RIR_file, bDebug=False ):
#  asn_table = LoadAsnTable( filename=ASN_file, bDebug=False ):
#

import numpy as np
from ipaddr import IPv4Network
from ipaddr import IPv6Network
from ipaddr import IPNetwork
from ipaddr import IPAddress
from datetime import timedelta, datetime
from time import strftime, strptime

# DOMESTIC cidrs in RIR files are identified by this two letter code
global COUNTRY
COUNTRY='BR'

# Customize the following values ---------------------------
# Document here the ISP's own networks (all packages have ip-src or ip-dest in one of these networks)
global local_asn
global ournets4
global ournets6
local_asn = 21911
ournets4 = [ '200.169.96.0/20','187.18.48.0/20' ]
ournets6 = [ '2001:12c8::/32' ]

# From here on there is nothing the user should change ------------------------------
# Database files
global CIDR_file
global RIR_file
global ASN_file
global SEPC
global SEPX
CIDR_file = 'CIDR.csv'
RIR_file  = 'RIR.txt'  # only renamed 'delegated-lacnic-latest.txt'
ASN_file  = 'ASN.csv'
SEPC = ',' # csv files delimiter
SEPX = '|' # delimiter for RIR files

# ASN codes for internal use
global UNKNOWN
global DOMESTIC
global INTERNATIONAL
global RESERVED
global BADASN
UNKNOWN = 0L
DOMESTIC = -1L
INTERNATIONAL = -2L
RESERVED = -3L
BADASN = -4L

# time intervals for data visualization
BAR01min = 01*60 # 1 minuto = 60 seconds
BAR10min = 10*60 # timedelta(minutes=10) = 600 seconds
BAR60min = 60*60 # timedelta(hours=1) = 3600 seconds

# #############################################################
# IPv4 addresses have '.' while IPv6 have ':' separators
# works for both ip and cidr
def isIPv4( sIp ):
    """ isIPv4( sIp ) checks if sIp is an IPv4 (true) or IPv6 (false)
    """
    return (sIp.find(':')==-1)

# #############################################################
def validCidr( sCidr ):
    """ (sCidr,iMask) = validCidr( sCidr ) appends '.0', '.0.0' or '.0.0.0' to IPv4 networks + corrects IPv4 and IPv6 networks mask\n
    validCidr('17/7') == '17.0.0.0/7'
    validCidr('187.18.48/20') == '187.18.48.0/20'
    validCidr('187.18.48/33') == '187.18.48.0/32'
    validCidr('187.18.48.33') == '187.18.48.33/32'
    validCidr('2001:12c8::/32') == '2001:12c8::/32'
    validCidr('2001:12c8::1') == '2001:12c8::1/128'
    """

    cidr = sCidr.split('/')
    mask = 0

    if isIPv4(cidr[0]):  # checks that it is not IPv6
        try:
            mask = int(cidr[1])
            if mask<0 or mask>32:
                mask = 32
        except:
            mask = 32
        ipv4 = cidr[0].split('.')
        try:
            byte0 = int(ipv4[0])
        except:
            byte0 = '0'
        try:
            byte1 = int(ipv4[1])
        except:
            byte1 = '0'
        try:
            byte2 = int(ipv4[2])
        except:
            byte2 = '0'
        try:
            byte3 = int(ipv4[3])
        except:
            byte3 = '0'
        cidrout = '%s.%s.%s.%s/%s' % ( byte0, byte1, byte2, byte3, mask  )
    else:
        try:
            mask = int(cidr[1])
            if mask<0 or mask>128:
                mask = 128
        except:
            mask = 128
        cidrout = '%s/%s' % ( cidr[0], mask  )

    return( cidrout,mask )


# #############################################################
def HashKey( sCidr ):
    """ Long = HashKey( sCidr ) generates a hash value to be the key of the dictionary entry

    """

    assert isinstance(sCidr,str)
    assert sCidr.find('/')>0  # must receive a network with mask delimiter and...
    network = sCidr.split('/')
    assert int(network[1])>0  # ...a mask must be set
    hashvalue = hash( IPNetwork(sCidr) )

    return ( hashvalue  )

# #############################################################
def LoadCidrTable( cidr4_table, cidr6_table, net_masks, filename=CIDR_file, bDebug=False ):
    """LoadCidrTable( cidr4_table, cidr6_table, net_masks, filename, bDebug )_ loads table
    relating known CIDR to ASN filename is a CSV with <CIDR>,<ASN> per line
    """

    [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6] = net_masks

    if bDebug:

        cidr4_table[ HashKey('192.168.0.0/16') ] = [(IPv4Network('192.168.0.0/16'),RESERVED)]
        cidr4_table[ HashKey('187.18.48.0/20') ] = [(IPv4Network('187.18.48.0/20'),21911)]
        cidr4_table[ HashKey('200.169.96.0/20')] = [(IPv4Network('200.169.96.0/20'),21911)]
        cidr4_table[ HashKey('187.95.192.0/20')] = [(IPv4Network('187.95.192.0/20'),53091)]
        cidr4_table[ HashKey('189.2.0.0/15')   ] = [(IPv4Network('189.2.0.0/15'),4230)]
        cidr4_table[ HashKey('200.9.199.0/24') ] = [(IPv4Network('200.9.199.0/24'),15256)]

        cidr6_table[ HashKey('::/128')        ] = [(IPv6Network('::/128'),RESERVED)]
        cidr6_table[ HashKey('2001:12c8::/32')] = [(IPv6Network('2001:12c8::/32'),21911)]
        cidr6_table[ HashKey('2804:a8::/32')  ] = [(IPv6Network('2804:a8::/32'),4230)]
        cidr6_table[ HashKey('2801:9e::/32')  ] = [(IPv6Network('2801:9e::/32'),15256)]

        MaxMaskLen4 = 24
        MinMaskLen4 = 15
        MaxMaskLen6 = 128
        MinMaskLen6 = 32

    else:

        try:
            file = open( filename )
            bSkipLine = True  # skip first line with column headers
            for record in file:
                record = record.strip()
                if not bSkipLine and len(record)>0 and record[0]!='#':
                    record = record.split(',')
                    try:
                        (sCidr,mask) = validCidr(record[0])
                        asn = long(record[1])
                        key = HashKey(sCidr)
                        ipn = IPNetwork(sCidr)
                        if isIPv4(sCidr): # to place IPv4 networks up first in
                            if cidr4_table.has_key( key ):
                                if cidr4_table[ key ][0][0] != ipn:
                                    cidr4_table[ key ].append( (ipn, asn) )
                            else:
                                cidr4_table[ key ] = [ (ipn, asn) ]

                            MaxMaskLen4 = max(MaxMaskLen4,ipn.prefixlen)
                            MinMaskLen4 = min(MinMaskLen4,ipn.prefixlen)

                        else:
                            if cidr6_table.has_key( key ):
                                if cidr6_table[ key ][0][0] != ipn:
                                    cidr6_table[ key ].append( (ipn, asn) )
                            else:
                                cidr6_table[ key ] = [ (ipn, asn) ]

                            MaxMaskLen6 = max(MaxMaskLen6,ipn.prefixlen)
                            MinMaskLen6 = min(MinMaskLen6,ipn.prefixlen)
                    except:
                        print 'LoadCidrTable() failed to read line starting with %s' % (record[0])

                bSkipLine = False

            file.close()
        except:
            print 'LoadCidrTable() failed to open file "%s" ' % (CIDR_file)

    net_masks = [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6]

    return ( cidr4_table, cidr6_table, net_masks )


# #############################################################
def LoadRirTable( cidr4_table, cidr6_table, net_masks, filename=RIR_file, bDebug=False ):
    """LoadRirTable( cidr4_table, cidr6_table, net_masks, filename=RIR_file, bDebug=False )\n
    Loads RIR (regional internet registry) table from\n
    ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
    """

    [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6] = net_masks

    # for debugging only
    if bDebug:

        cidr4_table[ HashKey('200.168.95.0/20') ] = [(IPv4Network('200.168.95.0/20') ,DOMESTIC) ]
        cidr4_table[ HashKey('201.1.2.0/24')    ] = [(IPv4Network('201.1.2.0/24')    ,DOMESTIC) ]
        cidr4_table[ HashKey('187.8.48.0/25')   ] = [(IPv4Network('187.8.48.0/25')   ,DOMESTIC) ]

        cidr6_table[ HashKey('2001:1280::/32')  ] = [(IPv6Network('2001:1280::/32')  ,DOMESTIC) ]
        cidr6_table[ HashKey('2001:1284::/32')  ] = [(IPv6Network('2001:1284::/32')  ,DOMESTIC) ]
        cidr6_table[ HashKey('2804:d40::/32')   ] = [(IPv6Network('2804:d40::/32')   ,DOMESTIC) ]
        cidr6_table[ HashKey('2001:12f8:1::/48')] = [(IPv6Network('2001:12f8:1::/48'),DOMESTIC) ]

        MaxMaskLen4 = max(MaxMaskLen4,25)
        MinMaskLen4 = min(MinMaskLen4,20)
        MaxMaskLen6 = max(MaxMaskLen6,48)
        MinMaskLen6 = min(MinMaskLen6,32)

    else:

        try:
            f = open( filename )
            bOk = True
        except:
            print 'LoadRirTable() failed to open file "%s" ' % (RIR_file)

        if bOk:
            for record in f:

                record = record.strip()
                if len(record)>0 and record[0]!='#':

                    # rec = "lacnic|BR|ipv4|131.0.20.0|1024|20140703|allocated"
                    # rec = "lacnic|BR|ipv6|2001:1280::|32|20071219|allocated"
                    record = record.split( SEPX )
                    country = record[1]
                    rectype = record[2]
                    network = record[3]

                    if (country==COUNTRY and rectype=='ipv4'):
                        try:
                            hosts = int(record[4])
                            # lookup dictionary for better performance
                            mask_table = { 256:24, 512:23, 1024:22, 2048:21, 4096:20, 8192:19, 16384:18, \
                                           32768:17, 65536:16, 131072:15, 262144:14, 524288:13, 1048576:12 }
                            # if not in the dict calculate the mask
                            if 256 <= hosts <= 1048576:
                                mask = mask_table[ hosts ]
                            else:
                                if hosts<=0:
                                    hosts=1
                                mask = 32-int(np.log(hosts)/np.log(2))
                                #print mask

                            sCidr = network +'/'+ str(mask)
                            nCidr = IPv4Network( sCidr )
                            key = HashKey( sCidr )
                            #
                            # check if the key already exist and in this case extend the dictionary entry with a list
                            # because hash collision (ie. 2 dif ips have the same hash value) may happen
                            # in this case, performance will degrade (hopefully this is a rare event)
                            #
                            # A (rare) example is the key value 0 that was generated for 2 networks:
                            # 0: [(IPv4Network('240.0.0.0/4'), -3L), (IPv4Network('255.255.255.255/32'), -3L)],
                            #

                            if cidr4_table.has_key( key ):
                                if cidr4_table[ key ][0][0] != nCidr:
                                    cidr4_table[ key ].append( (nCidr,DOMESTIC) )
                                else:
                                    #print "LoadRirTable() detected duplicate CIDR with IPv4 %s " % (network)
                                    pass
                            else:
                                cidr4_table[ key ] = [ (nCidr,DOMESTIC) ]

                            MaxMaskLen4 = max(MaxMaskLen4,nCidr.prefixlen)
                            MinMaskLen4 = min(MinMaskLen4,nCidr.prefixlen)
                        except:
                            print "LoadRirTable() failed with IPv4 %s " % (record[3])

                    if (country==COUNTRY and rectype=='ipv6'):
                        try:
                            mask = int(record[4])
                            sCidr = network +'/'+ str(mask)
                            nCidr = IPv6Network(sCidr)
                            key = HashKey( sCidr )
                            if cidr6_table.has_key( key ):
                                if cidr6_table[ key ][0][0] != nCidr:
                                    cidr6_table[ key ].append( (nCidr,DOMESTIC) )
                                else:
                                    #print "LoadRirTable() detected duplicate CIDR with IPv6 %s " % (network)
                                    pass
                            else:
                                cidr6_table[ key ] = [ (nCidr,DOMESTIC) ]

                            MaxMaskLen6 = max(MaxMaskLen6,nCidr.prefixlen)
                            MinMaskLen6 = min(MinMaskLen6,nCidr.prefixlen)
                        except:
                            print "LoadRirTable() failed with IPv6 %s " % (record[3])

        net_masks = [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6]
        f.close()

    return ( cidr4_table, cidr6_table, net_masks )


# #############################################################
def LoadAsnTable( filename=ASN_file, bDebug=False ):
    """ Loads CSV file with <asn>,<entity>
    """

    asn_table = {}

    # for debugging only
    if bDebug:

        asn_table = { 21911:'Dualtec', 53091:'Nomer', 4230:'Embratel', 15256:'Itau', \
                     -1:'DOMESTIC', -2:'INTERNATIONAL', -3:'RESERVED' } # should never return an UNKNOWN asn

    else:

        try:
            f = open( filename )
            bSkipLine = True # skip fisrt line
            for record in f:
                record = record.strip()
                if not bSkipLine and len(record)>0 and record[0]!='#':
                    record = record.split(SEPC)
                    try:
                        asn = long(record[0])
                        entity = (record[1]).strip()
                        company = ((record[2]).strip()).capitalize()
                        asn_table[ asn ] = (entity,company)
                    except:
                        print 'LoadAsnTable() failed to read record "%s" ' % (record)
                bSkipLine = False
            f.close()
        except:
            print 'LoadAsnTable() failed to open file "%s" ' % (ASN_file)

    return asn_table


# #############################################################
def LookupIp( sIp, table, net_masks ):
    """ LookupIp( sIp, table, net_masks ) returns ASN associated with a CIDR if found, else returns asn=UNKNOWN"""

    iAsn = UNKNOWN
    sCidr = '?'  # to diff from '(NA)'
    bMatch = False

    [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6] = net_masks

    #print 'LookupIp() table len = '+str( len(table) )
    assert isinstance( sIp,str )
    assert sIp.strip()<>''
    assert len(table)>0
    assert MaxMaskLen4>0
    assert MinMaskLen4>0
    assert MaxMaskLen6>0
    assert MinMaskLen6>0

    # CIDR table is implemented as a dictionary with key _Pack( sCidr )
    # the routine tries different candidate cidr by masking the IP and
    # geneating a key to be looked-up in the CIDR table
    #
    # MaxMaskLenV and MinMaskLenV are collected while building the CIDR table
    # we use them as boundaries for maskLen to speed up processing

    if isIPv4( sIp ):
        MaxMaskLen = MaxMaskLen4
        MinMaskLen = MinMaskLen4
    else:
        MaxMaskLen = MaxMaskLen6
        MinMaskLen = MinMaskLen6

    maskLen = MaxMaskLen
    assert isinstance(maskLen,int)

    # IPNetwork('200.169.96.129/24').network  = '200.1269.96.0'
    # IPNetwork('200.169.96.129/25').network  = '200.1269.96.128'
    while maskLen >= MinMaskLen and not bMatch:
        # _pack() demands the network as string
        sCidr = str( IPNetwork(sIp+'/'+str(maskLen)).network )+'/'+str(maskLen)
        #print 'LookupIp() testing sCidr = %s ' % (sCidr)
        key = HashKey( sCidr )
        if table.has_key( key ):
            j=0  # index to navigate in a dictionary entry
            while j<len(table[ key ]) and not bMatch:
                if IPAddress(sIp) in table[ key ][j][0]:
                    bMatch = True
                else:
                    j += 1
            if bMatch:
                sCidr = (table[ key ][j][0]).compressed # compressed IPv6 address
                iAsn  = table[ key ][j][1]
                #print 'LookupIp( %s ) best match for (%s,%i) ' % (sIp,sCidr,iAsn)
        maskLen -= 1

    return ( sCidr,iAsn )

# #############################################################
def getCidrAsn( sIp, cidr_table, net_masks, local_resources ):
    """getCidrAsn( sIp, cidr_table, net_masks ) either returns (<cidr>,<asn>) or ('<ip>',INTERNATIONAL)\n
    It check ip tables in order: 1.local network, 2.CIDR+RIR table
    """

    iAsn = UNKNOWN
    sCidr = '(NA)'
    bLocal = False      # checks local networks
    aIp = IPAddress(sIp)

    local_asn = local_resources[0]
    ournets4  = local_resources[1]
    ournets6  = local_resources[2]

    if isIPv4(sIp):
        local_nets = ournets4
    else:
        local_nets = ournets6

    # check if it is a local ip to this ISP
    i = 0
    while i < len(local_nets) and not bLocal:
        if aIp in IPNetwork( local_nets[i] ):
            iAsn = local_asn
            sCidr = local_nets[i]
            bLocal = True
        i += 1

    if not bLocal:
        ( sCidr,iAsn ) = LookupIp( sIp, cidr_table, net_masks )

    if iAsn == UNKNOWN:
        iAsn = INTERNATIONAL
        sCidr = sIp+'/?'  # we dont have the CIDR for this IP so no mask info

    return ( sCidr,iAsn )

# #####################################################
def str2datetime( sDateTime ):
    """ str2datetime( sDateTime ) converts a string to a datetime object suppressing miliseconds

    str2datetime( '11/08/2014 0:0:3.2345' ) == datetime.datetime(2014, 11, 8, 0, 0, 3)
    """
    _dt = sDateTime
    _time = _dt.split('.')
    _dt = strptime( _time[0], "%m/%d/%Y %H:%M:%S" )
    # _dt = datetime.datetime.now().replace( microsecond=0 )
    return datetime( _dt.tm_year, _dt.tm_mon, _dt.tm_mday, _dt.tm_hour, _dt.tm_min , _dt.tm_sec )

# def getDate( sDatetime ):
#     """ (year, month, day) = getDate( sDatetime )
#     """
#     _time = sDatetime.split('.')  # get rid of miliseconds
#     _dt = strptime( _time[0], "%m/%d/%Y %H:%M:%S" )
#     return ( _dt.tm_year, _dt.tm_mon, _dt.tm_mday,0,0,0 )

def dt2slot( sDatetime, iDelta ):
    """ timeslot = dt2slot( sDatetime, iDelta ) where iDelta is the bar length measured in seconds (eg. DELTA60 for 1 hour)

    A 'timeslot' is an integer used to store the packet in a dataframe for later aggregation/visualization.
    """

    _time = sDatetime.split('.')  # get rid of miliseconds
    _dt = strptime( _time[0], "%m/%d/%Y %H:%M:%S" )
    RefDate = datetime( _dt.tm_year, _dt.tm_mon, _dt.tm_mday,0,0,0 )
    return ((str2datetime(sDatetime)-RefDate)/iDelta).seconds

