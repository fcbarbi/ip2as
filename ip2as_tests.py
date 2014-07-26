"""
ip2as-tests.py
IP to AS Traffic Analyzer - test module
"""
#
# Author: fcbarbi at gmail.com
# update July 2014
#

import unittest
from ip2as_functions import *
from ipaddr import IPNetwork

# from ip2as_functions import isIPv4
# from ip2as_functions import HashKey
# from ip2as_functions import validCidr
# from ip2as_functions import LoadCidrTable
# from ip2as_functions import LoadRirTable
# from ip2as_functions import LoadAsnTable
# from ip2as_functions import LookupIp
# from ip2as_functions import getCidrAsn

# from ip2as_functions import CIDR_file
# from ip2as_functions import RIR_file
# from ip2as_functions import ASN_file
# from ip2as_functions import UNKNOWN
# from ip2as_functions import DOMESTIC
# from ip2as_functions import INTERNATIONAL
# from ip2as_functions import RESERVED
# from ip2as_functions import BADASN

# Used in LoadXXXTable() to require the use of hard coded data
bDebug = True # True to debug using hard coded data

class TestClass(unittest.TestCase):

    def TestCidr( self, sCidr2Test, sCidr_ok, iMask_ok, bIPv4 ):
        """ TestCidr( sCidr2test, sCidr_ok, iMask_ok, bIPv4 ) """
        (cidr,mask) = validCidr( sCidr2Test )
        self.assertEqual( cidr, sCidr_ok )
        self.assertEqual( mask, iMask_ok )
        self.assertEqual( isIPv4( cidr ), bIPv4 )
        self.assertEqual( HashKey( cidr ), hash( IPNetwork(cidr) ) )
        print 'tested validCidr(),isIPv4() and HashKey() with %s ' % sCidr2Test

    def test(self):
        self.TestCidr( '17/7','17.0.0.0/7',7,True )
        self.TestCidr( '172.5/15','172.5.0.0/15',15,True )
        self.TestCidr( '187.18.48/20','187.18.48.0/20',20,True )
        self.TestCidr( '187.18.49/x','187.18.49.0/32',32,True )
        self.TestCidr( '187.18.50.123','187.18.50.123/32',32,True )
        self.TestCidr( '187.18.48/33','187.18.48.0/32',32,True )
        self.TestCidr( '2001:12c8::/32','2001:12c8::/32',32,False )
        self.TestCidr( '2001:12c8::1234','2001:12c8::1234/128',128,False )
        self.TestCidr( '2002::/16','2002::/16',16,False )
        self.TestCidr( '::/129','::/128',128,False )

def TestFunctions():
    """ TestFunctions() test basic functions, should be called first to validate routines used everywhere\n
    """
    unittest.main()

def TestTables( bDebug ):
    """ for debugging only uses the hard coded networks\n
    """

    # lookup tables
    cidr4_table = {}
    MaxMaskLen4 = 0
    MinMaskLen4 = 32
    cidr6_table = {}
    MaxMaskLen6 = 0
    MinMaskLen6 = 128
    net_masks = [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6]

    (cidr4_table,cidr6_table,net_masks) = LoadCidrTable( cidr4_table, cidr6_table, net_masks, CIDR_file, bDebug )

    print 'CIDR IPv4 table %d records ' % (len(cidr4_table))
    print 'CIDR IPv6 table %d records '% (len(cidr6_table))
    print '--------------------\n net_masks = %d,%d,%d,%d ' % tuple( [mask for mask in net_masks] )
    print '--------------------\n cidr4_table'
    print cidr4_table
    print '--------------------\n cidr6_table'
    print cidr6_table
    print '--------------------'

    (cidr4_table,cidr6_table,net_masks) = LoadRirTable(cidr4_table,cidr6_table, net_masks, RIR_file, bDebug )

    print 'CIDR IPv4 table %d records ' % (len(cidr4_table))
    print 'CIDR IPv6 table %d records '% (len(cidr6_table))
    print '--------------------\n net_masks = %d,%d,%d,%d ' % tuple( [mask for mask in net_masks] )
    print '--------------------\n cidr4_table'
    print cidr4_table
    print '--------------------\n cidr6_table'
    print cidr6_table
    print '--------------------\nEND'


def TestAll( bDebug ):
    """ for debugging only uses the hard coded networks """

    # lookup tables
    cidr4_table = {}
    MaxMaskLen4 = 0
    MinMaskLen4 = 32
    cidr6_table = {}
    MaxMaskLen6 = 0
    MinMaskLen6 = 128
    net_masks = [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6]
    asn_table = {}

    local_asn = 21911
    ournets4 = [ '200.169.96.0/20','187.18.48.0/20' ]
    ournets6 = [ '2001:12c8::/32' ]
    local_resources = [ local_asn, ournets4, ournets6 ]

    print 'CIDR'
    (cidr4_table,cidr6_table,net_masks) = LoadCidrTable( cidr4_table, cidr6_table, net_masks, CIDR_file, bDebug )
    print 'CIDR IPv4 table %d records ' % (len(cidr4_table))
    print 'CIDR IPv6 table %d records '% (len(cidr6_table))
    print 'net_masks = %d,%d,%d,%d ' % tuple( [mask for mask in net_masks] )

    (cidr,asn) = LookupIp('200.9.199.1',cidr4_table, net_masks)
    assert asn==15256

    (cidr,asn) = LookupIp('200.9.199.254',cidr4_table, net_masks ) # 15256
    assert asn==15256

    (cidr,asn) = LookupIp('200.9.198.1',cidr4_table, net_masks ) # UNKNOWN
    assert asn==UNKNOWN

    (cidr,asn) = LookupIp('2804:a8::1',cidr6_table, net_masks ) # 4230
    assert asn==4230

    print 'RIR'
    (cidr4_table,cidr6_table,net_masks) = LoadRirTable(cidr4_table,cidr6_table, net_masks, RIR_file, bDebug )
    print 'CIDR IPv4 table %d records ' % (len(cidr4_table))
    print 'CIDR IPv6 table %d records '% (len(cidr6_table))
    print 'net_masks = %d,%d,%d,%d ' % tuple( [mask for mask in net_masks] )

    (cidr,asn) = LookupIp('201.1.2.1',cidr4_table, net_masks) # DOMESTIC
    #print (cidr,asn)
    if bDebug:
        assert asn==DOMESTIC
    else:
        assert asn==27699L

    (cidr,asn) = LookupIp('2001:1280::1',cidr6_table, net_masks) # DOMESTIC
    #print (cidr,asn)
    if bDebug:
        assert asn==DOMESTIC
    else:
        assert asn==16685L

    ip_src = '200.9.199.1'
    if isIPv4( ip_src ):
        ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr4_table, net_masks, local_resources  )
    else:
        ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr6_table, net_masks, local_resources )
    assert asn_src==15256

    ip_src = '2804:a8::1'
    if isIPv4( ip_src ):
        ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr4_table, net_masks, local_resources  )
    else:
        ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr6_table, net_masks, local_resources )
    assert asn_src==4230

    asn_table = LoadAsnTable() # ASN_file, True ):
    print 'ASN table %d records ' % (len(asn_table))
    print asn_table

if __name__=="__main__":

    # test basic functions
    #TestFunctions()

    # test table load with hard coded data
    print '--------------------\n TestTables() with hard coded data'
    TestTables( True )

    # test table load + lookup with hard coded data
    print '--------------------\n TestAll() with hard coded data'
    TestAll( True )

    # test using real data
    #TestTables( False )
    print '--------------------\n TestAll() with real data'
    TestAll( False )