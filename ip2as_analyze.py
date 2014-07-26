"""
ip2as_analyze.py
IP to AS Traffic Analyzer
"""
#
# Author: fcbarbi at gmail.com
# update July 2014
##
# Usage: python ip2as_analyze
# After loading data from CIDR.csv, ASN.csv and RIR.txt and thr routine reads <filein> and generates <fileout>
#
# <filein> is CSV with this structure:
# date_time,ip_src,ip_dest,dataload
#
# <fileout> has this structure:
# date_time,ip_src,ip_dest,dataload,cidr_src,cidr_dest,asn-src,asn-dest,ent_src,ent_dest
#
# Better collect every 10 minutes for a one minute window of traffic to get a representative sample.
# In an intel i5 this routine processes 600 records per second so a data sample
# wih 3.6 million records takes less than 2 hours (=3.6*1e6/600/3600) to process.
#

# Traffic files
BaseFile = '_20141104'
FileIn  = BaseFile+'_in.txt'
FileOut = BaseFile+'_out.txt'

import os 
#import numpy as np
#import time
from datetime import timedelta
from datetime import datetime
from time import gmtime
from time import time
from time import strftime
from time import strptime

from ipaddr import IPAddress
from ipaddr import IPNetwork

from ip2as_functions import *
from ip2as_present import Report
import pandas as pd

local_resources = [ local_asn, ournets4, ournets6 ]
# traff data frame is used to aggregate and visualize traffic
traff = pd.DataFrame( [(0,0,0,0)], index=[('time','asn')], columns=['time','asn','loadi','loado'] )
iDelta = BAR10min  # 10 minutes bar in seconds = 10*60 = 600

# #############################################################
#def main( local_resources ):
#    return Analyze( local_resources )

# #############################################################
def Analyze( local_resources ):
    # lookup tables 
    cidr4_table = {}
    MaxMaskLen4 = 0
    MinMaskLen4 = 32
    cidr6_table = {}
    MaxMaskLen6 = 0
    MinMaskLen6 = 128
    asn_table  = {}
    net_masks = [MaxMaskLen4, MinMaskLen4, MaxMaskLen6, MinMaskLen6]
    recno = 1  # count lines in the output file

    print "building tables..."
    start_time = time()

    # build CIDR, RIR, ASN tables 
    ( cidr4_table,cidr6_table,net_masks ) = LoadCidrTable( cidr4_table,cidr6_table,net_masks )
    #print net_masks
    ( cidr4_table,cidr6_table,net_masks ) = LoadRirTable( cidr4_table,cidr6_table,net_masks )
    #print net_masks
    print 'CIDR IPv4 table %d records ' % (len(cidr4_table))
    print 'CIDR IPv6 table %d records '% (len(cidr6_table))

    asn_table  = LoadAsnTable()
    print 'ASN table %d records '% (len(asn_table))

    goOn = True    
    try:
        os.remove( FileOut )
    except:
        print "unable to delete file "+FileOut+" (it existed?)"

    try:
        fin  = open( FileIn )
        rec = (fin.readline()).strip()
    except:
        print "unable to open file "+FileIn
        goOn = False

    try:
        fout = open( FileOut, 'w' )
    except:
        print "unable to open file "+FileOut
        goOn = False

    goOn = goOn and not (rec=='' or rec=='\n')
    if goOn:
        print "processing started after %s secs" % (time()-start_time)
    else:
        print "processing has stopped, please check and retry"

    while goOn:
   
        if (recno%100==0):
            print str(recno) + ' records processed in %s secs' % (time()-start_time)
        
        record = rec.split( SEPC ) 
        date_time = (record[0]).strip()
        ip_src  = (record[1]).strip()
        ip_dest = (record[2]).strip()
        
        try: 
            load = int(record[3])
        except:
            load = 0
            # log error in load field
        
        cidr_src  = '(NA)' 
        cidr_dest = '(NA)' 
        asn_src  = UNKNOWN
        asn_dest = UNKNOWN

        if isIPv4( ip_src ):
            ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr4_table, net_masks, local_resources  )
        else:
            ( cidr_src,asn_src ) = getCidrAsn( ip_src, cidr6_table, net_masks, local_resources )
            
        if isIPv4( ip_dest ):
            ( cidr_dest,asn_dest ) = getCidrAsn( ip_dest, cidr4_table, net_masks, local_resources )
        else:
            ( cidr_dest,asn_dest ) = getCidrAsn( ip_dest, cidr6_table, net_masks, local_resources )
        
        rec_out = date_time + SEPC + ip_src + SEPC + ip_dest + SEPC + str(load)
        rec_out = rec_out + SEPC + cidr_src + SEPC + cidr_dest + SEPC + str(asn_src) + SEPC + str(asn_dest)
        
        if asn_table.has_key( asn_src ):
            ent_src = asn_table[ asn_src ][0]  # gets the shortcode for the entity
        else:
            ent_src = '(no entity for this asn)'
        if  asn_table.has_key( asn_dest ):   
            ent_dest = asn_table[ asn_dest ][0]
        else:
            ent_dest = '(no entity for this asn)'
        rec_out = rec_out + SEPC + ent_src + SEPC + ent_dest
        
        fout.write(rec_out+'\n')

        timeslot = dt2slot( date_time, iDelta )
        if asn_src==local_asn:
            traff.loc[recno] = (timeslot, asn_dest, 0, load)  # outgoing traffic
        else:
            traff.loc[recno] = (timeslot, asn_src, load, 0)

        rec = fin.readline()
        rec = rec.strip()
        recno += 1
        goOn = goOn and not (rec=='' or rec=='\n')

    fout.close()
    fin.close()
    
    print "File '%s' with %f records generated in %s secs" % (FileOut, recno-1, time()-start_time)

    #return ( cidr4_table,cidr6_table,net_masks )
    return ( traff )

# #############################################################
if __name__=="__main__":

    #cidr4 = {}
    #cidr6 = {}
    #( cidr4, cidr6, net_masks )=main( cidr4,cidr6 )
    #print cidr4
    #print cidr6

    #df = main( local_resources )
    traff = Analyze( local_resources )
    Report( traff, local_resources[0]  )
    # str(local_resources[0])+".htm"   # generates <local_asn>.htm

    print "IP analysis complete"

    
    
    