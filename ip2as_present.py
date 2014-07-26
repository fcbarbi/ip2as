
"""
ip2as_present.py
ip2as - IP to ASN Traffic Analyzer
Present Traffic data classified by ASN and entity
"""
#
# Author: fcbarbi at gmail.com
# Update: July 2014
#
# fig 1,2.Traffic in time: incoming and outgoing
# Table 1,2.Top 10 ASN by traffic load (incoming and outgoing)
# fig 2.Traffic:pie chart with incoming and outgoing traffic by entity
# fig 3.Peak traffic by ASN: time, asn_src, asn_dest, load
#

import pandas as pd
import matplotlib.pyplot as plt
import random  # debug only

def Report( traff, local_asn ):

    plt.ylabel('Traffic')
    plt.xlabel('Time')

    # fig 1.Time chart of aggregate inbound traffic
    traffg = traff.groupby(['time']).loadi.sum()
    plt.title('Inbound Traffic')
    plt.plot(traffg)
    plt.savefig( str(local_asn)+'_fig1.png')
    #plt.show()
    print "figure 1 generated"

    # fig 2.Time chart of aggregate outbound traffic
    traffg = traff.groupby(['time']).loado.sum()
    plt.title('Outbound Traffic')
    plt.plot(traffg)
    plt.savefig( str(local_asn)+'_fig2.png' )
    #plt.show()
    print "figure 2 generated"


    # fig 5.Time chart of inbound traffic from top 5 ASNs
    traffg = traff.groupby(['time','asn']).loadi.sum()
    traffg.sort(ascending=False)
    traffg.head(05)
    plt.title('Top 5 Inbound Traffic by ASN')
    plt.plot(traffg)
    plt.savefig( str(local_asn)+'_fig5.png')
    #plt.show()
    print "figure 5 generated"

    # fig 6.Time chart of outbound traffic to top 5 ASNs
    traffg = traff.groupby(['time','asn']).loado.sum()
    traffg.sort(ascending=False)
    traffg.head(05)
    plt.title('Top 5 Outbound Traffic by ASN')
    plt.plot(traffg)
    plt.savefig( str(local_asn)+'_fig6.png')
    #plt.show()
    print "figure 6 generated"

    plt.ylabel('')
    plt.xlabel('')

    # fig 3.Pie Chart with inbound traffic of top 5 ASN
    traffg = traff.groupby(['asn']).loadi.sum()
    traffg.sort(ascending=False)
    traffg.head(05)
    trafftot = sum( traffg.values[0:5] )
    traffp = []
    labels = []
    for i in xrange(5):
        if traffg.index[i]== -1:
            labels.append( 'DOMESTIC' )
        if traffg.index[i]== -2:
            labels.append( 'INTERNATIONAL' )
        if (traffg.index[i]!= -1) and (traffg.index[i]!= -2):
            labels.append( 'AS'+str(traffg.index[i]) )
        traffp.append( traffg.values[i]/trafftot )
    colors = [ 'red', 'orange', 'yellow', 'grey', 'white' ]
    explode = (0.1, 0, 0, 0, 0)
    plt.pie( traffp, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=90 )
    #plt.title = 'Top 5 Inbound Traffic by ASN'
    plt.axis('equal')
    plt.savefig( str(local_asn)+'_fig3.png')
    #plt.show()
    print "figure 3 generated"

    # fig 4.Pie Chart with outbound traffic of top 5 ASN
    traffg = traff.groupby(['asn']).loado.sum()
    traffg.sort(ascending=False)
    traffg.head(05)
    trafftot = sum( traffg.values[0:5] )
    traffp = []
    labels = []
    for i in xrange(5):
        if traffg.index[i]== -1:
            labels.append( 'DOMESTIC' )
        if traffg.index[i]== -2:
            labels.append( 'INTERNATIONAL' )
        if (traffg.index[i]!= -1) and (traffg.index[i]!= -2):
            labels.append( 'AS'+str(traffg.index[i]) )
        traffp.append( traffg.values[i]/trafftot )
    colors = [ 'red', 'orange', 'yellow', 'grey', 'white' ]
    explode = (0.1, 0, 0, 0, 0)
    plt.pie( traffp, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=90 )
    #plt.title = 'Top 5 Outbound Traffic by ASN'
    plt.axis('equal')
    plt.savefig( str(local_asn)+'_fig4.png')
    #plt.show()
    print "figure 4 generated"

if __name__=="__main__":

    # for debug only
    traff = pd.DataFrame( [(0,0,0,0)], index=[('time','asn')], columns=['time','asn','loadi','loado'] )
    i = 1
    for asn in (1,2,3,4,5,-1):
        for t in xrange(24):
            traff.loc[i]   = ( t, asn, random.randint(1e4,1e6), 0 )  # ingoing
            traff.loc[i+1] = ( t, asn, 0, random.randint(1e4,1e6) )  # outgoing
            i += 2
    Report( traff, 21911 ) #local_resources[0]  )
    print "reporting is done"

