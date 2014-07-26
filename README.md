IP-to-AS Traffic Analyzer in Python
======

#Introduction

This project developed in Python 2.7 offers a tool to classify IPv4 and IPv6 packet according to their source and destination ASN (Autonomous System Number). 

The internet is composed by interconnected networks known as Autonomous Systems (AS), each identified by an AS Number (ASN), see [1] for some statistics. To help provision network capacity Network Engineers need to understand the traffic patterns, in pacrticular the main sources and destinations of the ISP (Internet Service Provider) traffic. This exercise should be perfomed regularly to keep the network optimized. The basic idea is that an ISP can reduce operating costs by connecting directly to the most relevant networks (AS) to his customers. This direct connection increases the Quality of Service (QoS) perceived by the ISP customers and allows it to differentiate itself in the market by offering low "latency" (time to transport packets from source netwotk to destination network). 

This project covers a small portion but crucial part of what is usually known as "IP Flow Analysis" that is concerned with the type of traffic carried (whether it is TCP, ICMP or other protocols). There are some packages, like Cisco NetFlow and the open source FlowScan, that do IP traffic flow accounting. You may want to check [11] and [12]. Our approach is to focus on the IP to ASN mapping and make it easy to customize the analysis from the ISP perspective. 

##Implementation notes

This project is divided in two parts: information analysis and reporting in an intuitive way. A third part could be the data gathering process that should occur at a border router to be valid. This can be tricky since these devices handle huge traffic at the most relevant moments for our analysis. For now we assume traffic data was already collected with a sniffer (eg. TCPDUMP [2]). A variety of tools can be found at CAIDA [10]. 

To analyze data, we only need 4 pieces of information: 
* Date and Time of data collection, 
* Source IP Address, 
* Destination IP Address and 
* Total Data Length.

In the example data we take the perspective of an ISP (internet service provider) located in Brazil to classify the networks as either domestic or international. The domestic networks are detailed to a domestic ASN. We can be sure to have complete coverage since our data comes froms the Region Information Registry, LACNIC. 

A CIDR (Classless Inter-Domain Routing) is a network as represented by <ip>/<mask> as in 192.169.2.0/24 for IPv4, and 2001:db8::/32 for IPv6 (see [3]). We know all the CIDRs allocated for the country (BR for Brazil) even if we don't know to which ASN they relate. 

## Files

**CIDR.csv**
This is the list of the relevant networks. This is the key database of our project and relates CIDRs to the corresponding ASN (see [4]). This file should be regularly updated to reflect the most relevant networks from the ISP perspective. It also includes a list of reserved IP addresses [13] that should not be leaking out of the ISP's routers. All the CIDRs allocated for BRazil (as reported in delegated-lacnic-latest.txt) that are not in the CIDR.csv file are marked as DOMESTIC. 

**ASN.csv**
For a list of entities associated with each ASN you may refer to [7]. The biggest (and probably more relevant) networks are listed with their associated ASNs. This information is useful to better understand the collected data but is not necessary for our analysis. 

**RIR.txt (delegated-lacnic-latest.txt)**
This file contains a list of all resources (networks and ASNs) allocated to Brazil by LACNIC, the Latin American and Caribbean Internet Addresses Registry [9] that can be downloaded from [5]. This data file format documentation is at RIR-Statistics-Exchange-Format.txt (from [6]). 

**ip2as_analyze.py**
This is the main module and must be configured in the header with the data file to be analyzed. In a intel core 5 this routine can classify some 600 packets (lines) per second, taking some 2 hours to classify a data file with 3.6 million packets. 

**ip2as_functions.py**
This module holds functions common to all modules such as table building and look-up.
The look-up uses an IP address as input to locate the table entry for the tuple (CIDR,ASN).
The function returns the ASN associated to any IP address belonging to a CIDR. 
If no network is not found in the dictionary, the return value is either DOMESTIC or INTERNATIONAL.
The DOMESTIC networks are known by the RIR file where all resources designated to BRazil are listed.

**ip2as_gentd.py**
This module holds a routine to GENerate Test Data to validate the analyzer. It should be run to create a model data file in a format that the user will replicate when collecting real data from its production network. The best way to collect real data is with a packet sniffer connected to a trunk port of a switch where the border router is connected. Samples may be made during 1 minute every 10 or 30 minutes to generate a statistically signicant sample of the real traffic. 

**ip2as_present.py**
This module holds the routines to perform data aggregation and to generate graphics for visualization. In this version six graphics are generated with ".png" extensions (this could easily be changed to ".pdf" ou ".ps" files). 

**ip2as_tests.py**
This module holds all the testing procedures for the functions and must be used whenever changes are made to the functions to ensure code functionality. Note that we provide some basic data for debugging and the possibility of loading all the prodcutions tables. To choose between one way or another to generate data for debugging you must switch to debugging mode by altering a variable (bDebug) to True in the header of the file. 

**ipaddr.py**
Ipaddr is a "lightweight IPv4/IPv6 manipulation library in Python" developed by Google and available at [8]. You may want to download the most recent version but it is already included in this project files for convenience.

## References:

[1] http://www.potaroo.net/tools/asn32/

[2] http://www.tcpdump.org/

[3] http://tools.ietf.org/html/rfc4632

[4] http://www.team-cymru.org/Services/ip-to-asn.html

[5] ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest

[6] ftp://ftp.ripe.net/pub/stats/ripencc/RIR-Statistics-Exchange-Format.txt

[7] http://thyme.apnic.net/rviews/data-used-autnums

[8] https://pypi.python.org/pypi/ipaddr

[9] http://www.lacnic.net 

[10] http://www.caida.org/tools/

[11] https://www.usenix.org/conference/lisa-2000/flowscan-network-traffic-flow-reporting-and-visualization-tool

[12] https://apps.ubuntu.com/cat/applications/natty/flowscan/

[13] http://en.wikipedia.org/wiki/Reserved_IP_addresses

updated fcb July 25, 2014
