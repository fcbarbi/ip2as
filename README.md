ipasta
======

IP AS Traffic Analysis 


This project was developed in Python 2.7 to classify IPv4 and IPv6 traffic according to their ASN. 

The internet is composed of interconnected networks known as Autonomous Systems (AS), each identified by an AS Number (ASN), see [1] for some statistics. 
We need the source and destination of each IP packet to help provision network capacity. This exercise should be perfomed regularly to keep the network optimized. The basic idea is that an ISP can reduce operating costs by connecting directly to the most relevant networks. This direct connection increases the Quality of Service (QoS) perceived by the ISP customers and allows it to differentiate itself in the market by offering low latency. 

This project covers a small portion of what is usually known as IP Flow Analysis that is concerned with the type of traffic carried (whether it is TCP, ICMP or other protocols). There are some packages, like Cisco NetFlow and the open source FlowScan, that do IP traffic flow accounting. You may want to check [11] and [12]. Our approach is to focus on the IP to ASN mapping and make it easy to customize the analysis from an ISP perspective. 

This project is divided in two parts: information analysis and reporting in an intuitive way. A third part could be the data gathering process that should occur at a border router to be valid. This can be tricky since these devices handle huge traffic at the most relevant moments for our analysis. For now we assume traffic data was already collected with a sniffer (eg. TCPDUMP [2]). A variety of tools can be found at CAIDA [10]. 

To analyze data, we only need 4 pieces of information: 
	Date and Time of data collection, 
	Source IP Address, 
	Destination IP Address and 
	Total Data Length.

In the example data we take the perspective of an ISP (internet service provider) located in Brazil to classify the networks as either domestic or international. The domestic networks are detailed to a domestic ASN. We can be sure to have complete coverage since our data comes froms the Region Information Registry, LACNIC. 

A CIDR (Classless Inter-Domain Routing) is a network as represented by <ip>/<mask> as in 192.169.2.0/24 for IPv4, and 2001:db8::/32 for IPv6 (see [3]).
We know all the CIDRs allocated for the country (BR for Brazil) even if we dont know to which ASN they relate. 

CIDR.csv
This is the list of the relevant networks. This is the key database of our project and relates CIDRs to the corresponding ASN (see [4]). This file should be regularly updated to reflect the most relevant networks from the ISP perspective. It also includes a list of reserved IP addresses [13] that should not be leaking out of the ISP's routers. 

ASN.csv
For a list of entities associated with each ASN you may refer to [7]. The biggest (and probably more relevant) networks are listed with their associated ASNs. This information is useful to better understand the collected data but is not necessary for our analysis. 

delegated-lacnic-latest.txt
This file contains a list of all resources (networks and ASNs) allocated to Brazil by LACNIC, the Latin American and Caribbean Internet Addresses Registry [9] that can be downloaded from [5]. This data file format documentation is at RIR-Statistics-Exchange-Format.txt (from [6]). All the CIDRs allocated for BRazil that are not in the CIDR.csv file are marked as DOMESTIC. We believe that the level of detail in CIDR.csv depends on the user interests and geo location.

ip2asn.py
This module lookups up a table of tuples (ASN,CIDR) to supply the ASN associated with an IP address.
The function returns the ASN associated to any ip address belonging to a CIDR. 
If no network is not found in the dictionary, the return value is either DOMESTIC or INTERNATIONAL.

ipaddr.py
Ipaddr is a "lightweight IPv4/IPv6 manipulation library in Python" developed by Google and available at [8]. You may want to download the most recent version but it is already included in this project files for convenience.

DATA VISUALIZATION (TODO) ******************************
google ip traffic DATA VISUALIZATION tool

References:

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

update fcb 07 jul 2014
