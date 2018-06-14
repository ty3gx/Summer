# -*- coding: UTF-8 -*-

import re
import operator
import print_pcap
import logging
import lib.logger as logger
from datetime import datetime
from datetime import timedelta
import os
import GeoIP
from pyecharts import Geo
from urllib2 import Request, urlopen

THRESHOLD = 2
PRINT_LIMIT = 5

srcIP = {}
dstIP = {}
srcGeoIP = {}
dstGeoIP = {}
srcPort = {}
dstPort = {}
srcIPPort = {}
dstIPPort = {}
#srcISP = {}
#dstISP = {}
TCPPckCount = 0
UDPPckCount = 0
SYNFlagCount = 0
monListCount = 0
SSDPCount = 0
DNSCount = 0
abnormalFlags = 0
startTime = datetime.strptime("9999-12-31 23:59:59", "%Y-%m-%d %H:%M:%S")
endTime = datetime.strptime("0001-1-1 0:0:0", "%Y-%m-%d %H:%M:%S")

def get_isp_info(ip):
	import requests
	r = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=%s' %ip) #淘宝IP地址库接口       
	if  r.json()['code'] == 0 :
		i = r.json()['data']
                 
		country = i['country']  #国家 
		area = i['area']        #区域
		region = i['region']    #地区
		city = i['city']        #城市
		isp = i['isp']          #运营商
                            
		return isp
	else:
		return "N/A"

def parseFile(filename):
	g = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

	f = open(filename, 'r')
	for line in f:
		templine = line.strip()
		#print templine
		#print(raw_input()) //step mode
		if (templine[1:4] == "TCP" or templine[1:4] == "UDP"):
			ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', templine )
			#print ip[0] //srcIP
			#print ip[1] //dstIP
			global srcIP
			if srcIP.has_key(ip[0]):
				srcIP[ip[0]]+=1
			else:
				srcIP[ip[0]] = 1
			global dstIP
			if dstIP.has_key(ip[1]):
				dstIP[ip[1]]+=1
			else:
				dstIP[ip[1]] = 1

			srcG = g.record_by_name(ip[0])
			dstG = g.record_by_name(ip[1])
			if srcG is None:
				srcGStr = "N/A"
			else:
				if srcG["city"] is None: 
					srcG["city"] = "N/A"
				if srcG["region_name"] is None: 
					srcG["region_name"] = "N/A"
				if srcG["country_name"] is None: 
					srcG["country_name"] = "N/A"

				srcGStr = srcG["city"] + ", " + srcG["region_name"] + ", " + srcG["country_name"]

			if dstG is None:
				dstGStr = "N/A"
			else:
				if dstG["city"] is None: 
					dstG["city"] = "N/A"
				if dstG["region_name"] is None: 
					dstG["region_name"] = "N/A"
				if dstG["country_name"] is None: 
					dstG["country_name"] = "N/A"

				dstGStr = dstG["city"] + ", " + dstG["region_name"] + ", " + dstG["country_name"]

			global  srcGeoIP, dstGeoIP
			if srcGeoIP.has_key(srcGStr):
				srcGeoIP[srcGStr] += 1
			else: 
				srcGeoIP[srcGStr] = 1
			if dstGeoIP.has_key(dstGStr):
				dstGeoIP[dstGStr] += 1
			else: 
				dstGeoIP[dstGStr] = 1

			
			srcP = templine.split(ip[0] + ':', 1)[1].split('(')[0]
			dstP = templine.split(ip[1] + ':', 1)[1].split('(')[0]
			global srcIPPort
			if srcPort.has_key(srcP):
				srcPort[srcP]+=1
			else:
				srcPort[srcP] = 1
			global dstIPPort
			if dstPort.has_key(dstP):
				dstPort[dstP]+=1
			else:
				dstPort[dstP] = 1

			global srcIPPort
			if srcIPPort.has_key(ip[0] + ':' + srcP):
				srcIPPort[ip[0] + ':' + srcP]+=1
			else:
				srcIPPort[ip[0] + ':' + srcP] = 1
			global dstIPPort
			if dstIPPort.has_key(ip[1] + ':' + dstP):
				dstIPPort[ip[1] + ':' + dstP]+=1
			else:
				dstIPPort[ip[1] + ':' + dstP] = 1



			if (templine[1:4] == "TCP"): # TCP
				flags = [-1, -1, -1, -1, -1, -1] # URG, ACK, PSH, RST, SYN, FIN
				flagStr = templine.split("FLAGS=[")[1].split(']')[0]
				if "URG" in flagStr:
					flags[0] = 1
				else:
					flags[0] = 0
				if "ACK" in flagStr:
					flags[1] = 1
				else:
					flags[1] = 0
				if "PSH" in flagStr:
					flags[2] = 1
				else:
					flags[2] = 0
				if "RST" in flagStr:
					flags[3] = 1
				else:
					flags[3] = 0
				if "SYN" in flagStr:
					flags[4] = 1
				else:
					flags[4] = 0
				if "FIN" in flagStr:
					flags[5] = 1
				else:
					flags[5] = 0
				if (flags[4] and not flags[1]): # SYN no ACK
					tempTime =  templine.split('-')[0][-4:] + "-" + templine.split('-', 1)[1].split(']')[0]
					currentTime = datetime.strptime(tempTime, "%Y-%m-%d %H:%M:%S")
					global startTime
					global endTime
					if currentTime < startTime: 
						startTime = currentTime
					if currentTime > endTime:
						endTime = currentTime
					
					global SYNFlagCount
					SYNFlagCount += 1

				# URG, ACK, PSH, RST, SYN, FIN
				if (all(f == 0 for f in flags) or all(f == 1 for f in flags) or \
					(flags[4] and flags[5]) or (flags[4] and flags[3]) or  \
					(flags[5] and flags[3]) or (flags[0] and flags[2] and flags[5]) or \
					(flags[5] and not flags[0] and not flags[1] and not flags[2] and not flags[3]\
						and not flags[4]) or\
					(flags[0] and not flags[1] and not flags[2] and not flags[3] and not flags[4]\
						and not flags[5]) or\
					(flags[2] and not flags[0] and not flags[1] and not flags[3] and not flags[4]\
						and not flags[5])) :
					global abnormalFlags
					abnormalFlags += 1

				global TCPPckCount
				TCPPckCount += 1

			else:
				token = templine.split("DATA_BINARY=", 1)[1]
				if token[1] == '7' and token[9:11] == "2a" and srcP == "123": # NTP source port = 123 
				# moode is 7 and request MON_GETLIST_! (42)
					global monListCount
					monListCount += 1
				elif srcP == "1900": # SSDP port = 1900
					if "55 50 6e 50" in token and "53 54 3a" in token: # UPnP and ST:
						global SSDPCount
						SSDPCount += 1
				elif srcP == "53":
					global DNSCount
					DNSCount += 1
				global UDPPckCount
				UDPPckCount += 1


				
	f.close()


if __name__ == '__main__':
	import lib.mills as mills

	logger.generate_special_logger(level=logging.INFO,
                                   logtype="pcapanalyis",
                                   curdir=mills.path("log")
                                   ,
                                   ismultiprocess=False)
	from optparse import OptionParser

	assetip = None
	assetport = None

	from optparse import OptionParser

	parser = OptionParser()

	parser.add_option(
        "--pcapfile", dest="pcapfile",
        action='store', type='string',
        help="special the text file path",
        default="fw_cap_2016-01-08-13-48-17.pcap" # SYN flood packets
        #default="fw_cap_2017-02-07-18-40-15.pcap" # monlist packets
        #default="fw_cap_2017-02-08-17-22-15.pcap" # ssdp packets
    )

   	parser.add_option(
        "--assetip", dest="assetip",
        action='store', type='string',
        help="special the assetip for search, e.x. 10.0.0.4,10.0.0.5",
        default=assetip
    )

   	parser.add_option(
        "--assetport", dest="assetport",
        action='store', type='string',
        help="special the asset port for search, e.x. 80,443 ",
        default=assetport
    )

   	parser.add_option(
        "--printResult", dest="printResult",
        action='store', type='int',
        help= "special whether or not to print the result",
        default=0
    )

   	parser.add_option(
        "--storeResult", dest="storeResult",
        action='store', type='int',
        help= "special whether or not to store the result",
        default=1
    )

	parser.add_option(
        "--maxIP", dest="maxIP",
        action='store', type='int',
        help= "specify the amount of ip addresses want to output",
        default=5
    )

	parser.add_option(
    	"--graphIP", dest="graphIP",
		action='store', type='string',
		help= "Specify the output file of IP graph (enter 'None' to not graph)",
		default= "outGraph"
	)

   	(options, args) = parser.parse_args()
   	ppo = print_pcap.PCAPParse(options.pcapfile)
   	print("-------------------------------------------------------------------")
   	print "Start reading pcap file: "

   	outFile = options.pcapfile[0:len(options.pcapfile)-5]
   	outFile += "_result.txt"
   	if options.storeResult:
   		print "Output will be stored in file: " + outFile
   	f = open(outFile, 'w')

   	if options.assetip:
   		asset_ip = options.assetip.strip().split(",")
   		asset_ip = [i.strip() for i in asset_ip]
   	else: 
   		asset_ip = None

	if options.assetport:
		asset_port = options.assetport.strip().split(",")
		asset_port = [int(i.strip()) for i in asset_port]
   	else: 
   		asset_port = None

   	#ppo.output_pcap(asset_ip=asset_ip, asset_port=asset_port)

   	for l in ppo.search_pcap(asset_port=asset_port, asset_ip=asset_ip):

        	if options.printResult:
        		print l

        	f.write(l)
        	f.write('\n')

	f.close()

	print("-------------------------------------------------------------------")
	print "Start parsing result: "


	parseFile(outFile)

	sorted_srcIPPort = sorted(srcIPPort.items(), key=operator.itemgetter(1), reverse=True)
	sorted_dstIPPort = sorted(dstIPPort.items(), key=operator.itemgetter(1), reverse=True)

	sorted_srcIP = sorted(srcIP.items(), key=operator.itemgetter(1), reverse=True)
	sorted_dstIP = sorted(dstIP.items(), key=operator.itemgetter(1), reverse=True)

	#global srcISP, dstISP
	#for i in range (0, len(sorted_srcIP)):
	#	sISP = get_isp_info(sorted_srcIP[i][0])
	#	if srcISP.has_key(sISP):
	#		srcISP[sISP] += sorted_srcIP[i][1]
	#	else:
	#		srcISP[sISP] = sorted_srcIP[i][1]

	#for i in range (0, len(sorted_dstIP)):
	#	dISP = get_isp_info(sorted_dstIP[i][0])
	#	if dstISP.has_key(dISP):
	#		dstISP[dISP] += sorted_dstIP[i][1]
	#	else:
	#		dstISP[dISP] = sorted_dstIP[i][1]
			

	#sorted_srcISP = sorted(srcISP.items(), key=operator.itemgetter(1), reverse=True)
	#sorted_dstISP = sorted(dstISP.items(), key=operator.itemgetter(1), reverse=True)

	sorted_srcPort = sorted(srcPort.items(), key=operator.itemgetter(1), reverse=True)
	sorted_dstPort = sorted(dstPort.items(), key=operator.itemgetter(1), reverse=True)

	sorted_srcGeoIP = sorted(srcGeoIP.items(), key=operator.itemgetter(1), reverse=True)
	sorted_dstGeoIP = sorted(dstGeoIP.items(), key=operator.itemgetter(1), reverse=True)

	#import ip database
	gi = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

	#gi.close()

	print("-------------------------------------------------------------------")
	print("Summary: ")
	print("Total packets processed: " + str(UDPPckCount + TCPPckCount))

	tempCount = 0
	for tempIP in srcIP:
		if  srcIP[tempIP] <= THRESHOLD:
			tempCount += 1
	print("Number of source IPs: " + str(len(srcIP)))
	print("Number of destination IPs: " + str(len(dstIP)))
	#print("Number of source ISPs: " + str(len(srcISP)))
	#print("Number of destination ISPs: " + str(len(dstISP)))
	print("The number of source IPs with only two or less packets sent: " + str(tempCount))
	print("")
	print("TCP  packets processed: " + str(TCPPckCount))
	print("    SYN Flags found in TCP  packets: " + str(SYNFlagCount))
	print("    Abnormal Flags found in TCP  packets: " + str(abnormalFlags))
	print("UDP packets processed: " + str(UDPPckCount))
	print("    monlist requests found in UDP (NTP) packets: "  + str(monListCount))
	print("    DNS packets found in UDP packets: "  + str(DNSCount))
	print("    SSDP packets found in UDP packets: "  + str(SSDPCount))

	print("")
	print("Most frequent source IP cities: ")
	print(sorted_srcGeoIP[0:options.maxIP])
	print("Most frequent destination IP cities: ")
	print(sorted_dstGeoIP[0:options.maxIP])

	#print("")
	#print("Most frequent source ISPs: ")
	#print(sorted_srcISP[0:options.maxIP])
	#print("Most frequent destination ISPs: ")
	#print(sorted_dstISP[0:options.maxIP])

	print("")
	print("Most frequent source IP and ports:")
	print sorted_srcIPPort[0:options.maxIP]
	print("")
	print("Most frequent source IPs:")
	for i in range(0, options.maxIP):
		if i >= len(sorted_srcIP):
			break
		gir = gi.record_by_name(sorted_srcIP[i][0])
		print(str(sorted_srcIP[i]) + ": "), 
		if gir is not None:
			if gir["city"] is None:
				gir["city"] = "N/A"
			if gir["region_name"] is None:
				gir["region_name"] = "N/A"
			if gir["country_name"] is None:
				gir["country_name"] = "N/A"
			tempISP = get_isp_info(sorted_srcIP[i][0])
			print (gir["city"] + ", " + gir["region_name"] + ", " + gir["country_name"] + ", ISP: " + tempISP)
		else:
			print ("N/A")
	print("")
	print("Most frequent source ports:")
	print sorted_srcPort[0:options.maxIP]
	print("")
	print("Most frequent destination IP and ports:")
	print sorted_dstIPPort[0:options.maxIP]
	print("")
	print("Most frequent destination IPs:")
	for i in range(0, options.maxIP):
		if i >= len(sorted_dstIP):
			break
		gir = gi.record_by_name(sorted_dstIP[i][0])
		print(str(sorted_dstIP[i]) + ": "), 
		if gir is not None:
			if gir["city"] is None:
				gir["city"] = "N/A"
			if gir["region_name"] is None:
				gir["region_name"] = "N/A"
			if gir["country_name"] is None:
				gir["country_name"] = "N/A"
			tempISP = get_isp_info(sorted_srcIP[i][0])
			print (gir["city"] + ", " + gir["region_name"] + ", " + gir["country_name"] + ", ISP: " + tempISP)
		else:
			print ("N/A")
	print("")
	print("Most frequent destination ports:")
	print sorted_dstPort[0:options.maxIP]

	print("-------------------------------------------------------------------")
	print("Detailed analysis of IPs: ")
	headers = {
    	'Accept': 'application/json'
    }
	print("Most frequent source IPs:")
	for i in range(0, options.maxIP):
		if i >= len(sorted_srcIP):
			break
		print (str(sorted_srcIP[i]) + ": ")
		request = Request("https://api.ipdata.co/" + sorted_srcIP[i][0] + "/", headers=headers)
		response_body = urlopen(request).read()
  		print response_body

  	print("-------------------------------------------------------------------")
  	print("Most frequent destination IPs:")
	for i in range(0, options.maxIP):
		if i >= len(sorted_dstIP):
			break
		print (str(sorted_dstIP[i]) + ": ")
		request = Request("https://api.ipdata.co/" + sorted_dstIP[i][0] + "/", headers=headers)
		response_body = urlopen(request).read()
  		print response_body
	


	#print (geolite2.lookup(sorted_dstIP[0][0]).country)
	#print (geolite2.lookup(sorted_dstIP[0][0]).city.names)

	# print("Number of SYN packets processed per second: " + \
	#	str(SYNFlagCount / (timedelta.total_seconds(endTime - startTime) + 1)))

	### Graphing of IP sources ###

	# eliminate IP address sending few packets to ensure performance
	if cmp(options.graphIP, "None") is not 0: 

		tempI = 0
		for i in range (0, len(sorted_srcIP)):
			if sorted_srcIP[i][1] < THRESHOLD:
				tempI = i
				break

		if tempI > len(sorted_srcIP) + 1:
			tempI = len(sorted_srcIP) + 1

		geo_cities_coords = {}
		attr = []
		value = []
		for i in range (0, tempI):
			gir = gi.record_by_name(sorted_srcIP[i][0])
			if gir is not None:

				geo_cities_coords[sorted_srcIP[i][0]] = [float(gir["longitude"]), float(gir["latitude"])]

				attr.append(sorted_srcIP[i][0])
				value.append(sorted_srcIP[i][1])

		geo = Geo("Source IP geograpic distribution", title_color="#fff", title_text_size=22,
          	title_pos="center", title_top=20, width=1200,
          	height=600, background_color='#404a59')
		geo.add("", attr, value, visual_range=[0, sorted_srcIP[0][1]], visual_text_color="#fff",
        	is_visualmap=True, geo_cities_coords=geo_cities_coords, type = "heatmap", maptype="china")
		geo.render(options.graphIP + "_source.html")



		tempI = 0
		for i in range (0, len(sorted_dstIP)):
			if sorted_dstIP[i][1] < THRESHOLD:
				tempI = i
				break

		if tempI > len(sorted_dstIP) + 1:
			tempI = len(sorted_dstIP) + 1
	
		geo_cities_coords = {}
		attr = []
		value = []
		for i in range (0, tempI):
			gir = gi.record_by_name(sorted_dstIP[i][0])
			if gir is not None:

				geo_cities_coords[sorted_dstIP[i][0]] = [float(gir["longitude"]), float(gir["latitude"])]

				attr.append(sorted_dstIP[i][0])
				value.append(sorted_dstIP[i][1])

		geo = Geo("destination IP geograpic distribution", title_color="#fff", title_text_size=22,
          	title_pos="center", title_top=20, width=1200,
          	height=600, background_color='#404a59')
		geo.add("", attr, value, visual_range=[0, sorted_dstIP[0][1]], visual_text_color="#fff",
        	symbol_size=15, is_visualmap=True, geo_cities_coords=geo_cities_coords, type = "heatmap", maptype="china")
		geo.render(options.graphIP + "_destination.html")




	if not options.storeResult:
		os.remove(outFile)
