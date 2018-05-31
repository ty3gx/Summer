import re
import operator
import print_pcap
import logging
import lib.logger as logger
from datetime import datetime
from datetime import timedelta
import os
import GeoIP

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
TCPPckCount = 0
UDPPckCount = 0
SYNFlagCount = 0
monListCount = 0
SSDPCount = 0
startTime = datetime.strptime("9999-12-31 23:59:59", "%Y-%m-%d %H:%M:%S")
endTime = datetime.strptime("0001-1-1 0:0:0", "%Y-%m-%d %H:%M:%S")

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
				srcGStr = "none"
			else:
				if srcG["city"] is None: 
					srcG["city"] = "none"
				if srcG["region_name"] is None: 
					srcG["region_name"] = "none"
				if srcG["country_name"] is None: 
					srcG["country_name"] = "none"

				srcGStr = srcG["city"] + ", " + srcG["region_name"] + ", " + srcG["country_name"]

			if srcG is None:
				srcGStr = "none"
			else:
				if dstG["city"] is None: 
					dstG["city"] = "none"
				if dstG["region_name"] is None: 
					dstG["region_name"] = "none"
				if dstG["country_name"] is None: 
					dstG["country_name"] = "none"

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
				flags = templine.split("FLAGS=[")[1].split(']')[0]
				if ("SYN" in flags) and ("ACK" not in flags): # SYN flag
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
				global TCPPckCount
				TCPPckCount += 1
			else:
				token = templine.split("DATA_BINARY=", 1)[1]
				if token[1] == '7' and token[9:11] == "2a": 
				# moode is 7 and request MON_GETLIST_! (42)
					global monListCount
					monListCount += 1
				else:
					if srcP == "1900":
						global SSDPCount
						SSDPCount += 1
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
	print("The number of source IPs with only two or less packets sent: " + str(tempCount))
	print("")
	print("TCP  packets processed: " + str(TCPPckCount))
	print("    SYN Flags found in TCP  packets: " + str(SYNFlagCount))
	print("UDP packets processed: " + str(UDPPckCount))
	print("    monlist requests found in UDP (NTP) packets: "  + str(monListCount))
	print("    SSDP packets found in UDP packets: "  + str(SSDPCount))

	print("")
	print("Most frequent source IP cities: ")
	print(sorted_srcGeoIP[0:options.maxIP])
	print("Most frequent destination IP cities: ")
	print(sorted_dstGeoIP[0:options.maxIP])

	print("")
	print("Most frequent source IP and ports:")
	print sorted_srcIPPort[0:options.maxIP]
	print("")
	print("Most frequent source IPs:")
	for i in range(0, options.maxIP):
		gir = gi.record_by_name(sorted_srcIP[i][0])
		print(str(sorted_srcIP[i]) + ": "), 
		if gir is not None:
			print (gir["city"] + ", " + gir["region_name"] + ", " + gir["country_name"])
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
		gir = gi.record_by_name(sorted_dstIP[i][0])
		print(str(sorted_dstIP[i]) + ": "), 
		if gir is not None:
			print (gir["city"] + ", " + gir["region_name"] + ", " + gir["country_name"])
		else:
			print ("N/A")
	print("")
	print("Most frequent destination ports:")
	print sorted_dstPort[0:options.maxIP]

	#print (geolite2.lookup(sorted_dstIP[0][0]).country)
	#print (geolite2.lookup(sorted_dstIP[0][0]).city.names)

	# print("Number of SYN packets processed per second: " + \
	#	str(SYNFlagCount / (timedelta.total_seconds(endTime - startTime) + 1)))


	if not options.storeResult:
		os.remove(outFile)