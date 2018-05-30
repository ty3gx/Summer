
简介
------
该工具可以分析PCAP包并发现一些攻击包的特征。可以打印并储存详细的icmp / tcp / udp协议报文 (https://github.com/tanjiti/packet_analysis)

安装
------
* [pynids](https://jon.oberheide.org/pynids/)  
`bash install_pynids.bash`

* [dpkt](http://dpkt.readthedocs.io/en/latest/)  
`sudo apt-get install python-pip`  
`pip install dpkt`

* [requests](http://www.python-requests.org/en/master/)  
`pip install requests`

使用
------
读取PCAP数据包，打印报文分析结果  
`python parseFile.py --pcapfile=FILE_NAME`  
其他选项：  
`--printResult`: 打印详细的报文信息到标准输出，默认为0（不打印）  
`--saveResult`: 保存详细的报文信息到文件，默认为1（保存），保存路径为"原PCAP文件名_result.txt"  
`--assetip`: 仅分析该指定目的IP的报文信息
`--assetport`: 仅分析该指定目的端口的报文信息

 
功能
------
