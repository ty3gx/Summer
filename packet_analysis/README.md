
简介
------
该工具可以分析PCAP包并发现一些攻击包的特征。可以打印并储存详细的icmp / tcp / udp协议报文 (https://github.com/tanjiti/packet_analysis)

安装
------
#### Ubuntu (18.04)
* [pynids](https://jon.oberheide.org/pynids/)  
`bash install_pynids.bash`

* [dpkt](http://dpkt.readthedocs.io/en/latest/)  
`sudo apt-get install python-pip`  
`pip install dpkt`

* [requests](http://www.python-requests.org/en/master/)  
`pip install requests`

#### MacOS (10.13.2 High Sierra)
* [pynids](https://jon.oberheide.org/pynids/)  
`brew install libnids`

* [dpkt](http://dpkt.readthedocs.io/en/latest/)    
`pip install dpkt`

* [requests](http://www.python-requests.org/en/master/)  
`pip install requests`

使用
------
* 读取PCAP数据包，打印报文分析结果  
`python2 parseFile.py --pcapfile=FILE_NAME`  
* 其他选项：  
    * `--printResult`: 打印详细的报文信息到标准输出，默认为0（不打印）  
    * `--storeResult`: 保存详细的报文信息到文件，默认为1（保存），保存路径为"原PCAP文件名_result.txt"  
    * `--assetip`: 仅分析该指定目的IP的报文信息  
    * `--assetport`: 仅分析该指定目的端口的报文信息  

 
功能
------
* 分析IP地址与端口。
   * 找出出现频率最高的源地址与端口，及具体出现频率
   * 找出仅发送了很少包的源IP地址（默认为仅发送两个或更少包的源IP地址，可通过修改“PCK_LIMIT”值进行自定义）
   * 找出出现频率最高的目的地址与端口，及具体出现频率
   * 分别分析不同的源IP地址与目的IP地址的数量
   
* 分析具体的包文信息
   * 分析TCP包与UDP包的个数
   * 计算TCP包中SYN flag包（不含ACK flag的包）的个数 ——> 可能为SYN flood攻击
   * 计算UDP包中monlist请求的个数 ——> 可能为NTP monlist指令反射型分布式拒绝服务攻击
   * 计算SSDP包的个数 ——> 可能为SSDP反射放大攻击
   
   
   
