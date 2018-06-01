
简介
------
该工具可以分析PCAP包并发现一些攻击包的特征。可以打印并储存详细的 icmp / tcp / udp 协议报文 (https://github.com/tanjiti/packet_analysis)

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

* [GeoIP](https://github.com/maxmind/geoip-api-python)  
`sudo pip install GeoIP`  

* [pyecharts](http://pyecharts.org/#/zh-cn/)  
`sudo pip install pyecharts`  
另需安装地图文件包：  
`pip install echarts-countries-pypkg`  
`pip install echarts-china-provinces-pypkg`  
`pip install echarts-china-cities-pypkg`  
`pip install echarts-china-counties-pypkg`  
`pip install echarts-china-misc-pypkg`  

#### MacOS (10.13.2 High Sierra)
* [pynids](https://jon.oberheide.org/pynids/)  
`brew install libnids`

* [dpkt](http://dpkt.readthedocs.io/en/latest/)    
`pip install dpkt`

* [requests](http://www.python-requests.org/en/master/)  
`pip install requests`

* [GeoIP](https://github.com/maxmind/geoip-api-python)  
`pip install GeoIP`

* [pyecharts](http://pyecharts.org/#/zh-cn/)  
`pip install pyecharts`  
另需安装地图文件包：  
`pip install echarts-countries-pypkg`  
`pip install echarts-china-provinces-pypkg`  
`pip install echarts-china-cities-pypkg`  
`pip install echarts-china-counties-pypkg`  
`pip install echarts-china-misc-pypkg`  

使用
------
* 读取PCAP数据包，打印报文分析结果  
`python2 parseFile.py --pcapfile=FILE_NAME`  
* 其他选项：  
    * `--printResult`: 打印详细的报文信息到标准输出，默认为0（不打印）  
    * `--storeResult`: 保存详细的报文信息到文件，默认为1（保存），保存路径为"原PCAP文件名_result.txt"  
    * `--maxIP`: 指定结果中打印的最频繁出现的IP源/目的地址与端口的个数，默认值为5  
    * `--assetip`: 仅分析该指定目的IP的报文信息  
    * `--assetport`: 仅分析该指定目的端口的报文信息  
    * `--graphIP`: 指定IP地址来源图的保存路径，源IP地址的图会储存在“路径_source.html”，目标IP地址图会储存在“路径_destination.html”。默认地址为“outGraph_source.html”及“outGraph_destination.html”。如果不想打印图，指定此项选项为“None”

 
功能
------
* 分析IP地址与端口。
   * 找出出现频率最高的源地址与端口，及具体出现频率
   * 找出仅发送了很少包的源IP地址（默认为仅发送两个或更少包的源IP地址，可通过修改“THRESHOLD”值自行定义）
   * 找出出现频率最高的目的地址与端口，及具体出现频率
   * 分别分析不同的源IP地址与目的IP地址的数量
   * 分析统计源IP地址与目的IP地址所在城市  
   （使用了GeoIP及[GeoLite City](http://geolite.maxmind.com/download/geoip/database/LICENSE.txt)数据库进行分析，最新版本的数据库可[在此](https://dev.maxmind.com/geoip/legacy/geolite/)进行更新。当前使用的数据库为2018年三月更新的版本。）  
   `This product includes GeoLite data created by MaxMind, available from [http://www.maxmind.com]`
   * 将源IP地址及目标IP地址所在城市分别画图以便可视化分析，具体设定见使用中`--graphIP`选项，用浏览器即可打开见如下图可交互界面。默认剔除收发包少于或等于“THRESHOLD”值的IP地址以加强表现（此值默认为2，见上）
   ![Image](/images/IPGeoGraph.png "源IP地址分析地图")
   同时用户也可以通过更改代码中`geo.add()`函数中`maptype`参数自行更改想要显示的地图种类（范围），详情见[pyecharts官网](http://pyecharts.org/#/zh-cn/charts?id=geo%EF%BC%88%E5%9C%B0%E7%90%86%E5%9D%90%E6%A0%87%E7%B3%BB%EF%BC%89)中对该部分的说明，请确保下载对应的地图包。例如下图是使用同样的数据组，源地址使用`maptype="world"`，目标地址使用`maptype=u"成都"`画图得到的结果。
   ![Image](/images/IPGeoGraph_2.png "源IP地址分析地图")
   
* 分析具体的包文信息
   * 分析TCP包与UDP包的个数
   * 计算TCP包中SYN flag包（不含ACK flag的包）的个数 ——> 可能为SYN flood攻击
   * 计算UDP包中monlist请求的个数 ——> 可能为NTP monlist指令反射型分布式拒绝服务攻击
   * 计算SSDP包的个数 ——> 可能为SSDP反射放大攻击
   
   
   
   
   
