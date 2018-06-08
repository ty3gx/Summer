简介
######

[packet_analysis](https://github.com/ty3gx/Summer/tree/master/packet_analysis):  
------
包含Python工具用以分析PCAP包并发现一些攻击包的特征，进行IP地址分析与可视化绘图。可以打印并储存详细的 icmp / tcp / udp 协议报文。  
![Image](/images/IPGeoGraph.png "源IP地址分析地图")
![Image](/images/IPGeoGraph_2.png "源IP地址分析地图")

[protocols.md](https://github.com/ty3gx/Summer/blob/master/protocols.md):   
------
对于IP / IPv6 / UDP / TCP 协议报文格式的介绍，及报文格式的解析。

[DDoS.md](https://github.com/ty3gx/Summer/blob/master/DDoS.md): 
------
对于DDoS(Distributed Denial of Service)，分布式拒绝服务的完整介绍。包括对基于IP、TCP、HTTP、ICMP、SSL/TLS、UDP及DNS的多种DDoS/DoS攻击的详细介绍，以及对DDoS工具的分析。  

<table class="tg">
  <tr>
    <th class="tg-uys7">OSI层级</th>
    <th class="tg-uys7">攻击内容</th>
  </tr>
  <tr>
    <td class="tg-uys7" rowspan="11">基于网络 (数据链路层、网络层、传输层)的攻击</td>
    <td class="tg-uys7"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#ip%E7%A2%8E%E7%89%87%E6%94%BB%E5%87%BB">IP碎片攻击</a></td>
  </tr>
  <tr>
    <td class="tg-uys7"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#%E6%B3%AA%E6%BB%B4%E6%94%BB%E5%87%BB">泪滴攻击</a></td>
  </tr>
  <tr>
    <td class="tg-uys7"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#syn-flood-%E6%94%BB%E5%87%BB">SYN Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#syn-ack-flood-%E6%94%BB%E5%87%BB">其他TCP Flood攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#%E8%BF%9E%E6%8E%A5%E8%80%97%E5%B0%BD%E6%94%BB%E5%87%BB">连接耗尽攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#tcp%E5%BC%82%E5%B8%B8%E6%8A%A5%E6%96%87%E6%94%BB%E5%87%BB">TCP异常报文攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#tcp%E8%99%9A%E5%81%87%E4%BC%9A%E8%AF%9D%E6%94%BB%E5%87%BB">TCP虚假会话攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#land%E6%94%BB%E5%87%BB">LAND攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#icmp-flood-%E6%94%BB%E5%87%BB">ICMP Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#smurf%E6%94%BB%E5%87%BB">SMURF攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#%E6%AD%BB%E4%BA%A1%E4%B9%8Bping%E6%94%BB%E5%87%BB">死亡之Ping攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow" rowspan="4">基于DNS（传输层）的攻击</td>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#udp-flood-%E6%94%BB%E5%87%BB">UDP Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#udp%E5%88%86%E7%89%87%E6%94%BB%E5%87%BB">UDP分片攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#ntp%E5%8F%8D%E5%B0%84%E6%94%BE%E5%A4%A7%E6%94%BB%E5%87%BB">反射放大攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#dns%E6%94%BB%E5%87%BB">DNS攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow" rowspan="3">基于SSL/TLS协议（会话层及表示层）的攻击</td>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#ssl-flood-%E6%94%BB%E5%87%BB">SSL Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#https-flood-%E6%94%BB%E5%87%BB">HTTPS Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#thc-ssl-dos%E6%94%BB%E5%87%BB">THC-SSL-DoS攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow" rowspan="6">基于应用（表示层及应用层）的攻击</td>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#http-getpost-flood-%E6%94%BB%E5%87%BB">HTTP Get/Post Flood 攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#http%E6%85%A2%E9%80%9F%E6%94%BB%E5%87%BB">HTTP慢速攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#hash%E7%A2%B0%E6%92%9E%E6%94%BB%E5%87%BB">Hash碰撞攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#apache-%E6%9D%80%E6%89%8B%E6%94%BB%E5%87%BB">Apache 杀手攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#refref%E6%94%BB%E5%87%BB">RefRef攻击</a></td>
  </tr>
  <tr>
    <td class="tg-c3ow"><a href="https://github.com/ty3gx/Summer/edit/master/DDoS.md#xml-bomb-%E6%94%BB%E5%87%BB">XML Bomb 攻击</a></td>
  </tr>
</table>
