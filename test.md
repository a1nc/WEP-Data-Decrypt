# **WEP & MAC**

> **目录**
>>1. 安装libpcap
>>2. 安装aircrak-ng
>>3. 安装wireshark
>>4. 802.11管理帧格式
>>5. WEP加密原理
>>6. WEP中RC4加密算法
>>7. WEP中CRC32校验
>>8. 抓取包并分析

---

**运行环境**：<br>
操作系统:Ubuntu 16.04 64<br>
无线网卡:Netgear NETGEAR wg111 v2 RTL8187<br>

---
### **1.安装[libpcap](http://www.tcpdump.org)**

libpcap是unix/linux平台下的网络数据包捕获函数包，大多数网络监控软件都以它为基础。Windows平台对应的为winpcap<br>
安装libpcap后，我们可以自己写一个网络嗅探器。

> [<<libpcap使用>> CSDN BLOG](http://blog.csdn.net/htttw/article/details/7521053) 
[更详细的介绍及C语言例程]

``` shell
    $ wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
    $ tar xzvf libpcap-1.8.1.tar.gz
    $ cd libpcap-1.8.1
    $ ./configure
    $ make
    $ sudo make install

# 如果执行 ./configure 报错：
# configure: error: Neither flex nor lex was found.
# configure: error: yacc is insufficient to compile libpcap.
# 执行 $ sudo apt-get install flex bison 继续操作 

```

### **2.安装[aircrack-ng](http://www.aircrack-ng.org/)**

aircrack-ng是一套完整的跨平台WiFI网络安全评估工具，能够进行
监控网络数据包、网络攻击、
测试和破解WEP与WPA-PSK加密等。<br>
套件中包含:

* airodump-ng 用于捕获破解WEP密钥的802.11帧
* aircrack-ng 用于破解基于802.11协议的WEP以及WPA-PSK密钥
* aireplay-ng 用于强行向目标AP发送数据包
* airmon-ng 用于为整个套件配置一个网卡，开启无线网卡的monitor mode
* airbase-ng 用于建立Soft AP

我们需要使用其中的airmon-ng、airbase-ng两个工具
>[如何使用 Airbase-ng](http://www.aircrack-ng.org/doku.php?id=airbase-ng)

``` shell
    $ sudo apt-get install aircrack-ng
```

### **3.安装[wireshark](https://www.wireshark.org/)**
Wireshark（前称Ethereal）是一款跨平台的网络封包分析软件。网络
封包分析软件的功能是抓取网络封包，并尽可能显示出最为详细的网络
封包资料。在分析802.11无线数据格式及编写相关程序时需要利用到
wireshark软件

``` shell
    $ sudo apt-get install wireshark

#在使用wireshark抓包时建议使用 sudo wireshark
```

### **4. 802.11管理帧格式**

> 推荐书目 
>   *  《深入理解Android:Wi-Fi、NFC和GPS卷》(邓凡平,机械工业出版社)<br>
        [管理帧格式部分教程](http://book.2cto.com/201405/43270.html)
>   *  《802.11无线网络权威指南(第二版)》(Matthew S.Gast,O’Reilly)




