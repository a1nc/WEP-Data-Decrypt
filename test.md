# **WEPandMAC**

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
### **安装libpcap**

libpcap是unix/linux平台下的网络数据包捕获函数包，大多数网络监控软件都以它为基础。Windows平台对应的为winpcap<br>
安装libpcap后，我们可以自己写一个网络嗅探器。


1. 从http://www.tcpdump.org 下载 libpcap-1.8.1.tar.gz
``` shell
    $ tar xzvf libpcap-1.8.1.tar.gz
    $ cd libpcap
    $ ./configure
    $ make
    $ sudo make install
```

