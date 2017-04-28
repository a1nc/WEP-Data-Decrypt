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

### **5. WEP加密原理**

> [《How 802.11 Wireless Works》](https://technet.microsoft.com/en-us/library/cc757419(v=ws.10).aspx)
[一篇非常详细地解释了802.11无线网络工作原理的文章，涉及到WEP的加密解密介绍]

*基础的密码学*
```
    一串随机的文本[RandomText] xor 等长的明文[PlainText] ==> 密文[CipherText]
    同一串随机的文本[RandomText] xor 密文[CipherText] ==> 明文[PlainText]

    eg:
        01100011 ^ 01010101 = 00110110
        01100011 ^ 00110110 = 01010101
```

在802.11 无线网络中，WEP加密最重要的一点就是利用了该原理，但是其漏洞也是因为RandomText的生成
并不能保证一直不重复，并且采用的是伪随机方式生成。

5.1 **WEP密码设定**:<br>

支持WEP加密的设备通常支持多种长度的密钥，常见的有64bit,伪128bit,128bit甚至256bit。<br>
不过，本项目中我们采用的为airbase-ng 创建共享密钥方式下(shared key mode)默认的64位密钥。<br>

![WepWorkImg](https://github.com/a1nc/WEP-Data-Decrypt/raw/master/WepWork.png)

**注意**:<br>
* 1 当我们在此模式下设置密码时,比如设定密钥为:1112223334
    则对应的64位"WEP seed"为:
    >    *24bit IV(初始化向量) + 0x11 + 0x12 + 0x22 + 0x33 + 0x34*<br>
    >    IV(24bit)+0001 0001 0001 0010 0010 0010 0011 0011 0011 0100

* 2 WEP seed 通过RC4算法计算得出RC4 Key
    >   <1>. RC4 key 的产生过程则是WEP加密中伪随机数产生器工作的过程<br>
    >   <2>. 由于 IV 由AP产生，并且不同的厂家生成方式不一致，但是IV仅有24bit，在复杂并且流量大的网络环境下很容易在短时间内使用重复的
    IV进行生成WEP seed

* 3 Payload为要发送的数据，Payload与Header共同经过CRC32循环校验得到32bit ICV 
    >   Payload + ICV 用RC4加密算法进行加密处理


### **6. [WEP中RC4加密算法](https://zh.wikipedia.org/wiki/RC4)**

> RC4（来自Rivest Cipher 4的缩写）是一种流加密算法，密钥长度可变。它加解密使用相同的密钥，因此也属于对称加密算法。
RC4是有线等效加密（WEP）中采用的加密算法，也曾经是TLS可采用的算法之一。 ——[wikipedia](https://zh.wikipedia.org/wiki/RC4)

本项目中采用的RC4加密算法使用的一份[开源的代码](http://ju.outofmemory.cn/entry/152076)，需要注意的是在有的平台上面RC4代码中的**char**型数据需要更改为**unsigned char**

### **7. [WEP中CRC32校验](https://zh.wikipedia.org/wiki/%E5%BE%AA%E7%92%B0%E5%86%97%E9%A4%98%E6%A0%A1%E9%A9%97)**
> 循环冗余校验（英语：Cyclic redundancy check，通称“CRC”）是一种根据网络数据包或电脑文件等数据产生简短
固定位数校验码的一种散列函數，主要用来检测或校验数据传输或者保存后可能出现的错误。生成的数字在传输或者存
储之前计算出来并且附加到数据后面，然后接收方进行检验确定数据是否发生变化。一般来说，循环冗余校验的值都是32位的整数。
——[wikipedia](https://zh.wikipedia.org/wiki/%E5%BE%AA%E7%92%B0%E5%86%97%E9%A4%98%E6%A0%A1%E9%A9%97)

本项目中采用的CRC32校验程序使用的一份[开源的代码](https://www.oschina.net/code/snippet_1178986_50118)。

**注意**:
 * 1 在WEP中CRC计算的是Payload+ICV<br>
    eg:在WEP共享密钥认证方式(shared key mode)的过程中会向客户端发送一份ChallengeText(假设为128位明文)。<br>
      ``` 
             Payload (140bytes)= header (8bytes) + ChallengeText (128bytes) + ICV[CRC32] (4bytes)
      ```<br>
      此140Bytes数据将会被RC4加密算法进行加密，而密钥则是64bit WEP seed 产生的RC4 key。<br>
      最后，该数据包将发给AP进行验证。
    
 * 2 当AP收到发来的数据包时，会将数据包中明文的IV与自己存储的Key结合作为WEP seed 对140bytes 的数据进行解密<br>
    解密之后有 140bytes 数据，仅需要对1-136bytes 的数据进行循环校验，得出的校验值与 137-140bytes 的ICV进行对比，若相同，则该数据包是正确的。

 * 3 正因为如此，我们可以利用验证的这个过程，额外的传递一些信息。





