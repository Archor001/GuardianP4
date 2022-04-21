# GuardianP4
## Introduction

根据P4 Tutorial所学，设计了几个基础P4app，主要负责流量管理和流量匿名化，具体功能有IPv4匿名、IPv6匿名、包过滤防火墙和连接控制这四项。

According to the P4 Tutorial, I designed several basic P4apps, which are mainly responsible for traffic management and traffic anonymization. The specific functions include IPv4 anonymity, IPv6 anonymity, packet filtering firewall and connection control.

## Run

You can almost use this command to do the test:

```
sudo make run
mininet> xterm h1 h2
```

in h1's host:

```
tcpreplay -i eth0 
```

in h2's host:

```
tcpdump -i eth0 -nnnne 
```



## Result

可以使用wireshark抓取交换机出端口和入端口数据包

You can use wireshark to capture the data packets of the ingress and egress of the switch.

