# 连接控制

## Introduction

连接控制可以抽象理解为：子网内部主机可以相互访问，子网A主机可以访问子网B主机，子网B主机可以访问子网A主机当且仅当子网A向子网B建立起了连接。
link_control can be abstractly understood as: hosts inside the subnet can access each other, hosts on subnet A can access hosts on subnet B, and hosts on subnet B can access hosts on subnet A if and only when subnet A establishes a connection to subnet B.

使用布隆过滤器完成，视网络流量情况修改过滤器长度和哈希函数个数
Using Bloom filter to fulfil that proposal, Modify bloom_filter's length and the number of hash functions according to network traffic conditions

## Run

```
sudo make run
```

```
mininet> xterm h1 h2
```

in h1's host:

```
tcpreplay -i eth0 -L 500 ./data/smallFlows.pcap
```

in h2's host:

```
tcpdump -i eth0 -nnnne > tdump1
tcpdump -r ./data/smallFlow.pcap -c 500 -nnne > tdump
```

## Result

可以使用wireshark抓取交换机出端口和入端口数据包，或者对比tump1、tump2文件得到实验结果，通过查看外网向内网发送的数据包是否被丢弃来判断连接控制是否成功。

You can use wireshark to capture the data packets of the ingress and egress of the switch, or compare 'tump1' and 'tump2' files to get the experimental results. You can judge whether the connection control is successful by checking whether the data packets sent from the external network to the internal network are discarded.