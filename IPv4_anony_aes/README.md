# IPv4匿名

保留IP地址网络号，AES分组加密算法混淆主机号，bmv2交换机流表上采用ternary三元匹配，放行某子网下的流量同时进行匿名处理。

> AES密钥通过非对称加密方法发给接收方，不是本P4app的主要关注内容。

IP network address is reserved, while IP host address is anonymized by AES encryption algorithm. Using ternary match on the bmv2 switch flow tables to release the traffic under a certain subnet and perform anonymous processing at the same time. The AES key is sent to the receiver through asymmetric encryption, which is not the main concern of this P4app.

## Run

```
sudo make run
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

## 

## Result

可以使用wireshark抓取交换机出端口和入端口数据包，或者对比tump1、tump2文件得到实验结果，观察流表设置的子网下流量是否被匿名。

You can use wireshark to capture the data packets of the  ingress and egress of the switch, or compare 'tump1' and 'tump2' files  to get the experimental results. Observe whether the traffic under the subnet which is set in the flow table is anonymized

