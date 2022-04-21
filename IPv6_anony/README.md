# IPv6匿名

保留前64位IPv6网络地址，哈希混淆后64位EUI-64接口ID。

> 需要在convert.py中添加ipv6正则匹配和ipv6地址二进制转换

IP network address（the most significant 64bits） is reserved, while EUI-64 address (the least significant 64bits) is anonymized by hash algorithm.

Notes: you need to add ipv6 regular matching and ipv6_encode in convert.py

## Run

```
sudo make run
mininet> xterm h1 h2
```

in h1's host:

```
tcpreplay -i eth0 -L 500 ./data/ipv6Flows.pcap
```

in h2's host:

```
tcpdump -i eth0 -nnnne > tdump1
tcpdump -r ./data/smallFlow.pcap -c 500 -nnne > tdump
```

## 

## Result

可以使用wireshark抓取交换机出端口和入端口数据包，或者对比tump1、tump2文件得到实验结果，观察流表指定的IPv6流量是否被匿名。

You can use wireshark to capture the data packets of the  ingress and egress of the switch, or compare 'tump1' and 'tump2' files  to get the experimental results.

