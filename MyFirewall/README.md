# 包过滤

用户基于数据包五元组{源地址、目的地址、协议、源端口、目的端口}自定义过滤规则，支持联合过滤。

Users can customize filtering rules based on the tuple of data packets {source address, destination address, protocol, source port, destination port}, which support joint filtering.

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

## Result

可以使用wireshark抓取交换机出端口和入端口数据包，或者对比tump1、tump2文件得到实验结果，查看流表过滤规则下的数据包是否丢弃。

You can use wireshark to capture the data packets of the ingress and egress of the switch, or compare 'tump1' and 'tump2' files to get the experimental results. Check whether the data packets under the filtering rules of the flow table are discarded.

