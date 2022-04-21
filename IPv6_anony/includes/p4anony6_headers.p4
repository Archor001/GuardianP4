#include <core.p4>
#include <v1model.p4>


#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x086dd
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/************ HEADERS ************/

typedef bit<24> srcAddr_oui_t;
typedef bit<24> srcAddr_id_t;
typedef bit<24> dstAddr_oui_t;
typedef bit<24> dstAddr_id_t;

header ethernet_t { 
    dstAddr_oui_t dstAddr_oui;
    dstAddr_id_t  dstAddr_id;
    srcAddr_oui_t srcAddr_oui;
    srcAddr_id_t  srcAddr_id;
    bit<16> etherType;
}

header vlan_tag_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> etherType;
}

header ipv6_t {
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHeader;
    bit<8> hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> hdr_length;
    bit<16> checksum;
}


