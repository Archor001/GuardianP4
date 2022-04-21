#include "includes/firewall_headers.p4"

typedef bit<9>  egressSpec_t;
typedef bit<32> mask_t;
typedef bit<1> match_t;

struct headers { 
    ethernet_t       ethernet;
    vlan_tag_t       vlan;
    arp_rarp_t       arp;
    arp_rarp_ipv4_t  arp_ipv4;
    ipv4_t           ipv4;
    icmp_t           icmp;
    tcp_t            tcp;
    udp_t            udp;
}

struct metadata {
    bit<4> is_arp;
    bit<4> is_ipv4;
    bit<4> hashed_mac_srcAddr_oui;
    bit<4> hashed_mac_srcAddr_id;
    bit<4> hashed_mac_dstAddr_oui;
    bit<4> hashed_mac_dstAddr_id;
    dstAddr_oui_t dst_mac_mc_oui;
    srcAddr_oui_t src_mac_oui;
    srcAddr_id_t src_mac_id;
    dstAddr_oui_t dst_mac_oui;
    dstAddr_id_t dst_mac_id;
    bit<32> ipv4_srcip;
    bit<32> ipv4_dstip;
    bit<32> srcip_subnet_part;
    bit<32> srcip_hash_part;
    bit<32> dstip_subnet_part;
    bit<32> dstip_hash_part;
    bit<32> srcip_subnetmask;
    bit<32> dstip_subnetmask;
    bit<1> srcip_matched;
    bit<1> dstip_matched;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
    
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP: parse_icmp;
            IPPROTO_TCP : parse_tcp;
            IPPROTO_UDP : parse_udp;
            default: accept;
        }
    }
    
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.protoType) {
            ETHERTYPE_IPV4 : parse_arp_rarp_ipv4;
            default : accept;
        }
    }
    
    state parse_arp_rarp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        transition accept;
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /************ ACTIONS ************/
    
    /* Set output port */
    action set_egr_action(egressSpec_t egress_spec) {
        standard_metadata.egress_spec = egress_spec;
    }
    
    action nop_action() {
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    table filtering_tcp_tb {
        key = {
            hdr.ipv4.srcAddr : ternary;
            hdr.ipv4.dstAddr : ternary;
            hdr.ipv4.protocol: exact;
            hdr.tcp.srcPort  : range;
            hdr.tcp.dstPort  : range;
        }
        actions = {
            drop;
            nop_action;
        }
    }

    table filtering_udp_tb {
        key = {
            hdr.ipv4.srcAddr : ternary;
            hdr.ipv4.dstAddr : ternary;
            hdr.ipv4.protocol: exact;
            hdr.tcp.srcPort  : range;
            hdr.tcp.dstPort  : range;
        }
        actions = {
            drop;
            nop_action;
        }
    }

    table filtering_icmp_tb {
        key = {
            hdr.ipv4.srcAddr : ternary;
            hdr.ipv4.dstAddr : ternary;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            drop;
            nop_action;
        }
    }
    
    table forward_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_egr_action;
            nop_action;
        }
    }
    
    apply {
        forward_tb.apply();
        filtering_tcp_tb.apply();
        filtering_udp_tb.apply();
        filtering_icmp_tb.apply();
    }
}


control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	    update_checksum(
	    hdr.ipv4.isValid(),
        {     hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}


/*************************************************************************
 * ***********************  D E P A R S E R  *******************************
 * *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}



/*************************************************************************
 * ***********************  S W I T C H  *******************************
 * *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;