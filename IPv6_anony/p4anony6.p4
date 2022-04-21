#include "includes/p4anony6_headers.p4"

typedef bit<9>  egressSpec_t;
typedef bit<1> match_t;

struct headers { 
    ethernet_t       ethernet;
    vlan_tag_t       vlan;
    ipv6_t           ipv6;
    tcp_t            tcp;
    udp_t            udp;
}

struct metadata {
    bit<4> is_ipv6;
    bit<4> hashed_mac_srcAddr_oui;
    bit<4> hashed_mac_srcAddr_id;
    bit<4> hashed_mac_dstAddr_oui;
    bit<4> hashed_mac_dstAddr_id;
    dstAddr_oui_t dst_mac_mc_oui;
    srcAddr_oui_t src_mac_oui;
    srcAddr_id_t src_mac_id;
    dstAddr_oui_t dst_mac_oui;
    dstAddr_id_t dst_mac_id;
    bit<128> ipv6_srcip;
    bit<128> ipv6_dstip;
    
    bit<128> srcip_prefix_part;
    bit<128> srcip_hash_part;
    bit<128> srcip_hash_part1;
    bit<128> srcip_hash_part2;
    bit<128> dstip_prefix_part;
    bit<128> dstip_hash_part;
    bit<128> dstip_hash_part1;
    bit<128> dstip_hash_part2;

    bit<1> srcip_matched;
    bit<1> dstip_matched;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser AnonyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.src_mac_oui = hdr.ethernet.srcAddr_oui;
        meta.src_mac_id = hdr.ethernet.srcAddr_id;
        meta.dst_mac_oui = hdr.ethernet.dstAddr_oui;
        meta.dst_mac_id = hdr.ethernet.dstAddr_id;

        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV6 : parse_ipv6;
            default: accept;
        }
    }
    
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.is_ipv6 = (bit<4>) 1;
        meta.ipv6_srcip = hdr.ipv6.srcAddr;
        meta.ipv6_dstip = hdr.ipv6.dstAddr;
        meta.srcip_prefix_part = hdr.ipv6.srcAddr & 128w0xffffffffffffffff0000000000000000;
        meta.dstip_prefix_part = hdr.ipv6.dstAddr & 128w0xffffffffffffffff0000000000000000;
        meta.srcip_hash_part = hdr.ipv6.srcAddr & 128w0xffffffffffffffff;
        meta.dstip_hash_part = hdr.ipv6.dstAddr & 128w0xffffffffffffffff;
        
    
        transition select(hdr.ipv6.nextHeader) {
            IPPROTO_TCP : parse_tcp;
            IPPROTO_UDP : parse_udp;
            default: accept;
        }
    }
    
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV6 : parse_ipv6;
            default: accept;
        }
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

control AnonyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control AnonyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /************ ACTIONS ************/
    
    /* Set output port */
    action set_egr_action(egressSpec_t egress_spec) {
        standard_metadata.egress_spec = egress_spec;
    }
    
    action nop_action() {
    }
    
    action _drop_action() {
        mark_to_drop(standard_metadata);
    }
    
    action multicast_mac_catch_action() {
        meta.dst_mac_mc_oui = hdr.ethernet.dstAddr_oui & 0x110000;
    }

    action hash_mac_src_id_action() {
        hash(hdr.ethernet.srcAddr_id, HashAlgorithm.crc32, 32w0, {meta.src_mac_id}, 32w16777215);
        meta.hashed_mac_srcAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_src_oui_action() {
        hash(hdr.ethernet.srcAddr_oui, HashAlgorithm.crc32, 32w0, {meta.src_mac_oui}, 32w24);
        meta.hashed_mac_srcAddr_oui = (bit<4>) 1;
    }
    
    action hash_mac_dst_id_action() {
        hash(hdr.ethernet.dstAddr_id, HashAlgorithm.crc32, 32w0, {meta.dst_mac_id}, 32w16777215);
        meta.hashed_mac_dstAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_dst_oui_action() {
        hash(hdr.ethernet.dstAddr_oui, HashAlgorithm.crc32, 32w0, {meta.dst_mac_oui}, 32w24);
        meta.hashed_mac_dstAddr_oui = (bit<4>) 1;
    }
    
    action prepare_srcip_hash_action(match_t srcip_matched){
        meta.srcip_matched=srcip_matched;
    }

    action prepare_dstip_hash_action(match_t dstip_matched){
        meta.dstip_matched=dstip_matched;
    }


    action hash_and_modify_src_action() { 
        hash(meta.srcip_hash_part1, HashAlgorithm.crc32, 32w0, {meta.srcip_hash_part}, 32w0xffffffff);
        hash(meta.srcip_hash_part2, HashAlgorithm.crc32, 32w0, {(meta.srcip_hash_part1<<8w32) | meta.srcip_hash_part1}, 32w0xffffffff);
        meta.srcip_hash_part = (meta.srcip_hash_part1<<8w32) | meta.srcip_hash_part2;
    }
    action hash_and_modify_dst_action() { 
        hash(meta.dstip_hash_part1, HashAlgorithm.crc32, 32w0, {meta.dstip_hash_part}, 32w0xffffffff);
        hash(meta.dstip_hash_part2, HashAlgorithm.crc32, 32w0, {(meta.dstip_hash_part1<<8w32) | meta.dstip_hash_part1}, 32w0xffffffff);
        meta.dstip_hash_part = (meta.dstip_hash_part1<<8w32) | meta.dstip_hash_part2;
    }
    
    action ip_overwrite_action() { 
        hdr.ipv6.srcAddr = meta.srcip_prefix_part | meta.srcip_hash_part;
        hdr.ipv6.dstAddr = meta.dstip_prefix_part | meta.dstip_hash_part;

    }
    


    /************ CONTROL ************/
    table anony_mac_src_id_tb {
        key =  {
            standard_metadata.ingress_port : exact;
        }
        actions  = {
            hash_mac_src_id_action;
            nop_action;
        }
    }
    
    table anony_mac_src_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions =  {
            hash_mac_src_oui_action;
            nop_action;
        }
    }

    
    table anony_mac_dst_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_mac_dst_id_action;
            nop_action;
        }
    }
    
    table anony_mac_dst_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions =  {
            hash_mac_dst_oui_action;
            nop_action;
        }
    }
    
    
    table anony_srcip_tb {
        key = {
            meta.ipv6_srcip : ternary;
        }
        actions =  {
            prepare_srcip_hash_action;
            nop_action;
        }
    }
    
    table anony_dstip_tb {
        key = {
            meta.ipv6_dstip : ternary;
        }
    
        actions = {
            prepare_dstip_hash_action;
            nop_action;
        }
    }
    
    table hashing_src_tb {
        key = {
             standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_src_action;
            nop_action;
        }
    }

    table hashing_dst_tb {
        key =  {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_dst_action;
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
    
    table multicast_mac_catch_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            multicast_mac_catch_action;
        }
    }

    
    table ipv6_ip_overwite_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            ip_overwrite_action;
        }
    }
    
    apply {
        // Needed for catching multicast packets
        //  based on DST MAC address (starts with 01:xx:xx:xx:xx:xx)
        multicast_mac_catch_tb.apply();

        // Anonymize SRC MAC
        anony_mac_src_oui_tb.apply();
        anony_mac_src_id_tb.apply();

        // Only anonymize if DST MAC indicates
        //  that it's not a broadcast or multicast packet.
        if (hdr.ethernet.dstAddr_oui!=0xffffff) {
            if (hdr.ethernet.dstAddr_id!=0xffffff) {
                if (meta.dst_mac_mc_oui!=0x010000) {
                    anony_mac_dst_oui_tb.apply();
                    anony_mac_dst_id_tb.apply();
                }
            }
        }

        // Anoymize IPv6 SRC address (prep step)
        anony_srcip_tb.apply();
        if(meta.srcip_matched==1){
            hashing_src_tb.apply();
        }
        

        // Anoymize IPv6 DST address (prep step)
        anony_dstip_tb.apply();
        if(meta.dstip_matched==1){
            hashing_dst_tb.apply();
        }
        

        // Actual IPv6 address anonymization step
        if (meta.is_ipv6 == 1) {
            ipv6_ip_overwite_tb.apply();
        }

        // Forward packet based on input_port
        forward_tb.apply();
    }
}


control AnonyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control AnonyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {}
}


/*************************************************************************
 * ***********************  D E P A R S E R  *******************************
 * *************************************************************************/

control AnonyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}



/*************************************************************************
 * ***********************  S W I T C H  *******************************
 * *************************************************************************/

V1Switch(
    AnonyParser(),
    AnonyVerifyChecksum(),
    AnonyIngress(),
    AnonyEgress(),
    AnonyComputeChecksum(),
    AnonyDeparser()
) main;