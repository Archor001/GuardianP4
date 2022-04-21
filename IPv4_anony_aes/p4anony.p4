#include "includes/p4anony_headers.p4"    
#define LUT(FN) {0:FN(0xe0); 1:FN(0x01); 2:FN(0xb5); 3:FN(0x91); 4:FN(0xb3); 5:FN(0x65); 6:FN(0x24); 7:FN(0x56); 8:FN(0xfd); 9:FN(0xa7); 10:FN(0xdd); 11:FN(0xf2); 12:FN(0x20); 13:FN(0x44); 14:FN(0x52); 15:FN(0x8f); 16:FN(0x92); 17:FN(0xd0); 18:FN(0x97); 19:FN(0x11); 20:FN(0x08); 21:FN(0x2f); 22:FN(0xa0); 23:FN(0x22); 24:FN(0x68); 25:FN(0x07); 26:FN(0x6e); 27:FN(0x5e); 28:FN(0xbb); 29:FN(0x73); 30:FN(0x87); 31:FN(0xaa); 32:FN(0xac); 33:FN(0x7e); 34:FN(0x71); 35:FN(0xe6); 36:FN(0x7b); 37:FN(0xa3); 38:FN(0xef); 39:FN(0x10); 40:FN(0xf1); 41:FN(0xd9); 42:FN(0x0e); 43:FN(0x9d); 44:FN(0x18); 45:FN(0x47); 46:FN(0xae); 47:FN(0x58); 48:FN(0xab); 49:FN(0x48); 50:FN(0x84); 51:FN(0x21); 52:FN(0x15); 53:FN(0xb6); 54:FN(0x29); 55:FN(0x9f); 56:FN(0xdf); 57:FN(0xf8); 58:FN(0xad); 59:FN(0xb1); 60:FN(0xf7); 61:FN(0xe8); 62:FN(0xc2); 63:FN(0xd1); 64:FN(0x05); 65:FN(0x12); 66:FN(0xf4); 67:FN(0x6a); 68:FN(0xfc); 69:FN(0xc3); 70:FN(0x4a); 71:FN(0x7d); 72:FN(0x77); 73:FN(0x6f); 74:FN(0x5c); 75:FN(0x8d); 76:FN(0x8a); 77:FN(0xa2); 78:FN(0xe5); 79:FN(0xf0); 80:FN(0xfb); 81:FN(0xd5); 82:FN(0x3e); 83:FN(0xc5); 84:FN(0x09); 85:FN(0xaf); 86:FN(0x7f); 87:FN(0xd8); 88:FN(0x8c); 89:FN(0x4f); 90:FN(0xb0); 91:FN(0x3c); 92:FN(0x81); 93:FN(0xd4); 94:FN(0x99); 95:FN(0x43); 96:FN(0x1a); 97:FN(0x1e); 98:FN(0xa4); 99:FN(0xcd); 100:FN(0xcc); 101:FN(0xe7); 102:FN(0xe4); 103:FN(0xee); 104:FN(0x61); 105:FN(0xd2); 106:FN(0x32); 107:FN(0x89); 108:FN(0xda); 109:FN(0xbf); 110:FN(0x06); 111:FN(0xcb); 112:FN(0x02); 113:FN(0x5f); 114:FN(0xc7); 115:FN(0x9c); 116:FN(0x1b); 117:FN(0x04); 118:FN(0x25); 119:FN(0x98); 120:FN(0x59); 121:FN(0x62); 122:FN(0x3d); 123:FN(0x19); 124:FN(0xfa); 125:FN(0x0f); 126:FN(0xc4); 127:FN(0xc6); 128:FN(0x2a); 129:FN(0x4b); 130:FN(0x00); 131:FN(0x50); 132:FN(0xea); 133:FN(0x60); 134:FN(0x4e); 135:FN(0xf5); 136:FN(0xb4); 137:FN(0xde); 138:FN(0x9a); 139:FN(0x45); 140:FN(0x13); 141:FN(0x26); 142:FN(0xc9); 143:FN(0x33); 144:FN(0x41); 145:FN(0x31); 146:FN(0x85); 147:FN(0x28); 148:FN(0xcf); 149:FN(0x93); 150:FN(0xf3); 151:FN(0x67); 152:FN(0x9b); 153:FN(0x83); 154:FN(0xd6); 155:FN(0x69); 156:FN(0x75); 157:FN(0xb2); 158:FN(0x0c); 159:FN(0xec); 160:FN(0x16); 161:FN(0x63); 162:FN(0x51); 163:FN(0xe9); 164:FN(0xf6); 165:FN(0x2d); 166:FN(0xce); 167:FN(0xa5); 168:FN(0xba); 169:FN(0xa6); 170:FN(0x34); 171:FN(0xd7); 172:FN(0xbc); 173:FN(0xc1); 174:FN(0x53); 175:FN(0x3b); 176:FN(0xeb); 177:FN(0x7a); 178:FN(0x5d); 179:FN(0x66); 180:FN(0x1d); 181:FN(0x38); 182:FN(0xa8); 183:FN(0x5b); 184:FN(0x35); 185:FN(0x6b); 186:FN(0x1c); 187:FN(0x78); 188:FN(0x80); 189:FN(0x2c); 190:FN(0x76); 191:FN(0x54); 192:FN(0x8b); 193:FN(0x55); 194:FN(0x42); 195:FN(0x49); 196:FN(0xd3); 197:FN(0x94); 198:FN(0x64); 199:FN(0x79); 200:FN(0xb9); 201:FN(0x2e); 202:FN(0xf9); 203:FN(0x2b); 204:FN(0x1f); 205:FN(0xbe); 206:FN(0xfe); 207:FN(0xb8); 208:FN(0x36); 209:FN(0x6c); 210:FN(0x7c); 211:FN(0x23); 212:FN(0xed); 213:FN(0x27); 214:FN(0x95); 215:FN(0x14); 216:FN(0xbd); 217:FN(0xa1); 218:FN(0x0a); 219:FN(0x03); 220:FN(0xa9); 221:FN(0x90); 222:FN(0xc0); 223:FN(0xca); 224:FN(0x9e); 225:FN(0x57); 226:FN(0x3a); 227:FN(0x72); 228:FN(0x82); 229:FN(0x37); 230:FN(0xe2); 231:FN(0x74); 232:FN(0x86); 233:FN(0xdb); 234:FN(0x3f); 235:FN(0x30); 236:FN(0xb7); 237:FN(0x0d); 238:FN(0x5a); 239:FN(0xc8); 240:FN(0x40); 241:FN(0xdc); 242:FN(0x8e); 243:FN(0x0b); 244:FN(0x17); 245:FN(0x70); 246:FN(0x39); 247:FN(0xe3); 248:FN(0x4d); 249:FN(0x6d); 250:FN(0xff); 251:FN(0x96); 252:FN(0x4c); 253:FN(0x88); 254:FN(0x46); 255:FN(0xe1); }
#define c0 32w33751297   //02 03 01 01
#define c1 32w16909057   //01 02 03 01
#define c2 32w16843267   //01 01 02 03
#define c3 32w50397442   //03 01 01 02

typedef bit<9>  egressSpec_t;
typedef bit<32> mask_t;

struct headers { 
    ethernet_t       ethernet;
    vlan_tag_t       vlan;
    arp_rarp_t       arp;
    arp_rarp_ipv4_t  arp_ipv4;
    ipv4_t           ipv4;
    tcp_t            tcp;
    udp_t            udp;
}

header aes_meta_t{
    //每轮AES初始状态
    bit<32> r0;
    bit<32> r1;
    bit<32> r2;
    bit<32> r3;
    //每轮AES结束状态
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
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
    bit<32> dstip_subnet_part;
    bit<32> srcip_subnetmask;    //subnetmask是子网掩码的补，例如 10.0.1.0/24 的subnetmask=0xff 而不是0xffffff00
    bit<32> dstip_subnetmask;
    bit<128> srcip_aes_part;
    bit<128> dstip_aes_part;

    aes_meta_t aes;
    aes_meta_t save_aes;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser OntasParser(packet_in packet,
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
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.is_ipv4 = (bit<4>) 1;
        meta.ipv4_srcip = hdr.ipv4.srcAddr;
        meta.ipv4_dstip = hdr.ipv4.dstAddr;
        meta.srcip_subnet_part = hdr.ipv4.srcAddr;
        meta.dstip_subnet_part = hdr.ipv4.dstAddr;
    
        transition select(hdr.ipv4.protocol) {
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
        meta.is_arp = (bit<4>) 1;
        meta.ipv4_srcip = hdr.arp_ipv4.srcProtoAddr;
        meta.ipv4_dstip =  hdr.arp_ipv4.dstProtoAddr;
        meta.srcip_subnet_part = hdr.arp_ipv4.srcProtoAddr;
        meta.dstip_subnet_part = hdr.arp_ipv4.dstProtoAddr;
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

control OntasVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control OntasIngress(inout headers hdr,
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
    
    action hash_arp_mac_src_id_action() {
        hdr.arp_ipv4.srcHwAddr_id = hdr.ethernet.srcAddr_id;
    }
    
    action hash_arp_mac_src_oui_action() {
        hdr.arp_ipv4.srcHwAddr_oui = hdr.ethernet.srcAddr_oui;
    }
    
    action hash_mac_dst_id_action() {
        hash(hdr.ethernet.dstAddr_id, HashAlgorithm.crc32, 32w0, {meta.dst_mac_id}, 32w16777215);
        meta.hashed_mac_dstAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_dst_oui_action() {
        hash(hdr.ethernet.dstAddr_oui, HashAlgorithm.crc32, 32w0, {meta.dst_mac_oui}, 32w24);
        meta.hashed_mac_dstAddr_oui = (bit<4>) 1;
    }
    
    action hash_arp_mac_dst_id_action() {
        hdr.arp_ipv4.dstHwAddr_id = hdr.ethernet.dstAddr_id;
    }
    
    action hash_arp_mac_dst_oui_action() {
        hdr.arp_ipv4.dstHwAddr_oui = hdr.ethernet.dstAddr_oui;
    }
    


    action new_round() {
		meta.aes.t0=0;  meta.aes.t1=0;  meta.aes.t2=0;  meta.aes.t3=0;
	}

    //*******AES PADDING********
    action prepare_srcip_aes_action(mask_t mask1, mask_t mask2) {
        meta.srcip_subnet_part = meta.ipv4_srcip & mask1;
        meta.srcip_aes_part = (bit<128>)meta.ipv4_srcip & (bit<128>)mask2;

        meta.srcip_subnetmask =  mask2;
    }
    
    action prepare_dstip_aes_action(mask_t mask1,mask_t mask2) {
        meta.dstip_subnet_part = meta.ipv4_dstip & mask1;
        meta.dstip_aes_part = (bit<128>)meta.ipv4_dstip & (bit<128>)mask2;
    
        meta.dstip_subnetmask = mask2;
    }

    action read_cleartext(bit<128> plain){
        meta.aes.t0=plain[127:96];
        meta.aes.t1=plain[95:64];
        meta.aes.t2=plain[63:32];
        meta.aes.t3=plain[31:0];
    }

    //*******AES状态矩阵快照*******
    action save(){
        meta.save_aes=meta.aes;
    }

    //*******AES轮密钥加*******
    action mask_key(bit<128> maskKey){
        meta.aes.r0= meta.aes.t0^maskKey[127:96];
		meta.aes.r1= meta.aes.t1^maskKey[95:64];
		meta.aes.r2= meta.aes.t2^maskKey[63:32];
		meta.aes.r3= meta.aes.t3^maskKey[31:0];
    }

    //*******AES S盒代换*******
#define sbox_lut(T,SLICE,SLICE_BITS) action sbox_lut_##T##SLICE## (bit<8> value){\
        meta.aes.t##T##SLICE_BITS##=value;\
        }
    sbox_lut(0,0,[31:24])
    sbox_lut(0,1,[23:16])
    sbox_lut(0,2,[15:8])
    sbox_lut(0,3,[7:0])

    sbox_lut(1,0,[31:24])
    sbox_lut(1,1,[23:16])
    sbox_lut(1,2,[15:8])
    sbox_lut(1,3,[7:0])

    sbox_lut(2,0,[31:24])
    sbox_lut(2,1,[23:16])
    sbox_lut(2,2,[15:8])
    sbox_lut(2,3,[7:0])

    sbox_lut(3,0,[31:24])
    sbox_lut(3,1,[23:16])
    sbox_lut(3,2,[15:8])
    sbox_lut(3,3,[7:0])

    //*******行移位更新*******
#define row_shift(T,SLICE,SAVE_T,SAVE_SLICE,SLICE_BITS) action row_shift_##T##SLICE##_##SAVE_T##SAVE_SLICE## (){\
        meta.aes.t##T##SLICE_BITS##=meta.save_aes.t##SAVE_T##SLICE_BITS##;\
    }
    row_shift(0,0,0,0,[31:24])
    row_shift(0,1,1,1,[23:16])
    row_shift(0,2,2,2,[15:8])
    row_shift(0,3,3,3,[7:0])

    row_shift(1,0,1,0,[31:24])
    row_shift(1,1,2,1,[23:16])
    row_shift(1,2,3,2,[15:8])
    row_shift(1,3,0,3,[7:0])

    row_shift(2,0,2,0,[31:24])
    row_shift(2,1,3,1,[23:16])
    row_shift(2,2,0,2,[15:8])
    row_shift(2,3,1,3,[7:0])

    row_shift(3,0,3,0,[31:24])
    row_shift(3,1,0,1,[23:16])
    row_shift(3,2,1,2,[15:8])
    row_shift(3,3,2,3,[7:0])

    //*******列混合更新*******
#define column_mix(T,SLICE,SLICE_BITS) action column_mix_##T##SLICE## (bit<32> c){\
        bit<8> x0;\
        bit<8> x1;\
        bit<8> x2;\
        bit<8> x3;\
        bit<8> t_slice0=meta.aes.t##T##[31:24];\
        bit<8> t_slice1=meta.aes.t##T##[23:16];\
        bit<8> t_slice2=meta.aes.t##T##[15:8];\
        bit<8> t_slice3=meta.aes.t##T##[7:0];\
        if(c==c0){\
            x0=((t_slice0>>8w7) == 8w1) ? (((t_slice0 << 1) % 8w0xff) ^ 8w0x1b) : ((t_slice0 << 1) % 8w0xff);\
            x1=((t_slice1>>8w7) == 8w1) ? (((t_slice1<<1) % 8w0xff) ^ 8w0x1b ^ t_slice1) : (((t_slice1 << 1) % 8w0xff) ^ t_slice1);\
            x2=t_slice2;\
            x3=t_slice3;\
        }\
        if(c==c1){\
            x0=t_slice0;\
            x1=((t_slice1>>8w7) == 8w1) ? (((t_slice1<< 1 ) % 8w0xff) ^ 8w0x1b) : ((t_slice1 << 1) %8w0xff);\
            x2=((t_slice2>>8w7) == 8w1) ? (((t_slice2<<1) % 8w0xff) ^ 8w0x1b ^ t_slice2) : (((t_slice2 << 1) % 8w0xff) ^ t_slice2);\
            x3=t_slice3;\
        }\
        if(c==c2){\
            x0=t_slice0;\
            x1=t_slice1;\
            x2=((t_slice2>>8w7) == 8w1) ? (((t_slice2 << 1) % 8w0xff) ^ 8w0x1b) : ((t_slice2 << 1) % 8w0xff);\
            x3=((t_slice3>>8w7) == 8w1) ? (((t_slice3 << 1) % 8w0xff) ^ 8w0x1b ^ t_slice3) : (((t_slice3 << 1) % 8w0xff) ^ t_slice3);\
        }\
        if(c==c3){\
            x0=((t_slice0>>8w7) == 8w1) ? (((t_slice0 << 1) % 8w0xff) ^ 8w0x1b ^ t_slice0) : (((t_slice0 << 1) % 8w0xff) ^ t_slice0);\
            x1=t_slice1;\
            x2=t_slice2;\
            x3=((t_slice3>>8w7) == 8w1) ? (((t_slice3 << 1) % 8w0xff) ^ 8w0x1b) : ((t_slice3 << 1) % 8w0xff);\
        }\
        meta.aes.t##T##SLICE_BITS##=x0^x1^x2^x3;\
    }

    column_mix(0,0,[31:24])
    column_mix(0,1,[23:16])
    column_mix(0,2,[15:8])
    column_mix(0,3,[7:0])

    column_mix(1,0,[31:24])
    column_mix(1,1,[23:16])
    column_mix(1,2,[15:8])
    column_mix(1,3,[7:0])

    column_mix(2,0,[31:24])
    column_mix(2,1,[23:16])
    column_mix(2,2,[15:8])
    column_mix(2,3,[7:0])

    column_mix(3,0,[31:24])
    column_mix(3,1,[23:16])
    column_mix(3,2,[15:8])
    column_mix(3,3,[7:0])


    action ip_overwrite_action() { 
        hdr.ipv4.srcAddr = meta.srcip_subnet_part | (bit<32>)meta.srcip_aes_part;
        hdr.ipv4.dstAddr = meta.dstip_subnet_part | (bit<32>)meta.dstip_aes_part;

    }
    
    action arp_ip_overwrite_action() { 
        hdr.arp_ipv4.srcProtoAddr = meta.srcip_subnet_part | (bit<32>)meta.srcip_aes_part;
        hdr.arp_ipv4.dstProtoAddr = meta.dstip_subnet_part | (bit<32>)meta.dstip_aes_part;
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
    
    table anony_arp_mac_src_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_src_id_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_src_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions  = {
            hash_arp_mac_src_oui_action;
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
    
    table anony_arp_mac_dst_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_dst_id_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_dst_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_dst_oui_action;
            nop_action;
        }
    }
    
    table anony_srcip_tb {
        key = {
            meta.ipv4_srcip : ternary;
        }
        actions =  {
            prepare_srcip_aes_action;
            nop_action;
        }
    }
    
    table anony_dstip_tb {
        key = {
            meta.ipv4_dstip : ternary;
        }
    
        actions = {
            prepare_dstip_aes_action;
            nop_action;
        }
    }
    
 //轮密钥加
#define TABLE_MASK_KEY(ROUND,SUBKEY128) table mask_key_round_##ROUND##_tb {actions = {mask_key;}default_action = mask_key(SUBKEY128);}

    TABLE_MASK_KEY( 0,128w0x01010101020202020303030304040404)
    TABLE_MASK_KEY( 1,128w0x1c963acb1e9438c91d973bca19933fce)
    TABLE_MASK_KEY( 2,128w0xca151fe9d4812720c9161cead0852324)
    TABLE_MASK_KEY( 3,128w0xe916582b3d977f0bf48163e1240440c5)
    TABLE_MASK_KEY( 4,128w0x1fc0147822576b73d6d60892f2d24857)
    TABLE_MASK_KEY( 5,128w0xadbc39338feb5240593d5ad2abef1285)
    TABLE_MASK_KEY( 6,128w0x057264738a993633d3a46ce1784b7e64)
    TABLE_MASK_KEY( 7,128w0xaf3cf15c25a5c76ff601ab8e8e4ad5ea)
    TABLE_MASK_KEY( 8,128w0xdecb0c5cfb6ecb330d6f60bd8325b557)
    TABLE_MASK_KEY( 9,128w0xb09b00454bf5cb76469aabcbc5bf1e9c)
    TABLE_MASK_KEY(10,128w0xe41c75d1afe9bea7e973156c2ccc0bf0)

#define APPLY_MASK_KEY(ROUND) mask_key_round_##ROUND##_tb.apply();

//SBOX LUT,   r0~r3的切片视作流表匹配关键字            
//            流表匹配动作FUNC是一系列sbox_lut_##T##SLICE##函数 (即S盒替换) 函数参数定义在LUT表中
#define TABLE_SBOX_LUT(NAME,KEY,FUNC) table sbox_lut_##NAME##_tb {key={KEY:exact;}size=1024;actions={FUNC;}const entries=LUT(FUNC)}

    TABLE_SBOX_LUT(00,meta.aes.r0[31:24],sbox_lut_00)
    TABLE_SBOX_LUT(01,meta.aes.r0[23:16],sbox_lut_01)
    TABLE_SBOX_LUT(02,meta.aes.r0[15:8],sbox_lut_02)
    TABLE_SBOX_LUT(03,meta.aes.r0[7:0],sbox_lut_03)

    TABLE_SBOX_LUT(10,meta.aes.r1[31:24],sbox_lut_10)
    TABLE_SBOX_LUT(11,meta.aes.r1[23:16],sbox_lut_11)
    TABLE_SBOX_LUT(12,meta.aes.r1[15:8],sbox_lut_12)
    TABLE_SBOX_LUT(13,meta.aes.r1[7:0],sbox_lut_13)

    TABLE_SBOX_LUT(20,meta.aes.r2[31:24],sbox_lut_20)
    TABLE_SBOX_LUT(21,meta.aes.r2[23:16],sbox_lut_21)
    TABLE_SBOX_LUT(22,meta.aes.r2[15:8],sbox_lut_22)
    TABLE_SBOX_LUT(23,meta.aes.r2[7:0],sbox_lut_23)

    TABLE_SBOX_LUT(30,meta.aes.r3[31:24],sbox_lut_30)
    TABLE_SBOX_LUT(31,meta.aes.r3[23:16],sbox_lut_31)
    TABLE_SBOX_LUT(32,meta.aes.r3[15:8],sbox_lut_32)
    TABLE_SBOX_LUT(33,meta.aes.r3[7:0],sbox_lut_33)
    
    //单个block的LUT流表执行
#define SBOX_LUT_AP(i) sbox_lut_##i##_tb.apply();

    //所有16个block的LUT流表执行
#define SBOX_LUT_ALL_BLOCK SBOX_LUT_AP(00) SBOX_LUT_AP(01) SBOX_LUT_AP(02) SBOX_LUT_AP(03) SBOX_LUT_AP(10) SBOX_LUT_AP(11) SBOX_LUT_AP(12) SBOX_LUT_AP(13) SBOX_LUT_AP(20) SBOX_LUT_AP(21) SBOX_LUT_AP(22) SBOX_LUT_AP(23) SBOX_LUT_AP(30) SBOX_LUT_AP(31) SBOX_LUT_AP(32) SBOX_LUT_AP(33)

    


// ROW_SHIFT   无需匹配
//             流表匹配动作FUNC是一些列row_shift_##T##SLICE##_##SAVE_T##SAVE_SLICE##函数 (即行移位),将[SAVE_T,SAVE_SLICE]代表的block赋值[T,SLICE]的block
#define TABLE_ROW_SHIFT(NAME,FUNC) table row_shift_##NAME##_tb {actions={FUNC;}default_action=FUNC();}

    TABLE_ROW_SHIFT(00,row_shift_00_00)
    TABLE_ROW_SHIFT(01,row_shift_01_11)
    TABLE_ROW_SHIFT(02,row_shift_02_22)
    TABLE_ROW_SHIFT(03,row_shift_03_33)

    TABLE_ROW_SHIFT(10,row_shift_10_10)
    TABLE_ROW_SHIFT(11,row_shift_11_21)
    TABLE_ROW_SHIFT(12,row_shift_12_32)
    TABLE_ROW_SHIFT(13,row_shift_13_03)

    TABLE_ROW_SHIFT(20,row_shift_20_20)
    TABLE_ROW_SHIFT(21,row_shift_21_31)
    TABLE_ROW_SHIFT(22,row_shift_22_02)
    TABLE_ROW_SHIFT(23,row_shift_23_13)

    TABLE_ROW_SHIFT(30,row_shift_30_30)
    TABLE_ROW_SHIFT(31,row_shift_31_01)
    TABLE_ROW_SHIFT(32,row_shift_32_12)
    TABLE_ROW_SHIFT(33,row_shift_33_23)

#define ROW_SHIFT_AP(i) row_shift_##i##_tb.apply();
#define ROW_SHIFT save(); ROW_SHIFT_AP(00) ROW_SHIFT_AP(01) ROW_SHIFT_AP(02) ROW_SHIFT_AP(03) ROW_SHIFT_AP(10) ROW_SHIFT_AP(11) ROW_SHIFT_AP(12) ROW_SHIFT_AP(13) ROW_SHIFT_AP(20) ROW_SHIFT_AP(21) ROW_SHIFT_AP(22) ROW_SHIFT_AP(23) ROW_SHIFT_AP(30) ROW_SHIFT_AP(31) ROW_SHIFT_AP(32) ROW_SHIFT_AP(33) 
    

//COLUMN_MIX    无需匹配
//              流表匹配动作FUNC是一些列column_mix_##T##SLICE##_##SAVE_T##SAVE_SLICE##函数 (即行移位),将[SAVE_T,SAVE_SLICE]代表的block赋值[T,SLICE]的block将C行和T列做矩阵乘法得到结果保存到read block中
#define TABLE_COLUMN_MIX(NAME,FUNC,C) table column_mix_##NAME##_tb {actions={FUNC;}default_action=FUNC(C);}

    TABLE_COLUMN_MIX(00,column_mix_00,c0)
    TABLE_COLUMN_MIX(01,column_mix_01,c1)
    TABLE_COLUMN_MIX(02,column_mix_02,c2)
    TABLE_COLUMN_MIX(03,column_mix_03,c3)

    TABLE_COLUMN_MIX(10,column_mix_10,c0)
    TABLE_COLUMN_MIX(11,column_mix_11,c1)
    TABLE_COLUMN_MIX(12,column_mix_12,c2)
    TABLE_COLUMN_MIX(13,column_mix_13,c3)

    TABLE_COLUMN_MIX(20,column_mix_20,c0)
    TABLE_COLUMN_MIX(21,column_mix_21,c1)
    TABLE_COLUMN_MIX(22,column_mix_22,c2)
    TABLE_COLUMN_MIX(23,column_mix_23,c3)

    TABLE_COLUMN_MIX(30,column_mix_30,c0)
    TABLE_COLUMN_MIX(31,column_mix_31,c1)
    TABLE_COLUMN_MIX(32,column_mix_32,c2)
    TABLE_COLUMN_MIX(33,column_mix_33,c3)

#define COLUMN_MIX_AP(i) column_mix_##i##_tb.apply();
#define COLUMN_MIX save(); COLUMN_MIX_AP(00) COLUMN_MIX_AP(01) COLUMN_MIX_AP(02) COLUMN_MIX_AP(03) COLUMN_MIX_AP(10) COLUMN_MIX_AP(11) COLUMN_MIX_AP(12) COLUMN_MIX_AP(13) COLUMN_MIX_AP(20) COLUMN_MIX_AP(21) COLUMN_MIX_AP(22) COLUMN_MIX_AP(23) COLUMN_MIX_AP(30) COLUMN_MIX_AP(31) COLUMN_MIX_AP(32) COLUMN_MIX_AP(33) 

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
    
    table arp_ip_overwrite_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            arp_ip_overwrite_action;
        }
    }
    
    table ipv4_ip_overwite_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            ip_overwrite_action;
        }
    }
    
    apply {
        // Needed for catching multicast packets based on DST MAC address (starts with 01:xx:xx:xx:xx:xx)
        multicast_mac_catch_tb.apply();

        // Anonymize SRC MAC
        anony_mac_src_oui_tb.apply();
        anony_mac_src_id_tb.apply();

        // Only anonymize if DST MAC indicates that it's not a broadcast or multicast packet.
        if (hdr.ethernet.dstAddr_oui!=0xffffff) {
            if (hdr.ethernet.dstAddr_id!=0xffffff) {
                if (meta.dst_mac_mc_oui!=0x010000) {
                    anony_mac_dst_oui_tb.apply();
                    anony_mac_dst_id_tb.apply();
                }
            }
        }

        // If ARP reply and DST MAC is hashed, hash DST MAC in ARP packet too.
        if (hdr.arp.opcode == 2) {
            if (meta.hashed_mac_dstAddr_id == 1) {
                anony_arp_mac_dst_id_tb.apply();
            }
            if (meta.hashed_mac_dstAddr_oui == 1) {
                anony_arp_mac_dst_oui_tb.apply();
            }
        }

        // If SRC MAC is hashed, hash SRC MAC in ARP packet too.
        if (meta.hashed_mac_srcAddr_id == 1) {
            anony_arp_mac_src_id_tb.apply();
        }
        if (meta.hashed_mac_srcAddr_oui == 1) {
            anony_arp_mac_src_oui_tb.apply();
        }

        // Anoymize IPv4 SRC address 
        if(anony_srcip_tb.apply().hit){
            //填充明文串
            //read_cleartext(meta.srcip_aes_part);
            //第0轮轮密钥加
            APPLY_MASK_KEY(0)
            //1~9轮
                //sbox代换
                //行移位
                //列混合
                //轮密钥加
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(1);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(2);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(3);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(4);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(5);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(6);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(7);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(8);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(9);
            
            //第10轮
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;APPLY_MASK_KEY(10);
            
            meta.srcip_aes_part[127:96]=meta.aes.r0;
            meta.srcip_aes_part[95:64]=meta.aes.r0;
            meta.srcip_aes_part[63:32]=meta.aes.r0;
            meta.srcip_aes_part[31:0]=meta.aes.r0;
            
            meta.srcip_aes_part = meta.srcip_aes_part & (bit<128>)meta.srcip_subnetmask;
        }
        

        // Anoymize IPv4 DST address 
        if(anony_dstip_tb.apply().hit){
            //填充明文串
            read_cleartext(meta.dstip_aes_part);
            //第0轮轮密钥加
            APPLY_MASK_KEY(0)
            //1~9轮
                //sbox代换
                //行移位
                //列混合
                //轮密钥加
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(1);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(2);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(3);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(4);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(5);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(6);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(7);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(8);
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;COLUMN_MIX;APPLY_MASK_KEY(9);
            
            //第10轮
            new_round();SBOX_LUT_ALL_BLOCK;ROW_SHIFT;APPLY_MASK_KEY(10);
            
            meta.dstip_aes_part[127:96]=meta.aes.r0;
            meta.dstip_aes_part[95:64]=meta.aes.r0;
            meta.dstip_aes_part[63:32]=meta.aes.r0;
            meta.dstip_aes_part[31:0]=meta.aes.r0;

            meta.dstip_aes_part = meta.dstip_aes_part & (bit<128>)meta.dstip_subnetmask;
        }
        

        if (meta.is_arp == 1) {
            arp_ip_overwrite_tb.apply();
        }

        if (meta.is_ipv4 == 1) {
            ipv4_ip_overwite_tb.apply();
        }

        forward_tb.apply();
    }
}



control OntasEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control OntasComputeChecksum(inout headers  hdr, inout metadata meta) {
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

control OntasDeparser(packet_out packet, in headers hdr) {
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
    OntasParser(),
    OntasVerifyChecksum(),
    OntasIngress(),
    OntasEgress(),
    OntasComputeChecksum(),
    OntasDeparser()
) main;