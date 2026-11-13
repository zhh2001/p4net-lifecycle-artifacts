#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct headers { ethernet_t ethernet; ipv4_t ipv4; }
struct metadata { }

parser L3Parser(packet_in packet, out headers hdr, inout metadata meta,
              inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: ipv4;
            default: accept;
        }
    }
    state ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control L3Verify(inout headers hdr, inout metadata meta) {
    apply { }
}

control L3Ingress(inout headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    action forward(bit<48> dst_mac, bit<48> src_mac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { forward; drop; }
        size = 1024;
        default_action = drop();
    }
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ihl == 5 && hdr.ipv4.ttl > 1) {
            ipv4_lpm.apply();
        } else { drop(); }
    }
}

control L3Egress(inout headers hdr, inout metadata meta,
               inout standard_metadata_t standard_metadata) {
    apply { }
}

control L3Checksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control L3Deparser(packet_out packet, in headers hdr) {
    apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); }
}

V1Switch(L3Parser(), L3Verify(), L3Ingress(), L3Egress(), L3Checksum(),
         L3Deparser()) main;
