/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 0x06;
const bit<8> PROTO_UDP = 0x11;
const bit<16> TYPE_GTP = 0x868;
const bit<8> pdu_container = 0x85;

typedef bit<16>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

const ip4Addr_t espelhoIP = 0xC0A83A66; //192.168.58.102
const macAddr_t espelhoMAC = 0x00154d000001; //MAC porta dados do espelho (enp0s10)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<8>    diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNumber;
	bit<32> ackNumber;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

header tcpOptions_t {
	varbit<320> options;
}

header udp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> length;
	bit<16> checksum;
}

header gtp_t {
	bit<3>  version_field_id;
	bit<1>  proto_type_id;
	bit<1>  spare;
	bit<1>  extension_header_flag_id;
	bit<1>  sequence_number_flag_id;
	bit<1>  npdu_number_flag_id;
	bit<8>  msgtype;
	bit<16> msglen;
	bit<32> teid;
	bit<24> padding;
}

header gtp_ext_t {
	bit<8> next_extension;
}

header pdu_container_t {
	bit<8> length;
	bit<4> pdu_type;
	bit<5> spare;
	bit<1> rqi;
	bit<6> qosid;
}

header gambiarra_t {
}

struct metadata {
	bit<2> clone_flag;

	bit<1> ehTunelGTP;

	bit<1> clone_flag_1;
	egressSpec_t stored_decapture_inf;
	ip4Addr_t stored_decapture_ip;
	port_t stored_decapture_port;
	macAddr_t stored_decapture_mac;

	egressSpec_t stored_mirror_inf;
	port_t stored_mirror_port;
}

struct headers {
	ethernet_t	ethernet;
	ipv4_t		ipv4;
	tcp_t		tcp;
	tcpOptions_t	tcpOptions;
	udp_t		udp;
	gtp_t		gtp;
	gtp_ext_t	gtp_ext;
	pdu_container_t	pdu_container;
	gtp_ext_t	gtp_ext2;
	ipv4_t		ipv4_inner;
	udp_t		udp_inner;
//	gambiarra_t	gambis;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

	bit<8> optionsLen;

	state start {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType){
			TYPE_IPV4: parse_ipv4; //Se for IPv4
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.dstAddr) {
			//espelhoIP: parse_transport; //Se IP dst == espelho -> Analisar transporte
			//default: accept;
			default: parse_transport;
		}
	}

	state parse_transport {
		transition select(hdr.ipv4.protocol) {
			PROTO_TCP: parse_tcp; //TCP
			PROTO_UDP: parse_udp; //UDP
			default: accept;
		}
	}

	state parse_gtp {
		packet.extract(hdr.gtp);
		transition select(hdr.gtp.extension_header_flag_id) {
			1: parse_gtp_ext;
			0: parse_ipv4_inner;
		}
	}

	state parse_gtp_ext {
		packet.extract(hdr.gtp_ext);
		transition select(hdr.gtp_ext.next_extension) {
			pdu_container: parse_pdu_container;
			0: parse_ipv4_inner;
		}
	}

	state parse_pdu_container {
		packet.extract(hdr.pdu_container);
		transition parse_gtp_ext2;
	}

	state parse_gtp_ext2 {
		packet.extract(hdr.gtp_ext2);
		transition select(hdr.gtp_ext2.next_extension) {
			0: parse_ipv4_inner;
		}
	}

	state parse_ipv4_inner {
		packet.extract(hdr.ipv4_inner);
		transition select(hdr.ipv4_inner.dstAddr) {
			espelhoIP: parse_transport_inner;
			default: accept;
		}
	}

	state parse_transport_inner {
		transition select(hdr.ipv4_inner.protocol) {
			PROTO_UDP: parse_udp_inner;
			default: accept;
		}
	}
	
	state parse_udp_inner {
    		packet.extract(hdr.udp_inner);
	    	transition accept;
	}

	state parse_tcp {
		packet.extract(hdr.tcp);

        	optionsLen = 4 * (bit<8>) (hdr.tcp.dataOffset - 5);

		transition select (optionsLen) {
			0: accept;
			default: parse_tcp_options;
		}
	}

	state parse_udp {
    		packet.extract(hdr.udp);
	    	transition select(hdr.udp.dstPort) {
	                TYPE_GTP: parse_gtp;
        	        default: accept;
		}
	}

	state parse_tcp_options {
		packet.extract(hdr.tcpOptions, (bit<32>) (optionsLen << 3));
		transition accept;
	}
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	action drop() {
		mark_to_drop();
	}

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t egressPort) {
		hdr.ethernet.dstAddr = dstAddr;
		standard_metadata.egress_spec = egressPort;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}
	
	action change_egress_port(egressSpec_t egressPort) {
		standard_metadata.egress_spec = egressPort;
	}

	table ipv4_lpm {
		key = {
		    hdr.ipv4.dstAddr: lpm;
		}
		actions = {
		    ipv4_forward;
		    drop;
		    NoAction;
		}
		size = 1024;
		default_action = NoAction();
    	}

	action encaminhaDecapture_inner (egressSpec_t egressPort, egressSpec_t defaultEgressPort, port_t dataPort, ip4Addr_t ip_dec1, port_t port_dec1, macAddr_t mac_dec1) {

		meta.stored_mirror_inf = defaultEgressPort;
                standard_metadata.egress_spec = defaultEgressPort;
                hdr.ipv4_inner.ttl = hdr.ipv4_inner.ttl - 1;
		meta.stored_decapture_inf = egressPort;
		meta.stored_mirror_port = dataPort;

		if (ip_dec1 != 0 && port_dec1 != 0 && mac_dec1 != 0) {
			meta.clone_flag_1 = 0x1;
			meta.stored_decapture_ip = ip_dec1;
			meta.stored_decapture_mac = mac_dec1;
			meta.stored_decapture_port = port_dec1;
			meta.ehTunelGTP = 1;	
		}

        }

	action encaminhaDecapture (egressSpec_t egressPort, egressSpec_t defaultEgressPort, ip4Addr_t ip_dec1, port_t port_dec1, macAddr_t mac_dec1) {

		meta.stored_mirror_inf = defaultEgressPort;
                standard_metadata.egress_spec = defaultEgressPort;
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		meta.stored_mirror_port = hdr.udp.dstPort;
		meta.stored_decapture_inf = egressPort;

		if (ip_dec1 != 0 && port_dec1 != 0 && mac_dec1 != 0) {
			meta.clone_flag_1 = 0x1;
			meta.stored_decapture_ip = ip_dec1;
			meta.stored_decapture_mac = mac_dec1;
			meta.stored_decapture_port = port_dec1;
		}

        }

	table espelho_udp {
		key = { hdr.ipv4.srcAddr : exact;
			hdr.udp.srcPort : exact;
			hdr.ipv4.dstAddr : exact;
			hdr.udp.dstPort : exact; }
		actions = {
			encaminhaDecapture;
			drop;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}
	
	table drop_packet_middleware {
		key = { hdr.ipv4.srcAddr : exact;
			hdr.udp.srcPort : exact;
			hdr.ipv4.dstAddr : exact;
			hdr.udp.dstPort : exact; }
		actions = {
			drop;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	table espelho_udp_inner {
                key = { hdr.udp_inner.srcPort : exact;
                        hdr.ipv4_inner.dstAddr : exact;
                        hdr.udp_inner.dstPort : exact; }
                actions = {
                        encaminhaDecapture_inner;
                        drop;
                        NoAction;
                }
                size = 2;
                default_action = NoAction();
        }

	table force_egress_port {
		key = { hdr.ipv4.dstAddr : exact; }
		actions = {
			change_egress_port;
			drop;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}
	
	table force_egress_port_inner {
		key = { hdr.ipv4_inner.dstAddr : exact; }
		actions = {
			change_egress_port;
			drop;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	apply {
		if (hdr.ipv4.isValid()) {
			
			if (hdr.tcp.isValid()) {
				ipv4_lpm.apply();
			}
			else if (hdr.udp.isValid()) {

				if (drop_packet_middleware.apply().hit) {
					drop();
				}
				// drop_packet_middleware.apply();
				else if (hdr.gtp.isValid()){
					if (hdr.ipv4_inner.isValid()){						
						if (hdr.udp_inner.isValid()){

							if (standard_metadata.instance_type == (bit<4>) 0x1) {
								if (force_egress_port_inner.apply().hit) {
									hdr.gtp.setInvalid();
									hdr.gtp_ext.setInvalid();
									hdr.pdu_container.setInvalid();
									hdr.gtp_ext2.setInvalid();
									hdr.ipv4.setInvalid();
									hdr.udp.setInvalid();

									hdr.ipv4_inner.srcAddr = espelhoIP;
									hdr.ipv4_inner.dstAddr = meta.stored_decapture_ip;
									hdr.ethernet.srcAddr = espelhoMAC;
									hdr.ethernet.dstAddr = meta.stored_decapture_mac;
									hdr.udp_inner.srcPort = meta.stored_mirror_port;
									hdr.udp_inner.dstPort = meta.stored_decapture_port;
								}	
							}
							else if (espelho_udp_inner.apply().hit) {
							
								if (meta.clone_flag_1 == 0x1 && standard_metadata.egress_instance == 0x0) {
									meta.clone_flag = 0x1;
									meta.ehTunelGTP = 0x1;	
									clone3(CloneType.I2I, 1, meta);
								}

								standard_metadata.egress_spec = meta.stored_mirror_inf;

							}
							else {
								ipv4_lpm.apply();
							}
						}
						else {
							ipv4_lpm.apply();
						}
					}
					else {
						ipv4_lpm.apply();
					}
				}
				else {
					if (standard_metadata.instance_type == (bit<4>) 0x1) {
						if(force_egress_port.apply().hit) {
							standard_metadata.egress_spec = meta.stored_decapture_inf;
							hdr.ipv4.dstAddr = meta.stored_decapture_ip;
							hdr.ipv4.srcAddr = espelhoIP;
							hdr.ethernet.srcAddr = espelhoMAC;
							hdr.ethernet.dstAddr = meta.stored_decapture_mac;
							hdr.udp.srcPort = meta.stored_mirror_port;
							hdr.udp.dstPort = meta.stored_decapture_port;
						}
					}
					else if (espelho_udp.apply().hit) {
						if (meta.clone_flag_1 == 0x1 && standard_metadata.egress_instance == 0x0) {
							meta.clone_flag = 0x1;
							clone3(CloneType.I2I, 1, meta);
						}
						standard_metadata.egress_spec = meta.stored_mirror_inf;
					}
					else {
						ipv4_lpm.apply();
					}
				}
			}
			else {
				ipv4_lpm.apply();
			}
		}
		else {
			ipv4_lpm.apply();
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

	apply {
		/*	
		if (standard_metadata.instance_type == (bit<4>) 0x8 || standard_metadata.instance_type == (bit<4>) 0x1) { //I2E ou I2I

			if (meta.clone_flag == 0x1) {
				if (meta.ehTunelGTP == 0x1) {
					hdr.gtp.setInvalid();
					hdr.gtp_ext.setInvalid();
					hdr.pdu_container.setInvalid();
					hdr.gtp_ext2.setInvalid();
					hdr.ipv4.setInvalid();
					hdr.udp.setInvalid();

					standard_metadata.egress_spec = meta.stored_decapture_inf;
					hdr.ipv4_inner.srcAddr = espelhoIP;
					hdr.ipv4_inner.dstAddr = meta.stored_decapture_ip;
					hdr.ethernet.srcAddr = espelhoMAC;
					hdr.ethernet.dstAddr = meta.stored_decapture_mac;
					hdr.udp_inner.srcPort = meta.stored_mirror_port;
					hdr.udp_inner.dstPort = meta.stored_decapture_port;
				}
				else {
					standard_metadata.egress_spec = meta.stored_decapture_inf;
					hdr.ipv4.dstAddr = meta.stored_decapture_ip;
					hdr.ipv4.srcAddr = espelhoIP;
					hdr.ethernet.srcAddr = espelhoMAC;
					hdr.ethernet.dstAddr = meta.stored_decapture_mac;
					hdr.udp.srcPort = meta.stored_mirror_port;
					hdr.udp.dstPort = meta.stored_decapture_port;
				}
			}
		}
		*/
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {

		update_checksum(
			hdr.ipv4.isValid(),
			{ hdr.ipv4.version,
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
			HashAlgorithm.csum16
		);

		update_checksum(
                        hdr.ipv4_inner.isValid(),
                        { hdr.ipv4_inner.version,
                        hdr.ipv4_inner.ihl,
                        hdr.ipv4_inner.diffserv,
                        hdr.ipv4_inner.totalLen,
                        hdr.ipv4_inner.identification,
                        hdr.ipv4_inner.flags,
                        hdr.ipv4_inner.fragOffset,
                        hdr.ipv4_inner.ttl,
                        hdr.ipv4_inner.protocol,
                        hdr.ipv4_inner.srcAddr,
                        hdr.ipv4_inner.dstAddr },
                        hdr.ipv4_inner.hdrChecksum,
                        HashAlgorithm.csum16
                );

		update_checksum_with_payload(
			hdr.udp.isValid(),
			{ hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr,
			8w0,
			hdr.ipv4.protocol,
			hdr.udp.length,
			hdr.udp.srcPort,
			hdr.udp.dstPort,
			hdr.udp.length//,
			//16w0 
			},
			hdr.udp.checksum,
			HashAlgorithm.csum16
		);
		update_checksum_with_payload(
			hdr.udp_inner.isValid(),
			{ hdr.ipv4_inner.srcAddr,
			hdr.ipv4_inner.dstAddr,
			8w0,
			hdr.ipv4_inner.protocol,
			hdr.udp_inner.length,
			hdr.udp_inner.srcPort,
			hdr.udp_inner.dstPort,
			hdr.udp_inner.length//,
			//16w0 
			},
			hdr.udp_inner.checksum,
			HashAlgorithm.csum16
		);

	}
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
