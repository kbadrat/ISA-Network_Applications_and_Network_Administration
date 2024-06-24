#ifndef FLOWP_HPP
#define FLOWP_HPP
#include "Base.hpp"

class Flow {
public:
    // Struct for map key value.
    struct NF5_header
    {
        u_int32_t src_ip;
        u_int32_t dst_ip;
        u_int16_t src_port;
        u_int16_t dst_port = 0x00;
        u_int8_t protocol;
        
    };
    NF5_header _header;
    // Flow packet body.
    u_int32_t flow_packets;
    u_int32_t flow_start;
    u_int32_t nexthop_ip = 0x00;
    u_int32_t flow_octets = 0x00;
    u_int32_t flow_finish = 0x00;

	u_int16_t if_index_in;
    u_int16_t src_as;
    u_int16_t if_index_out = 0x00;
    u_int16_t dst_as = 0x00;
    u_int16_t pad2 = 0x00;

	u_int8_t tcp_flags;
	u_int8_t src_mask;
    u_int8_t pad1 = 0x00;
    u_int8_t tos = 0x00;
    u_int8_t dst_mask = 0x00;

    // Variables for class methods.
    u_int32_t nano_time;

    time_t s_time;
   

    Flow get_flow(){return *this;}
    
    u_int32_t exporter_currTime(struct pcap_pkthdr *hdr);

    // Check duplicates.
    bool TCP_flow_check(struct ip* p_ip, const struct tcphdr* hdr_tcp, struct pcap_pkthdr hdr);
    bool UDP_flow_check(struct ip* p_ip, const struct udphdr* hdr_udp, struct pcap_pkthdr hdr);
    bool ICMP_flow_check(struct ip* p_ip, const struct icmp_hdr* hdr_icmp, struct pcap_pkthdr hdr);

    // Store packets in a list of flows.
    void store_TCP_packet(struct ip* p_ip, const struct tcphdr* hdr_tcp, struct pcap_pkthdr hdr);
    void store_UDP_packet(struct ip* p_ip, const struct udphdr* my_udp, struct pcap_pkthdr hdr);
    void store_ICMP_packet(struct ip* p_ip, struct pcap_pkthdr hdr);
};
#endif