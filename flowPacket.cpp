#include "Base.hpp"
#include "FlowP.hpp"

u_int32_t Flow::exporter_currTime(struct pcap_pkthdr *hdr) { 

    long double tmp_time = hdr->ts.tv_sec;
    tmp_time = tmp_time*1000 + hdr->ts.tv_usec/1000;

	return (tmp_time - system_time);
	
}

bool Flow::TCP_flow_check(struct ip* p_ip, const struct tcphdr* hdr_tcp, struct pcap_pkthdr hdr) {
	
	if (this->_header.protocol == p_ip->ip_p &&
		this->_header.src_ip == p_ip->ip_src.s_addr &&
		this->_header.dst_ip == p_ip->ip_dst.s_addr &&
		this->_header.src_port == hdr_tcp->th_sport &&
		this->_header.dst_port == hdr_tcp->th_dport &&
		!((this->tcp_flags & TH_FIN) || (this->tcp_flags & TH_RST))
		) 
		{
		if ((hdr.ts.tv_sec - this->s_time) < input_argv.inactive_timer) 
		{
			this->flow_packets += 1;
			this->tcp_flags = (this->tcp_flags | hdr_tcp->th_flags);
			this->flow_finish = exporter_currTime(&hdr);
			return true;
		} 
	}
	return false;
}

bool Flow::UDP_flow_check(struct ip* p_ip, const struct udphdr* hdr_udp, struct pcap_pkthdr hdr)
{
	if (this->_header.protocol == p_ip->ip_p &&
		this->_header.src_ip == p_ip->ip_src.s_addr &&
		this->_header.dst_ip == p_ip->ip_dst.s_addr &&
		this->_header.src_port == hdr_udp->uh_sport &&
		this->_header.dst_port == hdr_udp->uh_dport &&
		!((this->tcp_flags & TH_FIN) || (this->tcp_flags & TH_RST))
		) 
		{
		if ((hdr.ts.tv_sec - this->s_time) < input_argv.inactive_timer) 
		{
			this->flow_packets += 1;
			this->flow_finish = exporter_currTime(&hdr);
			return true;
		} 
	}
	return false;
}

bool Flow::ICMP_flow_check(struct ip* p_ip, const struct icmp_hdr* hdr_icmp, struct pcap_pkthdr hdr)
{
	if 
	(	this->_header.protocol == p_ip->ip_p &&
		this->_header.src_ip == p_ip->ip_src.s_addr &&
		this->_header.dst_ip == p_ip->ip_dst.s_addr &&
		this->_header.src_port == hdr_icmp->ic_sport &&
		this->_header.dst_port == hdr_icmp->ic_dport
	)
	{
		if ((hdr.ts.tv_sec - this->s_time) < input_argv.inactive_timer) 
		{
			this->flow_packets += 1;
			this->flow_finish = exporter_currTime(&hdr);
			return true;
		} 
	}
	return false;
}


void Flow::store_TCP_packet(struct ip* p_ip, const struct tcphdr* hdr_tcp, struct pcap_pkthdr hdr) {
	// Protocol.
	this->_header.protocol = p_ip->ip_p;
	this->tos = p_ip->ip_tos;
	// SRC and DST IP.
	this->_header.src_ip = p_ip->ip_src.s_addr;
	this->_header.dst_ip = p_ip->ip_dst.s_addr;
	// Ports.
	this->_header.src_port = hdr_tcp->th_sport;
	this->_header.dst_port = hdr_tcp->th_dport;
	// TCP Flags.
	this->tcp_flags = hdr_tcp->th_flags;

	this->flow_packets = 1;
	this->flow_octets = hdr.len;
	
	this->flow_start = this->flow_finish = exporter_currTime(&hdr);
}

void Flow::store_UDP_packet(struct ip* p_ip, const struct udphdr* hdr_udp, struct pcap_pkthdr hdr) {
	// Proto and TOS.
	this->_header.protocol = p_ip->ip_p;
	this->tos = p_ip->ip_tos;
	// IP addresses.
	this->_header.src_ip = p_ip->ip_src.s_addr;
	this->_header.dst_ip = p_ip->ip_dst.s_addr;
	// Ports.
	this->_header.src_port = hdr_udp->uh_sport;
	this->_header.dst_port = hdr_udp->uh_dport;
	// Rest.
	this->tcp_flags = 0x00;
	this->flow_packets = 1;
	this->flow_octets = ntohs(hdr_udp->uh_ulen);

	this->flow_start = this->flow_finish = exporter_currTime(&hdr);
}

void Flow::store_ICMP_packet(struct ip* p_ip, struct pcap_pkthdr hdr) {
	// Proto and TOS.
	this->_header.protocol = p_ip->ip_p;
	this->tos = p_ip->ip_tos;
	// IP addresses.
	this->_header.src_ip = p_ip->ip_src.s_addr;
	this->_header.dst_ip = p_ip->ip_dst.s_addr;

	this->_header.src_port = 0x00;
	this->_header.dst_port = 0x00;

	this->tcp_flags = 0x00;
	
	this->flow_packets = 1;
	this->flow_octets = ntohs(p_ip->ip_len);

	this->flow_start = this->flow_finish = exporter_currTime(&hdr);
}