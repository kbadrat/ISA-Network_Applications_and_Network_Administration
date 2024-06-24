#ifndef UDPP_HPP
#define UDPP_HPP
#include "Base.hpp"
#include "FlowP.hpp"

class UDP {
private:

	// Flow packet structure for udp connection.
	struct NF5_HDR 
	{
		u_int16_t version;
		u_int16_t flows;
		u_int32_t uptime_ms;
		u_int32_t time_sec;
		u_int32_t time_nanosec;
		u_int32_t flow_sequence;
		u_int8_t engine_type;
		u_int8_t engine_id;
		u_int16_t sampling_interval;
	};
	struct NF5_BD {
		u_int32_t src_ip;
		u_int32_t dst_ip;
		u_int32_t nexthop_ip;
		u_int16_t if_index_in;
		u_int16_t if_index_out;
		u_int32_t flow_packets;
		u_int32_t flow_octets;
		u_int32_t flow_start;
		u_int32_t flow_finish;
		u_int16_t src_port;
		u_int16_t dst_port;
		u_int8_t pad1;
		u_int8_t tcp_flags;
		u_int8_t protocol;
		u_int8_t tos;
		u_int16_t src_as;
		u_int16_t dst_as;
		u_int8_t src_mask;
		u_int8_t dst_mask;
		u_int16_t pad2;
		
	};

	NF5_BD flow_body;
	NF5_HDR flow_hdr;

	struct sockaddr_in dest_addr; 
	struct hostent *host;

	u_int8_t * s_packet;
	u_int8_t * f_packet;

	int socket_desc;                        
	int sendto_flag;

	
	int packet_size = sizeof(struct NF5_BD) * MAX_FLOWS;
	int send_packet_size = sizeof(struct NF5_HDR) + packet_size;

public:
		// Connection to host. 
		UDP();
		// Close connection and free memory.
		~UDP();	

		// Create header for a flow packet.
		void new_header(u_int16_t flowNum, u_int32_t flowSeq, Flow flow);
		
		// Adds flows to packet.
		void add_flow(Flow p_flow, int hdr_offset);

		// Send flows to host.
		void send_flows();
		
		// Clear cache.
		void reset();
};
#endif