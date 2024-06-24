#include "Base.hpp"
#include "UDPP.hpp"
#include "FlowP.hpp"

UDP::UDP() 
{
	f_packet = new (std::nothrow) u_int8_t[packet_size];
	s_packet = new (std::nothrow) u_int8_t[send_packet_size];

	if (s_packet == NULL || f_packet == NULL) 
	{
		err(1, "ERROR: Can't allocate memory");
	}

	memset(s_packet, 0, send_packet_size);
	memset(f_packet, 0, packet_size);
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&flow_hdr, 0, sizeof(flow_hdr));


	if ((socket_desc = socket(AF_INET , SOCK_DGRAM , 0)) == -1)
	    err(1,"ERROR: Can't create socket\n");

	if ( (host = gethostbyname(&input_argv.ip[0u]) ) == NULL) {
        err(1, "ERROR: Can't get address\n");
    }

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(input_argv.port);
	memcpy(&dest_addr.sin_addr, host->h_addr, host->h_length);
}

void UDP::add_flow(Flow flow, int offset) 
{
	flow_body.src_ip = flow._header.src_ip;
	flow_body.dst_ip = flow._header.dst_ip;
	flow_body.nexthop_ip = htonl(flow.nexthop_ip);
	flow_body.if_index_in = 0;
	flow_body.if_index_out = 0;
	flow_body.flow_packets = htonl(flow.flow_packets);
	flow_body.flow_octets = htonl(flow.flow_octets);
	flow_body.flow_start 	= htonl(flow.flow_start);
	flow_body.flow_finish = htonl(flow.flow_finish);
	flow_body.src_port = flow._header.src_port;
	flow_body.dst_port = flow._header.dst_port;
	flow_body.pad1 = flow.pad1;
	flow_body.tcp_flags = flow.tcp_flags;
	flow_body.protocol = flow._header.protocol;
	flow_body.tos = flow.tos;
	flow_body.src_as = 0;
	flow_body.dst_as = 0;
	flow_body.src_mask = flow.src_mask;
	flow_body.dst_mask = flow.dst_mask;
	flow_body.pad2 = flow.pad2;

	memcpy(f_packet + (offset * sizeof(struct NF5_BD)), &flow_body, sizeof(flow_body));
}

void UDP::send_flows() 
{
	memcpy(s_packet, &flow_hdr, sizeof(flow_hdr));
	memcpy(s_packet + sizeof(flow_hdr), f_packet, packet_size);
	
	sendto_flag = sendto(socket_desc, s_packet, send_packet_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));

	// Check result.
	if (sendto_flag == -1)
      	err(1,"ERROR: sendto() failed:");
    else if (sendto_flag != send_packet_size)
    	err(1,"ERROR: sendto(): buffer written partially");
}

void UDP::new_header(u_int16_t flows_num, u_int32_t flow_seq, Flow flw) 
{
	flow_hdr.version = htons(5);
	flow_hdr.flows = htons(flows_num);
	flow_hdr.uptime_ms = htonl(flw.flow_finish);
	flow_hdr.time_sec = htonl((flw.flow_finish + system_time)/1000);
	flow_hdr.time_nanosec = htonl((flw.flow_finish + system_time)*1000);
	flow_hdr.flow_sequence = htonl(flow_seq);
	flow_hdr.engine_type = 0x2A;
	flow_hdr.engine_id = 0x2A;
	flow_hdr.sampling_interval = htons((0x01 << 14) | (1 & 0x3FFF));

}

void UDP::reset() 
{
	memset(f_packet, 0, packet_size);
	memset(&flow_hdr, 0, sizeof(flow_hdr));
	memset(s_packet, 0, send_packet_size);
}

UDP::~UDP() 
{
	delete s_packet;
	delete f_packet;
	close(socket_desc);
}