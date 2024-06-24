#include "Base.hpp"
#include "FlowP.hpp"
#include "UDPP.hpp"

// Linking global variables from Base.hpp.
argv_options input_argv;
pcap_packet_structure pp_nf;
long double system_time;

// Structure for correct key comparing.
struct compare
{
	bool operator()(Flow::NF5_header first , Flow::NF5_header second) const 
	{
		return std::make_pair(first.protocol, first.dst_ip) > std::make_pair(second.protocol, second.dst_ip);
	}
};

void split_argv(const std::string &str, char ch, std::vector<std::string> &args);
void argv_parser(int argc, char *argv[]);
// Creates a key from a packet header and sort flows into packets.
void sort_flows(std::map<struct Flow::NF5_header, Flow, compare> &cache, std::list<Flow> &flows, bool single);
// Sends sorted flows packets to connector via UDP. 
void UDP_export(std::map<struct Flow::NF5_header, Flow, compare> &cache, UDP &socket);

int seq = 0;
int p_index;

int main(int argc, char *argv[]) 
{
	argv_parser(argc, argv);

	int packet_count = 0;

	char errbuf[ERR_BUFFER];
	
	// Handler that stores files from input.pcap.
	pcap_t *pcap_handler;
	u_int ip_size;
	
	bool is_stored;
	// Object that deals with collector.
	UDP socket;

	// List for non sorted flows.
	std::list<Flow> flows;
	// Map that stores flows sorted via header key.
	std::map<struct Flow::NF5_header, Flow, compare> sorted_flows; 
	
	// Try to open input.pcap.
	if ((pcap_handler = pcap_open_offline(input_argv.input_file.c_str(), errbuf)) == nullptr)
	{
		std::cerr << "Can't open file " << input_argv.input_file << " for reading";
		exit(1);
	}
	
	// Reading input.pcap.
	while ((pp_nf.pcap_packet = pcap_next(pcap_handler,&pp_nf.pcap_header)) != nullptr)
	{
		Flow temp;

		// Set system uptime on a first run.
		if (packet_count == 0) 
		{
			system_time = pp_nf.pcap_header.ts.tv_sec;
			system_time = system_time*1000 + pp_nf.pcap_header.ts.tv_usec/1000;
		}

		packet_count++;
		pp_nf.ip = (struct ip*) (pp_nf.pcap_packet+E_OFFSET);
		ip_size = pp_nf.ip->ip_hl*4;
		
		// Skip IPv6 packets.
		if (pp_nf.ip->ip_v != 4) 
			continue;

		// Sort packets from input.pcap.
		switch (pp_nf.ip->ip_p) 
		{
			case ICMP_PROTOCOL:
				pp_nf.hdr_icmp = (struct icmp_hdr *)(pp_nf.pcap_packet+E_OFFSET+ip_size); 
				is_stored = false;

				if (flows.empty())
				{
		    		temp.store_ICMP_packet(pp_nf.ip,pp_nf.pcap_header);
					flows.push_back(temp);
				} else {
					
					for (std::list<Flow>::iterator iter = flows.begin();iter != flows.end();iter++ )
					{
						if (iter->ICMP_flow_check(pp_nf.ip, pp_nf.hdr_icmp, pp_nf.pcap_header))
						{
			    			is_stored = true;
			    			break;
						}
					}
					if (!is_stored) 
					{
						temp.store_ICMP_packet(pp_nf.ip,pp_nf.pcap_header);
						flows.push_back(temp);
					}
				}

				break;

			case TCP_PROTOCOL:

				pp_nf.hdr_tcp = (struct tcphdr *) (pp_nf.pcap_packet+E_OFFSET+ip_size); 
				is_stored = false;
				
				if (flows.empty())
				{
		    		temp.store_TCP_packet(pp_nf.ip, pp_nf.hdr_tcp, pp_nf.pcap_header);
					flows.push_back(temp);
				} else {
					
					for (std::list<Flow>::iterator iter = flows.begin();iter != flows.end();iter++ ) 
					{
						if (iter->TCP_flow_check(pp_nf.ip, pp_nf.hdr_tcp, pp_nf.pcap_header)) 
						{
			    			is_stored = true;
			    			break;
						}
					}
					if (!is_stored) 
					{
						temp.store_TCP_packet(pp_nf.ip, pp_nf.hdr_tcp, pp_nf.pcap_header);
						flows.push_back(temp);
					}
				}
				
				break;

			case UDP_PROTOCOL:

				pp_nf.hdr_udp = (struct udphdr *) (pp_nf.pcap_packet+E_OFFSET+ip_size);
				is_stored = false;

				if (flows.empty())
				{
		    		temp.store_UDP_packet(pp_nf.ip, pp_nf.hdr_udp, pp_nf.pcap_header);
					flows.push_back(temp);
				} else {
					
					for (std::list<Flow>::iterator iter = flows.begin();iter != flows.end();iter++ ) 
					{
						if (iter->UDP_flow_check(pp_nf.ip, pp_nf.hdr_udp, pp_nf.pcap_header)) 
						{
			    			is_stored = true;
			    			break;
						}
					}
					if (!is_stored) 
					{
						temp.store_UDP_packet(pp_nf.ip, pp_nf.hdr_udp, pp_nf.pcap_header);
						flows.push_back(temp);
					}
				}
				
				break;

			default:
				exit(0);
				break;
		}

		// Sort flows.
		if (flows.size() == input_argv.cache_size)
			sort_flows(sorted_flows, flows, true);
		
		// Check if we need to send our flows(if time passed).
		if (!sorted_flows.empty())
		{
			if (sorted_flows.begin()->second.flow_finish - sorted_flows.end()->second.flow_start > input_argv.active_timer*1000) 
			{
				UDP_export(sorted_flows, socket);
				sorted_flows.clear();
			}
		}

	} 

	// Sort what is left.
	sort_flows(sorted_flows, flows, false);

	// Send what is left.
	if (!flows.empty()) {
		UDP_export(sorted_flows, socket);
	}
	
	// Clean up.
	sorted_flows.clear();
	flows.clear();
	pcap_close(pcap_handler);

	return 0;
}


void split_argv(const std::string &str, char ch, std::vector<std::string> &args) 
{    
    args.clear();
    std::stringstream ss(str);
    std::string item;
    while (getline(ss, item, ch))
        args.push_back(item);
}




void argv_parser(int argc, char *argv[]) 
{
	static struct option long_options[] = 
	{
		{"input",		required_argument, 	NULL, 'f'},
		{"collector",	required_argument, 	NULL, 'c'},
		{"interval",	required_argument, 	NULL, 'a'},
		{"max-flows",	required_argument, 	NULL, 'm'},
		{"tcp-timeout",	required_argument, 	NULL, 'i'},
		{NULL, 0, NULL, 0}
	};


	int o_index = 0;
	int arg;

	// Fill the options sin_addr.
	while ((arg = getopt_long (argc, argv, "f:c:a:m:i:", long_options, &o_index)) != -1 ) {
		switch(arg) {
			case 'f':
				input_argv.input_file = optarg;
				break;
			case 'c':
				{
					std::string tmp(optarg);
					std::vector<std::string> seglist;
					split_argv(tmp, ':', seglist);
					if (seglist.size() > 1)
						input_argv.port = stoi(seglist[1]);
					input_argv.ip = seglist[0];
					
				}
				break;
			case 'a':
				input_argv.active_timer = atoi(optarg);
				break;
			case 'm':
				input_argv.cache_size = atoi(optarg);
				break;
			case 'i':
				input_argv.inactive_timer = atoi(optarg);
				break;
			default:
				break;
		}
	}
}



void sort_flows(std::map<struct Flow::NF5_header, Flow, compare> &cache,std::list<Flow> &flows, bool single)
{
	if (single) 
	{
		cache[flows.front()._header] = flows.front();
    	flows.pop_front();
	} else 
	{
		std::list<Flow >::iterator iter;

		for (iter = flows.begin(); iter != flows.end(); iter++)
			cache[iter->_header] = iter->get_flow();
	}
}


void UDP_export(std::map<struct Flow::NF5_header, Flow, compare> &cache, UDP &socket)
{
	
	int total_packets = cache.size() % MAX_FLOWS;
	int exported_packets = (int)(cache.size() / MAX_FLOWS) * MAX_FLOWS;
	std::map<struct Flow::NF5_header, Flow>::iterator iter;

	for (iter = cache.begin(); iter != cache.end(); iter++) 
	{
    	socket.add_flow(iter->second, p_index);
    	p_index++;
    	if (p_index == MAX_FLOWS) 
		{
    		socket.new_header(p_index, seq, iter->second);
    		seq += 30;
			socket.send_flows();
			p_index = 0;
			socket.reset();
    	}			
	}

	if (total_packets != 0) 
	{
		iter = cache.begin();
		advance(iter, exported_packets - 1);
		seq += total_packets;
		socket.new_header(total_packets, seq, iter->second);
		socket.send_flows();
		socket.reset();
		p_index = 0;
	}
}