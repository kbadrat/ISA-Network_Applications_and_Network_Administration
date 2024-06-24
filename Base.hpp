#ifndef BASE_HPP
#define BASE_HPP
#include <iostream>
#include <cstdio>
#include <ctime>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <err.h>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <getopt.h>
#include <list>
#include <iomanip>
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <map>


#define ERR_BUFFER (256)
#define E_OFFSET (14)
#define MAX_FLOWS (30)
#define ICMP_PROTOCOL (1)
#define TCP_PROTOCOL (6)
#define UDP_PROTOCOL (17)


struct icmp_hdr
{
	unsigned short  ic_sport;
	unsigned short  ic_dport;  
};

struct pcap_packet_structure{
	const u_char *pcap_packet;
	struct ip *ip;
	const struct tcphdr *hdr_tcp;    
	const struct udphdr *hdr_udp;  
	const struct icmp_hdr *hdr_icmp;  
	struct pcap_pkthdr pcap_header;  
};


struct argv_options 
{
	std::string input_file = "-";
	std::string ip = "127.0.0.1";
	int port = 2055;
	unsigned int active_timer = 60;
	int inactive_timer = 10;
	unsigned int cache_size = 1024;
};

// Global variables.
extern argv_options input_argv;
extern pcap_packet_structure pp_nf;
extern long double system_time;
#endif