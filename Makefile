CC=g++
CFLAGS=-std=c++17 -g -Wall

all: flow

flow:
	$(CC) $(CFLAGS) flowPacket.cpp NetFlow_Exporter.cpp udp.cpp -o flow -lpcap

clean:
	rm -f flow