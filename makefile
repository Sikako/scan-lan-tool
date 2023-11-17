CC = gcc

ipscanner: main.o pcap.o fill_packet.o debug_tools.o fill_packet.h pcap.h
	$(CC) -o ipscanner main.o pcap.o fill_packet.o debug_tools.o -lpcap

main.o: main.c
	$(CC) -c main.c

pcap.o: pcap.c
	$(CC) -c pcap.c

fill_packet.o: fill_packet.c
	$(CC) -c fill_packet.c

debug_tools.o: debug_tools.c
	$(CC) -c debug_tools.c

.INTERMEDIATE: main.o pcap.o fill_packet.o debug_tools.o