all: send_arp

send_arp: main.o
	gcc -o send_arp main.o -lpcap

main.o: main.c
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o send_arp

