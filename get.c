/*
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
*/
#include <stdio.h>
#include <stropts.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <string.h>



int getmac(void* mac_){

struct ifreq s;

int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

strcpy(s.ifr_name, "eth0");

if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

int i;

memcpy(mac_,s.ifr_addr.sa_data,6);

for (i = 0; i < 6; ++i)

printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);

puts("");
return 0;
}
return 1;
}


char myd[10]={0,};

void getip(void* ip,char* pargv_)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET&&strcmp(ifa->ifa_name, myd)==0) {
            
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            
            inet_ntop(AF_INET,&(sa->sin_addr),ip,INET_ADDRSTRLEN);
            
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, ip);
        }
    }

    freeifaddrs(ifap);
    return;
}

/*

int main(int argc,char* argv[])

{
  if(argc!=2) return 0;
    
  uint8_t myip[15];
  
  uint8_t mymac[6];

  strncpy(myd,argv[1],strlen(argv[1]));

  myd[strlen(argv[1])]='\0';

  printf("myd %s\n",myd);

  gett(myip,myd);
  
  printf("%s\n",myip);

  getmac(mymac);

  for (int i = 0; i < 6; ++i)

  printf(" %02x", mymac[i]);

  puts("");

}

*/