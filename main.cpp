#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct ethernet{
	unsigned char des_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
};
struct _ip{
	unsigned short protocol;
	unsigned char src_ip[4];
	unsigned char des_ip[4];
};

struct _tcp{
	unsigned int src_port;
	unsigned int des_port;
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct ethernet eth;
    struct _ip ip;
    struct _tcp tcp;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen );
    
    for(int i=0;i<6;i++) eth.des_mac[i]=packet[i];
    for(int i=0;i<6;i++) eth.src_mac[i]=packet[i+6];
     
    printf("src mac addr : ");
    for(int i=0;i<6;i++){
	printf("%02x",eth.src_mac[i]);
	if(i!=5) printf(":");
    }
    printf("\n");

    printf("des mac addr : ");
    for(int i=0;i<6;i++){
	printf("%02x",eth.des_mac[i]);
	if(i!=5) printf(":");
    }
    printf("\n");
    
    if(packet[12]==0x08 && packet[13]==0x00)eth.type=0x0800;
    else {
	    printf("\n\n");
	    continue;
    }

       
    printf("Type : %04x ( IP )\n",eth.type);
    
    for(int i=0;i<4;i++) ip.src_ip[i]=packet[i+26];
    for(int i=0;i<4;i++) ip.des_ip[i]=packet[i+30];

    printf("src ip addr : ");
    for(int i=0;i<4;i++){
	printf("%d",ip.src_ip[i]);
	if(i!=3) printf(".");
    }
    printf("\n");

    printf("des ip addr : ");
    for(int i=0;i<4;i++){
	printf("%d",ip.des_ip[i]);
	if(i!=3) printf(".");
    }
    printf("\n");

    if(packet[23]==0x06)ip.protocol=0x06;
    else {
	    printf("\n\n");
	    continue;
    }
    printf("Protocol %d ( TCP )\n",ip.protocol);

    int port;
    port =  (int)packet[34]*256+(int)packet[35];
    tcp.src_port = port;

    port = (int)packet[36]*256+(int)packet[37];
    tcp.des_port = port;

    printf("src port addr : ");
    printf("%d\n",tcp.src_port);

    printf("des port addr : ");
    printf("%d\n",tcp.des_port);
	
    for(int i =0;i<16;i++)printf("%02x ",packet[54+i]);
    printf("\n\n\n");
  }

  pcap_close(handle);
  return 0;
}
