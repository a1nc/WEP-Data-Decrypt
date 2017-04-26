#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "rc4.c"
#include "myhex.c"

//func
void GetPacket(u_char *,const struct pcap_pkthdr *,const u_char *);


int main()
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  devStr = "mon0";
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
  
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
   
  int id = 0;
  pcap_loop(device, -1, GetPacket, (u_char*)&id);
  pcap_close(device);
  return 0;
}



void GetPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  int * id = (int *)arg;  
  //printf("id: %d\n", ++(*id));
  //printf("Packet length: %d\n", pkthdr->len);
  //printf("Number of bytes: %d\n", pkthdr->caplen);
  //printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  char c0 = 0x00;
  char cb0 = 0xb0;
  char c8 = 0x8;
  if(packet[26]==0x40 && packet[27]==0x00)
  {
       printf("%02x%02x%02x%02x\n",packet[24],packet[25],packet[26],packet[27]);
       printf("MAC: ");
       int i;
       for(i=0;i<5;i++)
       {
           printf("%02x:",packet[36+i]);
       }
           printf("%02x\n\n",packet[36+i]);
  }
}
