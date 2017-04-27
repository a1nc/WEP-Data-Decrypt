#include <pcap.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "myhex.h"
#include "myhex.c"
#include "crc32.c"
#include "rc4.h"
#include "rc4.c"

//
u_char ChallengeTextMem[1024][128];
int ChallengeTextCount = 0;
u_char StudentKey[200][5];
int StudentKeyCount = 0;

//func
void GetPacket(u_char *,const struct pcap_pkthdr *,const u_char *);
int CheckApMac(const u_char *,const u_char *);
int CheckChallengeText(const u_char*);
int CheckChallengePacket(const u_char*);
void ChallengeTextWrite(const u_char*);
void LoadStuKey(void);

int main()
{
  char errBuf[PCAP_ERRBUF_SIZE];
  char* DevName;
  //DevName = "ens33";
  DevName = "mon0";
  char* MacRecord[12];
  LoadStuKey();
  FILE* fp;
  char ch;
  if((fp=fopen("mac.data","r"))==NULL)
  {
      printf("data open error\n");
      getchar();
      //exit(1);
  }
  ch = fgetc(fp);
  while(ch!=EOF)
  {
      putchar(ch);
      ch = fgetc(fp);
  }
  fclose(fp);
 // DevName = "mon0";
  pcap_t* Device = pcap_open_live(DevName, 65535, 1, 0, errBuf);

  if(!Device)
  {
    printf("Error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
   
  int id = 0;
  pcap_loop(Device, -1, GetPacket, (u_char*)&id);
  pcap_close(Device);
  return 0;
}


void GetPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  int * id = (int *)arg; 
  u_char *macinput; 
  //printf("id: %d\n", ++(*id));
  //printf("Packet length: %d\n", pkthdr->len);
  //printf("Number of bytes: %d\n", pkthdr->caplen);
  //printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));  

  if(packet[26]==0xb0 && packet[27]==0x40 && CheckApMac(packet,macinput)==1)
  {
       //printf("%02x%02x%02x%02x\n",packet[24],packet[25],packet[26],packet[27]);
    // printf("Authen Device MAC: ");
    // int i;
    // for(i=0;i<5;i++)
    // {
    //    printf("%02x:",packet[36+i]);
    // }
    // printf("%02x\n\n",packet[36+i]);
  }
  
  if(CheckChallengeText(packet)==1)
  {
     // printf("Challenge Text: \n");
    for(int i=0;i<128;i++)
    {
       // printf("%02x ",packet[i+44]);
       // if((i+1)%16==0)putchar('\n');
        ChallengeTextMem[ChallengeTextCount][i]=packet[i+44];
    }


    // putchar('\n');
    // for(int i=0;i<128;i++)
    // {
    //     printf("%02x ",ChallengeTextMem[ChallengeTextCount][i]);
    //     if((i+1)%16==0)putchar('\n');
    // }
    // ChallengeTextCount++;
  }

  if(CheckChallengePacket(packet)==1)
  {
       int datalength=140;
        u_char dataStream[datalength];
        // printf("\nCipherText\n");
        for(int i=0;i<datalength;i++)
        {
            dataStream[i]=packet[i+54];
        }

    for(int i=0;i<StudentKeyCount;i++)
    {
       
        int calc32length=136;
        struct rc4_state state;
        
       
        u_char encryp[datalength];
        u_char crc32data[calc32length];
        uint32_t crc32value;
        
        u_char key[8];
        key[0]=0xb0;
        key[1]=0x2c;
        key[2]=0x09;
        for(int j=0;j<5;j++)
        {
            key[j+3]=StudentKey[i][j];
        }
        
       
        // printf("\nKey: b02c09%02x%02x%02x%02x%02x\n",key[3],
        //        key[4],
        //        key[5],
        //        key[6],
        //        key[7] );
        rc4_init(&state,key,8);
        rc4_crypt(&state,dataStream,encryp,datalength);

        //printf("\nDecrptText:\n");
        //   for (int i = 0; i < datalength ; i++)
        // {
        //      printf("%02x ",encryp[i]);
        //     if((i+1)%16==0)
        //      {
        //          putchar('\n');
        //      }
        //  }
        
        //printf("\n-----------------------\n");
        for(int i=0;i<calc32length;i++)
        {
            crc32data[i]=encryp[i];
            //printf("%02x ",crc32data[i]);
            //if((i+1)%16==0)putchar('\n');
        }
        //printf("\n-----------------------\n");
        crc32value = crc32(crc32data,136);
        //printf("\nCRC32: %08x \n",crc32value);
        u_char a1 = crc32value&0x000000ff;
        crc32value=crc32value>>8;
        u_char a2 = crc32value&0x000000ff;
        crc32value=crc32value>>8;
        u_char a3 = crc32value&0x000000ff;
        crc32value=crc32value>>8;
        u_char a4 = crc32value&0x000000ff;
        //printf("%02x %02x %02x %02x ",a1,a2,a3,a4);
        if(a1==encryp[136]&&a2==encryp[137]&&a3==encryp[138]&&a4==encryp[139])
        {
            //printf("\nConnect!!!!\n");
            printf("\nTime: %s",ctime((const time_t *)&pkthdr->ts.tv_sec));
            printf("MAC: ");
            int j;
            for(j=0;j<5;j++)
            {
                printf("%02x:",packet[36+j]);
            }
            printf("%02x\n",packet[36+j]);
            printf("StuID: %02x%02x%02x%02x%02x\n",StudentKey[i][0],
                                                    StudentKey[i][1],
                                                    StudentKey[i][2],
                                                    StudentKey[i][3],
                                                    StudentKey[i][4]);
        }
    }
  }
}

int CheckApMac(const u_char* packet,const u_char* inputMac)
{
    u_char MAC[6];
    MAC[0]=0x00;
    MAC[1]=0x18;
    MAC[2]=0X4d;
    MAC[3]=0xbb;
    MAC[4]=0xcc;
    MAC[5]=0x91;
    for(int i=0;i<6;i++)
    {
        if(MAC[i]!=packet[30+i])
        {
            return -1;
            //not AP's mac
        }
    }
    return 1;
    //is AP's MAC
}

int CheckChallengeText(const u_char* packet)
{
    if(packet[38]==0x02 &&packet[42]==0x10)
    {
        return 1;
        //is Challenget Text packet
    }
    return -1;
    //not CTP
}

int CheckChallengePacket(const u_char* packet)
{
    u_char *macinput;
    if(CheckApMac(packet,macinput)!=1)
    {
        return -1;
        //not Send to this AP Packet 
    }
    if(packet[26]==0xb0 && packet[27]==0x40 /*&& packet[50]==0xb0 &&packet[51]==0x2c &&packet[52]==0x09 */&&packet[53]==0x00)
    {
        //printf("Get An Authentication Packet : \n");
    }
    else
    {
        return -1;
        //not Challenget Packet
    }

    // for(int i=0;i<140;i++)
    // {
    //     printf("%02x ",packet[i+54]);
    //     if((i+1)%16==0)putchar('\n');
    // }
    // putchar('\n');

    return 1;
}


void LoadStuKey(void)
{
    FILE* fp;
    u_char u_char_TempStuKey[5];
    u_char char_TempStuKey[10];
    if((fp=fopen("stukey.data","r"))==NULL)
    {
        printf("Error stukey.data open fail\n");
    }
    while(!feof(fp))
    {
           //printf("%c",ch)
            fscanf(fp,"%s",char_TempStuKey);
           // puts(char_TempStuKey);
            HexDataToChar(StudentKey[StudentKeyCount],char_TempStuKey,5);
            printf("%02x %02x %02x %02x %02x\n",StudentKey[StudentKeyCount][0],StudentKey[StudentKeyCount][1],StudentKey[StudentKeyCount][2],StudentKey[StudentKeyCount][3],StudentKey[StudentKeyCount][4]);        
            StudentKeyCount++;
    }
    //printf("StudentKeyCount: %d\n",StudentKeyCount);
}
