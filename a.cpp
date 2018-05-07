#include <iostream>
#include <pcap.h>
#include <time.h>
#include <stdint.h>
#include <string>
#include <fstream>
#include <string.h>
#include <pthread.h>

using namespace std;

#define STU_NUM_LEN 10
////////////////////
#define uch unsigned char
uch challenge_text_arr[1024][128];
int challenge_text_count = 0;
uch student_num_arr[1024][6];
int student_count = 0;
int packet_count = 0;
int packet_safe = 0;
////////////////////
static const uint32_t crc32tab[] = {
        0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
        0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
        0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
        0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
        0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
        0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
        0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
        0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
        0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
        0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
        0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
        0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
        0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
        0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
        0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
        0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
        0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
        0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
        0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
        0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
        0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
        0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
        0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
        0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
        0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
        0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
        0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
        0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
        0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
        0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
        0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
        0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
        0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
        0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
        0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
        0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
        0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
        0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
        0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
        0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
        0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
        0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
        0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
        0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
        0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
        0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
        0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
        0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
        0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
        0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
        0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
        0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
        0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
        0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
        0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
        0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
        0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
        0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
        0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
        0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
        0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
        0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
        0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
        0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};
////////////////////

//about pcap
void GetPacket(uch *arg,const struct pcap_pkthdr* pkthdr,const uch* packet);

//about rc4 encrypt and decrypt
void swap_bytes(uch*a, uch *b);
void rc4_init(struct rc4_state *state, const uch *key, int keylen);
void rc4_crypt(struct rc4_state *state,const uch *inbuf, uch *outbuf, int buflen);

//about crc 
uint32_t crc32(const uch *buf,uint32_t size);

//about load data and print info
void write_checkin_record(char *time,char *id,char *mac);
void load_student_info(void);
void load_pre_mac(void);
char* hex_to_char(uch *input_hex,int hex_length);
uch * char_to_hex(char *input_char,int char_length);

//about datapacket
#define BEACON_FRAME_SIGN 0x80
#define BEACON_FRAME_SET 12
#define MAC_OFFSET_BEACON 22
#define MAC_LEN 6
#define MAC_OFFSET_PACKET 30

#define IV_START_SET 50
#define IV_LEN 3

#define SEQ1_MANAGEMENT_SET 26
#define SEQ1_MANAGEMENT_VAL 0xb0
#define SEQ1_SEQFLAG_SET 52
#define SEQ1_SEQFLAG_VAL 0x01

#define SEQ2_MANAGEMENT_SET 13
#define SEQ2_MANAGEMENT_VAL 0xb0
#define SEQ2_SEQFLAG_SET 39
#define SEQ2_SEQFLAG_VAL 0x02
#define SEQ2_TEXTFLAG_SET 42
#define SEQ2_TEXTFLAG_VAL 0x10

#define SEQ3_MANAGEMENT_SET 26
#define SEQ3_MANAGEMENT_VAL 0xb0
#define SEQ3_PROTECT_SET 27
#define SEQ3_PROTECT_VAL 0x40
#define SEQ3_KEYINDEX_SET 53
#define SEQ3_KEYINDEX_VAL 0x00 

#define  SEQ3_DATA_START 54
#define  SEQ3_DATA_LEN 140
#define CRC32_LEN 136

struct pth_param{
    const struct pcap_pkthdr* pkthdr;
    const unsigned char* packet;
    int length;
};

pth_param packet_buffer[1024];
int packet_offset = 0;

/*Beacon Frame: packet[12]==0x80*/
int pth_flag = 0;
uch ap_mac[MAC_LEN];
int get_ap_mac = 0;
int is_beacon(const uch *packet);
void set_ap_mac(uch *input_mac);
int mac_flag(void){return get_ap_mac;}
int check_ap_mac(const uch *);
int check_challenge_text(const uch*);
int check_challenge_packet(const uch*);
void packet_detail_check(const uch* packet,const struct pcap_pkthdr* pkthdr,const int length);

int is_beacon(const uch *packet){
     if(packet[BEACON_FRAME_SET] == BEACON_FRAME_SIGN ){
        unsigned char input_mac[MAC_LEN];
        for(int i=0;i<MAC_LEN;i++)
            input_mac[i]=packet[MAC_OFFSET_BEACON+i];
        set_ap_mac(input_mac);
        return 1;
    }
    return  -1;
}

void set_ap_mac(uch *input_mac){
    for(int i=0;i<MAC_LEN;i++)
        ap_mac[i]=input_mac[i];
}

int check_ap_mac(const uch* packet){
    for(int i=0;i<MAC_LEN;i++){
        if(ap_mac[i]!=packet[MAC_OFFSET_PACKET+i])
            return -1;
    }
    return 1;
}

int check_auth_1(const uch* packet){
    if(packet[ SEQ1_MANAGEMENT_SET]== SEQ1_MANAGEMENT_VAL 
    && packet[ SEQ1_SEQFLAG_SET]== SEQ1_SEQFLAG_VAL){
        return 1;
    }else{
        return -1;
    }
}

int check_auth_2(const uch* packet){
    if(packet[ SEQ2_MANAGEMENT_SET]== SEQ2_MANAGEMENT_VAL 
    && packet[ SEQ2_SEQFLAG_SET]== SEQ2_SEQFLAG_VAL){
        return 1;
    }else{
        return -1;
    }
}

int check_auth_3(const uch* packet){
    if(packet[ SEQ3_MANAGEMENT_SET]== SEQ3_MANAGEMENT_VAL 
    && packet[ SEQ3_PROTECT_SET]== SEQ3_PROTECT_VAL 
    && packet[ SEQ3_KEYINDEX_SET]== SEQ3_KEYINDEX_VAL){
        return 1;
    }else{
        return -1;
    }     
}

void get_init_vector(const uch* packet,uch* iv){
    //IV_LEN 3    
    for(int i=0;i<IV_LEN;i++)
        iv[i]=packet[IV_START_SET+i];
}

////////////////////////////////////////////////////////////////////////
struct rc4_state {
    uch  perm[256];
    uch  index1;
    uch  index2;
};

void swap_bytes(uch *a,uch *b){
    uch temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

void rc4_init(struct rc4_state *state,const uch *key,int keylen){
    uch j;
    int i;
    /* Initialize state with identity permutation */
    for (i = 0; i < 256; i++)
        state->perm[i] = (u_char)i;
        state->index1 = 0;
        state->index2 = 0;

    /* Randomize the permutation using key data */
    for (j = i = 0; i < 256; i++) {
        j += state->perm[i] + key[i % keylen];
        swap_bytes(&state->perm[i], &state->perm[j]);
    }
}

void rc4_crypt(struct rc4_state *state,const uch *inbuf,uch *outbuf,int buflen){
    int i;
    uch j;

    for (i = 0; i < buflen; i++) {
        /* Update modification indicies */
        state->index1++;
        state->index2 += state->perm[state->index1];

        /* Modify permutation */
        swap_bytes(&state->perm[state->index1],&state->perm[state->index2]);

        /* Encrypt/decrypt next byte */
        j = state->perm[state->index1] + state->perm[state->index2];
        outbuf[i] = inbuf[i] ^ state->perm[j];
    }
}

//////////////////////////////////////////////////////////////////////////
uint32_t crc32(const uch* buf,uint32_t size){
    uint32_t i, crc;
    crc = 0xFFFFFFFF;
    for (i = 0; i < size; i++)
        crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    return crc^0xFFFFFFFF;
}

///////////////////////////////////////////////////////////////////////////
uch * char_to_hex(char *input_char,int char_length){
    //only support lower case alphabets and numbers range 0x0 to 0xf
    uch *output_hex;
    output_hex = new uch[(char_length+1)/2];
    for(int i=0,j=0;i<char_length;i+=2,j++){
        output_hex[i/2] = 0x00;

        (input_char[i]>='0' && input_char[i]<='9') 
        ? output_hex[j]=(((input_char[i]-0x30)&0x0f)<<4)&0xf0  
        : output_hex[j]=(((input_char[i]-0x57)&0x0f)<<4)&0xf0 ;
        
        (input_char[i+1]>='0' && input_char[i+01]<='9') 
        ? output_hex[j]=output_hex[j]|((input_char[i+1]-0x30)&0x0f)
        : output_hex[j]=output_hex[j]|((input_char[i+1]-0x57)&0x0f);
    }
    return output_hex;
}

char* hex_to_char(uch *input_hex,int hex_length){
    char *output_char;
    output_char = new char[hex_length*2];
    uch temp_hex;
    char temp_head = 0x00;
    char temp_rear = 0x00;
    for(int i=0;i<hex_length*2;i+=2){
        temp_hex=input_hex[i/2];
        temp_rear = temp_hex & 0x0f;
        temp_head = (temp_hex>>4) & 0x0f;

        (temp_head>=0x0 && temp_head<=0x09) ? output_char[i]=temp_head+0x30 : output_char[i]=temp_head+0x57;
        (temp_rear>=0x0 && temp_rear<=0x09) ? output_char[i+1]=temp_rear+0x30 : output_char[i+1]=temp_rear+0x57;
    }
    return output_char;
}

void write_checkin_record(char *time,char *id,char *mac){
    cout<<"Time: "<<time;
    cout<<"ID:   "<<id;
    cout<<"MAC:  "<<mac;
}

void load_student_info(void){
    ifstream file;
    file.open("student.data",ios::in);

    uch *temp_info;
    uch student_num_uch[STU_NUM_LEN/2];
    char student_num_char[STU_NUM_LEN];
    if(file.fail()){
        cout<<"SYSTEM: Error during loading student.data"<<endl;
    }
    while(!file.eof()){
        file.getline(student_num_char,STU_NUM_LEN+1);
        //cout<<"STUDENT: "<<student_num_char<<" LENGTH: "<<sizeof(student_num_char)<<endl;
        temp_info = new uch[STU_NUM_LEN/2+1];
        temp_info = char_to_hex(student_num_char,sizeof(student_num_char));
        int offset=0;
        while(*temp_info!=NULL){
            student_num_arr[student_count][offset]=*temp_info;
            temp_info++;
            offset++;
        }
        
        int temp_count = 0;
        cout<<student_count<<" STUDENT ID: ";
        while(student_num_arr[student_count][temp_count]!=NULL){
            printf("%02x ",student_num_arr[student_count][temp_count]);
            temp_count++;
        }
        cout<<endl;
        student_count++;
    }
    file.close();
}

void *say_hello(void *args){
   while(true){
       if(packet_offset>0 && packet_safe==1){
           cout<<"1 log"<<endl;
           packet_offset--;
           //printf("Pthread packet len:%d\n",packet_buffer[packet_offset].length);
           packet_detail_check(packet_buffer[packet_offset].packet,packet_buffer[packet_offset].pkthdr,packet_buffer[packet_offset].length);
           cout<<"2 log"<<endl;
           
       }
   }
}

int main(){
   load_student_info();
    //sys.FuncLoadMAC();
    pthread_t tid;
    int ret = pthread_create(&tid,NULL,say_hello,NULL);
    if(ret!=0){
        cout<<"Pth create error."<<endl;
    }
    
    char errBuf[PCAP_ERRBUF_SIZE];
    char *DevName;
    DevName = "mon0";
    pcap_t * Device = pcap_open_live(DevName,65535,1,0,errBuf);

    if(!Device){
        cout<<"Error: pcap_open_live():"<<errBuf<<endl;
        return 0;
    }

    int id=0;
    pcap_loop(Device,-1,GetPacket,(u_char*)&id);
    pcap_close(Device);
    return 0;
}


void packet_detail_check(const uch* packet,const struct pcap_pkthdr* pkthdr,const int length){
        uch IV[3]={0x0};
        get_init_vector(packet,IV);
        cout<<"Test"<<endl;
        printf("TEST packet len:%d\n",length);
        //get the challenge data in this packet
        
        //change a here ***********
        //u_char dataStream[SEQ3_DATA_LEN];
        u_char *dataStream;
        dataStream = new u_char [length-SEQ3_DATA_START-4];

        for(int i=0;i< length-SEQ3_DATA_START-4;i++)
            dataStream[i]=packet[i+ SEQ3_DATA_START];
        
        //generate the true key
        for(int stu_offset=0;stu_offset<student_count;stu_offset++){
            u_char key[8]={0x00};
            for(int i=0;i<3;i++)
                key[i]=IV[i];

            for(int j=0;j<5;j++)
                    key[j+3]=student_num_arr[stu_offset][j];
            
            u_char encryp[length-SEQ3_DATA_START-4];
            u_char crc32data[length-SEQ3_DATA_START-8];
            uint32_t crc32value;
            struct rc4_state state;
            rc4_init(&state,key,8);
            rc4_crypt(&state,dataStream,encryp,length-SEQ3_DATA_START-4);
            delete []dataStream;
            for(int i=0;i<(length-SEQ3_DATA_START-8);i++)
                crc32data[i]=encryp[i];

            uch crc2byte_arr[4]={0x00};
            crc32value = crc32(crc32data,length-SEQ3_DATA_START-8);
            for(int i=0;i<4;i++){
                crc2byte_arr[i]=crc32value&0x000000ff;
                crc32value=crc32value>>8;
            }

            uch ICV[4]={0x00};
            for(int i=0;i<4;i++){
                ICV[i]=encryp[length-SEQ3_DATA_START-8+i];
            }

            if(crc2byte_arr[0]==ICV[0]
            && crc2byte_arr[1]==ICV[1]
            && crc2byte_arr[2]==ICV[2]
            && crc2byte_arr[3]==ICV[3]){     
                cout<<"Pcap get time: "<<ctime((const time_t *)&pkthdr->ts.tv_sec);

                char *TempStuKey;
                TempStuKey = new char [10];
                memset(TempStuKey,0,10);
                cout<<TempStuKey<<endl;
                TempStuKey=hex_to_char(student_num_arr[stu_offset],5);
                cout<<TempStuKey<<endl;

                unsigned char TempMAC[6];
                char *MACPrint;
                MACPrint = new char [12];
                for(int j=0;j<6;j++){
                    TempMAC[j] = packet[36 + j];}
                
                MACPrint = hex_to_char(TempMAC,6);
                cout<<MACPrint<<endl;
                break;
            }
        }
}
//int i=0;





void GetPacket(unsigned char *arg,const struct pcap_pkthdr* pkthdr,const unsigned char *packet)
{    
    if((packet_count++)%200==0){
        cout<<"We Get 200 packet"<<endl;
        //printf("packet len:%d\n",pkthdr->len);

    }
    if(check_auth_3(packet)==1){
        //printf("AUTH3 len:%d\n",pkthdr->len);
        packet_safe = 0;
        pth_param param;
        //struct pcap_pkthdr temp
        param.pkthdr=pkthdr;
        param.packet=packet;
        param.length=pkthdr->len;
        packet_buffer[packet_offset]=param;
        packet_offset++;
        packet_safe = 1;
        //pthread_exit(NULL);
    }
}
