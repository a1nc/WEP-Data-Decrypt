#include <iostream>
#include <pcap.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <fstream>
using namespace std;

void GetPacket(unsigned char *arg,const struct pcap_pkthdr* pkthdr,const unsigned char *packet);
/////////////////
#define STU_KEY_LENGTH 10
/////////////////
using namespace std;

unsigned char ChallengeTextMem[1024][128];
int CTCount = 0;
unsigned char StudentKey[200][6];
int SKCount = 0;

struct st_FuncFuncHexToChar{
    unsigned char head;
    unsigned char rear;
};

/////////////////
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
/////////////////

struct rc4_state {
    unsigned char  perm[256];
    unsigned char  index1;
    unsigned char  index2;
};

class RC4{

public:
    void swap_bytes(unsigned char *a, unsigned char *b);
    void rc4_init(struct rc4_state *state, const unsigned char *key, int keylen);
    void rc4_crypt(struct rc4_state *state,const unsigned char *inbuf, unsigned char *outbuf, int buflen);
};

void RC4::swap_bytes(unsigned char *a, unsigned char *b)
{
    unsigned char temp;

    temp = *a;
    *a = *b;
    *b = temp;
}

/*
 * Initialize an RC4 state buffer using the supplied key,
 * which can have arbitrary length.
 */
void RC4::rc4_init(struct rc4_state *const state, const u_char *key, int keylen)
{
    u_char j;
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

/*
 * Encrypt some data using the supplied RC4 state buffer.
 * The input and output buffers may be the same buffer.
 * Since RC4 is a stream cypher, this function is used
 * for both encryption and decryption.
 */
void RC4::rc4_crypt(struct rc4_state *const state,
                    const u_char *inbuf, u_char *outbuf, int buflen)
{
    int i;
    u_char j;

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

class CRC{
private:
public:
    uint32_t crc32( const unsigned char *buf, uint32_t size)
    {
        uint32_t i, crc;
        crc = 0xFFFFFFFF;
        for (i = 0; i < size; i++)
            crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
        return crc^0xFFFFFFFF;
    }
};

class System{
private:
    ofstream ofp;
public:
    void FuncWriteRecord(char *time,char *id,char * mac)
    {
        cout<<time<<id<<mac<<endl;
        ofp<<time<<endl;
        ofp<<id<<endl;
        ofp<<mac<<endl;
    }
    void FuncSetAPsMAC(void);
    void FuncLoadStuKey(void);
    void FuncLoadMAC(void);
    void FuncFuncHexToChar(unsigned char *,char *,int );
    void FuncHexToChar(unsigned char *,char *,int );
    char* FuncPrintTime(void)
    {
        time_t timep;
        time(&timep);
        cout<<ctime(&timep);
        return ctime(&timep);
    }
    char* FuncPrintMAC(const unsigned char *packet)
    {
        unsigned char TempMAC[6];
        char MACPrint[13];
        memset(MACPrint,0,13);
        for(int j=0;j<6;j++)
        {
            TempMAC[j] = packet[36 + j];
        }
        FuncHexToChar(TempMAC,MACPrint,6);
        cout<<MACPrint<<endl;
        return MACPrint;
    }
    char* FuncPrintStudentKey(int index)
    {
        char TempStuKey[11];
        memset(TempStuKey,0,11);
        FuncHexToChar(StudentKey[index],TempStuKey,5);
        cout<<TempStuKey<<endl;
        return TempStuKey;
    }
};

void System::FuncHexToChar(unsigned char *hexstr, char *charstr, int length)
{
    unsigned char TempCh;
    char Temp=0x00;
    int j = 0;
    for(int i=0;i<length;i++)
    {
        TempCh = hexstr[i];
        Temp = TempCh & 0x0f;
        if(Temp >= 0x0 && Temp <=0x9)
        {
            charstr[j+1] = Temp+0x30;
        }
        else
        {
            charstr[j+1] = Temp+0x57;
        }
        TempCh = TempCh>>4;
        Temp = TempCh & 0x0f;
        if(Temp >= 0x0 && Temp <=0x9)
        {
            charstr[j] = Temp+0x30;
        }
        else
        {
            charstr[j] = Temp+0x57;
        }
        j=j+2;
    }
}

void System::FuncLoadMAC(void)
{
    ifstream fp;
    ofp.open("record.txt",ios::out);
    char MAC[50];
    fp.open("mac.data",ios::in);
    if(fp.fail())
    {
        cout<<"SYSTEM: Error during load MAC"<<endl;
    }
    while(!fp.eof())
    {
        fp.getline(MAC,50);
        cout<<"MAC: "<<MAC<<endl;
    }
    fp.close();
}

void System::FuncLoadStuKey(void)
{
    ifstream fp;

    unsigned char StuKey_uchar[STU_KEY_LENGTH/2];
    char StuKey_char[STU_KEY_LENGTH];
    fp.open("stukey.data",ios::in);
    if(fp.fail())
    {
        cout<<"SYSTEM: Error during loading stukey"<<endl;
    }
    while(!fp.eof())
    {
        fp.getline(StuKey_char,STU_KEY_LENGTH+1);
        cout<<StuKey_char<<strlen(StuKey_char)<<endl;
        int Length = strlen(StuKey_char)/2;
        FuncFuncHexToChar(StudentKey[SKCount],StuKey_char,Length);
        for(int i=0;i<Length;i++)
        {
            cout<<hex<<StudentKey[SKCount][i]<<" ";
        }
        cout<<endl;
        SKCount++;
    }
    fp.close();
}

void System::FuncFuncHexToChar(unsigned char *DataStream,char *CipherText,int Length)
{
    unsigned char ChTemp;
    st_FuncFuncHexToChar MyCh;
    int DataCount=0;
    for(int i=0;i<Length*2;i=i+2)
    {
        if(CipherText[i]>='0'&&CipherText[i]<='9')
        {
            //ChTemp=ChTemp&0x00;
            ChTemp = CipherText[i] - 0x30;
            ChTemp = ChTemp &0x0f;
            ChTemp = ChTemp<<4;
            MyCh.head=ChTemp;
        }
        else
        {
            ChTemp = CipherText[i] - 0x57;
            ChTemp = ChTemp&0x0f;
            ChTemp = ChTemp<<4;
            MyCh.head = ChTemp;
        }
        if(CipherText[i+1]>='0'&&CipherText[i+1]<='9')
        {
            //ChTemp=ChTemp&0x00;
            ChTemp = CipherText[i+1] - 0x30;
            ChTemp = ChTemp &0x0f;
            MyCh.rear=ChTemp;
        }
        else
        {
            ChTemp = CipherText[i+1] - 0x57;
            ChTemp = ChTemp&0x0f;
            MyCh.rear = ChTemp;
        }
        DataStream[DataCount]=MyCh.head + MyCh.rear;
        DataCount++;
    }
}

class DataPacket{
private:
    unsigned char APsMAC[6];
    int FlagGetAPsMAC = 0;
public:
    int JugIsBeacon(const unsigned char *packet);
    void FuncSetAPsMAC(unsigned char *inputMAC);

    int FlagMAC(void)
    {
        return FlagGetAPsMAC;
    }

    void SetFlagMAC(int flag)
    {
        if((flag == 0) || (flag == 1))
        {
            FlagGetAPsMAC = flag;
        }
    }

    int CheckApMac(const unsigned char *);
    int CheckChallengeText(const unsigned char *);
    int CheckChallengePacket(const unsigned char *);
    //void ChallengeTextWrite(const unsigned char *);
};

int DataPacket::JugIsBeacon(const unsigned char *packet)
{
    /*Beacon Frame: packet[12]==0x80*/
    if(packet[12] == 0x80 )
    {
        unsigned char inputMAC[6];
        for(int i=0;i<6;i++)
        {
            inputMAC[i]=packet[22+i];
        }
        FuncSetAPsMAC(inputMAC);
        return 1;
    }
    return  -1;
}

void DataPacket::FuncSetAPsMAC(unsigned char *inputMAC)
{
    for(int i=0;i<6;i++)
    {
        APsMAC[i]=inputMAC[i];
    }
}

int DataPacket::CheckApMac(const unsigned char *packet)
{
    for(int i=0;i<6;i++)
    {
        if(APsMAC[i]!=packet[30+i])
        {
            return -1;
            //Not AP's MAC
        }
    }
    return 1;
    //Is AP's MAC
}

int DataPacket::CheckChallengeText(const unsigned char *packet)
{
    if(packet[38]==0x02 && packet[42]==0x10)
    {
        return 1;
        //Is ChallengeText packet
    }
    else
    {
        return -1;
        //Not CTP
    }
}

int DataPacket::CheckChallengePacket(const unsigned char *packet)
{
    if(DataPacket::CheckApMac(packet)!=1)
    {
        return -1;
        //Not Send to this Ap
    }
    if(packet[26]==0xb0 && packet[27]==0x40 && packet[53]==0x00)
    {

    }
    else
    {
        return -1;
    }
    return 1;
}

System  sys;
DataPacket datapacket;
CRC crc;
RC4 rc4;

int main()
{


    sys.FuncLoadStuKey();
    sys.FuncLoadMAC();

    char errBuf[PCAP_ERRBUF_SIZE];
    char *DevName;
    DevName = "mon0";
    pcap_t * Device = pcap_open_live(DevName,65535,1,0,errBuf);

    if(!Device)
    {
        cout<<"Error: pcap_open_live():"<<errBuf<<endl;
        return 0;
    }

    int id=0;
    pcap_loop(Device,-1,GetPacket,(u_char*)&id);
    pcap_close(Device);
    return 0;
}

void GetPacket(unsigned char *arg,const struct pcap_pkthdr* pkthdr,const unsigned char *packet)
{
    int *id = (int *)arg;
    if(datapacket.JugIsBeacon(packet) == 1 && datapacket.FlagMAC()==0)
    {
        //To Get The APsMAC at the first time get the Beacon Frame
        datapacket.SetFlagMAC(1);
    }

    if(datapacket.CheckChallengeText(packet)==1)
    {
        //Challenge Text Buffer
        for(int i=0;i<128;i++)
        {
            ChallengeTextMem[CTCount][i]=packet[i+44];
        }
    }

    if(datapacket.CheckChallengePacket(packet)==1)
    {
        int datalength=140;
        u_char dataStream[datalength];

        for(int i=0;i<datalength;i++)
        {
            dataStream[i]=packet[i+54];
        }

        for(int i=0;i<SKCount;i++)
        {

            int calc32length=136;
            struct rc4_state state;

            u_char encryp[datalength];
            u_char crc32data[calc32length];
            uint32_t crc32value;
            u_char key[8];
            key[0]=packet[50+0];
            key[1]=packet[50+1];
            key[2]=packet[50+2];

            for(int j=0;j<5;j++)
            {
                key[j+3]=StudentKey[i][j];
            }

            rc4.rc4_init(&state,key,8);
            rc4.rc4_crypt(&state,dataStream,encryp,datalength);

            for(int i=0;i<calc32length;i++)
            {
                crc32data[i]=encryp[i];
            }
            crc32value = crc.crc32(crc32data,136);
            u_char a1 = crc32value&0x000000ff;
            crc32value=crc32value>>8;
            u_char a2 = crc32value&0x000000ff;
            crc32value=crc32value>>8;
            u_char a3 = crc32value&0x000000ff;
            crc32value=crc32value>>8;
            u_char a4 = crc32value&0x000000ff;

            if(a1==encryp[136]&&a2==encryp[137]&&a3==encryp[138]&&a4==encryp[139])
            {
                sys.FuncPrintTime();
                sys.FuncPrintStudentKey(i);
                sys.FuncPrintMAC(packet);
//                sys.FuncWriteRecord(sys.FuncPrintTime(),sys.FuncPrintStudentKey(i),sys.FuncPrintMAC(packet));
            }
        }
    }
}
