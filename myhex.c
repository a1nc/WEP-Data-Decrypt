#include "myhex.h"
#include <stdio.h>
#include <string.h>

void HexDataToChar(unsigned char *dataStream,unsigned char *CipherText)
{
    unsigned char chTemp;
    struct HexToChar MYCH;
    int DataCount=0;
    for(int ii=0;ii<140*2;ii=ii+2)
	{
		if(CipherText[ii]>='0'&&CipherText[ii]<='9')
		{
			//chTemp=chTemp&0x00;
			chTemp = CipherText[ii] - 0x30;
			chTemp = chTemp &0x0f;
			chTemp = chTemp<<4;
			MYCH.head=chTemp;
		}
		if(CipherText[ii]>='a'&&CipherText[ii]<='f')
		{
			chTemp = CipherText[ii] - 0x57;
			chTemp = chTemp&0x0f;
			chTemp = chTemp<<4;
			MYCH.head = chTemp;
		}
		if(CipherText[ii+1]>='0'&&CipherText[ii+1]<='9')
		{
			//chTemp=chTemp&0x00;
			chTemp = CipherText[ii+1] - 0x30;
			chTemp = chTemp &0x0f;
			MYCH.rear=chTemp;
		}
		if(CipherText[ii+1]>='a'&&CipherText[ii+1]<='f')
		{
			chTemp = CipherText[ii+1] - 0x57;
			chTemp = chTemp&0x0f;
			MYCH.rear = chTemp;
		}
		//printf("%02x ",MYCH.head+MYCH.rear);
		dataStream[DataCount]=MYCH.head+MYCH.rear;
  		DataCount++;		
	}
}
