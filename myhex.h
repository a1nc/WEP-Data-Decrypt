#ifndef _MYHEX_H_
#define _MYHEX_H_

struct HexToChar{
	unsigned char head;
	unsigned char rear;
};

extern void HexDataToChar(unsigned char *dataStream,unsigned char *CipherText);
#endif