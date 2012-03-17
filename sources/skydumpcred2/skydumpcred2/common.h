/*\
|*| Common functions for skype_login.c and skype_cred.c
|*| Functions were taken from:
|*|
|*| Skype Login v0.105 by Sean O'Neil.
|*| Copyright (c) 2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
|*| Includes: Password Login, User Registration
|*|
|*| Date: 08.07.2009
|*|
\*/

#define reverse_bytes(x,i,j,n)	for(i=0;(i)<(n/2);(i)++)((j)=(x)[i],(x)[i]=_bswap32((x)[(n)-1-(i)]),(x)[(n)-1-(i)]=_bswap32(j))

unsigned long MD5_Skype_Password (const char *username, const char *password, unsigned char *hash128);
void AES_CTR (const unsigned long *key, unsigned char *pkt, const u32 bytes, const u32 IV);
int Decrypt_Credentials(unsigned char *pData, unsigned char *credentials);
