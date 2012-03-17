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

#include "SkypeControl/skype_basics.h"
#include "md5/md5.h"
#include "sha1/sha1.h"
#include "rijndael/rijndael.h"
#include "miracl/miracl.h"
#include "common.h"

struct bigtype	skype_credentials_mod = {64, (u32*)skype_credentials_key};	// Skype 2048-bit credentials modulus


unsigned long MD5_Skype_Password (const char *username, const char *password, unsigned char *hash128)
{
	MD5_state		skyper = MD5_INIT;
	
	MD5_update (&skyper, username, (u32) strlen (username));
	MD5_update (&skyper, "\nskyper\n", 8);
	MD5_update (&skyper, password, (u32) strlen (password));
	MD5_end (&skyper);
	memcpy (hash128, skyper.hash, 16);
	return 16;
}

void AES_CTR (const unsigned long *key, unsigned char *pkt, const u32 bytes, const u32 IV)
{
	unsigned long		blk[8] = {IV, IV, 0, 0}, ks[60], i, j;
	
	aes_256_setkey (key, ks);
	for (j = 0; j+16 < bytes; j += 16)
	{
		aes_256_encrypt (blk, blk+4, ks);
		dword(pkt,j+ 0) ^= _bswap32(blk[4]);
		dword(pkt,j+ 4) ^= _bswap32(blk[5]);
		dword(pkt,j+ 8) ^= _bswap32(blk[6]);
		dword(pkt,j+12) ^= _bswap32(blk[7]);
		blk[3]++;
	}
	if (j < bytes)
	{
		aes_256_encrypt (blk, blk+4, ks);
		for (i = 0; j < bytes; j++, i++) pkt[j] ^= ((u8 *)(blk+4))[i^3];
	}
}

int Decrypt_Credentials(unsigned char *pData, unsigned char *credentials)
{
	int i;
	unsigned int j;
	unsigned char *s;
	unsigned long hash[5+1];
	struct bigtype		c = {64, (u32*)(pData)}, y = {64, (u32*) credentials};

	/* Decrypt */
	reverse_bytes (c.w,i,j,64);
	power (_MIPP_ &c, 0x10001, &skype_credentials_mod, &y);
	reverse_bytes (y.w,i,j,64);

	/* Restore source buffer back*/
	reverse_bytes (c.w,i,j,64);

	/* Verify */
	if (!(s = memchr (credentials, 0x41, 80))) 
	{
		fprintf (stderr, "Credentials don't contain mandatory 0x41 marker byte\n");
		return -1;
	}
	SHA1_hash (s, (u32)(credentials+255-20-s), hash);
	printf ("Credentials SHA-1 = "); bindump (hash, 20);
	for (i = 0; i < 5; i++) 
		if (dword(credentials,255-20+i*4) != _bswap32(hash[i])) 
		{
			fprintf (stderr, "Credentials SHA-1 checksum mismatch.\n");
			return -1;
		}
	printf ("Valid Credentials!\n");
	return 0;
}
