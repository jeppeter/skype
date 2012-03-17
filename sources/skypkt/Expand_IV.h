#ifndef _Expand_IV_
#define _Expand_IV_

#include <stdio.h>
#include <string.h>

#include "Process_IV.h"


#define CRC1(s,g)		(s=((s)&1)?((s)>>1)^(g):((s)>>1))
#define CRC8(s,g)		for(j=0;j<8;j++)CRC1(s,g);
#define CRC32(s,g)		for(j=0;j<32;j++)CRC1(s,g);
static u32 crc8  (const u8  *x, u32 n){u32 j,z=-1;for(;n;n--){z^=*x++;CRC8 (z,0xEDB88320);}return z;}
static u32 crc32 (const u32 *x, u32 n){u32 j,z=-1;for(;n;n--){z^=*x++;CRC32(z,0xEDB88320);}return z;}

typedef struct _RC4_context
{
	u32						from_IP, to_IP, from_port, to_port, seq;
	u8						i, j, s[256];
	struct _RC4_context		*next;
} RC4_context;


extern void decrypt_all (u8 * b, u32 bsize);
extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test); // RC4 encrypt/decrypt (test=1 leaves rc4 context unaltered)
extern void Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags); // Main RC4 IV expansion function

extern u32 Expand_IVa (u32 * const key, u32 n);	// Top-layer RC4 IV expansion function
extern u32 Expand_IVb (u32 * const key, u32 n);	// Top-layer RC4 IV expansion function

extern u32 Expand_IV1 (u32 * const key, u32 n);
extern u32 Expand_IV2 (u32 * const key, u32 n);
extern u32 Expand_IV3 (u32 * const key, u32 n);
extern u32 Expand_IV4 (u32 * const key, u32 n);
extern u32 Expand_IV5 (u32 * const key, u32 n);
extern u32 Expand_IV6 (u32 * const key, u32 n);
extern u32 Expand_IV7 (u32 * const key, u32 n);
extern u32 Expand_IV8 (u32 * const key, u32 n);
extern u32 Expand_IV9 (u32 * const key, u32 n);
extern u32 Expand_IV10 (u32 * const key, u32 n);
extern u32 Expand_IV11 (u32 * const key, u32 n);
extern u32 Expand_IV12 (u32 * const key, u32 n);
extern u32 Expand_IV13 (u32 * const key, u32 n);
extern u32 Expand_IV14 (u32 * const key, u32 n);
extern u32 Expand_IV15 (u32 * const key, u32 n);
extern u32 Expand_IV16 (u32 * const key, u32 n);
extern u32 Expand_IV17 (u32 * const key, u32 n);
extern u32 Expand_IV18 (u32 * const key, u32 n);
extern u32 Expand_IV19 (u32 * const key, u32 n);
extern u32 Expand_IV20 (u32 * const key, u32 n);
extern u32 Expand_IV21 (u32 * const key, u32 n);
extern u32 Expand_IV22 (u32 * const key, u32 n);
extern u32 Expand_IV23 (u32 * const key, u32 n);
extern u32 Expand_IV24 (u32 * const key, u32 n);

#define	Recurse_IV1(key,n)	{if (Expand_IV1 (key, n)) 1;}
#define	Recurse_IV2(key,n)	{if (Expand_IV2 (key, n)) 1;}
#define	Recurse_IV3(key,n)	{if (Expand_IV3 (key, n)) 1;}
#define	Recurse_IV4(key,n)	{if (Expand_IV4 (key, n)) 1;}
#define	Recurse_IV5(key,n)	{if (Expand_IV5 (key, n)) 1;}
#define	Recurse_IV6(key,n)	{if (Expand_IV6 (key, n)) 1;}
#define	Recurse_IV7(key,n)	{if (Expand_IV7 (key, n)) 1;}
#define	Recurse_IV8(key,n)	{if (Expand_IV8 (key, n)) 1;}
#define	Recurse_IV9(key,n)	{if (Expand_IV9 (key, n)) 1;}
#define	Recurse_IV10(key,n)	{if (Expand_IV10 (key, n)) 1;}
#define	Recurse_IV11(key,n)	{if (Expand_IV11 (key, n)) 1;}
#define	Recurse_IV12(key,n)	{if (Expand_IV12 (key, n)) 1;}
#define	Recurse_IV13(key,n)	{if (Expand_IV13 (key, n)) 1;}
#define	Recurse_IV14(key,n)	{if (Expand_IV14 (key, n)) 1;}
#define	Recurse_IV15(key,n)	{if (Expand_IV15 (key, n)) 1;}
#define	Recurse_IV16(key,n)	{if (Expand_IV16 (key, n)) 1;}
#define	Recurse_IV17(key,n)	{if (Expand_IV17 (key, n)) 1;}
#define	Recurse_IV18(key,n)	{if (Expand_IV18 (key, n)) 1;}
#define	Recurse_IV19(key,n)	{if (Expand_IV19 (key, n)) 1;}
#define	Recurse_IV20(key,n)	{if (Expand_IV20 (key, n)) 1;}
#define	Recurse_IV21(key,n)	{if (Expand_IV21 (key, n)) 1;}
#define	Recurse_IV22(key,n)	{if (Expand_IV22 (key, n)) 1;}
#define	Recurse_IV23(key,n)	{if (Expand_IV23 (key, n)) 1;}
#define	Recurse_IV24(key,n)	{if (Expand_IV24 (key, n)) 1;}

static u32 Test_IV1 (u32 * const key, const u32 n) { Process_IV1(); return 0; }
static u32 Test_IV2 (u32 * const key, const u32 n) { Process_IV2(); return 0; }
static u32 Test_IV3 (u32 * const key, const u32 n) { Process_IV3n(n); return 0; }
static u32 Test_IV4 (u32 * const key, const u32 n) { Process_IV4(); return 0; }
static u32 Test_IV5 (u32 * const key, const u32 n) { Process_IV5(); return 0; }
static u32 Test_IV6 (u32 * const key, const u32 n) { Process_IV6(); return 0; }
static u32 Test_IV7 (u32 * const key, const u32 n) { Process_IV7n(n); return 0; }
static u32 Test_IV8 (u32 * const key, const u32 n) { Process_IV8(); return 0; }
static u32 Test_IV9 (u32 * const key, const u32 n) { Process_IV9(); return 0; }
static u32 Test_IV10 (u32 * const key, const u32 n) { Process_IV10(); return 0; }
static u32 Test_IV11 (u32 * const key, const u32 n) { Process_IV11(); return 0; }
static u32 Test_IV12 (u32 * const key, const u32 n) { Process_IV12(); return 0; }
static u32 Test_IV13 (u32 * const key, const u32 n) { Process_IV13(); return 0; }
static u32 Test_IV14 (u32 * const key, const u32 n) { Process_IV14(); return 0; }
static u32 Test_IV15 (u32 * const key, const u32 n) { Process_IV15(); return 0; }
static u32 Test_IV16 (u32 * const key, const u32 n) { Process_IV16n(n); return 0; }
static u32 Test_IV17 (u32 * const key, const u32 n) { Process_IV17(); return 0; }
static u32 Test_IV18 (u32 * const key, const u32 n) { Process_IV18n(n); return 0; }
static u32 Test_IV19 (u32 * const key, const u32 n) { Process_IV19(); return 0; }
static u32 Test_IV20 (u32 * const key, const u32 n) { Process_IV20n(n); return 0; }
static u32 Test_IV21 (u32 * const key, const u32 n) { Process_IV21(); return 0; }
static u32 Test_IV22 (u32 * const key, const u32 n) { Process_IV22(); return 0; }
static u32 Test_IV23 (u32 * const key, const u32 n) { Process_IV23(); return 0; }
static u32 Test_IV24 (u32 * const key, const u32 n) { Process_IV24(); return 0; }
static u32 Test_IV25 (u32 * const key, const u32 n) { Process_IV25(); return 0; }
static u32 Test_IV26 (u32 * const key, const u32 n) { Process_IV26(); return 0; }
static u32 Test_IV27 (u32 * const key, const u32 n) { Process_IV27(); return 0; }
static u32 Test_IV28 (u32 * const key, const u32 n) { Process_IV28(); return 0; }
static u32 Test_IV29 (u32 * const key, const u32 n) { Process_IV29n(n); return 0; }
static u32 Test_IV30 (u32 * const key, const u32 n) { Process_IV30n(n); return 0; }
static u32 Test_IV31 (u32 * const key, const u32 n) { Process_IV31(); return 0; }
static u32 Test_IV32 (u32 * const key, const u32 n) { Process_IV32(); return 0; }
static u32 Test_IV33 (u32 * const key, const u32 n) { Process_IV33n(n); return 0; }
static u32 Test_IV34 (u32 * const key, const u32 n) { Process_IV34(); return 0; }
static u32 Test_IV35 (u32 * const key, const u32 n) { Process_IV35(); return 0; }
static u32 Test_IV36 (u32 * const key, const u32 n) { Process_IV36n(n); return 0; }
static u32 Test_IV37 (u32 * const key, const u32 n) { Process_IV37(); return 0; }
static u32 Test_IV38 (u32 * const key, const u32 n) { Process_IV38(); return 0; }
static u32 Test_IV39 (u32 * const key, const u32 n) { Process_IV39n(n); return 0; }
static u32 Test_IV40 (u32 * const key, const u32 n) { Process_IV40(); return 0; }
static u32 Test_IV41 (u32 * const key, const u32 n) { Process_IV41(); return 0; }
static u32 Test_IV42 (u32 * const key, const u32 n) { Process_IV42(); return 0; }
static u32 Test_IV43 (u32 * const key, const u32 n) { Process_IV43(); return 0; }
static u32 Test_IV44 (u32 * const key, const u32 n) { Process_IV44(); return 0; }
static u32 Test_IV45 (u32 * const key, const u32 n) { Process_IV45(); return 0; }
static u32 Test_IV46 (u32 * const key, const u32 n) { Process_IV46(); return 0; }
static u32 Test_IV47 (u32 * const key, const u32 n) { Process_IV47n(n); return 0; }
static u32 Test_IV48 (u32 * const key, const u32 n) { Process_IV48(); return 0; }
static u32 Test_IV49 (u32 * const key, const u32 n) { Process_IV49n(n); return 0; }
static u32 Test_IV50 (u32 * const key, const u32 n) { Process_IV50(); return 0; }
static u32 Test_IV51 (u32 * const key, const u32 n) { Process_IV51n(n); return 0; }
static u32 Test_IV52 (u32 * const key, const u32 n) { Process_IV52n(n); return 0; }
static u32 Test_IV53 (u32 * const key, const u32 n) { Process_IV53(); return 0; }
static u32 Test_IV54 (u32 * const key, const u32 n) { Process_IV54(); return 0; }
static u32 Test_IV55 (u32 * const key, const u32 n) { Process_IV55(); return 0; }
static u32 Test_IV56 (u32 * const key, const u32 n) { Process_IV56(); return 0; }
static u32 Test_IV57 (u32 * const key, const u32 n) { Process_IV57(); return 0; }
static u32 Test_IV58 (u32 * const key, const u32 n) { Process_IV58n(n); return 0; }
static u32 Test_IV59 (u32 * const key, const u32 n) { Process_IV59(); return 0; }
static u32 Test_IV60 (u32 * const key, const u32 n) { Process_IV60(); return 0; }
static u32 Test_IV61 (u32 * const key, const u32 n) { Process_IV61n(n); return 0; }
static u32 Test_IV62 (u32 * const key, const u32 n) { Process_IV62n(n); return 0; }
static u32 Test_IV63 (u32 * const key, const u32 n) { Process_IV63n(n); return 0; }
static u32 Test_IV64 (u32 * const key, const u32 n) { Process_IV64(); return 0; }
static u32 Test_IV65 (u32 * const key, const u32 n) { Process_IV65(); return 0; }
static u32 Test_IV66 (u32 * const key, const u32 n) { Process_IV66(); return 0; }
static u32 Test_IV67 (u32 * const key, const u32 n) { Process_IV67n(n); return 0; }
static u32 Test_IV68 (u32 * const key, const u32 n) { Process_IV68n(n); return 0; }
static u32 Test_IV69 (u32 * const key, const u32 n) { Process_IV69(); return 0; }
static u32 Test_IV70 (u32 * const key, const u32 n) { Process_IV70(); return 0; }
static u32 Test_IV71 (u32 * const key, const u32 n) { Process_IV71n(n); return 0; }
static u32 Test_IV72 (u32 * const key, const u32 n) { Process_IV72n(n); return 0; }

#endif
