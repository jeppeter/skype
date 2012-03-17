#ifndef _Process_IV_
#define _Process_IV_

#include <stdlib.h>

#include "crypto/crypto.h"
/*
#define u8				unsigned char
#define u16				unsigned short
#define u32				unsigned long

#define rotl32(x, n)				_lrotl (x, n)	// using ROL x,n on Intel
#define rotr32(x, n)				_lrotr (x, n)	// using ROR x,n on Intel
*/


#pragma warning				(disable:4307)

#define byte(x)				(*(u8 *)(x))
#define word(x)				(*(u16 *)(x))
#define dword(x)			(*(u32 *)(x))
#define qword(x)			(*(u64 *)(x))
#define bswap16(x)			((((x)>>8)&0xFF)+(((x)&0xFF)<<8))

static __forceinline u32  weight (u32 x) { u32 b = 0; for (; x; b++) x &= x-1; return b; }


static const u8           u32root_table[256] =
{
	 1,  1,  1,  2,  2,  2,  2,  2,  3,  3,  3,  3,  3,  3,  3,  4,
	 4,  4,  4,  4,  4,  4,  4,  4,  5,  5,  5,  5,  5,  5,  5,  5,
	 5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
	 7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,
	 8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
	 9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
	 9,  9,  9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
	10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16,
};

static const u8				u32cos_table[256] =
{
	0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,
	0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,
	0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,
	1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,
	1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,
	1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,
	1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,
	1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1
};

static const u8				u32sin_table[256] =
{
	0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,
	0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,
	0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,
	0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,
	0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,
	0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,
	1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,0,
	1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,0,0,1
};

#define u32root(n)			(u32root_table[(n)&0xFF])
#define u32cos(n)			(u32cos_table[(n)&0xFF])
#define u32sin(n)			(u32sin_table[(n)&0xFF])

#define Process_IV1()		(key[10] ^= key[7] - 0x354C1FF2)
#define Process_IV2()		(key[17] += key[13] - 0x292C1156)
#define Process_IV3n(n)		(key[13] |= u32cos(n) ? 0x1510A109 : key[14])
#define Process_IV4()		(key[15] ^= (key[14] < 0x291B9650) ? key[14] : key[2])
#define Process_IV5()		(key[ 3] ^= key[0] + 0x4376FF7)
#define Process_IV6()		{key[ 9]  = rotl32 (key[9], rotl32 (key[1], 14)); if (key[9] & 1) return 1;}
#define Process_IV7n(n)		(key[13] ^= (n < 0x2E0AF4F7) ? n : key[15])
#define Process_IV8()		(key[ 6] *= 0x1304694A * key[11])
#define Process_IV9()		(key[ 6] ^= u32cos(key[7]) ? 0x1AB1E599 : key[18])
#define Process_IV10()		(key[ 5] += key[11] | 0xEA02A83)
#define Process_IV11()		(key[ 6]  = rotl32 (key[6], key[13] - 18))
#define Process_IV12()		(key[11] ^= key[15] | 0x11273409)
#define Process_IV13()		(key[ 2] += 0xEA2D3D5D * key[7])
#define Process_IV14()		{key[ 3] -= key[17] | 0x2433636; if (key[3] & 1) return 1;}
#define Process_IV15()		(key[ 3] += key[9] + 0x48210C78)
#define Process_IV16n(n)	(key[ 0]  = rotl32 (key[0], (n>>17)&0x1F))
#define Process_IV17()		(key[ 9]  = rotr32 (key[9], u32cos(key[9]) ? 20 : key[0]))
#define Process_IV18n(n)	(key[ 5] *= rotl32 (n, 3))
#define Process_IV19()		(key[16] &= (key[11] < 0x5578A05) ? key[11] : key[16])
#define Process_IV20n(n)	(key[17] ^= n + 0x378E4553)
#define Process_IV21()		(key[ 4] ^= 17 * key[0])
#define Process_IV22()		(key[ 2] ^= u32sin(key[17]) ? 0x1C0E70BF : key[5])
#define Process_IV23()		(key[16] = rotr32 (key[16], key[10] - 11))
#define Process_IV24()		(key[ 6] += 0x975C61BA - key[8])
#define Process_IV25()		{key[ 7] += rotr32 (key[7], 21); if (key[7] & 1) return 1;}
#define Process_IV26()		{key[ 1] ^= u32cos(key[3]) ? 0x7C23395 : key[18]; if (key[1] & 1) return 1;}
#define Process_IV27()		(key[ 9] += 0x3A82007 - key[14])
#define Process_IV28()		{key[ 0] *= 33 * key[0]; if (key[0] & 1) return 1;}
#define Process_IV29n(n)	{key[10] = rotl32 (key[10], n-6); if (key[10] & 1) return 1;}
#define Process_IV30n(n)	(key[ 2] -= u32sin(n) ? 0x73423C3 : key[7])
#define Process_IV31()		(key[ 2] ^= key[15] + 0x57CE331)
#define Process_IV32()		(key[ 9]  = rotr32 (key[9], key[17]*18))
#define Process_IV33n(n)	(key[ 7] += n + 0x30B6FC95)
#define Process_IV34()		(key[18] ^= key[10] + 0x1EE65B0C)
#define Process_IV35()		(key[14] ^= u32cos(key[9]) ? 0x73CD560C : key[4])
#define Process_IV36n(n)	(key[ 7] -= n | 0x270927A3)
#define Process_IV37()		(key[ 7] ^= key[10] - 0x3035E544)

#define Process_IV38()		{if (key[5] & 1) return 1;}
#define Process_IV39n(n)	(key[9 ] *= u32sin(n) ? 0x28D781D2 : key[10])
#define Process_IV40()		(key[11] -= key[12] << 5)
#define Process_IV41()		(key[8 ] ^= u32cos(key[17]) ? 0x3544CA5E : key[8])
#define Process_IV42()		(key[ 1] -= key[16] | 0x59C1677)
#define Process_IV43()		{key[11] += 0xF6B10986 - key[14]; if (key[11] & 1) return 1;}
#define Process_IV44()		(key[ 4] ^= key[19] - 0x303D46FE)
#define Process_IV45()		(key[ 9] ^= u32cos(key[11]) ? 0xEEB638B : key[6])
#define Process_IV46()		(key[16] ^= (key[18] < 0xE87F32) ? key[18] : key[11])
#define Process_IV47n(n)	(key[12] *= u32cos(n) ? 0x1734D89C : key[5])
#define Process_IV48()		(key[11] |= key[4] - 0x224114CD)
#define Process_IV49n(n)	(key[11] &= 110 * n)
#define Process_IV50()		(key[ 2] &= key[18] - 0x37CF1A3F)

#define Process_IV51n(n)	(key[19] &= n + 0x3CB6C01E)
#define Process_IV52n(n)	(key[ 9]  = rotl32 (key[9], n * 19))
#define Process_IV53()		(key[18] -= 122 * key[6])
#define Process_IV54()		(key[11]  = rotl32 (key[11], u32cos(key[5]) ? 19 : key[11]))
#define Process_IV55()		(key[11] += 0x29CC7F53 - key[5])
#define Process_IV56()		(key[12] -= 66 * key[2])
#define Process_IV57()		{key[ 7] += key[2] ^ 0x376E1538; if (key[7] & 1) return 1;}
#define Process_IV58n(n)	(key[15] -= u32cos(n) ? 0x344432F : key[18])
#define Process_IV59()		(key[ 7] ^= u32root (key[15]))
#define Process_IV60()		(key[10]  = rotr32 (key[10], key[14] + 6))

#define Process_IV61n(n)	(key[ 6] += (n < 0x61F0BAA) ? n : key[16])
#define Process_IV62n(n)	(key[ 1] ^= rotl32 (n, 8))
#define Process_IV63n(n)	(key[12]  = rotr32 (key[12], key[18] ^ 9))
#define Process_IV64()		(key[ 0]  = rotl32 (key[0], 8 * key[18]))
#define Process_IV65()		(key[17] ^= 0x2F961 * key[4])
#define Process_IV66()		(key[ 6] ^= rotr32 (key[14], 28))
#define Process_IV67n(n)	(key[ 2] &= rotr32 (n, 17))
#define Process_IV68n(n)	{key[16] &= (key[12] < 0x28165E7B) ? key[12] : n; if (key[16] & 1) return 1;}
#define Process_IV69()		(key[ 9] -= rotr32 (key[16], 25))
#define Process_IV70()		{key[ 1] ^= (key[4] < 0x196D816A) ? key[4] : key[17]; if (key[1] & 1) return 1;}

#define Process_IV71n(n)	{u32 jv   = n + (u32sin (key[7]) ? 0xCC95AFBF : key[9]);\
							 key[ 2] += jv + 0xE6ECDA3,\
							 key[ 9] &= u32sin(key[7]) ? 0x13D68223 : jv,\
							 key[15] += 0x38245913 - key[12],\
							 key[16] = rotr32 (key[16], 30 * key[17]),\
							 key[11] += 0x36F87E5B - key[5],\
							 key[ 2] += 102 * key[3],\
							 jv      *= rotl32 (key[5], 30),\
							 key[ 9] += 123 * jv,\
							 key[ 5] = rotl32 (key[5], key[16] - 11),\
							 key[10] |= u32sin(key[4]) ? 0x84EDC63 : key[4];}

#define Process_IV72n(n)	{u32 jv   = n & (u32cos(key[10]) ? 0xF998E196 : key[10]);\
							 key[ 6] ^= rotl32 (jv, 7),\
							 key[ 1] ^= jv - 0x4B327DA,\
							 key[ 7] += jv ^ 0x672E5A7,\
							 jv      ^= u32sin(jv) ? 0xBC91B04 : key[8],\
							 key[11] ^= key[6] & 0xBE53718,\
							 jv      ^= u32cos(key[2]) ? 0x9DADA8A4 : jv,\
							 key[ 0] -= 0x9DADA8A4 & key[6],\
							 key[13] += key[1] - 0x7B284744,\
							 key[ 3] ^= 20 * key[18],\
							 key[ 2] |= jv - 0x313BB22;}

#endif
