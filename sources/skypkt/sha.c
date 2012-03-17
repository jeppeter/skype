// Ruptor's 160-bit SHA HASH (breakable) in pure C

#include <string.h>
#include "sha.h"

#define SHA_v		1	// 1 for SHA-1, 0 for the original SHA, or make it variable

#define SHA_LAST_BLOCK_BITS		(SHA_BLOCK_BITS - 64)
#define SHA_LAST_BLOCK_BYTES	(SHA_LAST_BLOCK_BITS / 8)
#define SHA_LAST_BLOCK_WORDS	(SHA_LAST_BLOCK_BYTES / sizeof (long))

// The initial expansion function

#define SHA_expand(i)	blk[i] = _lrotl (blk[i-3] ^ blk[i-8] ^ blk[i-14] ^ blk[i-16], SHA_v)

// The four SHA sub-rounds

#define SHA_R0(v,w,x,y,z,i) (z += blk[i] + 0x5A827999 + _lrotl (v, 5) + ((w&(x^y))^y)    , w = _lrotl (w, 30))
#define SHA_R1(v,w,x,y,z,i) (z += blk[i] + 0x6ED9EBA1 + _lrotl (v, 5) + (w^x^y)          , w = _lrotl (w, 30))
#define SHA_R2(v,w,x,y,z,i) (z += blk[i] + 0x8F1BBCDC + _lrotl (v, 5) + (((w|x)&y)|(w&x)), w = _lrotl (w, 30))
#define SHA_R3(v,w,x,y,z,i) (z += blk[i] + 0xCA62C1D6 + _lrotl (v, 5) + (w^x^y)          , w = _lrotl (w, 30))


static void SHA_block (SHA_state *SHA, const unsigned long *data)
{
	unsigned long				blk[80];
	register unsigned long		a, b, c, d, e;
	
	// Step A.	Copy the data buffer into the local work buffer
	memcpy (blk, data, SHA_BLOCK_BYTES);
	
	// Step B.	Expand the 16 words into 64 more temporary data words
	SHA_expand (16); SHA_expand (17); SHA_expand (18); SHA_expand (19); SHA_expand (20);
	SHA_expand (21); SHA_expand (22); SHA_expand (23); SHA_expand (24); SHA_expand (25);
	SHA_expand (26); SHA_expand (27); SHA_expand (28); SHA_expand (29); SHA_expand (30);
	SHA_expand (31); SHA_expand (32); SHA_expand (33); SHA_expand (34); SHA_expand (35);
	SHA_expand (36); SHA_expand (37); SHA_expand (38); SHA_expand (39); SHA_expand (40);
	SHA_expand (41); SHA_expand (42); SHA_expand (43); SHA_expand (44); SHA_expand (45);
	SHA_expand (46); SHA_expand (47); SHA_expand (48); SHA_expand (49); SHA_expand (50);
	SHA_expand (51); SHA_expand (52); SHA_expand (53); SHA_expand (54); SHA_expand (55);
	SHA_expand (56); SHA_expand (57); SHA_expand (58); SHA_expand (59); SHA_expand (60);
	SHA_expand (61); SHA_expand (62); SHA_expand (63); SHA_expand (64); SHA_expand (65);
	SHA_expand (66); SHA_expand (67); SHA_expand (68); SHA_expand (69); SHA_expand (70);
	SHA_expand (71); SHA_expand (72); SHA_expand (73); SHA_expand (74); SHA_expand (75);
	SHA_expand (76); SHA_expand (77); SHA_expand (78); SHA_expand (79);
	
	// Step C.	Set up first buffer
	a = SHA->hash[0];
	b = SHA->hash[1];
	c = SHA->hash[2];
	d = SHA->hash[3];
	e = SHA->hash[4];
	
	// Step D. SHA register mangling divided into 4 sub-rounds
    SHA_R0 (a,b,c,d,e, 0); SHA_R0 (e,a,b,c,d, 1); SHA_R0 (d,e,a,b,c, 2); SHA_R0 (c,d,e,a,b, 3); SHA_R0 (b,c,d,e,a, 4);
	SHA_R0 (a,b,c,d,e, 5); SHA_R0 (e,a,b,c,d, 6); SHA_R0 (d,e,a,b,c, 7); SHA_R0 (c,d,e,a,b, 8); SHA_R0 (b,c,d,e,a, 9);
	SHA_R0 (a,b,c,d,e,10); SHA_R0 (e,a,b,c,d,11); SHA_R0 (d,e,a,b,c,12); SHA_R0 (c,d,e,a,b,13); SHA_R0 (b,c,d,e,a,14);
	SHA_R0 (a,b,c,d,e,15); SHA_R0 (e,a,b,c,d,16); SHA_R0 (d,e,a,b,c,17); SHA_R0 (c,d,e,a,b,18); SHA_R0 (b,c,d,e,a,19);
    SHA_R1 (a,b,c,d,e,20); SHA_R1 (e,a,b,c,d,21); SHA_R1 (d,e,a,b,c,22); SHA_R1 (c,d,e,a,b,23); SHA_R1 (b,c,d,e,a,24);
	SHA_R1 (a,b,c,d,e,25); SHA_R1 (e,a,b,c,d,26); SHA_R1 (d,e,a,b,c,27); SHA_R1 (c,d,e,a,b,28); SHA_R1 (b,c,d,e,a,29);
	SHA_R1 (a,b,c,d,e,30); SHA_R1 (e,a,b,c,d,31); SHA_R1 (d,e,a,b,c,32); SHA_R1 (c,d,e,a,b,33); SHA_R1 (b,c,d,e,a,34);
	SHA_R1 (a,b,c,d,e,35); SHA_R1 (e,a,b,c,d,36); SHA_R1 (d,e,a,b,c,37); SHA_R1 (c,d,e,a,b,38); SHA_R1 (b,c,d,e,a,39);
    SHA_R2 (a,b,c,d,e,40); SHA_R2 (e,a,b,c,d,41); SHA_R2 (d,e,a,b,c,42); SHA_R2 (c,d,e,a,b,43); SHA_R2 (b,c,d,e,a,44);
	SHA_R2 (a,b,c,d,e,45); SHA_R2 (e,a,b,c,d,46); SHA_R2 (d,e,a,b,c,47); SHA_R2 (c,d,e,a,b,48); SHA_R2 (b,c,d,e,a,49);
	SHA_R2 (a,b,c,d,e,50); SHA_R2 (e,a,b,c,d,51); SHA_R2 (d,e,a,b,c,52); SHA_R2 (c,d,e,a,b,53); SHA_R2 (b,c,d,e,a,54);
	SHA_R2 (a,b,c,d,e,55); SHA_R2 (e,a,b,c,d,56); SHA_R2 (d,e,a,b,c,57); SHA_R2 (c,d,e,a,b,58); SHA_R2 (b,c,d,e,a,59);
    SHA_R3 (a,b,c,d,e,60); SHA_R3 (e,a,b,c,d,61); SHA_R3 (d,e,a,b,c,62); SHA_R3 (c,d,e,a,b,63); SHA_R3 (b,c,d,e,a,64);
	SHA_R3 (a,b,c,d,e,65); SHA_R3 (e,a,b,c,d,66); SHA_R3 (d,e,a,b,c,67); SHA_R3 (c,d,e,a,b,68); SHA_R3 (b,c,d,e,a,69);
	SHA_R3 (a,b,c,d,e,70); SHA_R3 (e,a,b,c,d,71); SHA_R3 (d,e,a,b,c,72); SHA_R3 (c,d,e,a,b,73); SHA_R3 (b,c,d,e,a,74);
	SHA_R3 (a,b,c,d,e,75); SHA_R3 (e,a,b,c,d,76); SHA_R3 (d,e,a,b,c,77); SHA_R3 (c,d,e,a,b,78); SHA_R3 (b,c,d,e,a,79);
	
	// Step E.	Build message hash
	SHA->hash[0] += a;
	SHA->hash[1] += b;
	SHA->hash[2] += c;
	SHA->hash[3] += d;
	SHA->hash[4] += e;
}

void __fastcall SHA_update (SHA_state *SHA, const void *data, unsigned long bytes)
{
	register unsigned long		i;
	
	if (bytes == 0) return;
	SHA->bits->u64n[0] += ((unsigned __int64) bytes) << 3;
	for (i = SHA_BLOCK_BYTES - SHA->pos; bytes >= i; i = SHA_BLOCK_BYTES)
	{
		memcpy (SHA->data->u8n + SHA->pos, data, i);
		bytes -= i;
		(char *) data += i;
		make_MSF_32 (SHA->data->u32n, SHA_BLOCK_WORDS);
		SHA_block (SHA, SHA->data->u32n);
	}
	memcpy (SHA->data->u8n + SHA->pos, data, bytes);
	SHA->pos += bytes;
}

void __fastcall SHA_end (SHA_state *SHA)
{
	OCTET						PADDED_BLOCK[SHA_BLOCK_OCTETS];
	register unsigned long		i = SHA->pos;
	
	SHA->data->u8n[i++] = 0x80;
	if (i <= SHA_LAST_BLOCK_BYTES)
	{
		bzero (SHA->data->u8n + i, SHA_LAST_BLOCK_BYTES - i);
		make_MSF_32 (SHA->data->u32n, (i+3) >> 2);
		SHA->data->u32n[SHA_BLOCK_WORDS-2] = SHA->bits->u32n[ord2(1)];
		SHA->data->u32n[SHA_BLOCK_WORDS-1] = SHA->bits->u32n[ord2(0)];
		SHA_block (SHA, SHA->data->u32n);
	}
	else
	{
		bzero (SHA->data->u8n + i, SHA_BLOCK_BYTES - i);
		make_MSF_32 (SHA->data->u32n, (i+3) >> 2);
		SHA_block (SHA, SHA->data->u32n);
		bzero (PADDED_BLOCK, SHA_BLOCK_BYTES - 8);
		PADDED_BLOCK->u32n[SHA_BLOCK_WORDS-2] = SHA->bits->u32n[ord2(1)];
		PADDED_BLOCK->u32n[SHA_BLOCK_WORDS-1] = SHA->bits->u32n[ord2(0)];
		SHA_block (SHA, PADDED_BLOCK->u32n);
	}
	make_LSF_32 (SHA->hash, SHA_HASH_WORDS);
}

void __fastcall SHA_hash (const void *data, unsigned long bytes, void *hash)
{
	SHA_state			SHA = SHA_INIT;
	
	if (bytes) for (;;)
	{
		if (bytes <= SHA_BLOCK_BYTES)
		{
			SHA_update (&SHA, data, bytes);
			SHA_end (&SHA);
			break;
		}
		SHA_update (&SHA, data, SHA_BLOCK_BYTES);
		bytes -= SHA_BLOCK_BYTES;
		(char *) data += SHA_BLOCK_BYTES;
	}
	memcpy (hash, (char *) SHA.hash, SHA_HASH_BYTES);
}
