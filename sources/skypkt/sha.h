// Ruptor's 160-bit SHA HASH (breakable) definition file

#ifndef _sha_h_
#define _sha_h_

/*!
	SHA-0/SHA-1 hash function, set to SHA-1 at present
	#define SHA_v 0 in <crypto/sha/sha.c> or turn it into a variable to calculate the original SHA-0
!*/

#include "crypto/crypto.h"

//! \brief SHA hash output size in bits
#define SHA_HASH_BITS		160
//! \brief SHA hash block size in bits
#define SHA_BLOCK_BITS		512

//! \brief SHA hash output size in 8-byte octets (3 octets; incomplete 3 octets!)
#define SHA_HASH_OCTETS		((SHA_HASH_BITS + 63) / 64)
//! \brief SHA hash block size in 8-byte octets (8 octets)
#define SHA_BLOCK_OCTETS	((SHA_BLOCK_BITS + 63) / 64)
//! \brief SHA hash output size in 32-bit words (5 words)
#define SHA_HASH_WORDS		(SHA_HASH_OCTETS * 2)
//! \brief SHA hash block size in 32-bit words (16 words)
#define SHA_BLOCK_WORDS		(SHA_BLOCK_OCTETS * 2)
//! \brief SHA hash output size in bytes (20 byte)
#define SHA_HASH_BYTES		(SHA_HASH_OCTETS * 8)
//! \brief SHA hash block size in bytes (64 byte)
#define SHA_BLOCK_BYTES		(SHA_BLOCK_OCTETS * 8)

//! \brief SHA context structure containing the intermediate state while calculating a hash of multiple blocks of data of variable size
typedef struct _SHA_state
{
	//! \brief Message hash
	unsigned long			hash[SHA_HASH_WORDS];
	//! \brief Last hashed block position
	unsigned long			pos;
	//! \brief 64-bit bit count
	OCTET					bits[1];
	//! \brief SHA_context data buffer
	OCTET					data[SHA_BLOCK_OCTETS];
} SHA_state;

//! \brief Initial values to assign to a locally defined SHA state to avoid calling SHA_init at run time
#define SHA_INIT { {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL}, 0, {0} }

//! Called once to initialize SHA context internal state for subsequent calls to SHA_update and SHA_end.
//! \brief initializes SHA context internal state
//! \retval SHA_context initialized with standard values
static __forceinline void __fastcall SHA_init (SHA_state *SHA_context) 
{ 
	SHA_context->hash[0] = 0x67452301UL; 
	SHA_context->hash[1] = 0xEFCDAB89UL; 
	SHA_context->hash[2] = 0x98BADCFEUL; 
	SHA_context->hash[3] = 0x10325476UL; 
	SHA_context->hash[4] = 0xC3D2E1F0UL; 
	SHA_context->pos = 0; 
	SHA_context->bits->u64n[0] = 0; 
}

//! \brief updates SHA internal state by hashing in a data block of specified arbitrary length
//! \pre SHA_context has to be initialized with SHA_INIT values or by SHA_init or by a previous call to SHA_update
//! \pre the source has to be converted to the network byte order or LSF byte order before hashing (see make_LSF)
//! \post the hash in SHA_context is incomplete until a call to SHA_end
//! \param data the actual data to be hashed in
//! \param bytes length in bytes of the data to be hashed in
//! \retval SHA_context is updated
EXTERN void __fastcall SHA_update (SHA_state *SHA_context, const void *data, unsigned long bytes);

//! \brief finalizes SHA internal state resulting in a SHA_HASH_BITS (160) bit or SHA_HASH_BYTES (20) byte long SHA hash
//! \pre SHA_context has to be initialized with SHA_INIT values or by SHA_init or by a previous call to SHA_update
//! \post SHA_context contains the final SHA_HASH_BYTES (20) byte long 160-bit SHA hash in SHA_contest->hash
EXTERN void __fastcall SHA_end (SHA_state *SHA_context);

//! To be used on single strings or single blobs of data. To hash multiple strings or multiple blocks use SHA_init, SHA_update and SHA_end functions instead.
//! \brief calculates SHA hash of a single block of data of specified length
//! \param data the actual data to be hashed in (in network byte order or in LSF byte order)
//! \param bytes length in bytes of the data to be hashed in
//! \retval hash contains final SHA_HASH_BYTES (20) byte long 160-bit SHA hash of the specified data
EXTERN void __fastcall SHA_hash (const void *data, unsigned long bytes, void *hash);

#endif
