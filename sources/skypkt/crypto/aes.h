// PureNoise CryptoLib (c) 1997-2004, PureNoise Ltd Vaduz <www.cryptolib.com>

#ifndef _crypto_aes_h_
#define _crypto_aes_h_

#include <crypto/crypto.h>

//! \brief AES encryption key size in bits (minimum 256 and it will probably remain at 256)
//! All the ciphers below must have the same key size, sorry.
#define CIPHER_KEY_BITS			256

//! \brief AES encryption block size in bits (usually 128 or 64)
// All the ciphers below must have the same block size, sorry.
#define CIPHER_BLOCK_BITS		128

//! \brief AES encryption key size in 8-byte octets (4 OCTETs)
#define CIPHER_KEY_OCTETS		((CIPHER_KEY_BITS + 63) / 64)

//! \brief AES encryption key size in 32-bit words (8 words)
#define CIPHER_KEY_WORDS		(CIPHER_KEY_OCTETS * 2)

//! \brief AES encryption key size in bytes (32 byte)
#define CIPHER_KEY_BYTES		(CIPHER_KEY_OCTETS * 8)

//! \brief AES encryption block size in 8-byte octets (2 OCTETs)
#define CIPHER_BLOCK_OCTETS		((CIPHER_BLOCK_BITS + 63) / 64)

//! \brief AES encryption block size in 32-bit words (4 words)
#define CIPHER_BLOCK_WORDS		(CIPHER_BLOCK_OCTETS * 2)

//! \brief AES encryption block size in bytes (16 byte)
#define CIPHER_BLOCK_BYTES		(CIPHER_BLOCK_OCTETS * 8)

//! Any reasonably-sized prime number willd do; 0x47 results in a two kilobit long keystream; larger numbers offer better security also slowing down encryption of small blocks
#define CHAOS_KEY_WORDS			61

// any number outside AES_CIPHERS range will result in a fast lightweight Chaos-only encryption
#define USE_CHAOS_ONLY			-1

//! \brief A list of supported ciphers.
//! If you do not want to include some of the ciphers, simply remove them from the arrays below and exclude their sources from compilation.
enum
{
	USE_TWOFISH = 0,			// 0 = default cipher (encrypt to me with this)
	USE_RC6,					// 1
	USE_SERPENT,				// 2
	USE_RIJNDAEL,				// 3
	AES_CIPHERS					// 4
};

//! A temporary key stream used for data encryption and decryption. Derived from a 256-bit key, usually a common session key using setkey_aes function or from a larger key using setkey_big function. It is not recommended to store a key stream for future use, but rather keep the key itself from which the key stream can be quickly derived at any time.
//! \brief Temporary keystream storage type required for all the symmetric ciphers
typedef struct _aes_keystream
{
	unsigned long			cipher;
	unsigned long			chaos_key[CHAOS_KEY_WORDS];
	union
	{
		struct _twofish_key
		{
			unsigned long		mk_tab[4][256];
			unsigned long		key[40];
		} twofish;
		struct _rc6_key
		{
			unsigned long		key[44];
		} rc6;
		struct _serpent_key
		{
			unsigned long		key[140];
		} serpent;
		struct _rijndael_key
		{
			unsigned long		e_key[64];
			unsigned long		d_key[64];
		} rijndael;
	};
} aes_keystream;

typedef aes_keystream * aes_keying (const unsigned long *, aes_keystream *);
typedef OCTET * aes_cipher (OCTET *one_block, const aes_keystream *);

EXTERN aes_keystream * twofish_setkey (const unsigned long *, aes_keystream *);
EXTERN aes_keystream * rc6_setkey (const unsigned long *, aes_keystream *);
EXTERN aes_keystream * serpent_setkey (const unsigned long *, aes_keystream *);
EXTERN aes_keystream * rijndael_setkey (const unsigned long *, aes_keystream *);

EXTERN OCTET * twofish_encrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * rc6_encrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * serpent_encrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * rijndael_encrypt (OCTET *one_block, const aes_keystream *);

EXTERN OCTET * twofish_decrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * rc6_decrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * serpent_decrypt (OCTET *one_block, const aes_keystream *);
EXTERN OCTET * rijndael_decrypt (OCTET *one_block, const aes_keystream *);

static aes_keying *aes_cipher_setkey[AES_CIPHERS] = {&twofish_setkey, &rc6_setkey, &serpent_setkey, &rijndael_setkey};
static aes_cipher *aes_cipher_encrypt[AES_CIPHERS] = {&twofish_encrypt, &rc6_encrypt, &serpent_encrypt, &rijndael_encrypt};
static aes_cipher *aes_cipher_decrypt[AES_CIPHERS] = {&twofish_decrypt, &rc6_decrypt, &serpent_decrypt, &rijndael_decrypt};

//! \brief Initializes AES encryption/decryption key stream for given AES key of CIPHER_KEY_BITS (256) size
//! \pre in_key has to be in LSF byte order (see make_LSF for 32-bit arrays)
//! \param key is not a big, but just a 32-bit type casted pointer to an exactly CIPHER_KEY_BYTES (32) long array of bytes
//! \retval ks the keystream to use for aes_encrypt, aes_decrypt, big_encrypt, big_decrypt, base64_encrypt, base64_decrypt
//! \returns pointer to ks
static __forceinline aes_keystream * aes_setkey (const unsigned long *key, const unsigned long cipher, aes_keystream *ks) { ks->cipher = cipher; return (cipher < AES_CIPHERS) ? aes_cipher_setkey[ks->cipher] (key, ks) : ks; }

//! Always encrypts the same block exactly the same way with the same key. Proper block chaining, data randomization and integrity validation are required to properly encrypt larger amounts of data. Use encrypt_big to encrypt larger blocks of data. To decrypt an encrypted block call aes_decrypt using the same keystream. Make sure all 32-bit or 64-bit numbers within the block are properly converted to some byte order. See macros from <crypto/crypto.h> like save32 or make_LSF to convert 32-bit values to LSF byte order.
//! \brief Encrypts a CIPHER_BLOCK_BITS (128) long block of data
//! \pre ks has to be initialized with aes_setkey or big_setkey
//! \pre one_block has to be in LSF byte order (see make_LSF for 32-bit arrays)
//! \post one_block is in LSF byte order
//! \param one_block the block to be encrypted
//! \param ks the keystream to use to encrypt the block
//! \retval one_block encrypted input returned in the same block
//! \returns pointer to one_block
static __forceinline OCTET * aes_encrypt (OCTET one_block[CIPHER_BLOCK_OCTETS], const aes_keystream *ks) { return aes_cipher_encrypt[ks->cipher] (one_block, ks); }

//! Decrypts a block of exactly CIPHER_BLOCK_BYTES (16) bytes if the same keystream is supplied. If the block was chained after encryption, make sure you unchain it before decrypting it, otherwise it will be overwritten. If the block was (also) chained before encryption, unchain its decrypted version as it is now. If the block contained any 32-bit or 64-bit numbers, convert them to the current machine's byte order using <crypto/crypto.h> macros like load32 or make_LSF.
//! \brief Decrypts a CIPHER_BLOCK_BITS (128) long block of data previously encrypted with aes_encrypt
//! \pre ks has to be initialized with aes_setkey or big_setkey
//! \pre one_block has to be in LSF byte order (see make_LSF for 32-bit arrays)
//! \post one_block is returned in LSF byte order
//! \param one_block the block to be decrypted
//! \param ks the keystream to use to decrypt the block
//! \retval one_block decrypted input
//! \returns pointer to one_block
static __forceinline OCTET * aes_decrypt (OCTET one_block[CIPHER_BLOCK_OCTETS], const aes_keystream *ks) { return aes_cipher_decrypt[ks->cipher] (one_block, ks); }

#endif // _crypto_aes_h_
