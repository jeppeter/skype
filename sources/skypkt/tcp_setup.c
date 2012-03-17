/*  
*
* Direct TCP connect to skype client
*
*/

// for rc4
#include "Expand_IV.h"

// for aes
#include "rijndael.h"

// for 41 
#include "decode41.h"

//#include "defs.h"

// rc4 obfuscation
extern void Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags);
extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test);

extern int Calculate_CRC32_For41(char *a2, int a3);
extern unsigned int Calculate_CRC32(char *crc32, int bytes);

// socket comm
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int need_close);

// sha1 and rsa crypto function
extern int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert);
extern int _get_decode_data(char *buf, int len, char *outbuf);
extern int _get_sign_data(char *buf, int len, char *outbuf);
extern int _get_unsign_cred(char *buf, int len, char *outbuf);
extern int _get_encode_data(char *buf, int len, char *outbuf);

// utils
extern int process_aes_crypt(char *data, int datalen, int usekey, int blkseq, int need_xor);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
extern int decode41(char *data, int len, char *text);
extern int process_aes(char *buf, int buf_len, int usekey, int blkseq, int need_xor);
extern int first_bytes_correction(char *header, int header_len, char *buf, int buf_len);

// blobs encode
int encode41_setup1pkt(char *buf, int buf_limit_len);
int encode41_setup2pkt(char *buf, int buf_limit_len);

// global data

RC4_context rc4_send;
RC4_context rc4_recv;

u8 CHALLENGE_RESPONSE[0x80];
u8 LOCAL_NONCE[0x80];


// ne ispolzuetsa... ???
//xot_iam cert
//+after..

u8 LOCAL_UIC[0x189]=
"\x00\x00\x01\x04\x00\x00\x00\x01\x77\x9E\x0F\xA9\x19\xE7\xFD\x5A"
"\x43\x87\x44\x0A\x7B\x9D\x27\xE3\x3D\xCE\xF5\xEA\x3C\xEB\x5C\x2C"
"\x3A\xD2\x80\x84\x73\x59\x60\x91\x1F\x1E\xBF\xE5\x94\x4D\x9B\xA0"
"\xED\xB9\xE9\xB6\xB8\xFC\xA5\x20\x4A\xBA\xC5\x55\x82\xA4\x32\x0C"
"\x1E\xD8\x50\xDE\xFD\x53\x8B\x38\xB8\x9B\x94\xD5\x95\xFF\x75\x7B"
"\x9D\x7C\x32\x85\xDA\x85\x15\x4D\x4D\x5F\x0A\x45\xCC\xDC\x3B\x2F"
"\xA9\x69\x6A\xD5\xE8\x35\xC0\xAC\x69\xB7\x28\x93\xA1\x58\x95\xD5"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\x7C\x7B\x10\xD1\xD6\xFE\x38\x6E\x02\xA9\x94\xE0\xF0\xF6\x7B\x65"
"\xCF\x2F\x7F\x9B\x59\x5A\x3D\xCE\x11\x85\x0F\x46\xB3\x79\x52\x59"
"\x45\xF2\x68\x08\xF0\x67\x16\x7F\x8A\xE5\x08\x4A\x4A\xC0\xBD\xB2"
"\x7C\x0B\xF3\x90\x9D\xC1\x67\xB8\x68\xBA\x6C\x6B\x56\x69\xFD\xA6"
"\xAF\x93\x24\xAA\x5C\x83\x22\x87\x22\x8E\xD6\xFA\x24\xBA\x89\xAA"
"\xBA\x1E\x92\xE8\xDA\x00\x01\x9D\xC6\xEC\x4D\x51\x0E\xC2\xAD\x09"
"\xAB\x73\x1F\xFF\xFE\x4B\x74\xA4\x87\x19\xF7\x03\xA5\x2C\xBA\x64"
"\x8D\x28\x12\x7D\x41\xBF\x82\xEE\x3C\xF1\x6C\x20\x18\xBC\xA4\x23"
"\x5E\x99\x69\x0C\x13\x7D\x69\xB8\x33\x94\xCC\x02\x4B\xA0\x83\xA3"
"\x00\xBC\x7A\x7C\x11\x85\xBA\x7A\xF1\x2E\x8A\xA6\x20\x62\x6D\x08"
"\x8B\xDD\x75\x92\x50\x15\xB5\xD1\x13\xCE\x2A\xB3\xB8\x1B\x7B\xE2"
"\xD0\x8F\x1E\xF7\xEB\x23\xEC\x76\x51\xBB\x97\x04\x9F\xA3\x45\x49"
"\x54\x69\xF8\x6C\x0E\x21\x13\x75\xD2\x49\x40\x4E\x08\x30\x0E\xCF"
"\xF4\xF1\x0A\x56\xD0\x8F\x31\x0A\x43\xFD\xA0\x83\xD8\x4D\x04\x0F"
"\x4B\xBC\x92\xC5\xBA\x26\xBF\xDB\xFB\xA3\xB1\x67\x63\x05\x1C\xF1"
"\x63\x6A\xA6\x7E\x40\x0F\x28\xD1\xAB\xBE\x49\xC3\x52\xAC\x23\x9D"
"\x9F\x80\xA3\x50\x58\xD5\xC1\xFE"
;



// 0x149
/*
"\x00\x00\x00\xC4\x00\x00\x00\x00\xB2\x55\xE8\x19\x9D\x44\x7E\xE9"
"\xC6\xA9\x33\x25\x98\x1A\x52\xE5\x29\x49\xB9\xF5\x17\x60\x65\x71"
"\x69\x10\xCE\xF9\xAA\x2A\xFD\x90\x80\x4C\x92\xFE\x78\xC6\x96\xCB"
"\x63\x07\x03\xB3\xE5\x07\x14\xBB\x45\x62\x57\x60\x9F\x4E\x83\x8C"
"\x43\x87\xEA\x89\x1F\x6A\xC3\xC1\xF8\xFF\xB2\xC8\xE7\xB5\x4D\xF3"
"\xF9\x4F\x4E\x7E\x5C\xEF\x49\x50\xCC\x96\x83\x5E\xCD\x8D\x56\x17"
"\xF6\x8B\xC2\x9D\xF3\xAF\xFB\xD7\xA2\x2E\x91\x6E\xAE\x7A\xD6\xAF"
"\x5D\x18\x38\x52\x17\x43\x04\xD1\xEE\xBF\x43\x82\x34\xBA\x61\x0B"
"\xEC\x3A\xF4\x3D\x82\x3D\x3D\x5A\x56\x39\x6F\xEC\x88\xC5\x04\x91"
"\x5B\xA4\x8B\x28\x75\x3F\xFD\xB0\xBF\xCF\x0E\x5E\xD0\x95\x38\xB6"
"\x5A\x50\x30\xD2\xB4\x88\x81\xA8\x89\xB8\xB1\x3C\x6E\xE4\xF1\x0F"
"\x9C\x85\x2E\x64\xC8\xDD\x3F\x36\xDD\xA1\xA8\xC1\x94\x4E\x70\x3B"
"\x2F\x60\x51\x9A\xDC\xAE\x8D\x30\x8D\x43\x82\xE9\xE4\x4F\x53\x97"
"\x55\x4E\x5F\xDB\x6E\xF4\x75\xE3\x81\x4C\xBC\xD9\xE8\x68\x85\x06"
"\x56\x58\x52\xE1\x78\xFF\x2F\x26\x95\x8C\xDF\x21\xB1\x0B\x94\x1F"
"\x1C\xCA\x55\x69\x97\x0F\xE4\xBE\x7D\x9F\x73\xFD\x8B\x13\x29\xBD"
"\x56\x39\x68\xEB\x2E\x84\x0A\x2A\x96\xC3\x27\x32\xE9\xCB\xB1\x9E"
"\xF5\xF0\x8D\x16\x5E\x3D\xC6\x7B\xCE\x3D\x18\x9B\xE5\x0D\x94\x51"
"\x94\x09\x50\xF0\xBC\x43\x5D\xD8\x04\xF5\xDC\xF6\x38\xB4\x1C\x78"
"\x94\xC9\xBB\xFD\x12\xC8\x22\x91\x71\xF9\x45\x04\x87\xD2\x81\x34"
"\x79\xDA\x1F\xD7\xF7\x50\xC2\x97"
;
*/

// now not used
// decrypted by xot_iam pub key
//
// buddy_authorizedxoteg_iam >
//
//0x15 + "buddy_authorizedxoteg_iam\x00" + 0x14 sha1 + 0xBC

u8 AFTER_CRED_LOCAL[0x81];

/*
u8 AFTER_CRED_LOCAL[0x81]=
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBA\x1D\xC6\x85"
"\xD1\xBC\xA2\xCA\x49\x5F\x22\xCC\xD9\x75\xDB\x35\x5C\x58\x9A\x98"
"\xB2\x62\x75\x64\x64\x79\x5F\x61\x75\x74\x68\x6F\x72\x69\x7A\x65"
"\x64\x78\x6F\x74\x65\x67\x5F\x69\x61\x6D\x00\x3E\xF9\xC4\xEA\xE9"
"\x8B\xA2\x08\x9E\x8D\xD7\xE2\x71\xD1\x3E\x53\xD2\xC6\xEE\x96\xBC"
;
*/


u8 remote_credentials[0x100];
u8 remote_pubkey[0x80];

u8 aes_key[0x20];
u32 REMOTE_SESSION_ID;
u32 LOCAL_SESSION_ID=0x259F;


// toje samoe v unknown newblk ..
// i v loge
//ChatPeer(,xoteg_iam:774ecb773834fa8e,INIT)::recv onLetsBeSyncBuddies(#xoteg_iam/$xot_iam;4fef7b015cbb8810, 1, 1)
//u8 unknown[]="\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5\x43\xA3\x14\xA9\xEF\x08";

//"\x75\x4E\xCB\x75\x38\x36\xFA\x8E\x01\xC1\xA9\x02\x28\x82\xA5\x43\xA5\x15\xA9\xEF\x08"
//"\x8C\x73\x71\x2B\x64\xCE\xB5\xC1\x01\xC0\xA8\x01\x1C\x81\xA5\x7B\xC0\x63\xBB\x8E\x9D"
u8 INIT_UNK[0x16]=
"\x75\xAA\xBB\xCC\x38\x36\xAA\xBB\x01\xCC\xA9\x02\x28\xDD\xA5\x43\xA5\x15\xA9\xEF\x08"
;


#define const1  0x55829E55;
#define const2  0x5F359B29;
#define const3  0xE9C261A9;
#define const4  0x49D198E2;
#define const5  0x49D198E7;

#define const6  0x013AF2C7;
#define const7  0x08DD791A;
#define const8  0x4208B88D;

#define const9  0x3D98FFD0;
#define const10 0x3D98FFD0;
#define const11 0x3D98FFD1;

#define const12 0x718CDA9C;
#define const13 0xA29917A7;



// internal session chat
//uint BLOB_0_1=0x55819F87;
uint BLOB_0_1=const1;

uint BLOB_0_2=const2;

uint BLOB_0_2__1=   const3;

//timestampt
uint BLOB_0_5=      const4;

uint BLOB_0_5__1=   const5;

uint BLOB_0_6=      const6;


uint BLOB_0_7=      const7;

uint BLOB_0_7__1=   const8;
uint BLOB_0_7__2=   const9;
uint BLOB_0_7__3=   const10;
uint BLOB_0_7__4=   const11;


uint BLOB_0_9=      const6;

uint BLOB_0_9__1=   const9;
uint BLOB_0_A=      const9;
uint BLOB_0_15=     const12;

uint BLOB_0_9__2 =  const11;
uint BLOB_0_A__1  = const11;
uint BLOB_0_15__1 = const13;


uint BLOB_0_F =     const9;


uint BLOB_0_A__2=   const7;
uint BLOB_0_A__3=   const8;




//64 bit challenge nonce
uint BLOB_1_9_ptr=0xDBDBCE66;
uint BLOB_1_9_size=0xF7BB5566;




u32 confirm[0x100];
u32 confirm_count;


u8 MSG_TEXT[0x1000];

/*
u8 MSG_TEXT[0x100]=
"Please visit or site here: www.opus-de1.org\n"
;
*/



/*
u8 CHAT_STRING[0x100]=
"#xoteg_iam/$xotabba;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xotabba"
;
*/

/*
u8 CHAT_STRING[0x100]=
"#xoteg111_iam/$xot_iam;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xot_iam"
;

u8 CHAT_PEERS[0x100]=
"xot_iam xoteg111_iam"
;
*/


/*
u8 CHAT_STRING[0x100]=
"#xoteg_iam/$shamanyst;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"shamanyst"
;

u8 CHAT_PEERS[0x100]=
"shamanyst xoteg_iam"
;
*/

u8 CHAT_STRING[0x100];

u8 REMOTE_NAME[0x100];

u8 CHAT_PEERS[0x100];

u8 CHAR_RND_ID[0x100]="4fea66013cdd0000";

/*
u8 CHAT_STRING[0x100]=
"#xot_iam/$shamanyst;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"shamanyst"
;

u8 CHAT_PEERS[0x100]=
"shamanyst xot_iam"
;
*/

/*
u8 CHAT_STRING[0x100]=
"#xoteg_iam/$xot_iam;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xot_iam"
;

u8 CHAT_PEERS[0x100]=
"xot_iam xoteg_iam"
;
*/



/*
u8 CHAT_STRING[0x100]=
"#xoteg_iam/$xotgogo;4fef7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xotgogo"
;

 u8 CHAT_PEERS[0x100]=
"xotgogo xoteg_iam"
;
*/


/*
u8 CHAT_STRING[0x100]=
"#xoteg_iam/$xot_parapet1parapet2parapet3;4fbf7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xot_parapet1parapet2parapet3"
;

 u8 CHAT_PEERS[0x100]=
"xot_parapet1parapet2parapet3 xoteg_iam"
;
*/

/*
u8 CHAT_STRING[0x100]=
"#xot_iam/$xot_parapet1parapet2parapet3;4fbf7b015cbb0000"
;

u8 REMOTE_NAME[0x100]=
"xot_parapet1parapet2parapet3"
;

 u8 CHAT_PEERS[0x100]=
"xot_parapet1parapet2parapet3 xot_iam"
;
*/

u8 NEWBLK[0x1000];
uint NEWBLK_LEN;

//"\x00\x00\x01\x04


u8 CREDENTIALS[0x105]=
"\x00\x00\x00\x01\x50\x6A\xF3\xC8\x9B\x67\xD0\x54\x4F\x36\xA0\x91"
"\x4A\xE8\x33\xF1\x72\xB6\xDF\x6A\xCB\x31\xAF\xCB\x07\x7E\x02\xA4"
"\x4A\xA8\xD1\x08\x32\x56\xEC\x76\x7F\x28\xC2\x4D\x71\x59\xB8\xB3"
"\x6E\xCF\xED\x9D\x38\x38\xF5\xFA\x89\xE3\xC4\x6D\xB5\xFE\x80\x97"
"\x7F\x67\x4E\xFE\xF6\xB9\x4D\xE2\x54\xD7\x90\xE1\x5E\xE9\xFF\x70"
"\xCF\xC2\x57\x2D\xF2\x74\xC2\xE3\x3C\x9A\x38\x14\xE2\xBB\xED\x51"
"\x26\xB5\xCA\x8F\xCA\x5E\x8D\x51\xCB\x01\x26\x01\x9E\xE2\xE1\x0C"
"\x7B\x79\x27\xC8\x62\xD2\x41\x6D\x39\xCE\x01\x68\x70\x56\x1D\xB7"
"\x72\x0C\x4F\x40\x82\x34\x38\x1F\x85\x72\x96\xA1\xA7\x50\x16\x64"
"\xD9\x23\x1F\x51\x35\xAE\x92\x5F\xF2\xF6\x87\x88\xA5\xD1\x1A\xF8"
"\xC0\x0A\xBF\x29\x56\xF9\x3D\x7C\xA2\x59\x7B\xD6\x4A\xA8\x55\x5B"
"\x6A\x7F\xB9\x14\xB8\x0E\xA8\x47\x3F\xB3\x92\x3B\x3E\x8B\x4C\x7B"
"\x74\xD6\xB6\xC0\x6E\xFF\xD6\xA4\x38\xAE\x0D\x7C\x75\xC6\x71\x65"
"\x62\x7A\xF7\x92\x98\x57\xB0\xBF\x52\x33\x59\xF8\x9F\xAF\x31\x80"
"\x78\x20\xF1\xDE\xDE\x07\xAD\x89\xBF\x7E\xBD\x9E\x74\xA3\x71\x07"
"\x70\x26\xE6\x77\x5D\xC8\x38\xCD\x9E\x6A\x10\x57\x02\xAF\xA0\x45"
"\xEC\xC9\xBB\xBD"
;

/*
"\x00\x00\x00\x01\x52"
"\x17\xBA\x30\x12\x45\x0C\x09\x93\xD1\x7A\x2A\x9D\x71\xE9\xA7\x49"
"\x85\x93\xE9\xD9\xBA\x54\x47\x9C\x51\x1A\x0B\x2B\x27\x83\xDB\xED"
"\x29\xFB\xAE\xC3\x85\x31\xC6\x10\x28\x71\x3F\xB6\x1D\x10\x2D\xDC"
"\x3B\x3E\xC8\x8E\xCF\xE1\x55\x66\xB4\x3D\xFE\x57\xE8\x28\x96\xE3"
"\x9C\xC3\x4C\x14\x46\x76\x58\xD0\x27\xF8\x1F\x3D\xF6\x4B\xAA\xAA"
"\x41\xBC\x4D\x0C\x8F\x19\x2F\xED\xDE\xC6\xE0\xBD\xAA\xF5\x23\x5D"
"\xE9\xDD\x08\x1E\x3B\x45\xDA\x7F\x31\xAC\x99\xC9\xD8\x2B\xAE\x65"
"\x9B\xB7\x49\xE3\xFC\x29\x41\xC2\x4A\x9C\xDD\x0A\xCF\x0C\x96\x3A"
"\xF6\x05\x26\x8B\x13\xF7\xD3\x41\x93\x14\x6C\x9B\x90\x72\xA0\xA9"
"\xF8\x1D\x81\xB4\x4D\xA2\x9D\xA9\x64\xC5\xFF\xE8\xB3\x77\xC0\x5A"
"\x97\xCD\x25\x15\xA4\x0A\xD1\x00\x0C\x0B\x4F\x0F\x29\xCA\xED\x94"
"\x06\x58\xEC\x8C\x97\x5E\x96\x30\x65\x4A\x15\xFC\x0B\xE0\xA3\x27"
"\x23\x40\x41\x26\x97\x65\xE0\x20\x58\x5B\xC7\x14\xE5\xF9\xFE\x10"
"\xAC\x2A\x5A\x4F\x5E\x49\x1E\x0E\xDB\x05\x5B\x57\xDE\xFA\xA7\xF1"
"\x85\x5D\x2A\xEC\x2B\xA7\xD6\xD1\x36\x1B\xE9\xD9\xEE\x5D\x80\x96"
"\x5A\x12\xB3\x31\xF6\xE7\x26\x91\x59\xC3\x23\xC6\xE8\xCE\x5A"
;
*/


uint CREDENTIALS_LEN=0x104;

// hash from CREDENTIALS with 00 00 00 01
u8 CREDENTIALS_HASH[0x15];


//crc of credentials
//uint UIC_CRC=0xEFE9B321;
uint UIC_CRC;


//no ascii strings
u8 AFTER_CRED[0x81]=
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBA\x6C\xF4\x1B"
"\x4B\xA7\x79\x08\xE7\xC0\x0F\xB4\x43\x2A\xF7\x57\x7A\xA5\xA3\x91"
"\x97\x41\x01\x04\x03\x15\x8C\x73\x71\x2B\x64\xCE\xB5\xC1\x01\xC0"
"\xA8\x01\x1C\x81\xA5\x7B\xC0\x63\xBB\x8E\x9D\x67\x5F\xD8\x42\x25"
"\x5A\xB4\x1C\x09\x61\xE0\x6E\x90\x36\x65\xE0\xC6\x40\x0E\xB4\xBC"
;

/*
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBA\x97\xBD\x63"
"\x4B\x1A\xEC\xC0\xED\x69\xFB\xE2\xE2\x3D\x09\xD8\x6A\xF7\xC0\x65"
"\x35\x41\x01\x04\x03\x15\xF6\xA5\xCC\xE2\xA3\xBF\xC5\xE3\x01\xC0"
"\xA8\x01\x0C\x33\x70\x42\x29\x5B\x69\x42\x1A\x0C\x36\x29\x1F\x0E"
"\xC0\x56\xF6\x64\x47\x3D\xB8\xD3\x78\x0D\x93\x3A\xC9\x34\x4E\xBC"
;
*/



u8 CREDENTIALS188[0x189]=
"\x00\x00\x01\x04\x00\x00\x00\x01\x52"
"\x17\xBA\x30\x12\x45\x0C\x09\x93\xD1\x7A\x2A\x9D\x71\xE9\xA7\x49"
"\x85\x93\xE9\xD9\xBA\x54\x47\x9C\x51\x1A\x0B\x2B\x27\x83\xDB\xED"
"\x29\xFB\xAE\xC3\x85\x31\xC6\x10\x28\x71\x3F\xB6\x1D\x10\x2D\xDC"
"\x3B\x3E\xC8\x8E\xCF\xE1\x55\x66\xB4\x3D\xFE\x57\xE8\x28\x96\xE3"
"\x9C\xC3\x4C\x14\x46\x76\x58\xD0\x27\xF8\x1F\x3D\xF6\x4B\xAA\xAA"
"\x41\xBC\x4D\x0C\x8F\x19\x2F\xED\xDE\xC6\xE0\xBD\xAA\xF5\x23\x5D"
"\xE9\xDD\x08\x1E\x3B\x45\xDA\x7F\x31\xAC\x99\xC9\xD8\x2B\xAE\x65"
"\x9B\xB7\x49\xE3\xFC\x29\x41\xC2\x4A\x9C\xDD\x0A\xCF\x0C\x96\x3A"
"\xF6\x05\x26\x8B\x13\xF7\xD3\x41\x93\x14\x6C\x9B\x90\x72\xA0\xA9"
"\xF8\x1D\x81\xB4\x4D\xA2\x9D\xA9\x64\xC5\xFF\xE8\xB3\x77\xC0\x5A"
"\x97\xCD\x25\x15\xA4\x0A\xD1\x00\x0C\x0B\x4F\x0F\x29\xCA\xED\x94"
"\x06\x58\xEC\x8C\x97\x5E\x96\x30\x65\x4A\x15\xFC\x0B\xE0\xA3\x27"
"\x23\x40\x41\x26\x97\x65\xE0\x20\x58\x5B\xC7\x14\xE5\xF9\xFE\x10"
"\xAC\x2A\x5A\x4F\x5E\x49\x1E\x0E\xDB\x05\x5B\x57\xDE\xFA\xA7\xF1"
"\x85\x5D\x2A\xEC\x2B\xA7\xD6\xD1\x36\x1B\xE9\xD9\xEE\x5D\x80\x96"
"\x5A\x12\xB3\x31\xF6\xE7\x26\x91\x59\xC3\x23\xC6\xE8\xCE\x5A\x73"
"\x1D\x12\x75\x41\x87\xEB\x30\xC4\x77\xD9\x4E\x58\x10\xC2\x71\x61"
"\xEC\x5A\x90\x88\x83\x73\x41\x30\x58\x87\x69\x8C\x39\xA7\xCA\x23"
"\xE1\xAF\x47\x0F\xA2\xD4\x67\x6E\x6D\x70\x29\x3E\x37\xD3\x30\x49"
"\xFC\xF5\x25\x69\x7D\x98\xF4\xDC\x50\xD7\x85\x33\x42\x33\xAB\x80"
"\x4E\xCF\x85\x5A\xE7\xE6\xBD\xC8\x89\x93\x04\xAE\xD3\x85\xD8\x5C"
"\x3E\xC5\x59\x77\xEB\xD6\x8E\x35\x20\x3D\xE9\xCF\xCE\x7B\x3A\x6B"
"\xB3\xD8\xFD\x96\xB5\xED\x05\x47\x5E\x14\xC1\x8C\xB7\x4E\x7B\x86"
"\xE4\x35\x3B\x8B\x3C\x5F\x84\x34\xE4\x1B\xD3\x53\x0F\xB2\x9D"
;


uint CREDENTIALS188_LEN=0x188;




	char xoteg_pub[]=
"\xC5\x69\xE5\x5F\x12\x2B\x46\x86\x70\x1C\x10"
"\xF8\x0A\x17\x1F\x95\x57\x55\xBC\xD2\xC1\x03\x5B\x3F\xD0\x84\x86"
"\xE2\xF1\x10\x96\x87\x16\xD3\x0C\x2B\x33\x76\x9E\x12\x77\x97\x7F"
"\xE7\xF7\xFF\xD9\xB9\xBB\xF5\x19\xE3\x2A\xFA\x56\xE1\x3B\x4A\x45"
"\xEF\x29\xE0\x95\x23\xFE\x58\x42\x72\x27\xAD\x03\xAF\x6E\x3C\xF7"
"\x05\xE4\x9F\x4D\xF4\xA5\x91\xFE\x8F\xDE\xDE\x1B\xA0\xD9\x94\xD7"
"\x43\x4F\x90\xEF\x38\xE1\xB8\x1B\xD2\xDC\x3D\xCA\x6F\x8B\x50\x60"
"\x94\xA4\x6B\x14\x10\x5B\x5F\xB1\xCA\x73\x1D\x56\x93\x5D\xF2\xF5"
"\x5E\x71\xC0\xF9\x95"
;

/*
"\xDB\x1D\x1B\x25\xCC"
"\x3F\x33\x96\x10\xFA\xC2\x16\x7C\x4E\x41\x01\xD3\xD7\x07\x17\x87"
"\xF3\x09\x24\x02\xC4\x43\xF1\xD2\xD2\x42\x4A\xC0\xAF\xD9\x9C\xF8"
"\x6D\x94\xE7\x7D\x83\x14\x0E\x2F\xCE\x51\xD1\xA6\xE1\xF1\xCF\x52"
"\x7F\xF4\x74\x36\x50\x98\x66\x5A\x52\xE3\x1D\x25\x3C\xB2\x2F\x95"
"\xBA\xDA\xE1\x02\x4A\xB2\x50\xF7\x56\x3C\xCE\xE3\xF9\x3A\x1B\x95"
"\x6B\xB3\x40\xDD\x6F\x22\x95\xD1\x53\xCC\xAC\xB7\xBA\x7B\x21\x60"
"\xE8\x2B\xDE\x8F\x19\x1B\x0D\x5F\x72\xC8\xF6\x92\x77\x87\x51\x39"
"\x26\xC3\x47\xF8\x43\xA2\x16\x06\xEB\x1C\xC9"
;
*/





	char xoteg_sec[]=
"\xC3\xD3\x81\xF6\x46\xDD\xAA\xBD\xDD\x23\xDA\x29\x52\x49\x11\xC9"
"\x60\xB2\xE9\xF5\xDE\x04\xE8\x55\x6B\x10\xAB\x85\x1F\x40\x27\x31"
"\xA6\x10\x80\x77\xB2\x3B\x2E\x1E\x7F\x87\x47\x17\xE2\x48\x67\xBF"
"\xF8\x94\xEF\xB3\x0A\x84\xFD\xFD\xBA\x84\xB8\xCE\xBF\xA9\xCA\x06"
"\x06\x22\x38\x00\xAD\xF4\xB0\x9D\x80\x88\x86\xEA\x85\x51\x45\x18"
"\xDD\xD7\x32\xD3\x85\x13\x20\x8E\x49\xA2\x92\xE8\xFF\x70\x5B\xBD"
"\x99\xE3\x9D\x21\xB0\xD0\xF4\xC2\xF6\xFD\xC9\xA5\x3F\xDE\xF7\x9E"
"\x27\x84\x3D\xB9\x58\xB5\xD6\xEB\xBC\xE0\xCD\x17\xE3\x47\x19\x99"
;

/*
"\x64\xBC\x42\xE8\xE3\xB8\x02\xCD\x71\x4C\xF7\xC2\x42\xAF\xEF\x6F"
"\x19\xA7\x78\x19\x37\x65\x62\xC4\x6D\x89\x31\xFB\x91\x83\x1C\xFB"
"\x25\x0F\x33\xAA\xD9\x03\xF8\x3B\x5D\x16\xD0\x37\x9D\x7E\xEB\x5A"
"\xC9\xB0\x82\xED\x5F\xEE\x77\xC2\x9D\xDD\xFB\xD2\xC2\x9F\xEC\xCD"
"\x75\x94\xAC\x3A\x1B\x9A\xAD\x5B\x6A\x54\x86\x63\xEE\x93\x78\x19"
"\x3D\xA2\xAB\xCC\xEA\xB1\x0F\x5D\x03\x14\x3A\x42\xBA\xFD\x37\x7B"
"\xDB\x56\x4C\x78\x11\x97\x0E\x1C\xB1\x86\xFA\x2E\x1F\x2E\xAA\x8E"
"\x2A\x2A\xA7\x7B\xBB\xEF\x75\x17\x46\xD1\x52\x0C\xBC\x50\x1A\x49"
;
*/





	char skype_pub[]=
"\xB8\x50\x6A\xEE\xD8\xED\x30\xFE\x1C\x0E\x67\x74\x87\x4B\x59\x20"
"\x6A\x77\x32\x90\x42\xA4\x9B\xE2\x40\x3D\xA4\x7D\x50\x05\x24\x41"
"\x06\x7F\x87\xBC\xD5\x7E\x65\x79\xB8\x3D\xF0\xBA\xDE\x2B\xEF\xF5"
"\xB5\xCD\x8D\x87\xE8\xB3\xED\xAC\x5F\x57\xFA\xBC\xCD\x49\x69\x59"
"\x74\xE2\xB5\xE5\xF0\x28\x7D\x6C\x19\xEC\xC3\x1B\x45\x04\xA9\xF8"
"\xBE\x25\xDA\x78\xFA\x4E\xF3\x45\xF9\x1D\x33\x9B\x73\xCC\x2D\x70"
"\xB3\x90\x4E\x11\xCA\x57\x0C\xE9\xB5\xDC\x4B\x08\xB3\xC4\x4B\x74"
"\xDC\x46\x35\x87\xEA\x63\x7E\xF4\x45\x6E\x61\x46\x2B\x72\x04\x2F"
"\xC2\xF4\xAD\x55\x10\xA9\x85\x0C\x06\xDC\x9A\x73\x74\x41\x2F\xCA"
"\xDD\xA9\x55\xBD\x98\x00\xF9\x75\x4C\xB3\xB8\xCC\x62\xD0\xE9\x8D"
"\x82\x82\x18\x09\x71\x05\x5B\x45\x7C\x06\xF3\x51\xE6\x11\x64\xFC"
"\x5A\x9D\xE9\xD8\x3D\x1D\x13\x78\x96\x40\x01\x38\x0B\x5B\x99\xEE"
"\x4C\x5C\x7D\x50\xAC\x24\x62\xA4\xB7\xEA\x34\xFD\x32\xD9\x0B\xD8"
"\xD4\xB4\x64\x10\x26\x36\x73\xF9\x00\xD1\xC6\x04\x70\x16\x5D\xF9"
"\xF3\xCB\x48\x01\x6A\xB8\xCA\x45\xCE\x68\x75\xA7\x1D\x97\x79\x15"
"\xCA\x82\x51\xB5\x02\x58\x74\x8D\xBC\x37\xFE\x33\x2E\xDC\x28\x55"
;







//////////////////////
// tcp first packet //
//////////////////////
unsigned int make_tcp_client_sess1_pkt1(char *ip,unsigned short port,unsigned int rnd)
{
	u8 result[0x1000];
	u8 recvbuf[0x1000];
	u32 recvlen;
	u32 local_rnd;
	u32 remote_rnd;
	u32	iv;
	char *pkt;
	int len;
	u8 send_pkt[]="\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03";
	int send_pkt_len=sizeof(send_pkt)-1;


	//memset(MSG_TEXT,0x42,10*1024-1);
	//MSG_TEXT[10*1024]=0;




	memcpy(CREDENTIALS188+0x04,CREDENTIALS,CREDENTIALS_LEN);

	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of CREDENTIALS 0x104 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,CREDENTIALS,CREDENTIALS_LEN);

		//print it
		show_memory(buf, CREDENTIALS_LEN, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, CREDENTIALS_LEN, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(CREDENTIALS_HASH,outbuf,0x14);

	};


	// modify hash
	memcpy(AFTER_CRED+0x3D,CREDENTIALS_HASH, 0x14);
	//modify init_unk
	memcpy(AFTER_CRED+0x56,INIT_UNK, 0x15);

	
	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of AFTER_CRED 0x80 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,AFTER_CRED+0x3D,0x80-0x14-1-0x3D);

		//print it
		show_memory(buf, 0x80-0x14-1-0x3D, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, 0x80-0x14-1-0x3D, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(AFTER_CRED+0x80-0x14-1,outbuf,0x14);

	};




	///////////////////////
	//RSA sign
	///////////////////////
	//for sign 0x80 byte after credentials
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy
		memcpy(buf,AFTER_CRED,0x80);
		
		//before RSA sign-ing
		show_memory(buf, 0x80, "RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		//copy rsa sign to credentials188 buffer
		memcpy(CREDENTIALS188+0x100+0x08,outbuf,0x80);

		//print credentials 0x188
		show_memory(CREDENTIALS188, CREDENTIALS188_LEN, "RSA SIGN cred188");

	};

	//exit(1);
	


	UIC_CRC=Calculate_CRC32( (char *)CREDENTIALS,CREDENTIALS_LEN);
	printf("UIC_CRC = %08X\n",UIC_CRC);


	//exit(1);


	printf("Sending first TCP packet\n");


	printf("send_pkt_len=0x%08X\n",send_pkt_len);


	// Make pkt for send
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	// 0-3: 4 byte of our local IV, e.g. rnd data
	local_rnd=rnd;
	local_rnd=bswap32(local_rnd);
	memcpy(pkt,(char*)&local_rnd,4);
	local_rnd=bswap32(local_rnd);
	len=len+4;

	// 4-14: 10 bytes of send_pkt data, tcp setup indicator
	memcpy(pkt+4,(char *)&send_pkt,send_pkt_len);
	len=len+send_pkt_len;
	
	// Encrypt data

	// Initialize RC4 obfuscation
	iv = rnd;
	printf("Local RC4 IV=0x%08X\n",iv);

	// Expand IV(our rnd)
	Skype_RC4_Expand_IV (&rc4_send, iv, 1);

	// Encrypt RC4
	show_memory(pkt+4, send_pkt_len, "Before RC4 encrypt");
	RC4_crypt (pkt+4, send_pkt_len, &rc4_send, 0);
	show_memory(pkt+4, send_pkt_len, "After RC4 encrypt");



	// Display pkt before sending
	show_memory(pkt, len, "Send pkt");

	// Sending packet
	len=tcp_talk(ip,port,pkt,len,result,0);
	if (len<=0) {
		printf("recv timeout\n");
		exit(1);
	};
	if (len>=1023) {
		printf("Not all data receive, len: 0x%08X\n",len);
		printf("Too big pkt recv, exiting...\n");
		exit(1);
	};

	// Display received pkt
	show_memory(result, len, "Result");



	// Sanity check
	if (len < 14){
		printf("Wrong packet length: 0x%08X, must >= 14\n");
		exit(1);
	};


	// Parse received packet

	// 0-3: Remote IV
	memcpy(&remote_rnd,result,4);

	// 4-14:Copy first 10(0x0a) bytes  of RC4 encoded data to recvbuf
	recvlen=10;
	memcpy(recvbuf,result+4,recvlen);


	// Decrypt RC4 data
	// first 0x0a

	// Initialize RC4 obfuscation
	// based on remote iv
	iv = bswap32(remote_rnd);
	printf("Remote RC4 iv=0x%08X\n",iv);

	// Expand RC4 remote IV
	Skype_RC4_Expand_IV (&rc4_recv, iv, 1);
	
	// Decrypt RC4
	// first 0x0a, not saving state !! so rc4_crypt 4-param test is - 1 !!!
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 1);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");	

	// Check decoded data

	// Check, if answer was correct
	// and rc4 initilization completed
	if (memcmp(recvbuf+2,send_pkt+2,8)!=0){
		printf("RC4 tcp flow handshake failed\n");
		exit(1);
	};


	//14-...


	// Sanity check
	if (len > 14){
		//printf("Wrong packet length: 0x%08X, must >= 14\n");


		recvlen=len-10-4;
		memcpy(recvbuf,result+14,recvlen);


		// Decrypt RC4
		// now we MUST save state !! so rc4_crypt 4-param test is - 0(not test) !!!
		show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
		RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
		show_memory(recvbuf, recvlen, "After RC4 decrypt");	


		// Check decoded data

		// Check, if answer was correct
		// and rc4 initilization completed
		if (memcmp(recvbuf+1,"\x03",1)!=0){
			printf("next msg len decode fail, RC4 tcp flow handshake failed (2)\n");
			exit(1);
		};

	};


	return 0;
};



///////////////////////////////
//tcp second packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt2(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd)
{
	u8 result[0x1000];
	u8 recvbuf[0x1000];
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	char *pkt;
	u32 iv;
	u8 sha1[0x14];
	u8 rnd64bit[0x8];

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;


	printf("Sending second TCP packet\n");


	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup1pkt(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "setup1pkt");


	// aes encrypt block 1
	blkseq=0x00;
	buf1_len=process_aes(buf1, buf1_len, 0, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	// header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	// aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;


	// Encrypt data

	// Initialize RC4 obfuscation
	iv = rnd;
	printf("Local RC4 IV=0x%08X\n",iv);

	// Expand IV(our rnd)
	Skype_RC4_Expand_IV (&rc4_send, iv, 1);

	// Encrypt RC4
	show_memory(pkt, len, "Before RC4 encrypt");
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk(ip,port,pkt,len,result,0);
	if (len<=0) {
		printf("recv timeout\n");
		exit(1);
	};
	
	// recv pkt
	show_memory(result, len, "Result");
	
	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);



	show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");


	/////////////////////////////////
	// Process received pkt
	/////////////////////////////////

	// check pkt size
	tmplen=get_packet_size(recvbuf, 4);
	tmplen=tmplen-1;
	if (tmplen > 0x1000){
		printf("pkt block size too big, len: 0x%08X\n",tmplen);
		exit(1);
	};
	if (tmplen <= 0){
		printf("pkt block size too small, len: 0x%08X\n",tmplen);
		exit(1);
	};

	// show header
	show_memory(recvbuf, 5, "Header");

	// doing aes decrypt
	blkseq=0x00;
	process_aes_crypt(recvbuf+5, recvlen-5, 0, blkseq, 0);



	/////////////////////////////
	// 41 decode
	/////////////////////////////
	// for getting remote session id
	// and rnd64bit challenge
	// and pubkey from credentials
	if (1){
		struct self_s self;
		int ret;
		u8 *data;
		u32 datalen;
		char *block_alloc2;
		u8 tmpbuf[0x100];
		int kk;

		data = recvbuf+5;
		datalen=recvlen-5;

		ret=unpack41_structure(data,datalen,(char *)&self);
		if (ret==-1) {
			printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		print_structure("Handshake pkt 44",(char *)&self,1);

		//get REMOTE_SESSION_ID
		memcpy(&REMOTE_SESSION_ID, self.heap_alloc_buf+8, 4);

		//print it
		printf("remote session id: 0x%08X\n",REMOTE_SESSION_ID);

		//get rnd64bit challenge
		memcpy(rnd64bit, self.heap_alloc_buf+0x34, 4);
		memcpy(rnd64bit+4, self.heap_alloc_buf+0x38, 4);

		//print it
		show_memory(rnd64bit, 8, "rnd64bit");

		// get credentials
		if (self.heap_alloc_struct_array_size[1]<0x188){
				printf("credentials size error\n");
				exit(1);
		};
        block_alloc2=self.heap_alloc_struct_array[1];
		memcpy(remote_credentials, block_alloc2+0x08, 0x100);
		show_memory(remote_credentials, 0x100, "remote credentials");

		//decrypt/unsign credentials by skype_pub
		_get_unsign_cred(remote_credentials, 0x100, tmpbuf);
        show_memory(tmpbuf, 0x100, "decrypt credentials");

		for(kk=0;kk<(0x100-1);kk++){
			if ( (tmpbuf[kk]==0x80) && (tmpbuf[kk+1]==0x01) ) {
				printf("1 kk=0x%08X\n",kk);
				break;
			};
		};
		
		kk=kk+2;
		printf("2 kk=0x%08X\n",kk);

		if ((kk+0x80) < 0x100) {
			memcpy(remote_pubkey,tmpbuf+kk,0x80);
		}else{
			printf("failed to find pubkey in credentials, kk=0x%08X\n",kk);
			exit(1);
		};

        show_memory(remote_pubkey, 0x80, "remote peer pubkey");

		free_structure((char *)&self);

	};



	/////////////////////
	// SHA1 digest
	/////////////////////
	//make hash of remote rnd64bit challenge(8byte) + 0x01(9byte)
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memset(buf,0x1,0x9);
		memcpy(buf,rnd64bit,8);

		//print it
		show_memory(buf, 9, "SHA1 input");

		//make sha1 hash
		//get_sha1_data(buf, 9, outbuf);
		_get_sha1_data(buf, 9, outbuf, 1);


		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(sha1,outbuf,0x14);

	};
	


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign rnd64bit challenge and sha1 hash of it
	if (1) {
		char *buf;
		char *outbuf;

// response on challenge
u8 challenge[]=
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBA\x66\xCE\x3F\xDB\xAA\x55\xB4\xF7\x01\xE9\x26\x8E\x38\x4C"
"\x3C\x06\x30\xF8\xD9\xA4\xBF\x47\x63\xDC\xB8\x4C\x33\xCF\x2C\xBC"
;
//padding
//64bit challenge
//sha160bit hash


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy challenge template
		memcpy(buf,challenge,0x80);
		
		//modify sha1 hash in challenge response
		memcpy(buf+0x80-0x14-1,sha1,0x14);

		//modify rnd64bit challenge in challenge response
		memcpy(buf+0x62,rnd64bit,8);

		//print challenge response data
		//before RSA sign-ing
		show_memory(buf, 0x80, "RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		//copy rsa sign to challenge_response buffer
		//for send this response in next pkt
		memcpy(CHALLENGE_RESPONSE,outbuf,0x80);

		//print rsa signed challenge response data
		show_memory(CHALLENGE_RESPONSE, 0x80, "RSA SIGN output");

	};
	

//	exit(1);


	return 0;
};





///////////////////////////////
//tcp third(3) packet
////////////////////////////////
unsigned int make_tcp_client_sess1_pkt3(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd){
	char result[0x1000];
	u8 recvbuf[0x1000];
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	char *pkt;
	char nonce[0x80];

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;




	printf("Sending third(3) TCP packet\n");


	/////////////////////////////
	// SHA1 digest
	/////////////////////////////
	// for getting aes key nonce1 (local)
	if (1) {
		char *buf;
		char *outbuf;

		//make local nonce
		char tmp[]=
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
;
		memcpy(LOCAL_NONCE, tmp, 0x80);
		// some strange thing, but needed
		LOCAL_NONCE[0]=0x01;

		
		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first integer is 0x00000000 !!!
		memcpy(buf+4,LOCAL_NONCE,0x80);
		
		// show data for hashing
		// integer(0x00) and 0x80 nonce
		show_memory(buf, 0x84, "local NONCE input");

		// making sha1 hash on nonce
		//get_sha1_data(buf, 0x84, outbuf, 1);
		
		_get_sha1_data(buf, 0x84, outbuf, 0);


		// copy local part of aes key
		memcpy(aes_key,outbuf,0x10);

		// show full aes session key
		show_memory(aes_key, 0x10, "AES KEY local");
	};

	/////////////////////////////
	// RSA encode
	/////////////////////////////
	// for encrypting local nonce
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// copy encrypted nonce
		memcpy(buf,LOCAL_NONCE,0x80);
		
		// rsa decrypt nonce
		show_memory(buf, 0x80, "Before RSA encrypt nonce");
		_get_encode_data(buf, 0x80, outbuf);
		show_memory(outbuf, 0x80, "After RSA encrypt nonce");

		// copy decrypted nonce
		memcpy(LOCAL_NONCE,outbuf,0x80);

	};





	//////////////////////////////////////////////////
	// modify nonce blob, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x22d,local_nonce,0x80);


	//////////////////////////////////////////////////
	// modify challenge response blob, in aes data
	//////////////////////////////////////////////////
	//emcpy(aes_41data+0x1a6,CHALLENGE_RESPONSE,0x80);

	//////////////////////////////////////////////////
	// change uic cert to new, becouse of expire 
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x17,aes_41data_remote_uic,0x188);

	//////////////////////////////////////////////////
	// change uic cert2, becouse of keys change
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x02B1,aes_41data_local_uic,0x188);
	
	
	
	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup2pkt(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "setup2pkt");

	// aes encrypt block 1
	blkseq=0x01;
	buf1_len=process_aes(buf1, buf1_len, 0, blkseq, 0);



	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	//aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	/////////////////////////////////
	// RC4 encrypt pkt
	/////////////////////////////////
	show_memory(pkt, len, "Before RC4 encrypt");		
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");		


	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk(ip,port,pkt,len,result,0);
	if (len<=0) {
		printf("recv timeout\n");
		exit(1);
	};
	
	// recv pkt
	show_memory(result, len, "Result");

	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);


	/////////////////////////////////
	// RC4 decrypt pkt
	/////////////////////////////////
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");


	/////////////////////////////////
	// Process received pkt
	/////////////////////////////////

	// check pkt size
	tmplen=get_packet_size(recvbuf, 4);
	tmplen=tmplen-1;
	if (tmplen > 0x1000){
		printf("pkt block size too big, len: 0x%08X\n",tmplen);
		exit(1);
	};
	if (tmplen <= 0){
		printf("pkt block size too small, len: 0x%08X\n",tmplen);
		exit(1);
	};

	// show header
	show_memory(recvbuf, 5, "Header");

	// doing aes decrypt
	blkseq=0x01;
	process_aes_crypt(recvbuf+5, recvlen-5, 0, blkseq, 0);




	/////////////////////////////
	// 41 decode
	/////////////////////////////
	// for getting crypted nonce
	if (1){
		struct self_s self;
		int ret;
		char *mybuf;
		int mysize;
		u8 *data;
		u32 datalen;
		
		data = recvbuf+5;
		datalen=recvlen-5;

		ret=unpack41_structure(data,datalen,(char *)&self);
		if (ret==-1) {
			printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		print_structure("Handshake pkt 57",(char *)&self,1);
		
		mybuf=self.heap_alloc_struct_array[0];
		mysize=self.heap_alloc_struct_array_size[0];

		// copy encrypted nonce from 41 encoding blob
		memcpy(nonce,mybuf,0x80);

		// display crypted nonce
		show_memory(nonce, 0x80, "RSA encrypted remote nonce");
		
		free_structure((char *)&self);
	};



	/////////////////////////////
	// RSA decode
	/////////////////////////////
	// for decrypting remote nonce
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// copy encrypted nonce
		memcpy(buf,nonce,0x80);
		
		// rsa decrypt nonce
		show_memory(buf, 0x80, "Before RSA decrypt nonce");
		_get_decode_data(buf, 0x80, outbuf);
		show_memory(outbuf, 0x80, "After RSA decrypt nonce");

		// copy decrypted nonce
		memcpy(nonce,outbuf,0x80);

	};



	///////////////////////
	// pre-defined data
	///////////////////////
	
	// aes key nonce1 (local)

	//for old xot_iam key
	//memcpy(aes_key,"\xA9\x45\x5C\x42\x7E\xCC\x79\x52\xF8\xA3\x07\xBD\xEA\xC8\x5B\x35",0x10);
	//memcpy(aes_key,"\xBD\x2E\xC3\x04\x10\xD8\x29\x03\x1A\xE4\x00\x97\x94\xB2\x3B\xE4",0x10);

	//for xot_iam
	//memcpy(aes_key,"\xE5\x9A\xA2\x55\xFD\xFF\xE5\xA0\x13\x66\xC8\x15\x3C\x69\x6D\xE6",0x10);

	//for xotabba
	//memcpy(aes_key,"\xC5\xC9\xEA\x82\x77\xFC\x51\x3C\x1A\xB2\xF1\x37\xEE\xCF\x4B\x39",0x10);




	/////////////////////////////
	// SHA1 digest
	/////////////////////////////
	// for getting aes key nonce2 (remote)
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first integer is 0x00000000 !!!
		memcpy(buf+4,nonce,0x80);
		
		// show data for hashing
		// integer(0x00) and 0x80 nonce
		show_memory(buf, 0x84, "NONCE input");

		// making sha1 hash on nonce
		//get_sha1_data(buf, 0x84, outbuf, 1);
		
		_get_sha1_data(buf, 0x84, outbuf, 0);


		// copy remote part of aes key
		memcpy(aes_key+0x10,outbuf,0x10);

		// show full aes session key
		show_memory(aes_key, 0x20, "AES KEY");


	};


	return 0;
};



