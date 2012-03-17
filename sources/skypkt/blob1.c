//
// setup pkt 1
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];

extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;

extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern u32 LOCAL_SESSION_ID;
extern u8 INIT_UNK[0x16];

extern uint BLOB_1_9_size;
extern uint BLOB_1_9_ptr;


int encode41_setup1pkt(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;

    //u8 remote_name[]="xot_iam";
	//local_session_id=0x249F;

	int buf_len;

	session_id=0x40DD;
	session_cmd=0x43;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 6, session_id, session_cmd, 0);



    // local session id
    blob.obj_type = 0;
	blob.obj_index = 3;
    blob.obj_data = LOCAL_SESSION_ID;;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// unknown blob ???
	// maybe rnd seed
    blob.obj_type = 4;
	blob.obj_index = 1;
    blob.obj_data = 0;
	blob.data_ptr = (uint)INIT_UNK;
	blob.data_size = sizeof(INIT_UNK)-1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// 64 bit challenge nonce
	// size first byte > 0x7f000000 ...
    blob.obj_type = 1;
	blob.obj_index = 9;
    blob.obj_data = 0;
	blob.data_ptr = BLOB_1_9_ptr;
	blob.data_size = BLOB_1_9_size;
	//blob.data_ptr = 0xDB3FCE66;
	//blob.data_size = 0xF7B455AA;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
    
	// some flag ??
	blob.obj_type = 0;
	blob.obj_index = 0x1B;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// remote skypename
	blob.obj_type = 3;
	blob.obj_index = 0;
    blob.obj_data = 0;
	blob.data_ptr = (int)REMOTE_NAME;
	blob.data_size = strlen(REMOTE_NAME)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag2 ??
	blob.obj_type = 0;
	blob.obj_index = 0x18;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};


/*
"\xDD\x81\x01\x43\x41\x06\x00\x03\x9F\x49\x04\x01\x15\x75\x4E\xCB"
"\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5\x43\xA3\x14\xA9"
"\xEF\x08\x01\x09\xF7\xB4\x55\xAA\xDB\x3F\xCE\x66\x00\x1B\x00\x03"
"\x00\x78\x6F\x74\x5F\x69\x61\x6D\x00\x00\x18\x01\xBB\xFD"
"\x00\x00"
*/




/*
==============================================
MY PKT 
==============================================
Session id:  0x000040DD (16605)
Session cmd: 0x00000043 (67)
MAIN: size(0x00000078)
00000000 00000003 0000249F 00000000 | 00000000 00000004 00000001 00000000 
00320A60 00000015 00000001 00000009 | 00000000 DB3FCE66 F7B455AA 00000000 
0000001B 00000000 00000000 00000000 | 00000003 00000000 00000000 00320AA8 
00000008 00000000 00000018 00000001 | 00000000 00000000 

next bytes: 0x00000000 0x00000003 0x0000249F 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x0000249F
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000001 0x00000000 0x00320A60 0x00000015 
obj_type :  0x00000004
obj_index:  0x00000001
data:       0x00000000
data_ptr:   0xALLOC001 0x00000015

next bytes: 0x00000001 0x00000009 0x00000000 0xDB3FCE66 0xF7B455AA 
obj_type :  0x00000001
obj_index:  0x00000009
data:       0x00000000
data_ptr:   0xDB3FCE66 0xF7B455AA

next bytes: 0x00000000 0x0000001B 0x00000000 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000001B
data:       0x00000000
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000000 0x00000000 0x00320AA8 0x00000008 
obj_type :  0x00000003
obj_index:  0x00000000
data:       0x00000000
data_ptr:   0xALLOC002 0x00000008

next bytes: 0x00000000 0x00000018 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000018
data:       0x00000001
data_ptr:   0x00000000 0x00000000


ALLOCATED: 1 size(0x00000015)
754ECB75 3834FA8E 01C0A801 2881A543 | A314A9EF 8000000 

ALLOCATED: 2 size(0x00000008)
786F745F 69616D00 

*/




