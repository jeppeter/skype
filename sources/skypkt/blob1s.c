//
// session 1 pkt
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode_recurs(char *buf, int buf_len, uint blob_count, int dodebug);
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

extern uint BLOB_0_1;


int encode41_sess1pkt1_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

	//u8 chat_string[]="#xoteg_iam/$xot_iam;4fef7b015cb20ad0";

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 4, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x0D;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob2 ALLOC1 chat name string
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_STRING;
	blob.data_size = strlen(CHAT_STRING)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1C;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 0x1D;
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


int encode41_sess1pkt1(char *buf, int buf_limit_len, char *chatstr){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	
	char intbuf[0x1000];
	int intbuf_len;

	session_id=0x6406;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 4, session_id, session_cmd, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = BLOB_0_1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt1_recurs(intbuf,sizeof(intbuf));

    blob.obj_type = 4;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 7;
    blob.obj_data = 5;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);



	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};


int encode41_sess1pkt2(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	u8 str_null[]="";


	session_id=0x872F;
	session_cmd=0x4C;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 3, session_id, session_cmd, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x2A;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 string with null len
    blob.obj_type = 3;
	blob.obj_index = 1;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};



//session 1 pkt 2
/*
"\xAF\x8E\x02\x4C\x41\x03\x00\x00\x2A\x00\x02\x00\x03\x01\x00"
"\xFE\x55\x00\x00"

*/

/*
==============================================
PKT:
==============================================
Session id:  0x0000872F (34607)
Session cmd: 0x0000004C (76)
MAIN: size(0x0000003C)
00000000 00000000 0000002A 00000000 | 00000000 00000000 00000002 00000000 
00000000 00000000 00000003 00000001 | 00000000 00320A60 00000001 

next bytes: 0x00000000 0x00000000 0x0000002A 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x0000002A
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000002 0x00000000 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000002
data:       0x00000000
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000001 0x00000000 0x00320A60 0x00000001 
obj_type :  0x00000003
obj_index:  0x00000001
data:       0x00000000
data_ptr:   0xALLOC001 0x00000001


ALLOCATED: 1 size(0x00000001)
00 

*/














// session 1 pkt1 recursion
/*
"\x41\x04\x00\x01\x0D\x03\x02\x23\x78\x6F\x74\x65\x67"
"\x5F\x69\x61\x6D\x2F\x24\x78\x6F\x74\x5F\x69\x61\x6D\x3B\x34\x66"
"\x65\x66\x37\x62\x30\x31\x35\x63\x62\x32\x30\x61\x64\x30\x00\x00"
"\x1C\x01\x00\x1D\x01"
*/

/*
==============================================
RECURS PKT:
==============================================
MAIN: size(0x00000050)
00000000 00000001 0000000D 00000000 | 00000000 00000003 00000002 00000000 
00320A60 00000025 00000000 0000001C | 00000001 00000000 00000000 00000000 
0000001D 00000001 00000000 00000000 | 

next bytes: 0x00000000 0x00000001 0x0000000D 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x0000000D
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000002 0x00000000 0x00320A60 0x00000025 
obj_type :  0x00000003
obj_index:  0x00000002
data:       0x00000000
data_ptr:   0xALLOC001 0x00000025

next bytes: 0x00000000 0x0000001C 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000001C
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000001D 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000001D
data:       0x00000001
data_ptr:   0x00000000 0x00000000


#xoteg_iam/$xot_iam;4fef7b015cb20ad0
ALLOCATED: 1 size(0x00000025)
23786F74 65675F69 616D2F24 786F745F | 69616D3B 34666566 37623031 35636232 
30616430 00 

*/





/*
// session 1 pkt1
u8 aes_41data_sess1pkt1[]=
"\x86\xC8\x01\x6D\x41\x04\x00\x01\x87\xBF\x86\xAC\x05\x00\x03\x00"
"\x04\x04\x32\x41\x04\x00\x01\x0D\x03\x02\x23\x78\x6F\x74\x65\x67"
"\x5F\x69\x61\x6D\x2F\x24\x78\x6F\x74\x5F\x69\x61\x6D\x3B\x34\x66"
"\x65\x66\x37\x62\x30\x31\x35\x63\x62\x32\x30\x61\x64\x30\x00\x00"
"\x1C\x01\x00\x1D\x01\x00\x07\x05\x8A\xDB"
"\x00\x00"
;
*/



/*
==============================================
PKT:
==============================================
Session id:  0x00006406 (25606)
Session cmd: 0x0000006D (109)
MAIN: size(0x00000050)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000000 
00000000 00000000 00000004 00000004 | 00000000 00320A60 00000032 00000000 
00000007 00000005 00000000 00000000 | 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000000 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000004 0x00000000 0x00320A60 0x00000032 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0xALLOC001 0x00000032

next bytes: 0x00000000 0x00000007 0x00000005 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x00000005
data_ptr:   0x00000000 0x00000000


ALLOCATED: 1 size(0x00000032)
41040001 0D030223 786F7465 675F6961 | 6D2F2478 6F745F69 616D3B34 66656637 
62303135 63623230 61643000 001C0100 | 1D010000 


*/


