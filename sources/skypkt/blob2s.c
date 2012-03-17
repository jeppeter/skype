//
// session 2 pkt
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
extern uint BLOB_0_7;
extern uint BLOB_0_9;
extern uint BLOB_0_2__1;

int encode41_sess2pkt2_recurs(char *buf, int buf_limit_len);
int encode41_sess2pkt2_recurs2(char *buf, int buf_limit_len);
int encode41_sess2pkt2_recurs3(char *buf, int buf_limit_len);


int encode41_sess2pkt1_ack(char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	session_id=0x10CC;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};


int encode41_sess2pkt2(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	char intbuf[0x1000];
	int intbuf_len;


	session_id=0xAA58;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 3, session_id, session_cmd, 0);


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
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess2pkt2_recurs(intbuf,sizeof(intbuf));

    blob.obj_type = 4;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);



	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};





int encode41_sess2pkt2_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

	//u8 chat_string[]="#xoteg_iam/$xot_iam;4fef7b015cb20ad0";
    //u8 peers[]="xot_iam xoteg_iam";
	u8 str_null[]="";

    
	char intbuf[0x1000];
	int intbuf_len;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 6, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x24;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2  chat string
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_STRING;
	blob.data_size = strlen(CHAT_STRING)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1B;
    blob.obj_data = 7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob4  peers
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob5 null string
    blob.obj_type = 3;
	blob.obj_index = 0x1E;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob6 recursive 41
	intbuf_len=encode41_sess2pkt2_recurs2(intbuf,sizeof(intbuf));
	
    // blob6 
    blob.obj_type = 5;
	blob.obj_index = 0x19;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


	

	
	
	
	
	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;
};





int encode41_sess2pkt2_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

    
	char intbuf[0x1000];
	int intbuf_len;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 4, 0);


    // blob1 recursive 41
	intbuf_len=encode41_sess2pkt2_recurs3(intbuf,sizeof(intbuf));
	
    // blob1 
    blob.obj_type = 5;
	blob.obj_index = 0;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 6;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = BLOB_0_7;
    //blob.obj_data = 0x08DD772A;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 9;
	blob.obj_data = BLOB_0_9;
    //blob.obj_data = 0x013AF0D7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
	
	
	
	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;
};



int encode41_sess2pkt2_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

/*
	u8 newblk[]=
"\x1C\xF7\xB2\xBA\x00\xF3\x09\xDA\xC1\x45\x3A\xCE\xFE"
"\x29\x72\xE8\xED\xA5\xED\x57\xA4\x27\xD0\x21\x62\x65\x66\x1C\x8A"
"\x4A\x3A\x00\x15\x44\x9B\x87\x5C\x1A\xDE\xB9\x7A\xB2\x31\x6D\xE6"
"\xF2\x29\x56\x3A\xA1\x30\x39\x29\x96\xA4\x34\x40\x15\x2E\xBA\xDC"
"\xE3\xF4\x8B\x73\x4C\x76\x68\xE3\x80\x63\x9F\xD7\x81\xBC\x26\xEC"
"\xC1\xA7\x1D\x25\x0D\xBA\x16\xC0\x41\xC4\xB1\xC4\x99\x7E\xE6\xA4"
"\x0A\xAB\x8A\xAF\x96\x60\x0D\x88\xDA\xCB\xD9\xA6\x22\xFF\xC9\xBB"
"\x66\x5F\xB6\x4D\xDA\xD6\xD0\x09\x22\x85\x1B\x85\x4A\xD3\xCA\x00"
"\xB5\x4A\xFD"
"\x01\x78\x6F\x74\x5F\x69\x61\x6D\x00\x00\x0A\xAA\xEE"
"\xF5\x46\x00\x0B\x01"
;

	uint newblk_len=sizeof(newblk)-1;
*/

/*

	u8 cred[]=
"\x00\x00\x00\x01\x9A\x12\x47"
"\xC4\x42\x25\x35\xE2\xD5\x28\xA7\x3E\x8C\x2B\x3E\x28\x26\x63\x10"
"\x55\x3F\xA3\x15\xDB\x93\xD7\xD3\xA5\xC4\x4B\x44\xEB\xE0\xAE\xB9"
"\x79\xE5\xCF\x3A\xBE\x8F\xA1\xD5\x71\x94\xD2\xE8\xE4\x0E\x52\x6D"
"\xA3\x7B\xDB\xE4\x9E\x2C\x9E\x18\x43\x38\x07\xF3\x50\x35\x8E\x43"
"\x0A\x7E\x69\xF0\x3D\x09\x26\x7F\x7E\x92\xB3\xE4\x3B\x17\x3D\x24"
"\x80\x50\x78\x2D\x52\xE4\xCE\x81\x85\x3E\xA3\x3B\xEC\x15\x32\xF8"
"\x5B\x22\x80\x04\xD3\xCD\xFA\x5B\xC6\x97\x34\xBE\xB7\x67\xC6\xCD"
"\x79\x47\x6A\x6B\x99\xA3\xF6\x68\x9C\x1E\x47\x1A\xA9\x43\x16\x2E"
"\xB9\x3E\xA4\x84\xAA\xCA\x0A\xCF\x97\x5D\x66\x09\x59\xFA\xEB\x9C"
"\x7D\x6D\xC0\x5B\x53\xCF\x57\xC3\x90\xC4\xA9\xFE\xCA\xEA\x75\x84"
"\xC9\x0D\x64\x9D\x14\x8C\x33\xA6\x80\x09\x4B\x86\x5E\xD8\x15\xBB"
"\xEE\xA0\xDA\x4B\x03\x47\x0B\xD2\xA2\x97\xAF\x32\x29\x94\x9E\x71"
"\xB1\x8C\xCB\x27\x6D\x84\x44\x78\x25\x27\x81\xD0\xC3\xA2\xDD\x9A"
"\x89\x4C\x4F\x91\x47\x25\x83\x49\xDE\x9A\x47\xD0\x51\x7F\x22\x2B"
"\xDB\xFD\xA5\xFF\x2C\x6F\xFD\xBC\xC6\x95\xE5\x89\xA2\xD0\x03\x8C"
"\x2C\x24\x9A\x2E\xFE\xCB\xA1\x9F\x69\x64\xB2\x10\x59"
;


	uint cred_len=sizeof(cred)-1;

*/

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 5, 0);


	
    // hz .. blob1 
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 8;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = BLOB_0_2__1;
    //blob.obj_data = 0xE9C150A9;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob4 newblk...
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)NEWBLK;
	blob.data_size = NEWBLK_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob5 credentials
    blob.obj_type = 4;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)CREDENTIALS;
	blob.data_size = CREDENTIALS_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

	
	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;
};



// session 2 pkt 3

int encode41_sess2pkt3(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	session_id=0xCD81;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 3, session_id, session_cmd, 0);


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

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 8;
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






int encode41_sess2pkt4_ack(char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	session_id=0x33F5;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;

};














/*
u8 aes_41data_sess2pkt3[]=
"\x81\x9B\x03\x6D\x41\x03\x00\x01\x87\xBF\x86\xAC\x05\x00\x03\x00"
"\x00\x08\x01\xA3\xF1"
"\x00\x00"
;
*/



/*
==============================================
PKT:
==============================================
Session id:  0x0000CD81 (52609)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000000 
00000000 00000000 00000000 00000008 | 00000001 00000000 00000000 

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

next bytes: 0x00000000 0x00000008 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000008
data:       0x00000001
data_ptr:   0x00000000 0x00000000


*/




/*

u8 aes_41data_sess2pkt2_recurs[]=

"\x41\x06\x00\x01\x24\x03\x02\x23\x78\x6F\x74\x65"
"\x67\x5F\x69\x61\x6D\x2F\x24\x78\x6F\x74\x5F\x69\x61\x6D\x3B\x34"
"\x66\x65\x66\x37\x62\x30\x31\x35\x63\x62\x32\x30\x61\x64\x30\x00"
"\x00\x1B\x07\x03\x12\x78\x6F\x74\x5F\x69\x61\x6D\x20\x78\x6F\x74"
"\x65\x67\x5F\x69\x61\x6D\x00\x03\x1E\x00\x05\x19

 \x41\x04
 \x05\x00"

"\x41\x05
\x00\x00\x08



\x00\x01\x01
\x00\x02\xA9\xA1\x85\xCE\x0E

\x04""\x03\x92\x01\x1C\xF7\xB2\xBA\x00\xF3\x09\xDA\xC1\x45\x3A\xCE\xFE"
"\x29\x72\xE8\xED\xA5\xED\x57\xA4\x27\xD0\x21\x62\x65\x66\x1C\x8A"
"\x4A\x3A\x00\x15\x44\x9B\x87\x5C\x1A\xDE\xB9\x7A\xB2\x31\x6D\xE6"
"\xF2\x29\x56\x3A\xA1\x30\x39\x29\x96\xA4\x34\x40\x15\x2E\xBA\xDC"
"\xE3\xF4\x8B\x73\x4C\x76\x68\xE3\x80\x63\x9F\xD7\x81\xBC\x26\xEC"
"\xC1\xA7\x1D\x25\x0D\xBA\x16\xC0\x41\xC4\xB1\xC4\x99\x7E\xE6\xA4"
"\x0A\xAB\x8A\xAF\x96\x60\x0D\x88\xDA\xCB\xD9\xA6\x22\xFF\xC9\xBB"
"\x66\x5F\xB6\x4D\xDA\xD6\xD0\x09\x22\x85\x1B\x85\x4A\xD3\xCA\x00"
"\xB5\x4A\xFD
\x01\x78\x6F\x74\x5F\x69\x61\x6D\x00\x00\x0A\xAA\xEE"
"\xF5\x46\x00\x0B\x01


\x04\x04\x84\x02\x00\x00\x00\x01\x9A\x12\x47"
"\xC4\x42\x25\x35\xE2\xD5\x28\xA7\x3E\x8C\x2B\x3E\x28\x26\x63\x10"
"\x55\x3F\xA3\x15\xDB\x93\xD7\xD3\xA5\xC4\x4B\x44\xEB\xE0\xAE\xB9"
"\x79\xE5\xCF\x3A\xBE\x8F\xA1\xD5\x71\x94\xD2\xE8\xE4\x0E\x52\x6D"
"\xA3\x7B\xDB\xE4\x9E\x2C\x9E\x18\x43\x38\x07\xF3\x50\x35\x8E\x43"
"\x0A\x7E\x69\xF0\x3D\x09\x26\x7F\x7E\x92\xB3\xE4\x3B\x17\x3D\x24"
"\x80\x50\x78\x2D\x52\xE4\xCE\x81\x85\x3E\xA3\x3B\xEC\x15\x32\xF8"
"\x5B\x22\x80\x04\xD3\xCD\xFA\x5B\xC6\x97\x34\xBE\xB7\x67\xC6\xCD"
"\x79\x47\x6A\x6B\x99\xA3\xF6\x68\x9C\x1E\x47\x1A\xA9\x43\x16\x2E"
"\xB9\x3E\xA4\x84\xAA\xCA\x0A\xCF\x97\x5D\x66\x09\x59\xFA\xEB\x9C"
"\x7D\x6D\xC0\x5B\x53\xCF\x57\xC3\x90\xC4\xA9\xFE\xCA\xEA\x75\x84"
"\xC9\x0D\x64\x9D\x14\x8C\x33\xA6\x80\x09\x4B\x86\x5E\xD8\x15\xBB"
"\xEE\xA0\xDA\x4B\x03\x47\x0B\xD2\xA2\x97\xAF\x32\x29\x94\x9E\x71"
"\xB1\x8C\xCB\x27\x6D\x84\x44\x78\x25\x27\x81\xD0\xC3\xA2\xDD\x9A"
"\x89\x4C\x4F\x91\x47\x25\x83\x49\xDE\x9A\x47\xD0\x51\x7F\x22\x2B"
"\xDB\xFD\xA5\xFF\x2C\x6F\xFD\xBC\xC6\x95\xE5\x89\xA2\xD0\x03\x8C"
"\x2C\x24\x9A\x2E\xFE\xCB\xA1\x9F\x69\x64\xB2\x10\x59



\x00\x06\x01"
"\x00\x07\xAA\xEE\xF5\x46
\x00\x09\xD7\xE1\xEB\x09"
;



*/

/*

MAIN PTR: 1
ALLOCATED: 1 size(0x00000025)
23786F74 65675F69 616D2F24 786F745F | 69616D3B 34666566 37623031 35636232 
30616430 00 

MAIN PTR: 1
ALLOCATED: 2 size(0x00000012)
786F745F 69616D20 786F7465 675F6961 | 6D000000 

MAIN PTR: 1
ALLOCATED: 3 size(0x00000001)
00 

MAIN PTR: 1
ALLOCATED: 4 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 2
ALLOCATED: 5 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 3
ALLOCATED: 6 size(0x00000092)
1CF7B2BA 00F309DA C1453ACE FE2972E8 | EDA5ED57 A427D021 6265661C 8A4A3A00 
15449B87 5C1ADEB9 7AB2316D E6F22956 | 3AA13039 2996A434 40152EBA DCE3F48B 
734C7668 E380639F D781BC26 ECC1A71D | 250DBA16 C041C4B1 C4997EE6 A40AAB8A 
AF96600D 88DACBD9 A622FFC9 BB665FB6 | 4DDAD6D0 0922851B 854AD3CA 00B54AFD 
01786F74 5F69616D 00000AAA EEF54600 | B010000 

MAIN PTR: 3
ALLOCATED: 7 size(0x00000104)
00000001 9A1247C4 422535E2 D528A73E | 8C2B3E28 26631055 3FA315DB 93D7D3A5 
C44B44EB E0AEB979 E5CF3ABE 8FA1D571 | 94D2E8E4 0E526DA3 7BDBE49E 2C9E1843 
3807F350 358E430A 7E69F03D 09267F7E | 92B3E43B 173D2480 50782D52 E4CE8185 
3EA33BEC 1532F85B 228004D3 CDFA5BC6 | 9734BEB7 67C6CD79 476A6B99 A3F6689C 
1E471AA9 43162EB9 3EA484AA CA0ACF97 | 5D660959 FAEB9C7D 6DC05B53 CF57C390 
C4A9FECA EA7584C9 0D649D14 8C33A680 | 094B865E D815BBEE A0DA4B03 470BD2A2 
97AF3229 949E71B1 8CCB276D 84447825 | 2781D0C3 A2DD9A89 4C4F9147 258349DE 
9A47D051 7F222BDB FDA5FF2C 6FFDBCC6 | 95E589A2 D0038C2C 249A2EFE CBA19F69 
64B21059 

MAIN OTHER: 1 size(0x0000008C)
next bytes: 0x00000000 0x00000001 0x00000024 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x00000024
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000002 0x00000000 0x00320A60 0x00000025 
obj_type :  0x00000003
obj_index:  0x00000002
data:       0x00000000
data_ptr:   0x00320A60 0x00000025

next bytes: 0x00000000 0x0000001B 0x00000007 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000001B
data:       0x00000007
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000012 0x00000000 0x00320AB8 0x00000012 
obj_type :  0x00000003
obj_index:  0x00000012
data:       0x00000000
data_ptr:   0x00320AB8 0x00000012

next bytes: 0x00000003 0x0000001E 0x00000000 0x00320B00 0x00000001 
obj_type :  0x00000003
obj_index:  0x0000001E
data:       0x00000000
data_ptr:   0x00320B00 0x00000001

next bytes: 0x00000005 0x00000019 0x00000000 0x00320B38 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000019
data:       0x00000000
data_ptr:   0x00320B38 0x00000000



MAIN OTHER: 2 size(0x00000064)
next bytes: 0x00000005 0x00000000 0x00000000 0x00320B80 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000000
data:       0x00000000
data_ptr:   0x00320B80 0x00000000

next bytes: 0x00000000 0x00000006 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000006
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000007 0x08DD772A 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x08DD772A
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000009 0x013AF0D7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000009
data:       0x013AF0D7
data_ptr:   0x00000000 0x00000000


MAIN OTHER: 3 size(0x0000008C)
next bytes: 0x00000000 0x00000000 0x00000008 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000008
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000001 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000002 0xE9C150A9 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000002
data:       0xE9C150A9
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x00320BC8 0x00000092 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0x00320BC8 0x00000092

next bytes: 0x00000004 0x00000004 0x00000000 0x00320C90 0x00000104 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0x00320C90 0x00000104


*/











// session 2 pkt 2


/*u8 aes_41data_sess2pkt2[]=
"\xD8\xD4\x02\x6D\x41\x03\x00\x01\x87\xBF\x86\xAC\x05\x00\x03\x01"
"\x04\x04\x88\x04\x41\x06\x00\x01\x24\x03\x02\x23\x78\x6F\x74\x65"
"\x67\x5F\x69\x61\x6D\x2F\x24\x78\x6F\x74\x5F\x69\x61\x6D\x3B\x34"
"\x66\x65\x66\x37\x62\x30\x31\x35\x63\x62\x32\x30\x61\x64\x30\x00"
"\x00\x1B\x07\x03\x12\x78\x6F\x74\x5F\x69\x61\x6D\x20\x78\x6F\x74"
"\x65\x67\x5F\x69\x61\x6D\x00\x03\x1E\x00\x05\x19\x41\x04\x05\x00"
"\x41\x05\x00\x00\x08\x00\x01\x01\x00\x02\xA9\xA1\x85\xCE\x0E\x04"
"\x03\x92\x01\x1C\xF7\xB2\xBA\x00\xF3\x09\xDA\xC1\x45\x3A\xCE\xFE"
"\x29\x72\xE8\xED\xA5\xED\x57\xA4\x27\xD0\x21\x62\x65\x66\x1C\x8A"
"\x4A\x3A\x00\x15\x44\x9B\x87\x5C\x1A\xDE\xB9\x7A\xB2\x31\x6D\xE6"
"\xF2\x29\x56\x3A\xA1\x30\x39\x29\x96\xA4\x34\x40\x15\x2E\xBA\xDC"
"\xE3\xF4\x8B\x73\x4C\x76\x68\xE3\x80\x63\x9F\xD7\x81\xBC\x26\xEC"
"\xC1\xA7\x1D\x25\x0D\xBA\x16\xC0\x41\xC4\xB1\xC4\x99\x7E\xE6\xA4"
"\x0A\xAB\x8A\xAF\x96\x60\x0D\x88\xDA\xCB\xD9\xA6\x22\xFF\xC9\xBB"
"\x66\x5F\xB6\x4D\xDA\xD6\xD0\x09\x22\x85\x1B\x85\x4A\xD3\xCA\x00"
"\xB5\x4A\xFD\x01\x78\x6F\x74\x5F\x69\x61\x6D\x00\x00\x0A\xAA\xEE"
"\xF5\x46\x00\x0B\x01\x04\x04\x84\x02\x00\x00\x00\x01\x9A\x12\x47"
"\xC4\x42\x25\x35\xE2\xD5\x28\xA7\x3E\x8C\x2B\x3E\x28\x26\x63\x10"
"\x55\x3F\xA3\x15\xDB\x93\xD7\xD3\xA5\xC4\x4B\x44\xEB\xE0\xAE\xB9"
"\x79\xE5\xCF\x3A\xBE\x8F\xA1\xD5\x71\x94\xD2\xE8\xE4\x0E\x52\x6D"
"\xA3\x7B\xDB\xE4\x9E\x2C\x9E\x18\x43\x38\x07\xF3\x50\x35\x8E\x43"
"\x0A\x7E\x69\xF0\x3D\x09\x26\x7F\x7E\x92\xB3\xE4\x3B\x17\x3D\x24"
"\x80\x50\x78\x2D\x52\xE4\xCE\x81\x85\x3E\xA3\x3B\xEC\x15\x32\xF8"
"\x5B\x22\x80\x04\xD3\xCD\xFA\x5B\xC6\x97\x34\xBE\xB7\x67\xC6\xCD"
"\x79\x47\x6A\x6B\x99\xA3\xF6\x68\x9C\x1E\x47\x1A\xA9\x43\x16\x2E"
"\xB9\x3E\xA4\x84\xAA\xCA\x0A\xCF\x97\x5D\x66\x09\x59\xFA\xEB\x9C"
"\x7D\x6D\xC0\x5B\x53\xCF\x57\xC3\x90\xC4\xA9\xFE\xCA\xEA\x75\x84"
"\xC9\x0D\x64\x9D\x14\x8C\x33\xA6\x80\x09\x4B\x86\x5E\xD8\x15\xBB"
"\xEE\xA0\xDA\x4B\x03\x47\x0B\xD2\xA2\x97\xAF\x32\x29\x94\x9E\x71"
"\xB1\x8C\xCB\x27\x6D\x84\x44\x78\x25\x27\x81\xD0\xC3\xA2\xDD\x9A"
"\x89\x4C\x4F\x91\x47\x25\x83\x49\xDE\x9A\x47\xD0\x51\x7F\x22\x2B"
"\xDB\xFD\xA5\xFF\x2C\x6F\xFD\xBC\xC6\x95\xE5\x89\xA2\xD0\x03\x8C"
"\x2C\x24\x9A\x2E\xFE\xCB\xA1\x9F\x69\x64\xB2\x10\x59\x00\x06\x01"
"\x00\x07\xAA\xEE\xF5\x46\x00\x09\xD7\xE1\xEB\x09\x5B\xDD"
"\x00\x00"

*/

/*
==============================================
PKT:
==============================================
Session id:  0x0000AA58 (43608)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000001 
00000000 00000000 00000004 00000004 | 00000000 00320A60 00000208 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000004 0x00000000 0x00320A60 0x00000208 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0xALLOC001 0x00000208


ALLOCATED: 1 size(0x00000208)
41060001 24030223 786F7465 675F6961 | 6D2F2478 6F745F69 616D3B34 66656637 
62303135 63623230 61643000 001B0703 | 12786F74 5F69616D 20786F74 65675F69 
616D0003 1E000519 41040500 41050000 | 08000101 0002A9A1 85CE0E04 0392011C 
F7B2BA00 F309DAC1 453ACEFE 2972E8ED | A5ED57A4 27D02162 65661C8A 4A3A0015 
449B875C 1ADEB97A B2316DE6 F229563A | A1303929 96A43440 152EBADC E3F48B73 
4C7668E3 80639FD7 81BC26EC C1A71D25 | 0DBA16C0 41C4B1C4 997EE6A4 0AAB8AAF 
96600D88 DACBD9A6 22FFC9BB 665FB64D | DAD6D009 22851B85 4AD3CA00 B54AFD01 
786F745F 69616D00 000AAAEE F546000B | 01040484 02000000 019A1247 C4422535 
E2D528A7 3E8C2B3E 28266310 553FA315 | DB93D7D3 A5C44B44 EBE0AEB9 79E5CF3A 
BE8FA1D5 7194D2E8 E40E526D A37BDBE4 | 9E2C9E18 433807F3 50358E43 0A7E69F0 
3D09267F 7E92B3E4 3B173D24 8050782D | 52E4CE81 853EA33B EC1532F8 5B228004 
D3CDFA5B C69734BE B767C6CD 79476A6B | 99A3F668 9C1E471A A943162E B93EA484 
AACA0ACF 975D6609 59FAEB9C 7D6DC05B | 53CF57C3 90C4A9FE CAEA7584 C90D649D 
148C33A6 80094B86 5ED815BB EEA0DA4B | 03470BD2 A297AF32 29949E71 B18CCB27 
6D844478 252781D0 C3A2DD9A 894C4F91 | 47258349 DE9A47D0 517F222B DBFDA5FF 
2C6FFDBC C695E589 A2D0038C 2C249A2E | FECBA19F 6964B210 59000601 0007AAEE 
F5460009 D7E1EB09 

*/









//session 2 pkt 1
/*

  "\xCC\x21\x47\x41\x00\xFF\xFF"
"\x00\x00"

*/

/*
first int <=0, guess is a error.., hz kuda 8
Flush_decode.. call fail with ret=0, jump on hzkuda4
*/


