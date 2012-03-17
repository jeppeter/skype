/*  
*
* Direct TCP connect to skype client
* cmd 109 session
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
extern int _get_sign_data(char *buf, int len, char *outbuf);
//extern int _get_unsign_cred(char *buf, int len, char *outbuf);

// utils
extern int get_blkseq(char *data, int datalen);
extern int process_aes_crypt(char *data, int datalen, int usekey, int blkseq, int need_xor);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
extern int decode41(char *data, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int process_aes(char *buf, int buf_len, int usekey, int blkseq, int need_xor);
extern int first_bytes_correction(char *header, int header_len, char *buf, int buf_len);

//blobs encode 
int encode41_sesspkt_ack(char *buf, int buf_limit_len, uint cmd);

extern int encode41_sess1pkt1(char *buf, int buf_limit_len);
extern int encode41_sess1pkt2(char *buf, int buf_limit_len);

extern int encode41_sess2pkt2(char *buf, int buf_limit_len);
extern int encode41_sess2pkt3(char *buf, int buf_limit_len);

extern int encode41_sess3pkt2(char *buf, int buf_limit_len);
extern int encode41_sess3pkt4(char *buf, int buf_limit_len);
extern int encode41_sess3pkt5(char *buf, int buf_limit_len);
extern int encode41_sess3pkt7(char *buf, int buf_limit_len);
extern int encode41_sess3pkt8(char *buf, int buf_limit_len);

extern int encode41_sess4pkt3(char *buf, int buf_limit_len);
extern int encode41_sess4pkt4(char *buf, int buf_limit_len);

extern int encode41_newblk1(char *buf, int buf_limit_len);
extern int encode41_newblk2(char *buf, int buf_limit_len);
extern int encode41_newblk3(char *buf, int buf_limit_len);

// global data

extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern u8 challenge_response[0x80];

extern u8 aes_key[0x20];
extern u32 remote_session_id;
extern u32 LOCAL_SESSION_ID;

extern u32 confirm[0x100];
extern u32 confirm_count;


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];


///////////////////////////////
//tcp four(4) packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt4(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd){
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[5];
	int pkt_block;
	int i;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;
	
	unsigned int chatrnd;



	tmplen=strlen(CHAT_STRING)-4;
	
	chatrnd=(rand() % 0x9);
	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
	tmplen++;
	printf("chatrnd=%d\n",chatrnd);
	chatrnd=(rand() % 0x9);
	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
	tmplen++;
	printf("chatrnd=%d\n",chatrnd);
	chatrnd=(rand() % 0x9);
	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
	tmplen++;
	printf("chatrnd=%d\n",chatrnd);
	chatrnd=(rand() % 0x9);
	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
	tmplen++;
	printf("chatrnd=%d\n",chatrnd);

	printf("CHAT ID:%s\n",CHAT_STRING);

	printf("::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	printf("Sending four TCP packet, session cmd 109, pkt 1\n");
	printf("::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	
	//////////////////////////////////////////////////
	// modify challenge response blob, in aes data
	//////////////////////////////////////////////////


	///////////////////////////////
	// first 41
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt1(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt1");

	//aes encrypt block 1
	blkseq=0x02;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	///////////////////////////////
	// second 41
	///////////////////////////////

	memset(buf2,0,sizeof(buf2));
  	buf2_len=encode41_sess1pkt2(buf2, sizeof(buf2));
	show_memory(buf2, buf2_len, "sess1pkt2");

	//aes encrypt block 2
	blkseq=0x03;
	buf2_len=process_aes(buf2, buf2_len, 1, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction, block 1
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt1header");


	/////////////////////////////////////
	// first bytes correction, block 2
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf2header_len=first_bytes_correction(buf2header, sizeof(buf2header)-1, buf2, buf2_len);
	show_memory(buf2header, buf2header_len, "sess1pkt2header");

	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//aes 1
	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	
	// aes 2
	memcpy(pkt+len,buf2header,buf2header_len);
	len=len+buf2header_len;
	
	memcpy(pkt+len,buf2,buf2_len);
	len=len+buf2_len;
	

	
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
	// processing response
	/////////////////////////////////
	// by aes blocks with 109 cmd each

	i=0;
	pkt_block=0;
	confirm_count=0;

	while(len > 0){
		pkt_block++;

		printf("PKT BLK: %d\n\n",pkt_block);

		// 1-2 bytes: - size,
		// 3 byte: 05
		// 4-5 byte - crc32 ^ sessid
		tmplen=get_packet_size(recvbuf+i, 4);
		tmplen=tmplen-1;
		if (tmplen > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",tmplen);
			exit(1);
		};
		if (tmplen <= 0){
			printf("pkt block size too small, len: 0x%08X\n",tmplen);
			exit(1);
		};

		//for small packets, header len - 4
		show_memory(recvbuf+i, 4, "Header");

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+4,tmplen-2);

		//aes decode
		process_aes_crypt(recvbuf+i+4, tmplen-2, 1, remote_blkseq, 1);

		//2bytes of size, encode rest of length
		//tmplen-2 , rest of len - 2 bytes of crc32 ^ sessid
		decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply1");

		//processing headers, need for cmd confirmation
		memcpy(header41,recvbuf+i+4,5);

		//remember first byte sess id, for send in confirmation
		if (header41[2]==0x6d){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x6d){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		if (header41[2]==0x4D){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4D){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		/*
		if (header41[2]==0x4C){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4C){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		*/

		len=len-tmplen-2;
		i=i+tmplen+2;

		printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		printf("len(current block)=%d\n",tmplen);
		printf("confirm_count=%d\n",confirm_count);

	};


	return 0;
};








///////////////////////////////
//tcp fifth(5) packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt5(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd){
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[5];
	int i,j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;
	
	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;
	
	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;
	

	u8 buf_newblk1[0x1000];
	int buf_newblk1_len;


/*
u8 newblk_unknown[]=
"\x41\x08\x00\x00\x01\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE2\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\xA0\xFB\xE3\xEC\x03\x03"
;
*/


	printf("::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	printf("Sending fifth(5) TCP packet, session cmd 109, pkt 2\n");
	printf("::::::::::::::::::::::::::::::::::::::::::::::::::\n");

	
	///////////////////////////////
	// first 41
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sesspkt_ack(buf1, sizeof(buf1), confirm[0]);
	show_memory(buf1, buf1_len, "sess2pkt1");

	// aes encrypt block 1
	blkseq=0x04;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	///////////////////////////////
	// second 41
	///////////////////////////////


	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;

	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		int tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// credentials
		memcpy(buf,CREDENTIALS, CREDENTIALS_LEN);

		// chatid 
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+NEWBLK_LEN,outbuf,0x14);
    	NEWBLK_LEN+=0x14;

	};




	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);


	memset(buf_newblk1,0,sizeof(buf_newblk1));
  	buf_newblk1_len=encode41_newblk1(buf_newblk1, sizeof(buf_newblk1));
	show_memory(buf_newblk1, buf_newblk1_len, "buf_newblk1");
	

	tmplen=buf_newblk1_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk1_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk1,tmplen);
	NEWBLK_LEN+=tmplen;


	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			printf("NEWBLK LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			exit(1);
	};

	NEWBLK[0x7f]=0xBC;

	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x12)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;


		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk1_len ){
			// aes41
			tlen=buf_newblk1_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk1+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};



		/*
	    memcpy(NEWBLK+NEWBLK_LEN,"\x01",1);
		NEWBLK_LEN++;

		tlen=strlen(REMOTE_NAME)+1;
	    memcpy(NEWBLK+NEWBLK_LEN,REMOTE_NAME,tlen);
		NEWBLK_LEN+=tlen;

	    memcpy(NEWBLK+NEWBLK_LEN,"\x00\x0A\xAA\xEE\xF5\x46\x00\x0B\x01", 9);
	    NEWBLK_LEN+=9;

		*/

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};


	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK new OUTPUT");
	
	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk RSA SIGN output");

	};
	


	memset(buf2,0,sizeof(buf2));
  	buf2_len=encode41_sess2pkt2(buf2, sizeof(buf2));
	show_memory(buf2, buf2_len, "sess2pkt2");

	//aes encrypt block 2
	blkseq=0x05;
	buf2_len=process_aes(buf2, buf2_len, 1, blkseq, 0);


	///////////////////////////////
	// third 41
	///////////////////////////////

	memset(buf3,0,sizeof(buf3));
  	buf3_len=encode41_sess2pkt3(buf3, sizeof(buf3));
	show_memory(buf3, buf3_len, "sess2pkt3");

	//aes encrypt block 3
	blkseq=0x06;
	buf3_len=process_aes(buf3, buf3_len, 1, blkseq, 0);

	///////////////////////////////
	// fourth 41
	///////////////////////////////
	memset(buf4,0,sizeof(buf4));
  	buf4_len=encode41_sesspkt_ack(buf4, sizeof(buf4), confirm[1]);
	show_memory(buf4, buf4_len, "sess2pkt4");

	//aes encrypt block 4
	blkseq=0x07;
	buf4_len=process_aes_crypt(buf4, buf4_len, 1, blkseq, 0);



	/////////////////////////////////////
	// first bytes correction, block 1
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess2pkt1header");


	/////////////////////////////////////
	// first bytes correction, block 2
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf2header_len=first_bytes_correction(buf2header, sizeof(buf2header)-1, buf2, buf2_len);
	show_memory(buf2header, buf2header_len, "sess2pkt2header");

	/////////////////////////////////////
	// first bytes correction, block 3
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf3header_len=first_bytes_correction(buf3header, sizeof(buf3header)-1, buf3, buf3_len);
	show_memory(buf3header, buf3header_len, "sess2pkt3header");


	/////////////////////////////////////
	// first bytes correction, block 4
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf4header_len=first_bytes_correction(buf4header, sizeof(buf4header)-1, buf4, buf4_len);
	show_memory(buf4header, buf4header_len, "sess2pkt4header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//block 1
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	
	// block 2
	memcpy(pkt+len,buf2header,buf2header_len);
	len=len+buf2header_len;
	memcpy(pkt+len,buf2,buf2_len);
	len=len+buf2_len;

	// block 3
	memcpy(pkt+len,buf3header,buf3header_len);
	len=len+buf3header_len;
	memcpy(pkt+len,buf3,buf3_len);
	len=len+buf3_len;
	
	// block 4
	memcpy(pkt+len,buf4header,buf4header_len);
	len=len+buf4header_len;
	memcpy(pkt+len,buf4,buf4_len);
	len=len+buf4_len;
	

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
	// processing response
	/////////////////////////////////
	// by aes blocks with 109 cmd each
	i=0;j=0;
	confirm_count=0;
	while(len > 0){
		j++;

		printf("PKT BLK: %d\n\n",j);

		tmplen=get_packet_size(recvbuf+i, 4);
		tmplen=tmplen-1;
		if (tmplen > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",tmplen);
			exit(1);
		};
		if (tmplen <= 0){
			printf("pkt block size too small, len: 0x%08X\n",tmplen);
			exit(1);
		};

		show_memory(recvbuf+i, 4, "Header");

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+4,tmplen-2);

		process_aes_crypt(recvbuf+i+4, tmplen-2, 1, remote_blkseq, 1);

		decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply2");


		//processing headers, need for cmd conformation
		memcpy(header41,recvbuf+i+4,5);

		//remember first byte sess id, for send in confirmation
		if (header41[3]==0x6d){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		if (header41[2]==0x6d){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[2]==0x4D){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4D){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};





		len=len-tmplen-2;
		i=i+tmplen+2;

		printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		printf("len(current block)=%d\n",tmplen);
		printf("confirm_count=%d\n",confirm_count);

	};



	//exit(1);

	return 0;
};









///////////////////////////////
//tcp sixth(6) packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt6(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd){
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[0x100];
	int i,j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;

	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;

	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;

	u8 buf5[0x1000];
	int buf5_len;
	u8 buf5header[0x10];
	int buf5header_len;

	u8 buf6[0x1000];
	int buf6_len;
	u8 buf6header[0x10];
	int buf6header_len;

	u8 buf7[0x1000];
	int buf7_len;
	u8 buf7header[0x10];
	int buf7header_len;

	u8 buf8[0x1000];
	int buf8_len;
	u8 buf8header[0x10];
	int buf8header_len;

	u8 buf9[0x1000];
	int buf9_len;
	u8 buf9header[0x10];
	int buf9header_len;

	u8 buf_newblk2[0x1000];
	int buf_newblk2_len;



/*
	u8 newblk_unknown[]="\x41\x08\x00\x00\x04\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE2\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\x9F\xFB\xE3\xEC\x03\x03"
;
*/

	printf("Sending sixth(6) TCP packet, session cmd 109, pkt 3\n");
	


	///////////////////////////////
	// first 41
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sesspkt_ack(buf1, sizeof(buf1), confirm[0]);
	show_memory(buf1, buf1_len, "sess3pkt1ack");

	// aes encrypt block 1
	blkseq=0x08;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	///////////////////////////////
	// second 41
	///////////////////////////////

	memset(buf2,0,sizeof(buf2));
  	buf2_len=encode41_sess3pkt2(buf2, sizeof(buf2));
	show_memory(buf2, buf2_len, "sess3pkt2");

	//aes encrypt block 2
	blkseq=0x09;
	buf2_len=process_aes(buf2, buf2_len, 1, blkseq, 0);



	///////////////////////////////
	// third 41
	///////////////////////////////

	memset(buf3,0,sizeof(buf3));
  	buf3_len=encode41_sesspkt_ack(buf3, sizeof(buf3), confirm[1]);
	show_memory(buf3, buf3_len, "sess3pkt3ack");

	//aes encrypt block 3
	blkseq=0x0A;
	buf3_len=process_aes(buf3, buf3_len, 1, blkseq, 0);


	///////////////////////////////
	// fouth block4 41
	///////////////////////////////



	//////////////////////////////////////////////////
	// modify credentials, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4+0xc5,aes_41data4_fix,0x100);


	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;


	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		int tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// credentials
		memcpy(buf,CREDENTIALS,CREDENTIALS_LEN);

		// + chatid 
		//memcpy(buf+4+0x100,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID 2 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) 2 OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+1,outbuf,0x14);
		NEWBLK_LEN+=0x14;

	};




	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4_newblk+0x15,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
	//memcpy(aes_41data4_newblk+0x15,CHAT_STRING,0x24);

	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);

	memset(buf_newblk2,0,sizeof(buf_newblk2));
  	buf_newblk2_len=encode41_newblk2(buf_newblk2, sizeof(buf_newblk2));
	show_memory(buf_newblk2, buf_newblk2_len, "buf_newblk2");


	tmplen=buf_newblk2_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk2_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk2,tmplen);
	NEWBLK_LEN+=tmplen;


	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			printf("NEWBLK2 LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			exit(1);
	};

	NEWBLK[0x7f]=0xBC;

	

	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x0c)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;

		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk2_len ){
			// aes41
			tlen=buf_newblk2_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk2+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};


		/*
		memcpy(NEWBLK+NEWBLK_LEN,"\x0E\x00\x00\x0F\x00\x00\x0A\x9D\xED\xA2\x90\x04", 0x0C);
	    NEWBLK_LEN=NEWBLK_LEN+0x0C;
		*/

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK 2 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) 2 OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};


	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK2 new OUTPUT");


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk 2 RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk 2 RSA SIGN output");

	};
	


	//////////////////////////////////////////////////
	// modify sign new block with hash on cred+chatid , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4+0x31,aes_41data4_newblk,0x80);



	
	memset(buf4,0,sizeof(buf4));
  	buf4_len=encode41_sess3pkt4(buf4, sizeof(buf4));
	show_memory(buf4, buf4_len, "sess3pkt4");

	//aes encrypt block 4
	blkseq=0x0B;
	buf4_len=process_aes(buf4, buf4_len, 1, blkseq, 0);



	///////////////////////////////
	// fifth block5 41
	///////////////////////////////

	
	memset(buf5,0,sizeof(buf5));
  	buf5_len=encode41_sess3pkt5(buf5, sizeof(buf5));
	show_memory(buf5, buf5_len, "sess3pkt5");

	//aes encrypt block 5
	blkseq=0x0C;
	buf5_len=process_aes(buf5, buf5_len, 1, blkseq, 0);


	///////////////////////////////
	// block6 41
	///////////////////////////////

	memset(buf6,0,sizeof(buf6));
  	buf6_len=encode41_sesspkt_ack(buf6, sizeof(buf6), confirm[2]);
	show_memory(buf6, buf6_len, "sess3pkt6ack");

	//aes encrypt block 6
	blkseq=0x0D;
	buf6_len=process_aes(buf6, buf6_len, 1, blkseq, 0);




	///////////////////////////////
	// seventh block7 41
	///////////////////////////////


	//////////////////////////////////////////////////
	// modify credentials, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data7+0x53,REMOTE_NAME,0x07);


	memset(buf7,0,sizeof(buf7));
  	buf7_len=encode41_sess3pkt7(buf7, sizeof(buf7));
	show_memory(buf7, buf7_len, "sess3pkt7");


	//aes encrypt block 7
	blkseq=0x0E;
	buf7_len=process_aes(buf7, buf7_len, 1, blkseq, 0);


	///////////////////////////////
	// eighth block8 41
	///////////////////////////////

	memset(buf8,0,sizeof(buf8));
  	buf8_len=encode41_sess3pkt8(buf8, sizeof(buf8));
	show_memory(buf8, buf8_len, "sess3pkt8");

	//aes encrypt block 8
	blkseq=0x0F;
	buf8_len=process_aes(buf8, buf8_len, 1, blkseq, 0);


	///////////////////////////////
	// block9 41
	///////////////////////////////

	memset(buf9,0,sizeof(buf9));
  	buf9_len=encode41_sesspkt_ack(buf9, sizeof(buf9), confirm[3]);
	show_memory(buf9, buf9_len, "sess3pkt9ack");

	//aes encrypt block 9
	blkseq=0x10;
	buf9_len=process_aes(buf9, buf9_len, 1, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction, block 1
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing	

	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess3pkt1header");

	/////////////////////////////////////
	// first bytes correction, block 2
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf2header_len=first_bytes_correction(buf2header, sizeof(buf2header)-1, buf2, buf2_len);
	show_memory(buf2header, buf2header_len, "sess3pkt2header");

	/////////////////////////////////////
	// first bytes correction, block 3
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	
	buf3header_len=first_bytes_correction(buf3header, sizeof(buf3header)-1, buf3, buf3_len);
	show_memory(buf3header, buf3header_len, "sess3pkt3header");

	/////////////////////////////////////
	// first bytes correction, block 4
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf4header_len=first_bytes_correction(buf4header, sizeof(buf4header)-1, buf4, buf4_len);
	show_memory(buf4header, buf4header_len, "sess3pkt4header");

	/////////////////////////////////////
	// first bytes correction, block 5
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf5header_len=first_bytes_correction(buf5header, sizeof(buf5header)-1, buf5, buf5_len);
	show_memory(buf5header, buf5header_len, "sess3pkt5header");

	/////////////////////////////////////
	// first bytes correction, block 6
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf6header_len=first_bytes_correction(buf6header, sizeof(buf6header)-1, buf6, buf6_len);
	show_memory(buf6header, buf6header_len, "sess3pkt6header");

	/////////////////////////////////////
	// first bytes correction, block 7
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf7header_len=first_bytes_correction(buf7header, sizeof(buf7header)-1, buf7, buf7_len);
	show_memory(buf7header, buf7header_len, "sess3pkt7header");

	/////////////////////////////////////
	// first bytes correction, block 8
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf8header_len=first_bytes_correction(buf8header, sizeof(buf8header)-1, buf8, buf8_len);
	show_memory(buf8header, buf8header_len, "sess3pkt8header");

	/////////////////////////////////////
	// first bytes correction, block 9
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf9header_len=first_bytes_correction(buf9header, sizeof(buf9header)-1, buf9, buf9_len);
	show_memory(buf9header, buf9header_len, "sess3pkt9header");



	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//block 1
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	
	// block 2
	memcpy(pkt+len,buf2header,buf2header_len);
	len=len+buf2header_len;
	memcpy(pkt+len,buf2,buf2_len);
	len=len+buf2_len;

	// block 3
	memcpy(pkt+len,buf3header,buf3header_len);
	len=len+buf3header_len;
	memcpy(pkt+len,buf3,buf3_len);
	len=len+buf3_len;
	
	// block 4
	memcpy(pkt+len,buf4header,buf4header_len);
	len=len+buf4header_len;
	memcpy(pkt+len,buf4,buf4_len);
	len=len+buf4_len;
	
	// block 5
	memcpy(pkt+len,buf5header,buf5header_len);
	len=len+buf5header_len;
	memcpy(pkt+len,buf5,buf5_len);
	len=len+buf5_len;
	
	// block 6
	memcpy(pkt+len,buf6header,buf6header_len);
	len=len+buf6header_len;
	memcpy(pkt+len,buf6,buf6_len);
	len=len+buf6_len;
	
	// block 7
	memcpy(pkt+len,buf7header,buf7header_len);
	len=len+buf7header_len;
	memcpy(pkt+len,buf7,buf7_len);
	len=len+buf7_len;
	
	// block 8
	memcpy(pkt+len,buf8header,buf8header_len);
	len=len+buf8header_len;
	memcpy(pkt+len,buf8,buf8_len);
	len=len+buf8_len;
	
	// block 9
	memcpy(pkt+len,buf9header,buf9header_len);
	len=len+buf9header_len;
	memcpy(pkt+len,buf9,buf9_len);
	len=len+buf9_len;
	


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
	// processing response
	/////////////////////////////////
	// by aes blocks with 109 cmd each
	i=0;j=0;
	confirm_count=0;
	while(len > 0){
		j++;

		printf("PKT BLK: %d\n\n",j);

		tmplen=get_packet_size(recvbuf+i, 4);
		tmplen=tmplen-1;
		if (tmplen > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",tmplen);
			exit(1);
		};
		if (tmplen <= 0){
			printf("pkt block size too small, len: 0x%08X\n",tmplen);
			exit(1);
		};

		show_memory(recvbuf+i, 4, "Header");//0x0b//0x08

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+4,tmplen-2);
		
		process_aes_crypt(recvbuf+i+4, tmplen-2, 1, remote_blkseq, 1);

		decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply3");


		//processing headers, need for cmd conformation
		memcpy(header41,recvbuf+i+4,5);

		//remember first byte sess id, for send in confirmation
		if (header41[3]==0x6d){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		if (header41[2]==0x6d){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[2]==0x4D){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4D){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};





		len=len-tmplen-2;
		i=i+tmplen+2;

		printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		printf("len(current block)=%d\n",tmplen);
		printf("confirm_count=%d\n",confirm_count);

	};


	//exit(1);


	return 0;
};






///////////////////////////////
//tcp seventh(7) packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt7(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd){
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[0x100];
	int i;
	int j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;


	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;

	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;

	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;

	u8 buf5[0x1000];
	int buf5_len;
	u8 buf5header[0x10];
	int buf5header_len;


	u8 buf_newblk3[0x1000];
	int buf_newblk3_len;


/*
	u8 newblk_unknown[]="\x41\x06\x00\x00\x03\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE7\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\xA1\xFB\xE3\xEC\x03\x03"
;
*/



	printf("Sending seventh(7) TCP packet, session cmd 109, pkt 4\n");
	


	///////////////////////////////
	// first 41
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sesspkt_ack(buf1, sizeof(buf1), confirm[0]);
	show_memory(buf1, buf1_len, "sess4pkt1ack");

	// aes encrypt block 1
	blkseq=0x11;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	///////////////////////////////
	// second 41
	///////////////////////////////

	memset(buf2,0,sizeof(buf2));
  	buf2_len=encode41_sesspkt_ack(buf2, sizeof(buf2), confirm[1]);
	show_memory(buf2, buf2_len, "sess4pkt2ack");

	//aes encrypt block 2
	blkseq=0x12;
	buf2_len=process_aes(buf2, buf2_len, 1, blkseq, 0);


	
	///////////////////////////////
	// thirth block3 41
	///////////////////////////////

	// uic crc

	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;


	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		uint tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// credentials
		memcpy(buf, CREDENTIALS, CREDENTIALS_LEN);

		// + chatid 
		//memcpy(buf+4+0x100,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID 3 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) 3 OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+1,outbuf,0x14);
		NEWBLK_LEN+=0x14;

	};


	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data3_newblk+0x15,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
	//memcpy(aes_41data3_newblk+0x15,CHAT_STRING,0x24);

	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);

	
	memset(buf_newblk3,0,sizeof(buf_newblk3));
  	buf_newblk3_len=encode41_newblk3(buf_newblk3, sizeof(buf_newblk3));
	show_memory(buf_newblk3, buf_newblk3_len, "buf_newblk3");


	tmplen=buf_newblk3_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk3_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk3,tmplen);
	NEWBLK_LEN+=tmplen;

	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			printf("NEWBLK2 LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			exit(1);
	};

	NEWBLK[0x7f]=0xBC;

	
	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x0a)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;


		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk3_len ){
			// aes41
			tlen=buf_newblk3_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk3+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};



		/*
		// message right after newblk
		memcpy(NEWBLK+NEWBLK_LEN,"\x02",1);
		NEWBLK_LEN++;

		memcpy(NEWBLK+NEWBLK_LEN,MSG_TEXT,strlen(MSG_TEXT));
		NEWBLK_LEN+=strlen(MSG_TEXT);

		memcpy(NEWBLK+NEWBLK_LEN,"\x00",1);
		NEWBLK_LEN++;
		*/


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x2000);
		memset(outbuf,0,0x200);


		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);		
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK 3 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) 3 OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};

	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK3 new OUTPUT");


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk 3 RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk 3 RSA SIGN output");

	};
	


	//////////////////////////////////////////////////
	// modify sign new block with hash on cred+chatid , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data3+0x35,aes_41data3_newblk,0x80);

	
	memset(buf3,0,sizeof(buf3));
  	buf3_len=encode41_sess4pkt3(buf3, sizeof(buf3));
	show_memory(buf3, buf3_len, "sess4pkt3");

	//aes encrypt block 3
	blkseq=0x13;
	buf3_len=process_aes(buf3, buf3_len, 1, blkseq, 0);


	///////////////////////////////
	// fourth block4 41
	///////////////////////////////

	memset(buf4,0,sizeof(buf4));
  	buf4_len=encode41_sess4pkt4(buf4, sizeof(buf4));
	show_memory(buf4, buf4_len, "sess4pkt4");

	//aes encrypt block 4
	blkseq=0x14;
	buf4_len=process_aes(buf4, buf4_len, 1, blkseq, 0);


	///////////////////////////////
	// block5 41
	///////////////////////////////
	
	memset(buf5,0,sizeof(buf5));
  	buf5_len=encode41_sesspkt_ack(buf5, sizeof(buf5), confirm[2]);
	show_memory(buf5, buf5_len, "sess4pkt5ack");

	//aes encrypt block 4
	blkseq=0x15;
	buf5_len=process_aes(buf5, buf5_len, 1, blkseq, 0);



	/////////////////////////////////////
	// first bytes correction, block 1
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing	

	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess4pkt1header");

	/////////////////////////////////////
	// first bytes correction, block 2
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf2header_len=first_bytes_correction(buf2header, sizeof(buf2header)-1, buf2, buf2_len);
	show_memory(buf2header, buf2header_len, "sess4pkt2header");

	/////////////////////////////////////
	// first bytes correction, block 3
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	
	buf3header_len=first_bytes_correction(buf3header, sizeof(buf3header)-1, buf3, buf3_len);
	show_memory(buf3header, buf3header_len, "sess4pkt3header");

	/////////////////////////////////////
	// first bytes correction, block 4
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf4header_len=first_bytes_correction(buf4header, sizeof(buf4header)-1, buf4, buf4_len);
	show_memory(buf4header, buf4header_len, "sess4pkt4header");

	/////////////////////////////////////
	// first bytes correction, block 5
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing

	buf5header_len=first_bytes_correction(buf5header, sizeof(buf5header)-1, buf5, buf5_len);
	show_memory(buf5header, buf5header_len, "sess4pkt5header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//block 1
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	
	// block 2
	memcpy(pkt+len,buf2header,buf2header_len);
	len=len+buf2header_len;
	memcpy(pkt+len,buf2,buf2_len);
	len=len+buf2_len;

	// block 3
	memcpy(pkt+len,buf3header,buf3header_len);
	len=len+buf3header_len;
	memcpy(pkt+len,buf3,buf3_len);
	len=len+buf3_len;
	
	// block 4
	memcpy(pkt+len,buf4header,buf4header_len);
	len=len+buf4header_len;
	memcpy(pkt+len,buf4,buf4_len);
	len=len+buf4_len;
	
	// block 5
	memcpy(pkt+len,buf5header,buf5header_len);
	len=len+buf5header_len;
	memcpy(pkt+len,buf5,buf5_len);
	len=len+buf5_len;
	


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
	// processing response
	/////////////////////////////////
	// by aes blocks with 109 cmd each
	i=0;j=0;
	confirm_count=0;
	while(len > 0){
		j++;

		printf("PKT BLK: %d\n\n",j);

		tmplen=get_packet_size(recvbuf+i, 4);
		tmplen=tmplen-1;
		if (tmplen > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",tmplen);
			exit(1);
		};
		if (tmplen <= 0){
			printf("pkt block size too small, len: 0x%08X\n",tmplen);
			exit(1);
		};

		show_memory(recvbuf+i, 4, "Header");

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+4,tmplen-2);
		
		//aes decrypt
		process_aes_crypt(recvbuf+i+4, tmplen-2, 1, remote_blkseq, 1);

		//decode 41
		decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply4");

		//processing headers, need for cmd conformation
		memcpy(header41,recvbuf+i+4,5);

		//remember first byte sess id, for send in confirmation
		if (header41[3]==0x6d){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		if (header41[2]==0x6d){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[2]==0x4D){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4D){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};




		len=len-tmplen-2;
		i=i+tmplen+2;

		printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		printf("len(current block)=%d\n",tmplen);
		printf("confirm_count=%d\n",confirm_count);

	};



	return 0;
};


