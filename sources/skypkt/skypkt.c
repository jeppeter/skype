// skypkt.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <time.h>

#include <fcntl.h>
#include <io.h>

#include "miracl.h"
#include "short_types.h"


extern unsigned int make_tcp_client_sess1_pkt1(char *ip,unsigned short port,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt2(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt3(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt4(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt5(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt6(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);
extern unsigned int make_tcp_client_sess1_pkt7(char *ip,unsigned short port,unsigned int seqnum,unsigned int rnd);

extern unsigned char CHAT_STRING[0x100];
extern unsigned char REMOTE_NAME[0x100];
extern unsigned char MSG_TEXT[0x1000];


int main_skypeclient_tcpconnect_sess1();

extern int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred);
extern int parse_input_line2(char *line, char *str_remote_skype, char *destip, char *destport);
extern int restore_user_keypair(u32 *secret_p, u32 *secret_q, u8 *public_key, u8 *secret_key);
extern int show_memory(char *mem, int len, char *text);

extern u8 CREDENTIALS[0x105];
extern char xoteg_sec[0x81];
extern char xoteg_pub[0x81];

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CHAR_RND_ID[0x100];
extern u8 MSG_TEXT[0x1000];


char global_destip[0x1000];
unsigned short global_destport;


miracl *mip;
	

int parse_cmd_lines(int argc, char* argv[]) {
	int len;
	u32 secret_p[17], secret_q[17];
	char public_key[0x81];
	char secret_key[0x81];

	char str_skypename[0x1000];
	char user_cred[0x101];

	char str_remote_skype[1024];
	char destip[1024];
	char destport[1024];

	int fd;

	memset(public_key,0,sizeof(public_key));
	memset(secret_key,0,sizeof(secret_key));

	mip=mirsys (100, 0);

	if (argc!=3) {
		printf("wrong number of input parameters, %d, should be 3\n",argc);
		exit(1);
	};


	if ((argv[1]!=NULL) && (strlen(argv[1])>0)){
		parse_input_line(argv[1], secret_p, secret_q, (char*)&str_skypename, (char*)&user_cred);
	}else{
		printf("please specify inputs parameters\n");
		exit(1);
	};
	printf("skypename=%s\n",str_skypename);
	show_memory(user_cred,0x100,"cred:");

	memcpy(CREDENTIALS+4,user_cred,0x100);




	if ((argv[2]!=NULL) && (strlen(argv[2])>0)){
		parse_input_line2(argv[2], (char *)&str_remote_skype, (char *)&destip, (char *)&destport);
	}else{
		printf("please specify inputs parameters\n");
		exit(1);
	};
	printf("remote_skypename=%s\n",str_remote_skype);
	printf("destip=%s\n",destip);
	printf("destport=%s\n",destport);

	strcpy(global_destip,destip);
	global_destport=atoi(destport);


	restore_user_keypair(secret_p, secret_q, public_key, secret_key);


	memcpy(xoteg_pub,public_key,0x80);
	memcpy(xoteg_sec,secret_key,0x80);

	show_memory(xoteg_pub,0x80,"xoteg_pubkey:");
	show_memory(xoteg_sec,0x80,"xoteg_seckey:");

	show_memory(CREDENTIALS,0x104,"CREDENTIALS:");

	
	strcpy(REMOTE_NAME,str_remote_skype);

	strcat(CHAT_STRING,"#");
	strcat(CHAT_STRING,str_skypename);
	strcat(CHAT_STRING,"/$");
	strcat(CHAT_STRING,REMOTE_NAME);
	strcat(CHAT_STRING,";");
	strcat(CHAT_STRING,CHAR_RND_ID);

	strcat(CHAT_PEERS,REMOTE_NAME);
	strcat(CHAT_PEERS," ");
	strcat(CHAT_PEERS,str_skypename);


	//printf("Hello World!\n");

	printf("CHAT_STRING: %s\n",CHAT_STRING);
    printf("REMOTE_NAME: %s\n",REMOTE_NAME);
    printf("CHAT_PEERS: %s\n",CHAT_PEERS);


	fd=open("a_msg.txt",O_RDONLY);
	len=read(fd,&MSG_TEXT,0x1000);
	close(fd);
    
	if (len<=0){
		printf("file open error\n");
		exit(1);
	};
	if (len>=0x1000){
		printf("file too big\n");
		exit(1);
	};

	MSG_TEXT[len+1]=0;

 	printf("\nMSG_TEXT: %s\n",MSG_TEXT);


	return 0;
}


int main(int argc, char* argv[]){

	parse_cmd_lines(argc, argv);
	//exit(1);

	main_skypeclient_tcpconnect_sess1();

	return 0;
};



int main_skypeclient_tcpconnect_sess1(){
	char *ip;
	unsigned short port;
	unsigned short seqnum;
	unsigned int rnd;

	srand( time(NULL) );
	
	
	//printf("CHAT_STRING: %s\n",CHAT_STRING);
    //printf("REMOTE_NAME: %s\n",REMOTE_NAME);
	//printf("MSG_TEXT: %s\n",MSG_TEXT);
	//exit(1);


	//ip=strdup("212.96.122.54");
	//port=40333;

	//ip=strdup("212.96.122.54");
	//port=50300;

	//ip=strdup("212.96.122.54");
	//port=64135;

	ip=global_destip;
	port=global_destport;

	//ip=strdup("192.168.1.10");
	//port=42394;

	//ip=strdup("192.168.1.17");
	//port=33864;
	

	//seqnum=0x8d + (rand() % 0x1000);
	seqnum=rand() % 0x10000;



	//rnd=0x4409F434;
	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;



	make_tcp_client_sess1_pkt1(ip,port,rnd);

	make_tcp_client_sess1_pkt2(ip,port,seqnum+2,rnd);

	make_tcp_client_sess1_pkt3(ip,port,seqnum+2,rnd);

	make_tcp_client_sess1_pkt4(ip,port,seqnum+2,rnd);

	make_tcp_client_sess1_pkt5(ip,port,seqnum+2,rnd);

	make_tcp_client_sess1_pkt6(ip,port,seqnum+2,rnd);

	make_tcp_client_sess1_pkt7(ip,port,seqnum+2,rnd);


	//Sleep(10000);

	return 0;
};

