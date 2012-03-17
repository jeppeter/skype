// skylogin.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>
#include "skype_cred.h"


static void print_usage (char *pszPgm)
{
	printf (
		"Skype credentials dumper V0.2\n"
		"by leecher@dose.0wnz.at 2011\n"
		"with some modification by Efim Bushmanov [2011.07.23]\n\n"
		"Usage: %s -u <Username> [-p <Password>] [-f <Output file>]\n\n"
		"-u\tMandatory: Username of the user whose credentials to dump\n"
		"-p\tOptional: Password, if you want to verify credentials\n"
		"-f\tOptional: Output file to dump credentials to\n\n"
		"Example:\n"
		"%s -u johnfuckingdoe -f a_cred.txt\n",
		pszPgm, pszPgm);
}

int main(int argc, char* argv[]) 
{
	int i;
	char *pszUser = NULL, *pszPass = NULL, *pszDumpF = NULL;


	for (i=0; i<argc; i++)
	{
		if (argv[i][0]=='-')
		{
			switch (argv[i][1])
			{
			case 'u':
				if (++i>=argc) {
					fprintf (stderr, "Missing username\n");
					return -1;
				}
				pszUser=argv[i];
				break;
			case 'p':
				if (++i>=argc) {
					fprintf (stderr, "Missing password\n");
					return -1;
				}
				pszPass=argv[i];
				break;
			case 'f':
				if (++i>=argc) {
					fprintf (stderr, "Missing dump file\n");
					return -1;
				}
				pszDumpF=argv[i];
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			default:
				fprintf (stderr, "Unknown parameter: %s\n", argv[i]);
				break;
			}
		}
	}
	if (!pszUser)
	{
		print_usage(argv[0]);
		fprintf (stderr, "Please specifiy at least a username!\n");
		return -1;
	}

	skype_cred (pszUser, pszPass, pszDumpF);
	return 0;
}

