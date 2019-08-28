// xunyoucode.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "stdio.h"
#include "string.h"
#include <windows.h>
#include <WinCrypt.h>
#include <direct.h>

#ifndef OUT
#define OUT
#endif

#ifndef IN
#define IN
#endif

int decode(char* pEncode,int EncodeLen,OUT unsigned char* pDecode,OUT int* len)
{
	int retlen = 0;

	if(*pEncode == 0)
	{
		return 0;
	}

	char* var4_endl = pEncode + EncodeLen;

	bool var8 = false;
	int  varc = 0;

	char* lastEncode = pEncode + EncodeLen + 1; //NULL
	bool deCodeEnd = false;
	unsigned char* pMyDecode = pDecode;

	int intEax = 0;
	int intEdx = 0;

	while(var4_endl >= pEncode)
	{
		int intEdi = 0;
		int intEsi = 0;
		int intEcx = 0;

		while (intEcx < 4){
			if(pEncode == lastEncode)
			{
				deCodeEnd = true;
				break;
			}

			intEax = *pEncode;
			intEdx = intEax - 0x41;
			if((unsigned int)intEdx > 0x19){
				intEdx = intEax - 0x61;
				if((unsigned int)intEdx > 0x19){
					intEdx = intEax - 0x30;
					if((unsigned int)intEdx > 9){
						if(intEax != 0x2b){
							intEax -= 0x2f;
							/*总结一下,整个四句指令一起的意思就是, 如果r为0, 那么r中的值为val2, 如果r不为0, 那么r中的值会是val1. 即r ? val1 : val2*/
							if(intEax == 0){
								intEax = 0x3f;
							}else{
								intEax = -1;
							}
						}else{
							intEax = 0x3E;
						}
					}else{
						intEax += 4;
					}
				}else{
					intEax -= 0x47;
				}
			}else{
				intEax -= 0x41;
			}
			pEncode ++;
			if(intEax != -1){
				intEsi = intEsi<<6;
				intEsi = intEsi | intEax;
				intEdi += 6;
				intEcx ++;
			}
		}

		//deCodeEnd or intEcx >= 4
		if(!var8)
		{
			intEax = intEdi;
			//cdq
			if(intEax < 0){
				intEdx = -1;
			}else{
				intEdx = 0;
			}
			intEdx = intEdx & 7;
			intEax += intEdx;
			intEax /= 8;
			intEax += varc;
		}
		
		if (intEax >= *len)
		{
			var8 = true;
		}

		{
			intEax = intEdi;
			//cdq
			if(intEax < 0){
				intEdx = -1;
			}else{
				intEdx = 0;
			}
			intEdx = intEdx & 7;
			intEcx = 0x18;
			intEax += intEdx;
			intEcx -= intEdi;
			intEax /= 8;
			int cl = intEcx & 0x000000ff;
			intEsi = intEsi << cl;

			if(intEax > 0) //////////////////////?????????????????????????///////////////
			{
				varc += intEax;
			}

			while (intEax > 0)
			{
				if(var8 == false)
				{
					intEdx = intEsi;
					intEdx = intEdx >> 0x10;
					unsigned char bty = (unsigned char)(intEdx & 0x000000ff);
					*pMyDecode = (char)bty;
					pMyDecode++;
					retlen++;
					//printf("%02x ",bty);
				}
				intEsi = intEsi << 8;
				intEax --;
			}
		}
	}
	return retlen;
}

//-------------------------------------------------------------------
// This example uses the function MyHandleError, a simple error
// handling function to print an error message and exit 
// the program. 
// For most applications, replace this function with one 
// that does more extensive error reporting.

void MyHandleError(LPTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} // End of MyHandleError.


HCRYPTPROV hCryptProv;        

bool Prepare(unsigned char* crypted,int* len) 
{ 
	// Handle for the cryptographic provider context.
	// The name of the container.
	LPCTSTR pszContainerName = TEXT("MyContainer");
	LPCTSTR pszProvider = TEXT("Microsoft Base Cryptographic Provider v1.0");
	//---------------------------------------------------------------
	// Begin processing. Attempt to acquire a context by using the 
	// specified key container.
	if(!CryptAcquireContext(&hCryptProv,pszContainerName,pszProvider,PROV_RSA_FULL,CRYPT_NEWKEYSET))
	{	
		if (!CryptAcquireContext(&hCryptProv,NULL,pszProvider,PROV_RSA_FULL,0))
		{
			if (!CryptAcquireContext(&hCryptProv,NULL,pszProvider,PROV_RSA_FULL,0x20))
			{
				if (!CryptAcquireContext(&hCryptProv,NULL,pszProvider,PROV_RSA_FULL,0x28))
				{
					return false;
				}
			}
		}
	}
	
	HCRYPTKEY hKey = NULL;
	DWORD dwFlags = 0;
	HCRYPTHASH phHash = 0;
	BOOL bxx = CryptCreateHash(hCryptProv,0x8003,hKey,dwFlags,&phHash);
	if (!bxx)
	{
		printf("CryptCreateHash failed!\n");
		return false;
	}

	const char* hashkey = "lykjLdy173";
	bxx = CryptHashData(phHash,(const BYTE*)hashkey,0x0A,0);
	if (!bxx)
	{
		printf("CryptCreateHash failed!\n");
		return false;
	}
	
	ALG_ID Algid = 0x6801;
	HCRYPTKEY phKey = 0;

	bxx = CryptDeriveKey(hCryptProv,Algid,phHash,0,&phKey);
	if (!bxx)
	{
		printf("CrypteDeriveKey failed!\n");
		return false;
	}

	bxx = CryptDestroyHash(phHash);
	if (!bxx)
	{
		printf("CryptDestroyHash failed!\n");
		return false;
	}

	bxx = CryptDecrypt(phKey,NULL,FALSE,0,crypted,(DWORD*)len);
	if(!bxx){
		printf("CryptDecrypt failed!\n");
		return false;
	}

//	printf("%s\n",crypted);
	return true;
} // End main.

int decrypt(unsigned char* crypted,int* len)
{
	Prepare(crypted,len);

	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	//"C:\\Program Files (x86)\\xunyou\\config\\gameDataConfig.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\gamesdata.txt";
	//
	//
	//char path[] = "C:\\Program Files (x86)\\xunyou\\games.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\nodeNameOnArea.txt"
	//"C:\\Program Files (x86)\\xunyou\\xunyouplatform.txt"
	//"C:\\Program Files (x86)\\xunyou\\splist.txt"
	//"C:\\Program Files (x86)\\xunyou\\skin.txt"
	//"C:\\Program Files (x86)\\xunyou\\nodes.txt"
	//"C:\\Program Files (x86)\\xunyou\\newskin.txt"
	//"C:\\Program Files (x86)\\xunyou\\games.txt"
	//"C:\\Program Files (x86)\\xunyou\\gameconfig.txt"
	//"C:\\Program Files (x86)\\xunyou\\verinfo.ini"
	//"C:\\Program Files (x86)\\xunyou\\config\\xunyou.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\weibo.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\webp2p.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\webgametype.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\webgames.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\VS_PlatForm.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\verify.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\updateserver.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\subgames.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\startHistoryDataGameArea.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\privilegeGameTip.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\nodes2.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\nodelinename.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\nodeareas.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\newexcluderoute.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\mode4route.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\Hf_PlatForm.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\gametype.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\gamesUdpEnable.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\gamespf.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\gameserverorder.txt"
	//"C:\\Program Files (x86)\\xunyou\\config\\gameareaspro.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\gameAreaDR.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\Game_Info.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\AreaEqGame.txt";
	//"C:\\Program Files (x86)\\xunyou\\games.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\xunyou.txt";
	//gamesdata.txt

	char pathcwd[1024] = {0};
	getcwd(pathcwd,sizeof(pathcwd));

	char pathconf[1024] = {0};
	strcpy(pathconf,pathcwd);
	strcat(pathconf,"\\xunyou");
	mkdir(pathconf);
	strcat(pathconf,"\\config");
	mkdir(pathconf);
	
	char filelist[][256] = {
		"C:\\Program Files (x86)\\xunyou\\config\\nodeNameOnArea.txt",
		"C:\\Program Files (x86)\\xunyou\\xunyouplatform.txt",
		"C:\\Program Files (x86)\\xunyou\\splist.txt",
		"C:\\Program Files (x86)\\xunyou\\skin.txt",
		"C:\\Program Files (x86)\\xunyou\\nodes.txt",
		"C:\\Program Files (x86)\\xunyou\\newskin.txt",
		"C:\\Program Files (x86)\\xunyou\\games.txt",
		"C:\\Program Files (x86)\\xunyou\\gameconfig.txt",
		"C:\\Program Files (x86)\\xunyou\\verinfo.ini",
		"C:\\Program Files (x86)\\xunyou\\config\\xunyou.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\weibo.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\webp2p.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\webgametype.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\webgames.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\VS_PlatForm.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\verify.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\updateserver.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\subgames.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\startHistoryDataGameArea.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\privilegeGameTip.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\nodes2.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\nodelinename.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\nodeareas.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\newexcluderoute.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\mode4route.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\Hf_PlatForm.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gametype.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gamesUdpEnable.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gamespf.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gameserverorder.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gameareaspro.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\gameAreaDR.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\Game_Info.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\AreaEqGame.txt",
		"C:\\Program Files (x86)\\xunyou\\games.txt",
		"C:\\Program Files (x86)\\xunyou\\config\\xunyou.txt",
	};
	
	int n = sizeof(filelist)/sizeof(filelist[0]);


	printf("总共%d个文件\n",n);
	for (int i=0; i!=n; i++)
	{
		char filename[254] = {0};
		strcpy(filename,filelist[i]);
		printf("正在解密第%d个：%s\n",i+1,filename);
		FILE* pFile=fopen(filename,"rb");
		fseek(pFile, 0, SEEK_END);
		int len = ftell(pFile);
		char* szBuf=new char[len];
		memset(szBuf,0,len);
		fseek(pFile, 0, SEEK_SET);

		int iRead=fread_s(szBuf,len,1,len,pFile);
		printf("File read byte %d\n",iRead);
		fclose(pFile);

		unsigned char* newOne = new unsigned char[iRead];
		memset(newOne,0,iRead);

		int retlen = decode(szBuf,iRead,newOne,&iRead);
		//  	for (int i=0; i != retlen; i++)
		//  	{
		//  		printf("%02X",newOne[i]);
		//  		if((i+1)%4 == 0 )
		//  			printf("|");
		//  
		//  		if((i+1)%16)
		//  			printf(" ");
		//  		else{
		//  			printf("\n");
		//  		}
		//  	}
		//printf("\ndone!\n return len = 0x%x\n",retlen);
		decrypt(newOne,&retlen);
		
		//获取文件路径
		char szFilePath[1024] = {0};
		strcpy(szFilePath,filelist[i]);
		printf("%s\n",szFilePath);
		const char* tofind = "\\xunyou\\";
		char* last = strstr(szFilePath,tofind);
		if (last)
		{
			char* temp = last+1;
			do 
			{
				temp = strstr(last+1,tofind);
				if (temp){
					last = temp;
					printf("find one more!\n");
				}
			} while (temp!=NULL);
		}else{
			printf("error!not find path for create decrypted file for %s.",szFilePath);
			continue;
		}

		last = last + strlen(tofind);
		printf("%s\n",last);

		char destpathfordecryptedfile[256] = {0};
		strcpy(destpathfordecryptedfile,pathcwd);
		strcat(destpathfordecryptedfile,"\\xunyou\\");
		strcat(destpathfordecryptedfile,last);
		printf("mypath = %s\n",destpathfordecryptedfile);

		//fw
		FILE* fr = fopen(destpathfordecryptedfile,"wb");
		fprintf(fr,"%s",newOne);
		fclose(fr);

		delete [] newOne;
		delete [] szBuf;
	}


	char pathGamedata[] = "C:\\Program Files (x86)\\xunyou\\config\\gamesdata.txt";

	FILE* pFileGamedata=fopen(pathGamedata,"rb");

	fseek(pFileGamedata, 0, SEEK_END);
	int lenGamedata = ftell(pFileGamedata);
	printf("get file size = %d\n",lenGamedata);

	char* szBufGamedata=new char[lenGamedata+1];
	memset(szBufGamedata,0,lenGamedata+1);

	fseek(pFileGamedata, 0, SEEK_SET);

	int iReadGamedata=fread_s(szBufGamedata,lenGamedata,1,lenGamedata,pFileGamedata);

	printf("file read byte %dKB\n",iReadGamedata/1024);
	
	szBufGamedata[iReadGamedata] = 0; //set null


	char filepathforworlddata[256] = {0};
	strcpy(filepathforworlddata,pathcwd);
	strcat(filepathforworlddata,"\\xunyou\\config\\gamesdata.txt");

	FILE* pFr = fopen(filepathforworlddata,"wb");
	
	int findcount = 0;
	int bufsize = 1024*40;
	char* buffer = new char [bufsize];
	unsigned char* decodebuff = new unsigned char[bufsize];

	char* px = NULL;
	int pos = 0;
	
	do{
		px = strchr(szBufGamedata+pos+1,'=');
		if (px == NULL)
		{
			break;
		}
		pos = (int)(px - szBufGamedata);
//		printf("pos = %d ,sz[pos] = %c \n",pos,szBufGamedata[pos]);

		int id = 0;
		char* trimPos = szBufGamedata+pos;
		char* beginPos = trimPos - 1;
		while (*beginPos>= '0' && *beginPos <= '9')
		{
			beginPos--;
		}

		int count = trimPos - beginPos;
		
		char sznumber[10] = {0};
		memcpy(sznumber,beginPos+1,count-1);

		for (int i=0; i!=10; i++)
		{
			if (!(sznumber[i] >= '0' && sznumber[i] <= '9')){
				sznumber[i] = 0;
			}
		}

		char* pContent = trimPos+1;
		int contentlen = 0;
		char* end = strstr(pContent,"\r\n\r\n");
		if (end != NULL){
			contentlen = end - pContent;
		}

		if (contentlen == 0 )
		{
			break;
		}

		memset(buffer,0,bufsize);
		memset(decodebuff,0,bufsize);

//		printf("pContent = %s\n",buffer);
//		printf("sznumber = %d\n",atoi(sznumber));
		strncpy(buffer,pContent,contentlen);
		int retlen = decode(buffer,contentlen,decodebuff,&contentlen);
		decrypt(decodebuff,&retlen);

		if (pFr)
		{
			fprintf(pFr,"##block start id = %d##\r\n",atoi(sznumber));
			fprintf(pFr,"%s\r\n",decodebuff);
			fprintf(pFr,"##block end##\r\n\r\n");
		}

		findcount ++;

		printf("processed %d\r",findcount);

		if (szBufGamedata+pos+1 >= szBufGamedata+iReadGamedata){
			break;
		}
	}while ((px != NULL));

	fclose(pFr);

	printf("find count = %d\n",findcount);

	delete [] szBufGamedata;

	delete [] buffer;
	delete [] decodebuff;


// 	for (int i=0; i!=ids.size(); i++)
// 	{
// 		int id = ids[i];
// 		char dest[10];
// 		itoa(id,dest,10);
// 		GetPrivateProfileStringA(("main"),dest,NULL,buffer,bufsize,"C:\\Program Files (x86)\\xunyou\\config\\gamesdata.txt");
// 		int buffactuallysize = strlen(buffer);
// 		int retlen = decode(buffer,buffactuallysize,decodebuff,&buffactuallysize);
// 		decrypt(decodebuff,&retlen);
// //		printf("%s\n",decodebuff);
// 	}

	//"C:\\Program Files (x86)\\xunyou\\config\\gameDataConfig.txt";
	//"C:\\Program Files (x86)\\xunyou\\config\\gamesdata.txt";
// 	char copycmd[512] = {0};
// 	sprintf(copycmd,"copy /B C:\\Program Files (x86)\\xunyou\\config\\gameDataConfig.txt %s\\xunyou\\config\\gameDataConfig.txt",pathcwd);
// 	printf("%s\n",copycmd);
// 	system(copycmd);

	return 0;
}

