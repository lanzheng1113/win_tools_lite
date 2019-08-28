// test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <direct.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int _tmain(int argc, _TCHAR* argv[])
{
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
	printf("n = %d\n",n);
	for (int i=0; i!=n; i++)
	{
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
	}

	return 0;
}

