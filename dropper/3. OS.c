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
#include "2. STUBHandler.h"

#include "config.h"

/*************************************************************************
** This function check that the system is not too old or too new,       **
** it works with all the versions of Windows from Windows 2000 to       **
** Windows 8 included, in the asm code the function is called with a    **
** value (0 and 1) but actually it is not used, maybe it was used in    **
** debug mode.                                                          **
*************************************************************************/
void CheckSystemVersion(BOOL bBool)
{
	OSVERSIONINFO lpSysInfo;
	lpSysInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	
	if(!GetVersionEx(&lpSysInfo)
	|| lpSysInfo.dwPlatformId != VER_PLATFORM_WIN32_NT
	|| (lpSysInfo.dwMajorVersion < 5 && lpSysInfo.dwMajorVersion > 6))
	{
		DEBUG_P("Wrong system version detected.")
		return;
	}
	
	Core_Load();
}