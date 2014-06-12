/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES RED License, Version 1.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain a
 *  copy of the License bundled along with this file. Any kind of reproduction
 *  or duplication of any part of this file which conflicts with the License
 *  without prior written consent from NES is strictly prohibited.
 *
 *  Unless required by applicable law and agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */
//set ts=4 sw=4

#ifndef __SWITCH_MAIN_C__
#	define __SWITCH_MAIN_C__


#include "switch_ext.h"
#include "switch_defines.h"

#include "lib/thread.h"


static void switch_start (void);


int
main (
	int argc, char **argv)
{
	switch_start ();
	
	while (1)
	{
		xThread_sleep (1);
	}
	return 0;
}

void
switch_start (void)
{
	register uint16_t u16NumModules = sizeof (aoModuleList) / sizeof (aoModuleList[0]);
	
	for (uint16_t u16ModuleIndex = 0; u16ModuleIndex < u16NumModules; u16ModuleIndex++)
	{
		aoModuleList[u16ModuleIndex].poStart (&aoModuleList[u16ModuleIndex]);
	}
	return;
}


uint16_t
xIeeeCrc16 (
	uint8_t *pu8Buf, uint16_t u16BufSize)
{
	register uint32_t u32Sum = 0;
	
	for (;u16BufSize >= 2; u32Sum += *(uint16_t*) pu8Buf, u16BufSize -= 2, pu8Buf += 2);
	if (u16BufSize != 0)
	{
		u32Sum += *pu8Buf;
	}
	
	u32Sum = (u32Sum >> 16) + (u32Sum & 0xFFFF);
	u32Sum += u32Sum >> 16;
	return ~u32Sum;
}


uint32_t
xIeeeCrc32 (
	uint8_t *pu8Buf, uint16_t u16BufSize)
{
	return 0;
}


#endif	// __SWITCH_MAIN_C__
