/*
 *  Copyright (c) 2008-2015
 *      NES Dev <nes.open.switch@gmail.com>
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

#ifndef __BUFFER_C__
#	define __BUFFER_C__



#include "buffer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MOD_NAME "BUF"

#if 0
#include "lib/log.h"

#define Buf_log(_pri, _frmt, _args ...) xLog_print (MOD_NAME, _pri, _frmt, ## _args)
#else
#define Buf_log(_pri, _frmt, _args ...)
#endif



void *
xBuffer_alloc (
	uint32_t u32Size)
{
	void *pvAlloc = NULL;
	
// 	Buf_log (xLog_debug_c, "u32Size(%u)\n", u32Size);
	
	if ((pvAlloc = malloc (u32Size)) == NULL)
	{
		return NULL;
	}
	
	Buf_log (xLog_debug_c, "u32Size(%u), pvAlloc(%p)\n", u32Size, pvAlloc);
	return pvAlloc;
}

void *
xBuffer_cAlloc (
	uint32_t u32Size)
{
	void *pvAlloc = NULL;
	
// 	Buf_log (xLog_debug_c, "u32Size(%u)\n", u32Size);
	
	if ((pvAlloc = malloc (u32Size)) == NULL)
	{
		return NULL;
	}
	
	memset (pvAlloc, 0, u32Size);
	Buf_log (xLog_debug_c, "u32Size(%u), pvAlloc(%p)\n", u32Size, pvAlloc);
	return pvAlloc;
}

void *
xBuffer_copy (
	uint32_t u32Size, void *pvInit, uint32_t u32InitSize)
{
	void *pvAlloc = NULL;
	
	Buf_log (xLog_debug_c, "u32Size(%u), pvInit(%p), u32InitSize(%u)\n", u32Size, pvInit, u32InitSize);
	
	if ((pvAlloc = xBuffer_alloc (u32Size)) == NULL)
	{
		return NULL;
	}
	
	if (pvInit != NULL)
	{
		memcpy (pvAlloc, pvInit, u32InitSize);
	}
	
	return pvAlloc;
}

void
xBuffer_free (
	void *pvMem)
{
	Buf_log (xLog_debug_c, "pvMem(%p)\n", pvMem);
	
	free (pvMem);
	return;
}



#endif	// __BUFFER_C__
