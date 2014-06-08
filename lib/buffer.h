/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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

#ifndef __BUFFER_H__
#	define __BUFFER_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <stdlib.h>


#define XBUFFER_LIST(addr)			((struct iovec*) (addr))
#define XBUFFER_DATA(buf)			(XBUFFER_LIST (buf)->iov_base)
#define XBUFFER_LENGTH(buf)			(XBUFFER_LIST (buf)->iov_len)

#define XBUFFER_ADDR(addr)			((uint8_t*) (addr))

#define XBUFFER_ALLOC(sz)			xBuffer_alloc (sz)
#define XBUFFER_FREE(addr)			xBuffer_free (addr)


extern void *
	xBuffer_alloc (
		uint32_t u32Size);
extern void *
	xBuffer_cAlloc (
		uint32_t u32Size);
extern void *
	xBuffer_copy (
		uint32_t u32Size, void *pvInit, uint32_t u32InitSize);
extern void
	xBuffer_free (
		void *pvMem);


typedef struct iovec xBuffer_Vector_t;



#	ifdef __cplusplus
}
#	endif

#endif	// __BUFFER_H__
