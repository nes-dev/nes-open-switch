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

#ifndef __SYNC_H__
#	define __SYNC_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <unistd.h>

#ifndef _POSIX_THREADS
#	error "incompatible C library: Posix Thread support expected"
#endif	/* _POSIX_THREADS */

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "lib/bitmap.h"
#include "lib/list.h"
#include "lib/binaryTree.h"


typedef pthread_mutex_t xMLock_t;

#define xMLock_initInline() PTHREAD_MUTEX_INITIALIZER
#define xMLock_init(_pLock, _pLockAttr) pthread_mutex_init (_pLock, _pLockAttr)
#define xMLock_destroy(_pLock) pthread_mutex_destroy (_pLock)

#define xMLock_lock(_pLock) pthread_mutex_lock (_pLock)
#define xMLock_tryLock(_pLock) pthread_mutex_trylock (_pLock)
#define xMLock_unlock(_pLock) pthread_mutex_unlock (_pLock)


typedef pthread_rwlock_t xRwLock_t;

#define xRwLock_initInline() PTHREAD_RWLOCK_INITIALIZER
#define xRwLock_init(_pLock, _pLockAttr) pthread_rwlock_init (_pLock, _pLockAttr)
#define xRwLock_destroy(_pLock) pthread_rwlock_destroy (_pLock)

#define xRwLock_rdLock(_pLock) pthread_rwlock_rdlock (_pLock)
#define xRwLock_wrLock(_pLock) pthread_rwlock_wrlock (_pLock)
#define xRwLock_rdTryLock(_pLock) pthread_rwlock_tryrdlock (_pLock)
#define xRwLock_wrTryLock(_pLock) pthread_rwlock_trywrlock (_pLock)
#define xRwLock_unlock(_pLock) pthread_rwlock_unlock (_pLock)


typedef pthread_cond_t xCond_t;

#define xCond_initInline() PTHREAD_COND_INITIALIZER
#define xCond_init(_pCond, _pCondAttr) pthread_cond_init (_pCond, _pCondAttr)
#define xCond_destroy(_pCond) pthread_cond_destroy (_pCond)

#define xCond_wait(_pCond, _pLock) pthread_cond_wait (_pCond, _pLock)
#define xCond_timedWait(_pCond, _pLock, _pTime) pthread_cond_timedwait (_pCond, _pLock, _pTime)
#define xCond_signal(_pCond) pthread_cond_signal (_pCond)
#define xCond_broadcast(_pCond) pthread_cond_broadcast (_pCond)


enum
{
	xMessageQueue_flagsTx_c = 0,
	xMessageQueue_flagsRx_c = 1,
	xMessageQueue_flagsCount_c = 2,
	
	xMessage_flagsAckInline_c = 0,
	xMessage_flagsCount_c = 1,
};

typedef struct xMessageQueue_t
{
	uint32_t u32Index;
	
	xBitmap_declare (ubFlags, xMessageQueue_flagsCount_c);
	xSList_Head_t oTxList;
	xSList_Head_t oRxList;
	xSList_Head_t oAckList;
	xRwLock_t oLock;
	xBTree_Node_t oBTreeNode;
} xMessageQueue_t;

struct xMessageInfo_t;

typedef struct xMessage_t
{
	uint32_t u32Index;
	void *pvData;
	xBitmap_declare (ubFlags, xMessage_flagsCount_c);
	struct xMessageInfo_t *poMsgInfo;
	xSList_Node_t oQNode;
} xMessage_t;

typedef struct xMessageInfo_t
{
	uint16_t u32Type;
	uint16_t u16RxCount;
	xSList_Head_t oDstList;
	xRwLock_t oLock;
} xMessageInfo_t;


extern xMessageQueue_t *
xMessageQueue_create (uint32_t u32Index);
extern void
xMessageQueue_remove (xMessageQueue_t *poEntry);


extern xMessage_t *
xMessage_allocate (
	uint16_t u32Type, void *pvData);
extern bool
xMessage_send (
	xMessage_t *poMessage, xMessageQueue_t *poSrcQueue);
extern bool
xMessage_free (
	xMessage_t *poMessage, xMessageQueue_t *poSrcQueue);


extern xMessage_t *
xMessageDst_create (
	uint32_t u32Index, xMessage_t *poMessage);
extern bool
xMessageDst_remove (
	xMessage_t *poMsg, xMessageQueue_t *poDstQueue);



#	ifdef __cplusplus
}
#	endif

#endif	// __SYNC_H__
