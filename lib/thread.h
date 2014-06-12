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

#ifndef __THREAD_H__
#	define __THREAD_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <unistd.h>

#ifndef _POSIX_THREADS
#	error "incompatible C library: Posix Thread support expected"
#endif	/* _POSIX_THREADS */

#include <pthread.h>
#include <sched.h>
#include <time.h>

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/sync.h"

#define XTHREAD_MODULE_ID(pThread)	((pThread)->u32Index & 0xFFFF0000)
#define XTHREAD_TASK_ID(pThread)	((pThread)->u32Index & 0x0000FFFF)
#define XTHREAD_ID(u16ModuleId, u16TaskId)	(((uint32_t) (u16ModuleId) & 0xFFFF) << 16 | ((u16TaskId) & 0xFFFF))


typedef struct xThreadData_t
{
	xBTree_t			oBTree;
	xRwLock_t			oLock;
} xThreadData_t;

extern xThreadData_t oThreadData;


typedef void *(xThreadRoutine_t) (void *);

enum
{
	xThreadInfo_flagsMessage_c = 0,
	xThreadInfo_flagsCount_c = 1,
};

typedef struct xThreadInfo_t
{
	uint32_t				u32Index;
	uint8_t					u8SchedPolicy;
	uint8_t					u8Priority;
	xThreadRoutine_t	   *poStart;
	xThreadRoutine_t	   *poPause;
	xThreadRoutine_t	   *poResume;
	xThreadRoutine_t	   *poStop;
	pthread_t				oPThread;
	xBitmap_declare		   (ubFlags, xThreadInfo_flagsCount_c);
	xCond_t					oSignal;
	xMLock_t				oLock;
	void				   *pvData;
	xBTree_Node_t			oBTreeNode;
} xThreadInfo_t;

typedef pthread_mutex_t xThreadMutex_t;


extern xThreadInfo_t *xThread_create (xThreadInfo_t *pThread);
extern xThreadInfo_t *xThread_getByIndex (uint32_t u32Index);
extern xThreadInfo_t *xThread_getNext (xThreadInfo_t *pThread);
#define xThread_sleep(u32Seconds) sleep (u32Seconds)
#define xThread_uSleep(u32uSeconds) usleep (u32uSeconds)
#define xThread_nSleep(u32Seconds, u32nSeconds) nanosleep (&(struct timespec){.tv_sec = u32Seconds, .tv_nsec = u32nSeconds}, NULL)
#define xThread_schedYield() sched_yield ()


#if 0

pthread_equal
pthread_self
pthread_create
pthread_exit
pthread_join
pthread_cancel
pthread_cleanup_push
pthread_cleanup_pop
pthread_detach
pthread_mutex_init	PTHREAD_MUTEX_INITIALIZER
pthread_mutex_destroy
pthread_mutex_lock
pthread_mutex_trylock
pthread_mutex_unlock
pthread_rwlock_init
pthread_rwlock_destroy
pthread_rwlock_rdlock
pthread_rwlock_wrlock
pthread_rwlock_unlock
pthread_rwlock_tryrdlock
pthread_rwlock_trywrlock
pthread_cond_init	PTHREAD_COND_INITIALIZER
pthread_cond_destroy
pthread_cond_wait
pthread_cond_timedwait
pthread_cond_signal
pthread_cond_broadcast

pthread_attr_init
pthread_attr_destroy
pthread_attr_getdetachstate
pthread_attr_setdetachstate
pthread_attr_getstack
pthread_attr_setstack
pthread_attr_getstacksize
pthread_attr_setstacksize
pthread_attr_getguardsize
pthread_attr_setguardsize
pthread_getconcurrency
pthread_setconcurrency
pthread_mutexattr_init
pthread_mutexattr_destroy
pthread_mutexattr_getpshared
pthread_mutexattr_setpshared
pthread_mutexattr_gettype
pthread_mutexattr_settype
pthread_rwlockattr_init
pthread_rwlockattr_destroy
pthread_rwlockattr_getpshared
pthread_rwlockattr_setpshared
pthread_condattr_init
pthread_condattr_destroy
pthread_condattr_getpshared
pthread_condattr_setpshared

ftrylockfile
flockfile
funlockfile
getchar_unlocked
getc_unlocked
putchar_unlocked
putc_unlocked

pthread_key_create
pthread_key_delete
pthread_once
pthread_getspecific
pthread_setspecific
pthread_setcancelstate
pthread_testcancel
pthread_setcanceltype
pthread_sigmask
sigwait
pthread_kill
pread
pwrite

#endif



#	ifdef __cplusplus
}
#	endif

#endif	// __THREAD_H__
