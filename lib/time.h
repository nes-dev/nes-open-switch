/*
 *  Copyright (c) 2008-2015
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

#ifndef __TIME_H__
#	define __TIME_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>
#include <time.h>


enum
{
	xTime_typeMono_c = 1,
	xTime_typeLocal_c,
	xTime_typeUtc_c,
};


inline time_t
	xTime_getTime (uint32_t *pu32NanoSec, uint8_t u8Type);
inline uint64_t
	xTime_centiTime (uint8_t u8Type);


inline time_t
xTime_getTime (uint32_t *pu32NanoSec, uint8_t u8Type)
{
	register int iRetVal;
	struct timespec oTime;
	
	if ((iRetVal = clock_gettime (u8Type == xTime_typeMono_c ? CLOCK_MONOTONIC: CLOCK_REALTIME, &oTime)) == -1)
	{
		goto xTime_getTime_cleanup;
	}
	pu32NanoSec != NULL ? *pu32NanoSec = oTime.tv_nsec: 0;
	
xTime_getTime_cleanup:
	
	return iRetVal != 0 ? iRetVal: oTime.tv_sec;
}

inline uint64_t
xTime_centiTime (uint8_t u8Type)
{
	register uint64_t u64Time;
	uint32_t u32NanoSec = 0;
	
	if ((u64Time = xTime_getTime (&u32NanoSec, u8Type)) == (time_t) -1)
	{
		goto xTime_centiTime_cleanup;
	}
	u64Time = u64Time * 100 + u32NanoSec / 10000000;
	
xTime_centiTime_cleanup:
	
	return u64Time;
}



#	ifdef __cplusplus
}
#	endif

#endif	// __TIME_H__
