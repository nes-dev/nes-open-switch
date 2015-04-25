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

#ifndef __LOG_C__
#	define __LOG_C__



#include "log.h"

#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>


// #define _MK_STR(_v) #_v
// #define _LOG_PRI(_p) _MK_STR(_p)
// #define _LOG_TIME_CAL (time (&_log_time_sec), gmtime_r (&_log_time_sec, &_log_time_cal), strftime (_log_time_buff, LOG_TIME_BUFF_SIZE, "%Y-%m-%d %H:%M:%S", &_log_time_cal), _log_time_buff)
// #define _LOG_TIME_SEC ((long long unsigned int) time (NULL))

// #define xLog_strTimeCal(_mod, _pri, _frmt, _args ...) fprintf (stderr, "%s <" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, _LOG_TIME_CAL, __FILE__, __func__, __LINE__, ## _args)
// #define xLog_strTimeSec(_mod, _pri, _frmt, _args ...) fprintf (stderr, "%llu <" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, _LOG_TIME_SEC, __FILE__, __func__, __LINE__, ## _args)
// #define xLog_str(_mod, _pri, _frmt, _args ...) fprintf (stderr, "<" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, __FILE__, __func__, __LINE__, ## _args)
// #define xLog_append(_frmt, _args ...) fprintf (stderr, _frmt, ## _args)

#define CAST_LLU(_x) ((long long unsigned int) (_x))

#define _LOG_TIME_SEC time (NULL)
#define xLog_printInt2(_mod, _pri, _frmt, _args ...) fprintf (stderr, "%010llu.%06u <%u> %s@{%s:%s:%u}: " _frmt, CAST_LLU (_LOG_TIME_SEC), 0, _pri, _mod, __FILE__, __func__, __LINE__, ## _args)


int
xLog_printInt1 (
	char *pcMod, uint16_t u16Pri, const char *pcFile, const char *pcFunc, uint32_t u32Line,
	char *pcFrmt, ...)
{
	register int iRetVal;
	va_list pArgs;
	struct timespec oTime;
	
	if ((iRetVal = clock_gettime (CLOCK_MONOTONIC, &oTime)) == -1)
	{
		xLog_printInt2 (pcMod, u16Pri, "%s\n", strerror (errno));
		goto xLog_printInt1_cleanup;
	}
	oTime.tv_nsec /= 1000;
	
	va_start (pArgs, pcFrmt);
	iRetVal = fprintf (stderr, "%010llu.%06llu <%u> %s@{%s:%s:%u}: ", CAST_LLU (oTime.tv_sec), CAST_LLU (oTime.tv_nsec), u16Pri, pcMod, pcFile, pcFunc, u32Line);
	iRetVal > 0 ? iRetVal = vfprintf (stderr, pcFrmt, pArgs): 0;
	va_end (pArgs);
	
xLog_printInt1_cleanup:
	
	return iRetVal;
}

int
	xLog_appendInt1 (char *pcFrmt, ...)
{
	register int iRetVal;
	va_list pArgs;
	
	va_start (pArgs, pcFrmt);
	iRetVal = vfprintf (stderr, pcFrmt, pArgs);
	va_end (pArgs);
	
	return iRetVal;
}



#endif	// __LOG_C__
