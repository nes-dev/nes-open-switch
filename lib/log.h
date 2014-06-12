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

#ifndef __LOG_H__
#	define __LOG_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdio.h>

#define xLog_emerg_c		0	/* system is unusable */
#define xLog_alert_c		1	/* action must be taken immediately */
#define xLog_crit_c			2	/* critical conditions */
#define xLog_err_c			3	/* error conditions */
#define xLog_warning_c		4	/* warning conditions */
#define xLog_notice_c		5	/* normal but significant condition */
#define xLog_info_c			6	/* informational */
#define xLog_debug_c		7	/* debug-level messages */

#ifdef LOG_TIME_USED
#	include <time.h>

#	define LOG_TIME_BUFF_SIZE 20
time_t 		_log_time_sec;
struct tm 	_log_time_cal;
char 		_log_time_buff[LOG_TIME_BUFF_SIZE];
#endif

#define _MK_STR(_v) #_v
#define _LOG_PRI(_p) _MK_STR(_p)
#define _LOG_TIME_CAL (time (&_log_time_sec), gmtime_r (&_log_time_sec, &_log_time_cal), strftime (_log_time_buff, LOG_TIME_BUFF_SIZE, "%Y-%m-%d %H:%M:%S", &_log_time_cal), _log_time_buff)
#define _LOG_TIME_SEC ((long long unsigned int) time (NULL))

#define xLog_strTimeCal(_mod, _pri, _frmt, _args ...) fprintf (stderr, "%s <" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, _LOG_TIME_CAL, __FILE__, __func__, __LINE__, ## _args)
#define xLog_strTimeSec(_mod, _pri, _frmt, _args ...) fprintf (stderr, "%llu <" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, _LOG_TIME_SEC, __FILE__, __func__, __LINE__, ## _args)
#define xLog_str(_mod, _pri, _frmt, _args ...) fprintf (stderr, "<" _LOG_PRI(_pri) "> " _mod "@{%s:%s:%u}: " _frmt, __FILE__, __func__, __LINE__, ## _args)
#define xLog_append(_frmt, _args ...) fprintf (stderr, _frmt, ## _args)



#	ifdef __cplusplus
}
#	endif

#endif	// __LOG_H__
