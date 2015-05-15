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

#ifndef __LOG_H__
#	define __LOG_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>
#include <syslog.h>


#define xLog_emerg_c		LOG_EMERG		/* 0: system is unusable */
#define xLog_alert_c		LOG_ALERT		/* 1: action must be taken immediately */
#define xLog_crit_c			LOG_CRIT		/* 2: critical conditions */
#define xLog_err_c			LOG_ERR			/* 3: error conditions */
#define xLog_warning_c		LOG_WARNING		/* 4: warning conditions */
#define xLog_notice_c		LOG_NOTICE		/* 5: normal but significant condition */
#define xLog_info_c			LOG_INFO		/* 6: informational */
#define xLog_debug_c		LOG_DEBUG		/* 7: debug-level messages */

int
	xLog_printInt1 (
		char *pcMod, uint16_t u16Pri, const char *pcFile, const char *pcFunc, uint32_t u32Line, char *pcFrmt, ...);
int
	xLog_appendInt1 (char *pcFrmt, ...);

#define xLog_print(_mod, _pri, _frmt, _args ...) xLog_printInt1 (_mod, _pri, __FILE__, __func__, __LINE__, _frmt, ## _args)
#define xLog_append(_frmt, _args ...) xLog_appendInt1 (_frmt, ## _args)



#	ifdef __cplusplus
}
#	endif

#endif	// __LOG_H__
