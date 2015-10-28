/*
 *  Copyright (c) 2008-2015
 *      NES Repo <nes.repo@gmail.com>
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

#ifndef __COMMON_H__
#	define __COMMON_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#if __STDC_VERSION__ < 199901L
#	error "incompatible compiler: C99 expected"
#endif	/* __STDC_VERSION__ */

// #include "lib/lib.h"
// #include "lib/list.h"
// #include "lib/enum.h"
// #include "lib/log.h"

// #include <stdint.h>
// #include <stdbool.h>
// #include <stdio.h>


enum
{
	ZERO		= 0,
	ONE			= 1,
	TWO			= 2,
	THREE		= 3,
	FOUR		= 4,
	FIVE		= 5,
	SIX			= 6,
	SEVEN		= 7,
	EIGHT		= 8,
	NINE		= 9,
	TEN			= 10,
	ELEVEN		= 11,
	TWELVE		= 12,
	THIRTEEN	= 13,
	FOURTEEN	= 14,
	FIFTEEN		= 15,
	SIXTEEN		= 16,
};

// #define Switch_log(_module, _pri, _frmt, _args ...) xLog_print (_module, _pri, _frmt, ## _args)

// #define PTHREAD_OK 0


// extern char app_name[];



#	ifdef __cplusplus
}
#	endif

#endif	// __COMMON_H__
