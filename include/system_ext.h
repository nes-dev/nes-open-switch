/*
 *  Copyright (c) 2008-2016
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

#ifndef __SYSTEM_EXT_H__
#	define __SYSTEM_EXT_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>


extern void *system_init (void *pvArgv);
extern void *system_main (void *pvArgv);
extern void *system_start (void *pvArgv);

bool
	sysORTable_createRegister (
		const char *pc8Descr,
		xOid_t *poID, size_t u16ID_len);
bool
	sysORTable_removeRegister (
		xOid_t *poID, size_t u16ID_len);



#	ifdef __cplusplus
}
#	endif

#endif	// __SYSTEM_EXT_H__
