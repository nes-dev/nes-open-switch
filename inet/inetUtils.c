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

#ifndef __INETUTILS_C__
#	define __INETUTILS_C__



#include "inetUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include "inet_ext.h"

#include "lib/bitmap.h"

#include <stdbool.h>
#include <stdint.h>


static bool
	inetIfTable_stackModify (
		ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry,
		uint8_t u8Action, bool isLocked);


bool inetUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ip_c)) == NULL)
	{
		goto inetUtilsInit_unlock;
	}
	
	poNeIfTypeEntry->pfStackHandler = inetIfTable_stackModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ipForward_c)) == NULL)
	{
		goto inetUtilsInit_unlock;
	}
	
	poNeIfTypeEntry->pfStackHandler = inetIfTable_stackModify;
	
	bRetCode = true;
	
inetUtilsInit_unlock:
	
	ifTable_unLock ();
	return bRetCode;
}

bool
inetIfTable_stackModify (
	ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}



#endif	// __INETUTILS_C__
