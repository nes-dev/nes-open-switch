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

#ifndef __MPLSUTILS_C__
#	define __MPLSUTILS_C__



#include "mplsUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include <stdbool.h>
#include <stdint.h>


static neIfTypeStackHandler_t mplsInterfaceTable_stackHandler;

static neIfTypeStackHandler_t mplsTunnelTable_stackModify;


bool mplsUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_mpls_c)) == NULL)
	{
		goto mplsUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfStackHandler = mplsInterfaceTable_stackHandler;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_mplsTunnel_c)) == NULL)
	{
		goto mplsUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfStackHandler = mplsTunnelTable_stackModify;
	
	bRetCode = true;
	
mplsUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}


bool
mplsInterfaceTable_stackHandler (
	ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}


bool
mplsTunnelTable_stackModify (
	ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}



#endif	// __MPLSUTILS_C__
