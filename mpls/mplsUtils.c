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

#ifndef __MPLSUTILS_C__
#	define __MPLSUTILS_C__



#include "mplsLsrStdMIB.h"
#include "mplsUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include <stdbool.h>
#include <stdint.h>


static neIfTypeCreateHandler_t mplsInterfaceRowStatus_handler;
static neIfTypeEnableHandler_t mplsInterfaceAdminStatus_handler;
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
	
	poNeIfTypeEntry->pfCreateHandler = mplsInterfaceRowStatus_handler;
	poNeIfTypeEntry->pfEnableHandler = mplsInterfaceAdminStatus_handler;
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


static bool
	mplsInterfaceRowStatus_update (
		ifEntry_t *poIfEntry,
		mplsInterfaceEntry_t *poEntry, uint8_t u8RowStatus);


bool
mplsInterfaceRowStatus_handler (
	ifEntry_t *poIfEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register mplsInterfaceEntry_t *poEntry = NULL;
	
	poEntry = mplsInterfaceTable_getByIndex (poIfEntry->u32Index);
	
	if ((poEntry == NULL) ^ (u8RowStatus == xRowStatus_createAndWait_c))
	{
		goto mplsInterfaceRowStatus_handler_cleanup;
	}
	if (poEntry != NULL && poEntry->u8RowStatus == u8RowStatus)
	{
		goto mplsInterfaceRowStatus_handler_success;
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (!mplsInterfaceRowStatus_update (poIfEntry, poEntry, u8RowStatus))
		{
			goto mplsInterfaceRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RowStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!mplsInterfaceRowStatus_update (poIfEntry, poEntry, u8RowStatus))
		{
			goto mplsInterfaceRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RowStatus;
		break;
		
	case xRowStatus_createAndWait_c:
		if (poEntry != NULL || (poEntry = mplsInterfaceTable_createExt (poIfEntry->u32Index)) == NULL)
		{
			goto mplsInterfaceRowStatus_handler_cleanup;
		}
		
	case xRowStatus_destroy_c:
		if (!mplsInterfaceRowStatus_update (poIfEntry, poEntry, u8RowStatus))
		{
			goto mplsInterfaceRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		
		if (u8RowStatus == xRowStatus_destroy_c)
		{
			if (!mplsInterfaceTable_removeExt (poEntry))
			{
				goto mplsInterfaceRowStatus_handler_cleanup;
			}
		}
		break;
	}
	
mplsInterfaceRowStatus_handler_success:
	
	bRetCode = true;
	
mplsInterfaceRowStatus_handler_cleanup:
	
	return bRetCode;
}

bool
mplsInterfaceAdminStatus_handler (
	ifEntry_t *poIfEntry, int32_t i32AdminStatus)
{
	register bool bRetCode = false;
	register mplsInterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = mplsInterfaceTable_getByIndex (poIfEntry->u32Index)) == NULL)
	{
		goto mplsInterfaceAdminStatus_handler_cleanup;
	}
	
	poEntry->u8AdminStatus = i32AdminStatus;
	poEntry->i32Mtu = poIfEntry->i32Mtu;
	memcpy (poEntry->au8AdminFlags, poIfEntry->oNe.au8AdminFlags, sizeof (poEntry->au8AdminFlags));
	memcpy (poEntry->au8OperFlags, poIfEntry->oNe.au8OperFlags, sizeof (poEntry->au8OperFlags));
	memcpy (poEntry->au8Speed, poIfEntry->oNe.au8Speed, sizeof (poEntry->au8Speed));
	
	bRetCode = true;
	
mplsInterfaceAdminStatus_handler_cleanup:
	
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


bool
mplsInterfaceRowStatus_update (
	ifEntry_t *poIfEntry,
	mplsInterfaceEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	bRetCode = true;
	
// mplsInterfaceRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __MPLSUTILS_C__
