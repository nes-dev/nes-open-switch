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

#ifndef __LAG_UTILS_C__
#	define __LAG_UTILS_C__



#include "lagUtils.h"
#include "lagMIB.h"
#include "lag/lacp/lacpUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include "lag_ext.h"

#include "lib/bitmap.h"

#include <stdbool.h>
#include <stdint.h>


static neIfTypeEnableHandler_t lag_aggEnableModify;
static neIfTypeStatusModifier_t lag_aggStatusModify;
static neIfTypeStackHandler_t lag_aggStackModify;

neIfTypeStatusModifier_t lag_aggPortStatusModify;


bool lagUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ieee8023adLag_c)) == NULL)
	{
		goto lagUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = lag_aggEnableModify;
	poNeIfTypeEntry->pfStatusModifier = lag_aggStatusModify;
	poNeIfTypeEntry->pfStackHandler = lag_aggStackModify;
	
	bRetCode = true;
	
lagUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}

bool
lag_aggEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}

bool
lag_aggStatusModify (
	ifData_t *poIfEntry, int32_t i32OperStatus, bool bPropagate)
{
	return false;
}

bool
lag_aggStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}

bool
lag_aggPortStatusModify (
	ifData_t *poIfEntry, int32_t i32OperStatus, bool bPropagate)
{
	register bool bRetCode = false;
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (poIfEntry->u32Index)) == NULL)
	{
		goto lag_aggPortStatusModify_cleanup;
	}
	
	register bool bForce = poDot3adAggPortData->u8OperStatus == i32OperStatus && bPropagate;
	
	poDot3adAggPortData->u8OperStatus = i32OperStatus;
	
	if (!dot3adAggPortLacp_stateUpdate (poDot3adAggPortData, bForce))
	{
		goto lag_aggPortStatusModify_cleanup;
	}
	
	bRetCode = true;
	
lag_aggPortStatusModify_cleanup:
	
	return bRetCode;
}


bool
neAggRowStatus_update (
	neAggEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByAggEntry (poEntry);
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (!neIfStatus_modify (poDot3adAggData->u32Index, xOperStatus_notPresent_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poDot3adAggData, u8RowStatus))
		{
			goto neAggRowStatus_update_cleanup;
		}
		break;
		
	case xRowStatus_notInService_c:
		if (!neIfStatus_modify (poDot3adAggData->u32Index, xOperStatus_down_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poDot3adAggData, u8RowStatus))
		{
			goto neAggRowStatus_update_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
		if (!neIfStatus_modify (poDot3adAggData->u32Index, xOperStatus_notPresent_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poDot3adAggData, u8RowStatus))
		{
			goto neAggRowStatus_update_cleanup;
		}
		break;
	}
	
	bRetCode = true;
	
neAggRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
neAggPortRowStatus_update (
	neAggPortEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortEntry (poEntry);
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		
		if (!dot3adAggPortLacpStatus_update (poDot3adAggPortData, u8RowStatus))
		{
			goto neAggPortRowStatus_update_cleanup;
		}
		
		{
			ifData_t *poIfData = NULL;
			
			if (!ifData_getByIndexExt (poDot3adAggPortData->u32Index, true, &poIfData))
			{
				goto neAggPortRowStatus_update_cleanup;
			}
			
			xBitmap_setBit (poIfData->oNe.au8AdminFlags, neIfAdminFlags_lag_c, 1);
			ifData_unLock (poIfData);
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		/* TODO */
		
		{
			ifData_t *poIfData = NULL;
			
			if (!ifData_getByIndexExt (poDot3adAggPortData->u32Index, true, &poIfData))
			{
				goto neAggPortRowStatus_update_cleanup;
			}
			
			xBitmap_setBit (poIfData->oNe.au8AdminFlags, neIfAdminFlags_lag_c, 0);
			ifData_unLock (poIfData);
		}
		
		if (!dot3adAggPortLacpStatus_update (poDot3adAggPortData, u8RowStatus))
		{
			goto neAggPortRowStatus_update_cleanup;
		}
		break;
	}
	
	bRetCode = true;
	
neAggPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __LAG_UTILS_C__
