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


static ifType_enableHandler_t lagAgg_enableModify;
static ifType_statusModifier_t lagAgg_statusModify;
static ifType_stackHandler_t lagAgg_stackModify;

ifType_statusModifier_t lagAggPort_statusModify;


bool lagUtilsInit (void)
{
	register bool bRetCode = false;
	ifTypeEntry_t *poIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poIfTypeEntry = ifTypeTable_createExt (ifType_ieee8023adLag_c)) == NULL)
	{
		goto lagUtilsInit_cleanup;
	}
	
	poIfTypeEntry->pfEnableHandler = lagAgg_enableModify;
	poIfTypeEntry->pfStatusModifier = lagAgg_statusModify;
	poIfTypeEntry->pfStackHandler = lagAgg_stackModify;
	
	bRetCode = true;
	
lagUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}

bool
lagAgg_enableModify (
	ifEntry_t *poIfEntry, uint8_t u8AdminStatus)
{
	return false;
}

bool
lagAgg_statusModify (
	ifEntry_t *poIfEntry, uint8_t u8OperStatus, bool bPropagate)
{
	return false;
}

bool
lagAgg_stackModify (
	ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}

bool
lagAggPort_statusModify (
	ifEntry_t *poIfEntry, uint8_t u8OperStatus, bool bPropagate)
{
	register bool bRetCode = false;
	register dot3adAggPortEntry_t *poAggPort = NULL;
	
	dot3adAgg_wrLock ();
	
	if ((poAggPort = dot3adAggPortTable_getByIndex (poIfEntry->u32Index)) == NULL)
	{
		goto lagAggPort_statusModify_cleanup;
	}
	
	register bool bForce = poAggPort->u8OperStatus == u8OperStatus && bPropagate;
	
	poAggPort->u8OperStatus = u8OperStatus;
	
	if (!dot3adAggPortLacp_stateUpdate (poAggPort, bForce))
	{
		goto lagAggPort_statusModify_cleanup;
	}
	
	bRetCode = true;
	
lagAggPort_statusModify_cleanup:
	
	dot3adAgg_unLock ();
	return bRetCode;
}


bool
neAggRowStatus_update (
	dot3adAggEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	{
		register uint32_t u32Index = 0;
		register dot3adAggPortEntry_t *poAggPort = NULL;
		
		while (
			(poAggPort = dot3adAggPortTable_Group_getNextIndex (poEntry->oK.i32GroupType, poEntry->oK.u32GroupIndex, u32Index)) != NULL &&
			poAggPort->oK.i32GroupType == poEntry->oK.i32GroupType && poAggPort->oK.u32GroupIndex == poEntry->oK.u32GroupIndex)
		{
			u32Index = poAggPort->u32Index;
			
			if (!neAggPortRowStatus_handler (&poAggPort->oNe, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto neAggRowStatus_update_cleanup;
			}
		}
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (!ifStatus_modify (poEntry->u32Index, 0, xOperStatus_notPresent_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poEntry, u8RowStatus))
		{
			goto neAggRowStatus_update_cleanup;
		}
		break;
		
	case xRowStatus_notInService_c:
		if (!ifStatus_modify (poEntry->u32Index, 0, xOperStatus_down_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poEntry, u8RowStatus))
		{
			goto neAggRowStatus_update_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
		if (!ifStatus_modify (poEntry->u32Index, 0, xOperStatus_notPresent_c, true, false))
		{
			goto neAggRowStatus_update_cleanup;
		}
		
		/* TODO */
		
		if (!dot3adAggLacpStatus_update (poEntry, u8RowStatus))
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
	dot3adAggPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		
		if (!dot3adAggPortLacpStatus_update (poEntry, u8RowStatus))
		{
			goto neAggPortRowStatus_update_cleanup;
		}
		
		{
			ifEntry_t *poIfEntry = NULL;
			
			if (!ifTable_getByIndexExt (poEntry->u32Index, true, &poIfEntry))
			{
				goto neAggPortRowStatus_update_cleanup;
			}
			
			xBitmap_setBit (poIfEntry->oNe.au8AdminFlags, neIfAdminFlags_lag_c, 1);
			ifEntry_unLock (poIfEntry);
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		/* TODO */
		
		{
			ifEntry_t *poIfEntry = NULL;
			
			if (!ifTable_getByIndexExt (poEntry->u32Index, true, &poIfEntry))
			{
				goto neAggPortRowStatus_update_cleanup;
			}
			
			xBitmap_setBit (poIfEntry->oNe.au8AdminFlags, neIfAdminFlags_lag_c, 0);
			ifEntry_unLock (poIfEntry);
		}
		
		if (!dot3adAggPortLacpStatus_update (poEntry, u8RowStatus))
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
