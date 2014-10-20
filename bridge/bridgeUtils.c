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

#ifndef __BRIDGEUTILS_C__
#	define __BRIDGEUTILS_C__



#include "bridgeUtils.h"
#include "ethernet/ieee8021BridgeMib.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include <stdbool.h>
#include <stdint.h>


static neIfTypeEnableHandler_t bridge_pipEnableModify;


bool bridgeUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_pip_c)) == NULL)
	{
		goto bridgeUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = bridge_pipEnableModify;
	
	bRetCode = true;
	
bridgeUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}


bool
bridge_pipEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}


bool
ieee8021PbILan_createEntry (
	ieee8021BridgeBasePortEntry_t *poCnpPortEntry,
	ieee8021BridgeBasePortEntry_t *poPepPortEntry)
{
	register bool bRetCode = false;
	register ifStackEntry_t *poPepIfStackEntry = NULL;
	register ifStackEntry_t *poCepIfStackEntry = NULL;
	ifData_t *poPepIfData = NULL;
	ifData_t *poCnpIfData = NULL;
	ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (!ifData_createReference (poPepPortEntry->u32IfIndex, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poPepIfData) ||
		!ifData_createReference (poCnpPortEntry->u32IfIndex, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poCnpIfData))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poILanIfEntry = ieee8021BridgeILanIfTable_createExt (ifIndex_zero_c)) == NULL ||
		!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_active_c))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poPepIfStackEntry = ifStackTable_createExt (poPepIfData->u32Index, poILanIfEntry->u32IfIndex)) == NULL || !ifStackStatus_handler (poPepIfStackEntry, xRowStatus_active_c) ||
		(poCepIfStackEntry = ifStackTable_createExt (poCnpIfData->u32Index, poILanIfEntry->u32IfIndex)) == NULL || !ifStackStatus_handler (poCepIfStackEntry, xRowStatus_active_c))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	poPepPortEntry->u32IfIndex = poPepIfData->u32Index;
	poCnpPortEntry->u32IfIndex = poCnpIfData->u32Index;
	
	bRetCode = true;
	
ieee8021PbILan_createEntry_cleanup:
	
	poPepIfData != NULL ? ifData_unLock (poPepIfData): false;
	poCnpIfData != NULL ? ifData_unLock (poCnpIfData): false;
	
	if (!bRetCode)
	{
		poPepIfStackEntry != NULL ? ifStackTable_removeExt (poPepIfStackEntry): false;
		poCepIfStackEntry != NULL ? ifStackTable_removeExt (poCepIfStackEntry): false;
		poPepIfData != NULL ? ifData_removeReference (poPepIfData->u32Index, true, false, true): false;
		poCnpIfData != NULL ? ifData_removeReference (poCnpIfData->u32Index, true, false, true): false;
		poILanIfEntry != NULL ? ieee8021BridgeILanIfTable_removeExt (poILanIfEntry): false;
	}
	
	return bRetCode;
}

bool
ieee8021PbILan_removeEntry (
	ieee8021BridgeBasePortEntry_t *poCnpPortEntry,
	ieee8021BridgeBasePortEntry_t *poPepPortEntry)
{
	register bool bRetCode = false;
	register ifStackEntry_t *poIfStackEntry = NULL;
	ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (poPepPortEntry->u32IfIndex == 0)
	{
		goto ieee8021PbILan_removeEntry_cnpIf;
	}
	
	if ((poIfStackEntry = ifStackTable_getNextIndex (poPepPortEntry->u32IfIndex, 0)) != NULL &&
		poIfStackEntry->u32HigherLayer == poPepPortEntry->u32IfIndex &&
		(poILanIfEntry = ieee8021BridgeILanIfTable_getByIndex (poIfStackEntry->u32LowerLayer)) != NULL)
	{
		if (!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_destroy_c) ||
			!ieee8021BridgeILanIfTable_removeExt (poILanIfEntry))
		{
			goto ieee8021PbILan_removeEntry_cleanup;
		}
	}
	
	if (!ifData_removeReference (poPepPortEntry->u32IfIndex, true, false, true))
	{
		goto ieee8021PbILan_removeEntry_cleanup;
	}
	
ieee8021PbILan_removeEntry_cnpIf:
	
	if (poCnpPortEntry->u32IfIndex == 0)
	{
		goto ieee8021PbILan_removeEntry_success;
	}
	
	if ((poIfStackEntry = ifStackTable_getNextIndex (poCnpPortEntry->u32IfIndex, 0)) != NULL &&
		poIfStackEntry->u32HigherLayer == poPepPortEntry->u32IfIndex &&
		(poILanIfEntry = ieee8021BridgeILanIfTable_getByIndex (poIfStackEntry->u32LowerLayer)) != NULL)
	{
		if (!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_destroy_c) ||
			!ieee8021BridgeILanIfTable_removeExt (poILanIfEntry))
		{
			goto ieee8021PbILan_removeEntry_cleanup;
		}
	}
	
	if (!ifData_removeReference (poCnpPortEntry->u32IfIndex, true, false, true))
	{
		goto ieee8021PbILan_removeEntry_cleanup;
	}
	
ieee8021PbILan_removeEntry_success:
	
	poPepPortEntry->u32IfIndex = 0;
	poCnpPortEntry->u32IfIndex = 0;
	
	bRetCode = true;
	
ieee8021PbILan_removeEntry_cleanup:
	
	return bRetCode;
}



#endif	// __BRIDGEUTILS_C__
