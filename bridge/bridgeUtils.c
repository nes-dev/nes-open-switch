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
#include "ieee8021PbMib.h"
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
ieee8021PbVlanStaticTable_vlanHandler (
	ieee8021BridgeBaseEntry_t *pComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	
	if (pComponent->i32ComponentType != ieee8021BridgeBaseComponentType_sVlanComponent_c)
	{
		goto ieee8021PbVlanStaticTable_vlanHandler_success;
	}
	
	register uint16_t u16PortIndex = 0;
	
	xBitmap_scanBitRangeRev (
		pu8DisabledPorts, 0, xBitmap_bitLength (pComponent->u16Ports_len) - 1, 1, u16PortIndex)
	{
		register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
		
		if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (pComponent->u32ComponentId, u16PortIndex + 1)) == NULL)
		{
			continue;
		}
		
		register ieee8021PbEdgePortEntry_t *poIeee8021PbEdgePortEntry = NULL;
		
		if ((poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_getByIndex (poIeee8021PbCepEntry->u32BridgeBasePortComponentId, poIeee8021PbCepEntry->u32BridgeBasePort, poEntry->u32VlanIndex)) != NULL &&
			!ieee8021PbEdgePortRowStatus_handler (poIeee8021PbEdgePortEntry, xRowStatus_notInService_c))
		{
			goto ieee8021PbVlanStaticTable_vlanHandler_cleanup;
		}
	}
	
	xBitmap_scanBitRangeRev (
		pu8EnabledPorts, 0, xBitmap_bitLength (pComponent->u16Ports_len) - 1, 1, u16PortIndex)
	{
		register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
		
		if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (pComponent->u32ComponentId, u16PortIndex + 1)) == NULL)
		{
			continue;
		}
		
		register ieee8021PbEdgePortEntry_t *poIeee8021PbEdgePortEntry = NULL;
		
		if ((poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_getByIndex (poIeee8021PbCepEntry->u32BridgeBasePortComponentId, poIeee8021PbCepEntry->u32BridgeBasePort, poEntry->u32VlanIndex)) == NULL &&
			(poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_createExt (poIeee8021PbCepEntry->u32BridgeBasePortComponentId, poIeee8021PbCepEntry->u32BridgeBasePort, poEntry->u32VlanIndex)) == NULL)
		{
			goto ieee8021PbVlanStaticTable_vlanHandler_cleanup;
		}
		
		if (!ieee8021PbEdgePortRowStatus_handler (poIeee8021PbEdgePortEntry, poEntry->u8RowStatus))
		{
			goto ieee8021PbVlanStaticTable_vlanHandler_cleanup;
		}
	}
	
ieee8021PbVlanStaticTable_vlanHandler_success:
	
	bRetCode = true;
	
ieee8021PbVlanStaticTable_vlanHandler_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbVlanStaticRowStatus_handler (
	ieee8021BridgeBaseEntry_t *pComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	if (pComponent->i32ComponentType != ieee8021BridgeBaseComponentType_sVlanComponent_c)
	{
		goto ieee8021PbVlanStaticRowStatus_handler_success;
	}
	
	register uint16_t u16PortIndex = 0;
	
	xBitmap_scanBitRangeRev (
		poEntry->au8EgressPorts, 0, xBitmap_bitLength (pComponent->u16Ports_len) - 1, 1, u16PortIndex)
	{
		register ieee8021PbEdgePortEntry_t *poIeee8021PbEdgePortEntry = NULL;
		
		if ((poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_getByIndex (pComponent->u32ComponentId, u16PortIndex + 1, poEntry->u32VlanIndex)) == NULL)
		{
			continue;
		}
		
		if (!ieee8021PbEdgePortRowStatus_handler (poIeee8021PbEdgePortEntry, u8RowStatus))
		{
			goto ieee8021PbVlanStaticRowStatus_handler_cleanup;
		}
	}
	
ieee8021PbVlanStaticRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021PbVlanStaticRowStatus_handler_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbILan_createEntry (
	ieee8021BridgeBasePortEntry_t *poCnpPortEntry,
	ieee8021BridgeBasePortEntry_t *poPepPortEntry)
{
	register bool bRetCode = false;
	ifData_t *poPepIfData = NULL;
	register ifStackEntry_t *poPepIfStackEntry = NULL;
	register ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (poCnpPortEntry == NULL || poPepPortEntry == NULL)
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if (!ifData_createReference (poPepPortEntry->u32IfIndex, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poPepIfData))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poILanIfEntry = ieee8021BridgeILanIfTable_createExt (ifIndex_zero_c)) == NULL ||
		!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_active_c))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poPepIfStackEntry = ifStackTable_createExt (poPepIfData->u32Index, poILanIfEntry->u32IfIndex)) == NULL || !ifStackStatus_handler (poPepIfStackEntry, xRowStatus_active_c))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	poPepPortEntry->u32IfIndex = poPepIfData->u32Index;
	poCnpPortEntry->u32IfIndex = poILanIfEntry->u32IfIndex;
	
	bRetCode = true;
	
ieee8021PbILan_createEntry_cleanup:
	
	poPepIfData != NULL ? ifData_unLock (poPepIfData): false;
	
	if (!bRetCode)
	{
		poPepIfStackEntry != NULL ? ifStackTable_removeExt (poPepIfStackEntry): false;
		poPepIfData != NULL ? ifData_removeReference (poPepIfData->u32Index, true, false, true): false;
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
	ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (poPepPortEntry->u32IfIndex == 0)
	{
		goto ieee8021PbILan_removeEntry_cnpIf;
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
	
	if ((poILanIfEntry = ieee8021BridgeILanIfTable_getByIndex (poCnpPortEntry->u32IfIndex)) != NULL)
	{
		if (!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_destroy_c) ||
			!ieee8021BridgeILanIfTable_removeExt (poILanIfEntry))
		{
			goto ieee8021PbILan_removeEntry_cleanup;
		}
	}
	
ieee8021PbILan_removeEntry_success:
	
	poPepPortEntry->u32IfIndex = 0;
	poCnpPortEntry->u32IfIndex = 0;
	
	bRetCode = true;
	
ieee8021PbILan_removeEntry_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbbILan_createEntry (
	ieee8021BridgeBasePortEntry_t *poCbpPortEntry,
	uint32_t u32PipIfIndex,
	ieee8021BridgeBasePortEntry_t *poVipPortEntry)
{
	register bool bRetCode = false;
	ifData_t *poVipIfData = NULL;
	register ifStackEntry_t *poVipIfStackEntry = NULL;
	register ifStackEntry_t *poCbpIfStackEntry = NULL;
	register ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (poCbpPortEntry == NULL || u32PipIfIndex == 0 || poVipPortEntry == NULL)
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if (!ifData_createReference (poVipPortEntry->u32IfIndex, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poVipIfData))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if ((poILanIfEntry = ieee8021BridgeILanIfTable_createExt (ifIndex_zero_c)) == NULL ||
		!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_active_c))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if ((poVipIfStackEntry = ifStackTable_createExt (poVipIfData->u32Index, u32PipIfIndex)) == NULL || !ifStackStatus_handler (poVipIfStackEntry, xRowStatus_active_c) ||
		(poCbpIfStackEntry = ifStackTable_createExt (u32PipIfIndex, poILanIfEntry->u32IfIndex)) == NULL || !ifStackStatus_handler (poCbpIfStackEntry, xRowStatus_active_c))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	poVipPortEntry->u32IfIndex = poVipIfData->u32Index;
	poCbpPortEntry->u32IfIndex = poILanIfEntry->u32IfIndex;
	
	bRetCode = true;
	
ieee8021PbbILan_createEntry_cleanup:
	
	poVipIfData != NULL ? ifData_unLock (poVipIfData): false;
	
	if (!bRetCode)
	{
		poVipIfStackEntry != NULL ? ifStackTable_removeExt (poVipIfStackEntry): false;
		poCbpIfStackEntry != NULL ? ifStackTable_removeExt (poCbpIfStackEntry): false;
		poVipIfData != NULL ? ifData_removeReference (poVipIfData->u32Index, true, false, true): false;
		poILanIfEntry != NULL ? ieee8021BridgeILanIfTable_removeExt (poILanIfEntry): false;
	}
	
	return bRetCode;
}

bool
ieee8021PbbILan_removeEntry (
	ieee8021BridgeBasePortEntry_t *poCbpPortEntry,
	ieee8021BridgeBasePortEntry_t *poVipPortEntry)
{
	register bool bRetCode = false;
	ieee8021BridgeILanIfEntry_t *poILanIfEntry = NULL;
	
	if (poVipPortEntry->u32IfIndex == 0)
	{
		goto ieee8021PbbILan_removeEntry_cbpIf;
	}
	
	if (!ifData_removeReference (poVipPortEntry->u32IfIndex, true, false, true))
	{
		goto ieee8021PbbILan_removeEntry_cleanup;
	}
	
ieee8021PbbILan_removeEntry_cbpIf:
	
	if (poCbpPortEntry->u32IfIndex == 0)
	{
		goto ieee8021PbbILan_removeEntry_success;
	}
	
	if ((poILanIfEntry = ieee8021BridgeILanIfTable_getByIndex (poCbpPortEntry->u32IfIndex)) != NULL)
	{
		if (!ieee8021BridgeILanIfRowStatus_handler (poILanIfEntry, xRowStatus_destroy_c) ||
			!ieee8021BridgeILanIfTable_removeExt (poILanIfEntry))
		{
			goto ieee8021PbbILan_removeEntry_cleanup;
		}
	}
	
	if (!ifData_removeReference (poCbpPortEntry->u32IfIndex, true, false, true))
	{
		goto ieee8021PbbILan_removeEntry_cleanup;
	}
	
ieee8021PbbILan_removeEntry_success:
	
	poVipPortEntry->u32IfIndex = 0;
	poCbpPortEntry->u32IfIndex = 0;
	
	bRetCode = true;
	
ieee8021PbbILan_removeEntry_cleanup:
	
	return bRetCode;
}



#endif	// __BRIDGEUTILS_C__
