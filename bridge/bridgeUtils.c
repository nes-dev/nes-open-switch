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
#include "ethernet/ieee8021QBridgeMib.h"
#include "ieee8021PbMib.h"
#include "ieee8021PbbMib.h"
#include "ethernet/ethernetUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"

#include "lib/bitmap.h"

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
	ieee8021BridgeBaseEntry_t *poSComponent, ieee8021BridgeBasePortEntry_t *poCnpPort,
	ieee8021BridgeBaseEntry_t *poCComponent, ieee8021BridgeBasePortEntry_t *poPepPort)
{
	register bool bRetCode = false;
	register bool bPhyLocked = false;
	ifData_t *poPepIfData = NULL;
	register ieee8021BridgePhyData_t *poPepPhyData = NULL;
	register ieee8021BridgePhyData_t *poCnpPhyData = NULL;
	register ieee8021BridgeILanIfEntry_t *poCnpILanEntry = NULL;
	
	if (poCnpPort == NULL || poPepPort == NULL)
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if (!ifData_createReference (ifIndex_zero_c, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poPepIfData))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poCnpILanEntry = ieee8021BridgeILanIfTable_createRegister (ifIndex_zero_c)) == NULL)
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if (!ifStackTable_createRegister (poPepIfData->u32Index, poCnpILanEntry->u32IfIndex))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	ieee8021BridgePhyData_wrLock ();
	bPhyLocked = true;
	
	if ((poPepPhyData = ieee8021BridgePhyData_createExt (poPepIfData->u32Index, 0)) == NULL)
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if ((poCnpPhyData = ieee8021BridgePhyData_createExt (poCnpILanEntry->u32IfIndex, 0)) == NULL)
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if (!ieee8021BridgePhyData_attachComponent (poCComponent, poPepPort, poPepPhyData))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	if (!ieee8021BridgePhyData_attachComponent (poSComponent, poCnpPort, poCnpPhyData))
	{
		goto ieee8021PbILan_createEntry_cleanup;
	}
	
	bRetCode = true;
	
ieee8021PbILan_createEntry_cleanup:
	
	poPepIfData != NULL ? ifData_unLock (poPepIfData): false;
	
	if (!bRetCode)
	{
		if (poPepPhyData != NULL && poPepPort->u32IfIndex == poPepPhyData->u32IfIndex)
		{
			ieee8021BridgePhyData_detachComponent (poPepPort, poPepPhyData);
			ieee8021BridgePhyData_removeExt (poPepPhyData);
		}
		poPepIfData != NULL ? ifData_removeReference (poPepIfData->u32Index, true, false, true): false;
		if (poCnpPhyData != NULL && poCnpPort->u32IfIndex == poCnpPhyData->u32IfIndex)
		{
			ieee8021BridgePhyData_detachComponent (poCnpPort, poCnpPhyData);
			ieee8021BridgePhyData_removeExt (poCnpPhyData);
		}
		poCnpILanEntry != NULL ? ieee8021BridgeILanIfTable_removeRegister (poCnpILanEntry->u32IfIndex): false;
	}
	
	bPhyLocked ? ieee8021BridgePhyData_unLock (): false;
	
	return bRetCode;
}

bool
ieee8021PbILan_removeEntry (
	ieee8021BridgeBaseEntry_t *poSComponent, ieee8021BridgeBasePortEntry_t *poCnpPort,
	ieee8021BridgeBaseEntry_t *poCComponent, ieee8021BridgeBasePortEntry_t *poPepPort)
{
	register bool bRetCode = false;
	
	
	ieee8021BridgePhyData_wrLock ();
	
	if (poPepPort->u32IfIndex != 0)
	{
		register ieee8021BridgePhyData_t *poPepPhyData = NULL;
		
		if ((poPepPhyData = ieee8021BridgePhyData_getByIndex (poPepPort->u32IfIndex, 0)) == NULL ||
			!ieee8021BridgePhyData_detachComponent (poPepPort, poPepPhyData) ||
			!ieee8021BridgePhyData_removeExt (poPepPhyData))
		{
			goto ieee8021PbILan_removeEntry_phyCleanup;
		}
	}
	
	if (poCnpPort->u32IfIndex != 0)
	{
		register ieee8021BridgePhyData_t *poCnpPhyData = NULL;
		
		if ((poCnpPhyData = ieee8021BridgePhyData_getByIndex (poCnpPort->u32IfIndex, 0)) == NULL ||
			!ieee8021BridgePhyData_detachComponent (poCnpPort, poCnpPhyData) ||
			!ieee8021BridgePhyData_removeExt (poCnpPhyData))
		{
			goto ieee8021PbILan_removeEntry_phyCleanup;
		}
	}
	
	bRetCode = true;
	
ieee8021PbILan_removeEntry_phyCleanup:
	
	ieee8021BridgePhyData_unLock ();
	if (!bRetCode)
	{
		goto ieee8021PbILan_removeEntry_cleanup;
	}
	bRetCode = false;
	
	
	if (poPepPort->u32IfIndex == 0)
	{
		goto ieee8021PbILan_removeEntry_cnpIf;
	}
	
	if (!ifData_removeReference (poPepPort->u32IfIndex, true, false, true))
	{
		goto ieee8021PbILan_removeEntry_cleanup;
	}
	
ieee8021PbILan_removeEntry_cnpIf:
	
	if (poCnpPort->u32IfIndex == 0)
	{
		goto ieee8021PbILan_removeEntry_success;
	}
	
	if (!ieee8021BridgeILanIfTable_removeRegister (poCnpPort->u32IfIndex))
	{
		goto ieee8021PbILan_removeEntry_success;
	}
	
ieee8021PbILan_removeEntry_success:
	
	poPepPort->u32IfIndex = 0;
	poCnpPort->u32IfIndex = 0;
	
	bRetCode = true;
	
ieee8021PbILan_removeEntry_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbbILan_createEntry (
	ieee8021BridgeBaseEntry_t *poBComponent, ieee8021BridgeBasePortEntry_t *poCbpPort,
	uint32_t u32PipIfIndex,
	ieee8021BridgeBaseEntry_t *poIComponent, ieee8021BridgeBasePortEntry_t *poVipPort)
{
	register bool bRetCode = false;
	register bool bPhyLocked = false;
	ifData_t *poVipIfData = NULL;
	register ieee8021BridgePhyData_t *poVipPhyData = NULL;
	register ieee8021BridgePhyData_t *poCbpPhyData = NULL;
	register ieee8021BridgeILanIfEntry_t *poCbpILanEntry = NULL;
	
	if (poCbpPort == NULL || u32PipIfIndex == 0 || poVipPort == NULL)
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if (!ifData_createReference (ifIndex_zero_c, ifType_bridge_c, xAdminStatus_up_c, true, false, false, &poVipIfData))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if ((poCbpILanEntry = ieee8021BridgeILanIfTable_createRegister (ifIndex_zero_c)) == NULL)
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if (!ifStackTable_createRegister (poVipIfData->u32Index, u32PipIfIndex) ||
		!ifStackTable_createRegister (u32PipIfIndex, poCbpILanEntry->u32IfIndex))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	ieee8021BridgePhyData_wrLock ();
	bPhyLocked = true;
	
	if ((poVipPhyData = ieee8021BridgePhyData_createExt (poVipIfData->u32Index, 0)) == NULL)
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if ((poCbpPhyData = ieee8021BridgePhyData_createExt (poCbpILanEntry->u32IfIndex, 0)) == NULL)
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if (!ieee8021BridgePhyData_attachComponent (poIComponent, poVipPort, poVipPhyData))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	if (!ieee8021BridgePhyData_attachComponent (poBComponent, poCbpPort, poCbpPhyData))
	{
		goto ieee8021PbbILan_createEntry_cleanup;
	}
	
	bRetCode = true;
	
ieee8021PbbILan_createEntry_cleanup:
	
	poVipIfData != NULL ? ifData_unLock (poVipIfData): false;
	
	if (!bRetCode)
	{
		if (poVipPhyData != NULL && poVipPort->u32IfIndex == poVipPhyData->u32IfIndex)
		{
			ieee8021BridgePhyData_detachComponent (poVipPort, poVipPhyData);
			ieee8021BridgePhyData_removeExt (poVipPhyData);
		}
		poVipIfData != NULL ? ifData_removeReference (poVipIfData->u32Index, true, false, true): false;
		if (poCbpPhyData != NULL && poCbpPort->u32IfIndex == poCbpPhyData->u32IfIndex)
		{
			ieee8021BridgePhyData_detachComponent (poCbpPort, poCbpPhyData);
			ieee8021BridgePhyData_removeExt (poCbpPhyData);
		}
		poCbpILanEntry != NULL ? ieee8021BridgeILanIfTable_removeRegister (poCbpILanEntry->u32IfIndex): false;
	}
	
	bPhyLocked ? ieee8021BridgePhyData_unLock (): false;
	
	return bRetCode;
}

bool
ieee8021PbbILan_removeEntry (
	ieee8021BridgeBaseEntry_t *poBComponent, ieee8021BridgeBasePortEntry_t *poCbpPort,
	ieee8021BridgeBaseEntry_t *poIComponent, ieee8021BridgeBasePortEntry_t *poVipPort)
{
	register bool bRetCode = false;
	
	
	ieee8021BridgePhyData_wrLock ();
	
	if (poVipPort->u32IfIndex != 0)
	{
		register ieee8021BridgePhyData_t *poVipPhyData = NULL;
		
		if ((poVipPhyData = ieee8021BridgePhyData_getByIndex (poVipPort->u32IfIndex, 0)) == NULL ||
			!ieee8021BridgePhyData_detachComponent (poVipPort, poVipPhyData) ||
			!ieee8021BridgePhyData_removeExt (poVipPhyData))
		{
			goto ieee8021PbbILan_removeEntry_phyCleanup;
		}
	}
	
	if (poCbpPort->u32IfIndex != 0)
	{
		register ieee8021BridgePhyData_t *poCbpPhyData = NULL;
		
		if ((poCbpPhyData = ieee8021BridgePhyData_getByIndex (poCbpPort->u32IfIndex, 0)) == NULL ||
			!ieee8021BridgePhyData_detachComponent (poCbpPort, poCbpPhyData) ||
			!ieee8021BridgePhyData_removeExt (poCbpPhyData))
		{
			goto ieee8021PbbILan_removeEntry_phyCleanup;
		}
	}
	
	bRetCode = true;
	
ieee8021PbbILan_removeEntry_phyCleanup:
	
	ieee8021BridgePhyData_unLock ();
	if (!bRetCode)
	{
		goto ieee8021PbbILan_removeEntry_cleanup;
	}
	bRetCode = false;
	
	
	if (poVipPort->u32IfIndex == 0)
	{
		goto ieee8021PbbILan_removeEntry_cbpIf;
	}
	
	if (!ifData_removeReference (poVipPort->u32IfIndex, true, false, true))
	{
		goto ieee8021PbbILan_removeEntry_cleanup;
	}
	
ieee8021PbbILan_removeEntry_cbpIf:
	
	if (poCbpPort->u32IfIndex == 0)
	{
		goto ieee8021PbbILan_removeEntry_success;
	}
	
	if (!ieee8021BridgeILanIfTable_removeRegister (poCbpPort->u32IfIndex))
	{
		goto ieee8021PbbILan_removeEntry_success;
	}
	
	if (!ifData_removeReference (poCbpPort->u32IfIndex, true, false, true))
	{
		goto ieee8021PbbILan_removeEntry_cleanup;
	}
	
ieee8021PbbILan_removeEntry_success:
	
	poVipPort->u32IfIndex = 0;
	poCbpPort->u32IfIndex = 0;
	
	bRetCode = true;
	
ieee8021PbbILan_removeEntry_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbCVidRegistrationRowStatus_update (
	ieee8021PbCVidRegistrationEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	if ((poEntry->u8RowStatus == xRowStatus_active_c && u8RowStatus == xRowStatus_active_c) ||
		(poEntry->u8RowStatus != xRowStatus_active_c && u8RowStatus != xRowStatus_active_c))
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_success;
	}
	
	register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
	
	if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_cleanup;
	}
	
	register ieee8021BridgeBaseEntry_t *poCComponent = NULL;
	
	if ((poCComponent = ieee8021BridgeBaseTable_getByIndex (poIeee8021PbCepEntry->u32CComponentId)) == NULL)
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_cleanup;
	}
	
	register ieee8021QBridgeVlanStaticEntry_t *poCVlanStaticEntry = NULL;
	
	if ((poCVlanStaticEntry = ieee8021QBridgeVlanStaticTable_getByIndex (poIeee8021PbCepEntry->u32CComponentId, poEntry->u32CVid)) == NULL)
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_cleanup;
	}
	
	register ieee8021PbEdgePortEntry_t *poIeee8021PbEdgePortEntry = NULL;
	
	if ((poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort, poEntry->u32SVid)) != NULL &&
		!ieee8021QBridgeVlanStaticTable_vHandler (
			poIeee8021PbCepEntry->u32CComponentId, poEntry->u32CVid,
			u8RowStatus == xRowStatus_active_c, poEntry->i32UntaggedPep == ieee8021PbCVidRegistrationUntaggedPep_true_c, 1, poIeee8021PbEdgePortEntry->u32PepPort))
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c)
	{
		xBitmap_setBitRev (poCVlanStaticEntry->au8UntaggedPorts, poEntry->u32BridgeBasePort - 1, poEntry->i32UntaggedCep == ieee8021PbCVidRegistrationUntaggedCep_true_c);
	}
	
	if (!ieee8021QBridgeVlanStaticRowStatus_handler (poCComponent, poCVlanStaticEntry, u8RowStatus))
	{
		goto ieee8021PbCVidRegistrationRowStatus_update_cleanup;
	}
	
	if (poIeee8021PbEdgePortEntry != NULL)
	{
		u8RowStatus == xRowStatus_active_c ? poIeee8021PbEdgePortEntry->u32NumCVid++: poIeee8021PbEdgePortEntry->u32NumCVid--;
	}
	
ieee8021PbCVidRegistrationRowStatus_update_success:
	
	bRetCode = true;
	
ieee8021PbCVidRegistrationRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbbVipRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021PbbVipEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	
	if (poEntry->pOldEntry != NULL && poEntry->pOldEntry->u32ISid == poEntry->u32ISid)
	{
		goto ieee8021PbbVipRowStatus_update_updatePipIfIndex;
	}
	
	if (poEntry->pOldEntry == NULL || poEntry->pOldEntry->u32ISid == 0)
	{
		goto ieee8021PbbVipRowStatus_update_newISid;
	}
	
	xBTree_nodeRemove (&poEntry->oISid_BTreeNode, &oIeee8021PbbVipTable_ISid_BTree);
	poEntry->pOldEntry->u32ISid = 0;
	
ieee8021PbbVipRowStatus_update_newISid:
	
	if (poEntry->u32ISid == 0)
	{
		goto ieee8021PbbVipRowStatus_update_cleanup;
	}
	
	xBTree_nodeAdd (&poEntry->oISid_BTreeNode, &oIeee8021PbbVipTable_ISid_BTree);
	
	
ieee8021PbbVipRowStatus_update_updatePipIfIndex:
	
	if (poEntry->u32PipIfIndex != 0)
	{
		goto ieee8021PbbVipRowStatus_update_success;
	}
	
	register ieee8021PbbPipEntry_t *poIeee8021PbbPipEntry = NULL;
	register ieee8021PbbVipToPipMappingEntry_t *poIeee8021PbbVipToPipMappingEntry =
		ieee8021PbbVipToPipMappingTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort);
		
	if (poIeee8021PbbVipToPipMappingEntry != NULL && poIeee8021PbbVipToPipMappingEntry->u8RowStatus == xRowStatus_active_c &&
		(poIeee8021PbbPipEntry = ieee8021PbbPipTable_getByIndex (poIeee8021PbbVipToPipMappingEntry->u32PipIfIndex)) == NULL)
	{
		goto ieee8021PbbVipRowStatus_update_cleanup;
	}
	else if (
		(poIeee8021PbbPipEntry = ieee8021PbbPipTable_Comp_getNextIndex (poEntry->u32BridgeBasePortComponentId, 0)) == NULL ||
		poIeee8021PbbPipEntry->u32IComponentId != poEntry->u32BridgeBasePortComponentId)
	{
		goto ieee8021PbbVipRowStatus_update_cleanup;
	}
	
	xBitmap_setBitRev (poIeee8021PbbPipEntry->au8VipMap, poEntry->u32BridgeBasePort - 1, 1);
	poEntry->u32PipIfIndex = poIeee8021PbbPipEntry->u32IfIndex;
	
	
ieee8021PbbVipRowStatus_update_success:
	
	bRetCode = true;
	
ieee8021PbbVipRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbbVipToPipMappingRowStatus_update (
	ieee8021PbbVipToPipMappingEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		if (poEntry->pOldEntry == NULL)
		{
			if ((poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
			{
				goto ieee8021PbbVipToPipMappingRowStatus_update_cleanup;
			}
			memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		}
		
		if (u8RowStatus == xRowStatus_destroy_c)
		{
			poEntry->u32PipIfIndex = 0;
		}
		break;
	}
	
	
	if (poEntry->pOldEntry != NULL && poEntry->pOldEntry->u32PipIfIndex == poEntry->u32PipIfIndex)
	{
		goto ieee8021PbbVipToPipMappingRowStatus_update_updateVip;
	}
	
	if (poEntry->pOldEntry == NULL || poEntry->pOldEntry->u32PipIfIndex == 0)
	{
		goto ieee8021PbbVipToPipMappingRowStatus_update_newPipIfIndex;
	}
	
	{
		register ieee8021PbbPipEntry_t *poIeee8021PbbPipEntry = NULL;
		
		if ((poIeee8021PbbPipEntry = ieee8021PbbPipTable_getByIndex (poEntry->pOldEntry->u32PipIfIndex)) != NULL)
		{
			xBitmap_setBitRev (poIeee8021PbbPipEntry->au8VipMap, poEntry->u32BridgeBasePort - 1, 0);
		}
	}
	
	poEntry->pOldEntry->u32PipIfIndex = 0;
	
ieee8021PbbVipToPipMappingRowStatus_update_newPipIfIndex:
	
	if (poEntry->u32PipIfIndex != 0)
	{
		register ieee8021PbbPipEntry_t *poIeee8021PbbPipEntry = NULL;
		
		if ((poIeee8021PbbPipEntry = ieee8021PbbPipTable_getByIndex (poEntry->u32PipIfIndex)) == NULL)
		{
			goto ieee8021PbbVipToPipMappingRowStatus_update_cleanup;
		}
		xBitmap_setBitRev (poIeee8021PbbPipEntry->au8VipMap, poEntry->u32BridgeBasePort - 1, 1);
	}
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
	case xRowStatus_destroy_c:
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
	}
	
	
ieee8021PbbVipToPipMappingRowStatus_update_updateVip:
	{
		register ieee8021PbbVipEntry_t *poIeee8021PbbVipEntry = NULL;
		
		if ((poIeee8021PbbVipEntry = ieee8021PbbVipTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) != NULL &&
			!ieee8021PbbVipRowStatus_handler (poIeee8021PbbVipEntry, u8RowStatus | xRowStatus_fromParent_c))
		{
			goto ieee8021PbbVipToPipMappingRowStatus_update_cleanup;
		}
	}
	
	
	bRetCode = true;
	
ieee8021PbbVipToPipMappingRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __BRIDGEUTILS_C__
