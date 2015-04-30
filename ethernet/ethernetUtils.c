/*
 *  Copyright (c) 2008-2015
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

#ifndef __ETHERNET_UTILS_C__
#	define __ETHERNET_UTILS_C__



#include "ethernetUtils.h"
#include "ieee8021BridgeMib.h"
#include "ieee8021QBridgeMib.h"
#include "bridge/ieee8021PbMib.h"
#include "bridge/ieee8021PbbMib.h"
#include "bridge/bridgeUtils.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"
#include "hal/halEthernet.h"

#include "lag_ext.h"

#include "lib/bitmap.h"
#include "lib/list.h"
#include "lib/bitmap.h"
#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>


static neIfTypeEnableHandler_t ieee8021If_ethernetEnableModify;
static neIfTypeStatusModifier_t ieee8021If_ethernetStatusModify;
static neIfTypeStackHandler_t ieee8021If_ethernetStackModify;

static neIfTypeStackHandler_t ieee8021If_l2vlanStackModify;

static neIfTypeEnableHandler_t ieee8021If_bridgeEnableModify;
static neIfTypeStatusModifier_t ieee8021If_bridgeStatusModify;
static neIfTypeStackHandler_t ieee8021If_bridgeStackModify;

static neIfTypeEnableHandler_t ieee8021If_ilanEnableModify;
static neIfTypeStatusModifier_t ieee8021If_ilanStatusModify;
static neIfTypeStackHandler_t ieee8021If_ilanStackModify;


bool ethernetUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ethernetCsmacd_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ieee8021If_ethernetEnableModify;
	poNeIfTypeEntry->pfStatusModifier = ieee8021If_ethernetStatusModify;
	poNeIfTypeEntry->pfStackHandler = ieee8021If_ethernetStackModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_l2vlan_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfStackHandler = ieee8021If_l2vlanStackModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_bridge_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ieee8021If_bridgeEnableModify;
	poNeIfTypeEntry->pfStatusModifier = ieee8021If_bridgeStatusModify;
	poNeIfTypeEntry->pfStackHandler = ieee8021If_bridgeStackModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ilan_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ieee8021If_ilanEnableModify;
	poNeIfTypeEntry->pfStatusModifier = ieee8021If_ilanStatusModify;
	poNeIfTypeEntry->pfStackHandler = ieee8021If_ilanStackModify;
	
	bRetCode = true;
	
ethernetUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}


bool
ieee8021If_ethernetEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	register bool bRetCode = false;
	
	if (!halEthernet_ifConfigure (poIfEntry, halEthernet_ifAdminState_c))
	{
		goto ieee8021If_ethernetEnableModify_cleanup;
	}
	
	bRetCode = true;
	
ieee8021If_ethernetEnableModify_cleanup:
	
	return bRetCode;
}

bool
ieee8021If_ethernetStatusModify (
	ifData_t *poIfEntry, int32_t i32OperStatus, bool bPropagate)
{
	register bool bRetCode = false;
	
	/* TODO */
	
	if (xBitmap_getBit (poIfEntry->oNe.au8AdminFlags, neIfAdminFlags_lag_c) &&
		!lag_aggPortStatusModify (poIfEntry, i32OperStatus, bPropagate))
	{
		goto ieee8021If_ethernetStatusModify_cleanup;
	}
	
	bRetCode = true;
	
ieee8021If_ethernetStatusModify_cleanup:
	
	return bRetCode;
}

bool
ieee8021If_ethernetStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}

bool
ieee8021If_l2vlanStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}

bool
ieee8021If_bridgeEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}

bool
ieee8021If_bridgeStatusModify (
	ifData_t *poIfEntry, int32_t i32OperStatus, bool bPropagate)
{
	return false;
}

bool
ieee8021If_bridgeStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}

bool
ieee8021If_ilanEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}

bool
ieee8021If_ilanStatusModify (
	ifData_t *poIfEntry, int32_t i32OperStatus, bool bPropagate)
{
	return false;
}

bool
ieee8021If_ilanStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool isLocked)
{
	return true;
}


static bool
	ieee8021BridgeBaseDependentStatus_update (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
static bool
	ieee8021BridgeBaseRowStatus_halUpdate (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
static bool
	ieee8021BridgeBasePortDependentStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
static bool
	ieee8021BridgeBasePortRowStatus_halUpdate (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
static bool
	ieee8021QBridgePortRowStatus_halUpdate (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus);


bool
ieee8021BridgeBaseTable_hierUpdate (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (ieee8021QBridgeTable_getByIndex (poEntry->u32ComponentId) == NULL &&
			ieee8021QBridgeTable_createExt (poEntry->u32ComponentId) == NULL)
		{
			goto ieee8021BridgeBaseTable_hierUpdate_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
	{
		register ieee8021QBridgeEntry_t *poIeee8021QBridgeEntry = NULL;
		
		if ((poIeee8021QBridgeEntry = ieee8021QBridgeTable_getByIndex (poEntry->u32ComponentId)) != NULL &&
			!ieee8021QBridgeTable_removeExt (poIeee8021QBridgeEntry))
		{
			goto ieee8021BridgeBaseTable_hierUpdate_cleanup;
		}
		break;
	}
	}
	
	bRetCode = true;
	
ieee8021BridgeBaseTable_hierUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBaseTrafficClassesEnabled_update (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8TrafficClassesEnabled)
{
	register bool bRetCode = false;
	
	/* TODO */
	
	bRetCode = true;
	
// ieee8021BridgeBaseTrafficClassesEnabled_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBaseMmrpEnabledStatus_update (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8MmrpEnabledStatus)
{
	register bool bRetCode = false;
	
	/* TODO */
	
	bRetCode = true;
	
// ieee8021BridgeBaseMmrpEnabledStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBaseDependentStatus_update (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	register uint8_t u8TrafficClassesEnabled = u8RowStatus == xRowStatus_active_c ? poEntry->u8TrafficClassesEnabled: ieee8021BridgeBaseTrafficClassesEnabled_false_c;
	register uint8_t u8MmrpEnabledStatus = u8RowStatus == xRowStatus_active_c ? poEntry->u8MmrpEnabledStatus: ieee8021BridgeBaseMmrpEnabledStatus_false_c;
	
	if (!ieee8021BridgeBaseTrafficClassesEnabled_handler (poEntry, u8TrafficClassesEnabled, true) ||
		!ieee8021BridgeBaseMmrpEnabledStatus_handler (poEntry, u8MmrpEnabledStatus, true))
	{
		goto ieee8021BridgeBaseDependentStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeBaseDependentStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBaseRowStatus_update (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	
	if (!neIeee8021BridgeBaseRowStatus_handler (&poEntry->oNe, u8RowStatus))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c && !ieee8021BridgeBaseRowStatus_halUpdate (poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c && !ieee8021BridgeBaseDependentStatus_update (poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	
	register uint32_t u32VlanIndex = 0;
	register ieee8021QBridgeVlanStaticEntry_t *poIeee8021QBridgeVlanStaticEntry = NULL;
	
	while (
		(poIeee8021QBridgeVlanStaticEntry = ieee8021QBridgeVlanStaticTable_getNextIndex (poEntry->u32ComponentId, u32VlanIndex)) != NULL &&
		poIeee8021QBridgeVlanStaticEntry->u32ComponentId == poEntry->u32ComponentId)
	{
		u32VlanIndex = poIeee8021QBridgeVlanStaticEntry->u32VlanIndex;
		
		if (!ieee8021QBridgeVlanStaticRowStatus_handler (poEntry, poIeee8021QBridgeVlanStaticEntry, u8RowStatus | xRowStatus_fromParent_c))
		{
			goto ieee8021BridgeBaseRowStatus_update_cleanup;
		}
	}
	
	register ieee8021QBridgeVlanCurrentEntry_t *poIeee8021QBridgeVlanCurrentEntry = NULL;
	
	u32VlanIndex = 0;
	
	while (
		(poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_Vlan_getNextIndex (poEntry->u32ComponentId, u32VlanIndex)) != NULL &&
		poIeee8021QBridgeVlanCurrentEntry->u32ComponentId == poEntry->u32ComponentId)
	{
		u32VlanIndex = poIeee8021QBridgeVlanCurrentEntry->u32Index;
		
		if (!ieee8021QBridgeVlanCurrentRowStatus_handler (poEntry, poIeee8021QBridgeVlanCurrentEntry, u8RowStatus | xRowStatus_fromParent_c))
		{
			goto ieee8021BridgeBaseRowStatus_update_cleanup;
		}
	}
	
	
	register uint32_t u32Port = 0;
	register ieee8021QBridgeIngressVidXEntry_t *poIeee8021QBridgeIngressVidXEntry = NULL;
	
	u32VlanIndex = 0;
	
	while (
		(poIeee8021QBridgeIngressVidXEntry = ieee8021QBridgeIngressVidXTable_getNextIndex (poEntry->u32ComponentId, u32Port, u32VlanIndex)) != NULL &&
		poIeee8021QBridgeIngressVidXEntry->u32BridgeBasePortComponentId == poEntry->u32ComponentId)
	{
		u32Port = poIeee8021QBridgeIngressVidXEntry->u32BridgeBasePort;
		u32VlanIndex = poIeee8021QBridgeIngressVidXEntry->u32LocalVid;
		
		if (!ieee8021QBridgeIngressVidXRowStatus_handler (poIeee8021QBridgeIngressVidXEntry, u8RowStatus | xRowStatus_fromParent_c))
		{
			goto ieee8021BridgeBaseRowStatus_update_cleanup;
		}
	}
	
	register ieee8021QBridgeEgressVidXEntry_t *poIeee8021QBridgeEgressVidXEntry = NULL;
	
	u32Port = 0;
	u32VlanIndex = 0;
	
	while (
		(poIeee8021QBridgeEgressVidXEntry = ieee8021QBridgeEgressVidXTable_getNextIndex (poEntry->u32ComponentId, u32Port, u32VlanIndex)) != NULL &&
		poIeee8021QBridgeEgressVidXEntry->u32BridgeBaseComponentId == poEntry->u32ComponentId)
	{
		u32Port = poIeee8021QBridgeEgressVidXEntry->u32BridgeBasePort;
		u32VlanIndex = poIeee8021QBridgeEgressVidXEntry->u32LocalVid;
		
		if (!ieee8021QBridgeEgressVidXRowStatus_handler (poIeee8021QBridgeEgressVidXEntry, u8RowStatus | xRowStatus_fromParent_c))
		{
			goto ieee8021BridgeBaseRowStatus_update_cleanup;
		}
	}
	
	
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	u32Port = 0;
	
	while (
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getNextIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
		poIeee8021BridgeBasePortEntry->u32ComponentId == poEntry->u32ComponentId)
	{
		u32Port = poIeee8021BridgeBasePortEntry->u32Port;
		
		switch (poIeee8021BridgeBasePortEntry->i32Type)
		{
		case ieee8021BridgeBasePortType_customerVlanPort_c:
		{
			register ieee8021QBridgeCVlanPortEntry_t *poIeee8021QBridgeCVlanPortEntry = NULL;
			
			if ((poIeee8021QBridgeCVlanPortEntry = ieee8021QBridgeCVlanPortTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021QBridgeCVlanPortRowStatus_handler (poIeee8021QBridgeCVlanPortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_providerNetworkPort_c:
		{
			register ieee8021PbPnpEntry_t *poIeee8021PbPnpEntry = NULL;
			
			if ((poIeee8021PbPnpEntry = ieee8021PbPnpTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbPnpRowStatus_handler (poIeee8021PbPnpEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_customerNetworkPort_c:
		{
			register ieee8021PbCnpEntry_t *poIeee8021PbCnpEntry = NULL;
			
			if ((poIeee8021PbCnpEntry = ieee8021PbCnpTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbCnpRowStatus_handler (poIeee8021PbCnpEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_customerEdgePort_c:
		{
			register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
			
			if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbCepRowStatus_handler (poIeee8021PbCepEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_customerBackbonePort_c:
		{
			register ieee8021PbbCbpEntry_t *poIeee8021PbbCbpEntry = NULL;
			
			if ((poIeee8021PbbCbpEntry = ieee8021PbbCbpTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbbCbpRowStatus_handler (poIeee8021PbbCbpEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_virtualInstancePort_c:
		{
			register ieee8021PbbVipEntry_t *poIeee8021PbbVipEntry = NULL;
			
			if ((poIeee8021PbbVipEntry = ieee8021PbbVipTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbbVipRowStatus_handler (poIeee8021PbbVipEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_dBridgePort_c:
		{
			register ieee8021BridgeDot1dPortEntry_t *poIeee8021BridgeDot1dPortEntry = NULL;
			
			if ((poIeee8021BridgeDot1dPortEntry = ieee8021BridgeDot1dPortTable_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021BridgeDot1dPortRowStatus_handler (poIeee8021BridgeDot1dPortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		case ieee8021BridgeBasePortType_providerEdgePort_c:
		{
			register ieee8021PbEdgePortEntry_t *poIeee8021PbEdgePortEntry = NULL;
			
			if ((poIeee8021PbEdgePortEntry = ieee8021PbEdgePortTable_Pep_getByIndex (poEntry->u32ComponentId, u32Port)) != NULL &&
				!ieee8021PbEdgePortRowStatus_handler (poIeee8021PbEdgePortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
		
		default:
			if (!ieee8021BridgeBasePortRowStatus_handler (poEntry, poIeee8021BridgeBasePortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
	}
	
	
	if (u8RowStatus != xRowStatus_active_c && !ieee8021BridgeBaseDependentStatus_update (poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	if (u8RowStatus != xRowStatus_active_c && !ieee8021BridgeBaseRowStatus_halUpdate (poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	
	bRetCode = true;
	
ieee8021BridgeBaseRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBaseRowStatus_halUpdate (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_createAndWait_c ? halEthernet_componentCreate_c:
		u8RowStatus == xRowStatus_active_c ? halEthernet_componentEnable_c:
		u8RowStatus == xRowStatus_notReady_c ? halEthernet_componentDisable_c:
		u8RowStatus == xRowStatus_notInService_c ? halEthernet_componentDisable_c:
		u8RowStatus == xRowStatus_destroy_c ? halEthernet_componentDestroy_c: halEthernet_componentNone_c;
		
	if ((u8HalOpCode == halEthernet_componentDestroy_c && poEntry->u8RowStatus == xRowStatus_active_c && !halEthernet_componentConfigure (poEntry, halEthernet_componentDisable_c, NULL)) ||
		(u8HalOpCode != halEthernet_componentNone_c && !halEthernet_componentConfigure (poEntry, u8HalOpCode, NULL)))
	{
		goto ieee8021BridgeBaseRowStatus_halUpdate_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeBaseRowStatus_halUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortTable_hierUpdate (
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (ieee8021QBridgePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port) == NULL &&
			ieee8021QBridgePortTable_createExt (poEntry->u32ComponentId, poEntry->u32Port) == NULL)
		{
			goto ieee8021BridgeBasePortTable_hierUpdate_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
	{
		register ieee8021QBridgePortEntry_t *poIeee8021QBridgePortEntry = NULL;
		
		if ((poIeee8021QBridgePortEntry = ieee8021QBridgePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port)) != NULL &&
			!ieee8021QBridgePortTable_removeExt (poIeee8021QBridgePortEntry))
		{
			goto ieee8021BridgeBasePortTable_hierUpdate_cleanup;
		}
		break;
	}
	}
	
	bRetCode = true;
	
ieee8021BridgeBasePortTable_hierUpdate_cleanup:
	
	return bRetCode;
}

bool
neIeee8021BridgeBasePortAdminFlags_update (
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t *pu8AdminFlags)
{
	register bool bRetCode = false;
	
	register uint8_t u8BitIndex = neIeee8021BridgeBasePortAdminFlags_bMin_c;
	
	do
	{
		uint8_t u8BitNew = xBitmap_getBitRev (pu8AdminFlags, u8BitIndex);
		uint8_t u8BitOld = xBitmap_getBitRev (poEntry->oNe.au8AdminFlags, u8BitIndex);
		
		if (u8BitOld == u8BitNew)
		{
			continue;
		}
		
		switch (u8BitIndex)
		{
		case neIeee8021BridgeBasePortAdminFlags_bCosMapping_c:
		{
			register ieee8021BridgeUserPriorityRegenEntry_t *poPriorityRegenEntry = ieee8021BridgeUserPriorityRegenTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port, 0);
			
			if (u8BitNew && poPriorityRegenEntry == NULL &&
				ieee8021BridgeUserPriorityRegenTable_createEntry (poEntry->u32ComponentId, poEntry->u32Port, 0) == NULL)
			{
				goto neIeee8021BridgeBasePortAdminFlags_update_cleanup;
			}
			else if (!u8BitNew && poPriorityRegenEntry != NULL)
			{
				ieee8021BridgeUserPriorityRegenTable_removeEntry (poPriorityRegenEntry);
			}
			break;
		}
		
		case neIeee8021BridgeBasePortAdminFlags_bTCMapping_c:
		{
			register ieee8021BridgeTrafficClassEntry_t *poTrafficClassEntry = ieee8021BridgeTrafficClassTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port, 0);
			
			if (u8BitNew && poTrafficClassEntry == NULL &&
				ieee8021BridgeTrafficClassTable_createEntry (poEntry->u32ComponentId, poEntry->u32Port, 0) == NULL)
			{
				goto neIeee8021BridgeBasePortAdminFlags_update_cleanup;
			}
			else if (!u8BitNew && poTrafficClassEntry != NULL)
			{
				ieee8021BridgeTrafficClassTable_removeEntry (poTrafficClassEntry);
			}
			break;
		}
		
		case neIeee8021BridgeBasePortAdminFlags_bPCPMapping_c:
		{
			register ieee8021BridgePortDecodingEntry_t *poPcpDecodingEntry =
				ieee8021BridgePortDecodingTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port, poEntry->oPriority.i32CodePointSelection, 0);
				
			if (u8BitNew && poPcpDecodingEntry == NULL &&
				ieee8021BridgePortDecodingTable_createEntry (poEntry->u32ComponentId, poEntry->u32Port, poEntry->oPriority.i32CodePointSelection, 0) == NULL)
			{
				goto neIeee8021BridgeBasePortAdminFlags_update_cleanup;
			}
			else if (!u8BitNew && poPcpDecodingEntry != NULL)
			{
				ieee8021BridgePortDecodingTable_removeEntry (poPcpDecodingEntry);
			}
			
			register ieee8021BridgePortEncodingEntry_t *poPcpEncodingEntry =
				ieee8021BridgePortEncodingTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port, poEntry->oPriority.i32CodePointSelection, 0, 0);
				
			if (u8BitNew && poPcpEncodingEntry == NULL &&
				ieee8021BridgePortEncodingTable_createEntry (poEntry->u32ComponentId, poEntry->u32Port, poEntry->oPriority.i32CodePointSelection, 0, 0) == NULL)
			{
				goto neIeee8021BridgeBasePortAdminFlags_update_cleanup;
			}
			else if (!u8BitNew && poPcpEncodingEntry != NULL)
			{
				ieee8021BridgePortEncodingTable_removeEntry (poPcpEncodingEntry);
			}
			break;
		}
		
		case neIeee8021BridgeBasePortAdminFlags_bServiceUni_c:
		case neIeee8021BridgeBasePortAdminFlags_bServiceEnni_c:
		case neIeee8021BridgeBasePortAdminFlags_bServiceVuni_c:
		case neIeee8021BridgeBasePortAdminFlags_bSpanningTree_c:
			break;
			
		default:
			break;
		}
	} while (++u8BitIndex < neIeee8021BridgeBasePortAdminFlags_bCount_c);
	
	/* TODO */
	
	bRetCode = true;
	
neIeee8021BridgeBasePortAdminFlags_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortDependentStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	/* TODO */
	
	bRetCode = true;
	
// ieee8021BridgeBasePortDependentStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
	case xRowStatus_notReady_c:
		if (!ieee8021BridgeBasePortIfIndex_handler (poComponent, poEntry))
		{
			goto ieee8021BridgeBasePortRowStatus_update_cleanup;
		}
		
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		if (poEntry->pOldEntry == NULL)
		{
			if ((poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
			{
				goto ieee8021BridgeBasePortRowStatus_update_cleanup;
			}
			memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		}
		
		if (u8RowStatus == xRowStatus_destroy_c)
		{
			poEntry->u32IfIndex = 0;
			if (!ieee8021BridgeBasePortIfIndex_handler (poComponent, poEntry))
			{
				goto ieee8021BridgeBasePortRowStatus_update_cleanup;
			}
			
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
	}
	
	
	if (u8RowStatus == xRowStatus_active_c && !ieee8021BridgeBasePortRowStatus_halUpdate (poComponent, poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c && !ieee8021BridgeBasePortDependentStatus_update (poComponent, poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	
	register ieee8021QBridgePortEntry_t *poIeee8021QBridgePortEntry = NULL;
	
	if ((poIeee8021QBridgePortEntry = ieee8021QBridgePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Port)) != NULL &&
		!ieee8021QBridgePortRowStatus_handler (poComponent, poIeee8021QBridgePortEntry, u8RowStatus))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	
	if (u8RowStatus != xRowStatus_active_c && !ieee8021BridgeBasePortDependentStatus_update (poComponent, poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus != xRowStatus_active_c && !ieee8021BridgeBasePortRowStatus_halUpdate (poComponent, poEntry, u8RowStatus))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	
	bRetCode = true;
	
ieee8021BridgeBasePortRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortRowStatus_halUpdate (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c ? halEthernet_componentPortAttach_c:
		u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c ? halEthernet_componentPortDetach_c: halEthernet_componentNone_c;
		
	if (u8HalOpCode != halEthernet_componentNone_c && !halEthernet_componentConfigure (poComponent, u8HalOpCode, poEntry))
	{
		goto ieee8021BridgeBasePortRowStatus_halUpdate_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeBasePortRowStatus_halUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeXPortRowStatus_halUpdate (
	ieee8021BridgeBaseEntry_t *poComponent,
	void *pvEntry, int32_t i32Type, uint8_t u8CurStatus, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && u8CurStatus != xRowStatus_active_c ? halEthernet_portEnable_c:
		u8RowStatus != xRowStatus_active_c && u8CurStatus == xRowStatus_active_c ? halEthernet_portDisable_c: halEthernet_portNone_c;
		
	if ((u8HalOpCode != halEthernet_portNone_c && !halEthernet_portConfigure (poComponent, u8HalOpCode, i32Type, pvEntry)) ||
		(u8RowStatus == xRowStatus_destroy_c && !halEthernet_portConfigure (poComponent, halEthernet_portDestroy_c, i32Type, pvEntry)))
	{
		goto ieee8021BridgeXPortRowStatus_halUpdate_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeXPortRowStatus_halUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeDot1dPortRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BasePortComponentId, poEntry->u32BasePort)) == NULL)
	{
		goto ieee8021BridgeDot1dPortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus != xRowStatus_active_c &&
		!ieee8021BridgeXPortRowStatus_halUpdate (poComponent, poEntry, ieee8021BridgeBasePortType_dBridgePort_c, poEntry->u8RowStatus, u8RowStatus))
	{
		goto ieee8021BridgeDot1dPortRowStatus_update_cleanup;
	}
	
	if (!ieee8021BridgeBasePortRowStatus_handler (poComponent, poIeee8021BridgeBasePortEntry, u8RowStatus))
	{
		goto ieee8021BridgeDot1dPortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c &&
		!ieee8021BridgeXPortRowStatus_halUpdate (poComponent, poEntry, ieee8021BridgeBasePortType_dBridgePort_c, poEntry->u8RowStatus, u8RowStatus))
	{
		goto ieee8021BridgeDot1dPortRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeDot1dPortRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeCVlanPortRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeCVlanPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Number)) == NULL)
	{
		goto ieee8021QBridgeCVlanPortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus != xRowStatus_active_c &&
		!ieee8021BridgeXPortRowStatus_halUpdate (poComponent, poEntry, ieee8021BridgeBasePortType_customerVlanPort_c, poEntry->u8RowStatus, u8RowStatus))
	{
		goto ieee8021QBridgeCVlanPortRowStatus_update_cleanup;
	}
	
	if (!ieee8021BridgeBasePortRowStatus_handler (poComponent, poIeee8021BridgeBasePortEntry, u8RowStatus))
	{
		goto ieee8021QBridgeCVlanPortRowStatus_update_cleanup;
	}
	
	if (u8RowStatus == xRowStatus_active_c &&
		!ieee8021BridgeXPortRowStatus_halUpdate (poComponent, poEntry, ieee8021BridgeBasePortType_customerVlanPort_c, poEntry->u8RowStatus, u8RowStatus))
	{
		goto ieee8021QBridgeCVlanPortRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeCVlanPortRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanCurrentTable_vlanUpdate (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	xSList_Head_t oIfList;
	
	if (poEntry->u8RowStatus != xRowStatus_active_c)
	{
		goto ieee8021QBridgeVlanCurrentTable_vlanUpdate_success;
	}
	
	xSList_headInit (&oIfList);
	
	register uint16_t u16PortIndex = 0;
	
	xBitmap_scanCmp (
		pu8EnabledPorts, pu8DisabledPorts, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 0, u16PortIndex)
	{
		register halEthernet_ifEntry_t *poIfEntry = NULL;
		register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
		
		if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32ComponentId, u16PortIndex + 1)) == NULL ||
			poIeee8021BridgeBasePortEntry->u8RowStatus != xRowStatus_active_c)
		{
			continue;
		}
		
		if ((poIfEntry = xBuffer_cAlloc (sizeof (*poIfEntry))) == NULL)
		{
			continue;
		}
		
		poIfEntry->u32IfIndex = poIeee8021BridgeBasePortEntry->u32IfIndex;
		xBitmap_getBitRev (pu8DisabledPorts, u16PortIndex) != 0 ? xBitmap_setBit (poIfEntry->au8Flags, halEthernet_if_bVlanDisable, 1): 0;
		xBitmap_getBitRev (pu8EnabledPorts, u16PortIndex) != 0 ? xBitmap_setBit (poIfEntry->au8Flags, halEthernet_if_bVlanEnable, 1): 0;
		xBitmap_getBitRev (pu8UntaggedPorts, u16PortIndex) != 0 ? xBitmap_setBit (poIfEntry->au8Flags, halEthernet_if_bVlanUntagged, 1): 0;
		xSList_push (&poIfEntry->oNode, &oIfList);
	}
	
	if (oIfList.u32NumNode != 0 && !halEthernet_vlanConfigure (poEntry, halEthernet_vlanOperState_c, &oIfList, NULL))
	{
		goto ieee8021QBridgeVlanCurrentTable_vlanUpdate_cleanup;
	}
	
ieee8021QBridgeVlanCurrentTable_vlanUpdate_success:
	
	bRetCode = true;
	
ieee8021QBridgeVlanCurrentTable_vlanUpdate_cleanup:
	{
		register xSList_Node_t *poCurrNode = NULL;
		register xSList_Node_t *poNextNode = NULL;
		
		xSList_scanTailSafe (poCurrNode, poNextNode, &oIfList)
		{
			register halEthernet_ifEntry_t *poIfEntry = xSList_entry (poCurrNode, halEthernet_ifEntry_t, oNode);
			
			xSList_nodeRem (&poIfEntry->oNode, &oIfList);
			xBuffer_free (poIfEntry);
		}
	}
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanCurrentRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register bool bNewFdbSkip = false;
	register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
	
	if (poEntry->u32FdbId != 0 && (poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, poEntry->u32FdbId)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_cleanup;
	}
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		goto ieee8021QBridgeVlanCurrentRowStatus_update_updateLocal;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		bNewFdbSkip = true;
		break;
	}
	
	
ieee8021QBridgeVlanCurrentRowStatus_update_updateLocal:
	
	if (u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c &&
		!halEthernet_vlanConfigure (poEntry, halEthernet_vlanDisable_c, NULL, poIeee8021QBridgeFdbEntry))
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_cleanup;
	}
	
	
	if (poEntry->u32FdbId == 0)
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_newFdb;
	}
	
	poEntry->u32FdbId = 0;
	poIeee8021QBridgeFdbEntry->u32NumVlans--;
	
ieee8021QBridgeVlanCurrentRowStatus_update_newFdb:
	
	if (bNewFdbSkip)
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_fdbDone;
	}
	
	register uint32_t u32FdbId = 0;
	register ieee8021QBridgeLearningConstraintsEntry_t *poIeee8021QBridgeLearningConstraintsEntry = NULL;
	
	if ((poIeee8021QBridgeLearningConstraintsEntry = ieee8021QBridgeLearningConstraintsTable_getNextIndex (poEntry->u32ComponentId, poEntry->u32Index, 0)) != NULL &&
		poEntry->u32ComponentId == poIeee8021QBridgeLearningConstraintsEntry->u32ComponentId && poEntry->u32Index == poIeee8021QBridgeLearningConstraintsEntry->u32Vlan)
	{
		u32FdbId = poIeee8021QBridgeLearningConstraintsEntry->i32Set;
	}
	
	register ieee8021QBridgeLearningConstraintDefaultsEntry_t *poIeee8021QBridgeLearningConstraintDefaultsEntry = NULL;
	
	if (u32FdbId == 0 && (poIeee8021QBridgeLearningConstraintDefaultsEntry = ieee8021QBridgeLearningConstraintDefaultsTable_getByIndex (poEntry->u32ComponentId)) != NULL)
	{
		u32FdbId = poIeee8021QBridgeLearningConstraintDefaultsEntry->i32Set;
	}
	
	if (u32FdbId == 0 || (poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, u32FdbId)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_cleanup;
	}
	
	poEntry->u32FdbId = u32FdbId;
	poIeee8021QBridgeFdbEntry->u32NumVlans++;
	
ieee8021QBridgeVlanCurrentRowStatus_update_fdbDone:
	
	
	if (u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c &&
		!halEthernet_vlanConfigure (poEntry, halEthernet_vlanEnable_c, NULL, poIeee8021QBridgeFdbEntry))
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_update_cleanup;
	}
	
	
	bRetCode = true;
	
ieee8021QBridgeVlanCurrentRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticTable_vHandler (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	bool bEnable, bool bTagged, uint32_t u32Count, uint32_t u32Port, ...)
{
	register bool bRetCode = false;
	va_list oArgs;
	uint8_t *pu8EnabledPorts = NULL;
	uint8_t *pu8DisabledPorts = NULL;
	uint8_t *pu8UntaggedPorts = NULL;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021QBridgeVlanStaticEntry_t *poEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL ||
		(poEntry = ieee8021QBridgeVlanStaticTable_getByIndex (u32ComponentId, u32VlanIndex)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_vHandler_cleanup;
	}
	
	if ((pu8EnabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8DisabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8UntaggedPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_vHandler_cleanup;
	}
	
	va_start (oArgs, u32Port);
	
	do
	{
		if (xBitmap_getBitRev (poEntry->au8ForbiddenEgressPorts, u32Port - 1) == xBitmap_index_invalid_c)
		{
			bEnable ? xBitmap_setBitRev (pu8EnabledPorts, u32Port, 1): xBitmap_setBitRev (pu8DisabledPorts, u32Port, 1);
			xBitmap_setBitRev (pu8UntaggedPorts, u32Port, bEnable && !bTagged);
		}
		
		u32Count--;
		if (u32Count > 0)
		{
			u32Port = va_arg (oArgs, uint32_t);
		}
	}
	while (u32Count > 0);
	
	va_end (oArgs);
	
	if (!ieee8021QBridgeVlanStaticTable_vlanUpdater (poIeee8021BridgeBaseEntry, poEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
	{
		goto ieee8021QBridgeVlanStaticTable_vHandler_cleanup;
	}
	
	xBitmap_or (poEntry->au8EgressPorts, pu8EnabledPorts, poEntry->au8EgressPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_sub (poEntry->au8EgressPorts, poEntry->au8EgressPorts, pu8DisabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_or (poEntry->au8UntaggedPorts, poEntry->au8UntaggedPorts, pu8UntaggedPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_vHandler_cleanup:
	
	if (pu8EnabledPorts != NULL)
	{
		xBuffer_free (pu8EnabledPorts);
		xBuffer_free (pu8DisabledPorts);
		xBuffer_free (pu8UntaggedPorts);
	}
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (poComponent->i32ComponentType)
	{
	case ieee8021BridgeBaseComponentType_iComponent_c:
	case ieee8021BridgeBaseComponentType_bComponent_c:
	case ieee8021BridgeBaseComponentType_sVlanComponent_c:
		if (!ieee8021PbVlanStaticRowStatus_handler (poComponent, poEntry, u8RowStatus))
		{
			goto ieee8021QBridgeVlanStaticRowStatus_update_cleanup;
		}
		break;
	}
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticTable_vlanUpdate (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	
	switch (poComponent->i32ComponentType)
	{
	case ieee8021BridgeBaseComponentType_iComponent_c:
	case ieee8021BridgeBaseComponentType_bComponent_c:
	case ieee8021BridgeBaseComponentType_sVlanComponent_c:
		if (!ieee8021PbVlanStaticTable_vlanHandler (poComponent, poEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
		{
			goto ieee8021QBridgeVlanStaticTable_vlanUpdate_cleanup;
		}
		break;
	}
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_vlanUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgePortRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	if (ieee8021QBridgePortRowStatus_halUpdate (poComponent, poEntry, u8RowStatus))
	{
		goto ieee8021QBridgePortRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgePortRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgePortRowStatus_halUpdate (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c ? halEthernet_portQEnable_c:
		u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c ? halEthernet_portQDisable_c: halEthernet_portNone_c;
		
	if ((u8HalOpCode != halEthernet_portNone_c && !halEthernet_portConfigure (poComponent, u8HalOpCode, ieee8021BridgeBasePortType_none_c, poEntry)) ||
		(u8RowStatus == xRowStatus_destroy_c && !halEthernet_portConfigure (poComponent, halEthernet_portQDestroy_c, ieee8021BridgeBasePortType_none_c, poEntry)))
	{
		goto ieee8021QBridgePortRowStatus_halUpdate_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgePortRowStatus_halUpdate_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintsType_update (
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry, int32_t i32Type)
{
	register bool bRetCode = false;
	
	/* TODO */
	
	bRetCode = true;
	
// ieee8021QBridgeLearningConstraintsType_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintsStatus_update (
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	if (u8RowStatus == xRowStatus_active_c && !ieee8021QBridgeLearningConstraintsType_handler (poEntry, poEntry->i32Type, true))
	{
		goto ieee8021QBridgeLearningConstraintsStatus_update_cleanup;
	}
	
	/* TODO */
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintsStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeIngressVidXRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeIngressVidXEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c ? halEthernet_if_bVlanMapIngressEnable:
		u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c ? halEthernet_if_bVlanMapIngressDisable: halEthernet_if_bVlanNone;
		
	if ((u8HalOpCode != halEthernet_portNone_c && !halEthernet_ifVlanConfigure (poComponent, u8HalOpCode, poEntry)) ||
		(u8RowStatus == xRowStatus_destroy_c && !halEthernet_ifVlanConfigure (poComponent, halEthernet_if_bVlanMapIngressDestroy, poEntry)))
	{
		goto ieee8021QBridgeIngressVidXRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeIngressVidXRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeEgressVidXRowStatus_update (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeEgressVidXEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c ? halEthernet_if_bVlanMapEgressEnable:
		u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c ? halEthernet_if_bVlanMapEgressDisable: halEthernet_if_bVlanNone;
		
	if ((u8HalOpCode != halEthernet_portNone_c && !halEthernet_ifVlanConfigure (poComponent, u8HalOpCode, poEntry)) ||
		(u8RowStatus == xRowStatus_destroy_c && !halEthernet_ifVlanConfigure (poComponent, halEthernet_if_bVlanMapEgressDestroy, poEntry)))
	{
		goto ieee8021QBridgeEgressVidXRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeEgressVidXRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __ETHERNET_UTILS_C__
