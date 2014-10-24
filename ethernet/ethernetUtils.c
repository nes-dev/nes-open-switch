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

#include <stdbool.h>
#include <stdint.h>


static neIfTypeEnableHandler_t ethernet_portEnableModify;
static neIfTypeEnableHandler_t ethernet_bridgeEnableModify;
static neIfTypeEnableHandler_t ethernet_ilanEnableModify;


bool ethernetUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	ifTable_wrLock ();
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ethernetCsmacd_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ethernet_portEnableModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_l2vlan_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_bridge_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ethernet_bridgeEnableModify;
	
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ilan_c)) == NULL)
	{
		goto ethernetUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = ethernet_ilanEnableModify;
	
	bRetCode = true;
	
ethernetUtilsInit_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}


bool
ethernet_portEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	register bool bRetCode = false;
	
	if (!halEthernet_portConfigure (poIfEntry, halEthernet_portAdminState_c))
	{
		goto ethernet_portEnableModify_cleanup;
	}
	
	bRetCode = true;
	
ethernet_portEnableModify_cleanup:
	
	return bRetCode;
}


bool
ethernet_bridgeEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}

bool
ethernet_ilanEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}


bool
ieee8021BridgeBaseRowStatus_update (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	register uint32_t u32Port = 0;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
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
		
		default:
			if (!ieee8021BridgeBasePortRowStatus_handler (poEntry, poIeee8021BridgeBasePortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto ieee8021BridgeBaseRowStatus_update_cleanup;
			}
			break;
		}
	}
	
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_createAndWait_c ? halEthernet_componentCreate_c:
		u8RowStatus == xRowStatus_active_c ? halEthernet_componentEnable_c:
		u8RowStatus == xRowStatus_notReady_c ? halEthernet_componentDisable_c:
		u8RowStatus == xRowStatus_notInService_c ? halEthernet_componentDisable_c:
		u8RowStatus == xRowStatus_destroy_c ? halEthernet_componentDestroy_c: halEthernet_componentNone_c;
		
	if ((u8RowStatus == xRowStatus_destroy_c && poEntry->u8RowStatus == xRowStatus_active_c &&
		 !halEthernet_componentConfigure (poEntry, halEthernet_componentDisable_c, NULL)) ||
		!halEthernet_componentConfigure (poEntry, u8HalOpCode, NULL))
	{
		goto ieee8021BridgeBaseRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeBaseRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortRowStatus_update (
	ieee8021BridgeBaseEntry_t *pComponent,
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	register uint8_t u8HalOpCode =
		u8RowStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_active_c ? halEthernet_componentPortAttach_c:
		u8RowStatus != xRowStatus_active_c && poEntry->u8RowStatus == xRowStatus_active_c ? halEthernet_componentPortDetach_c: halEthernet_componentNone_c;
		
	if (u8HalOpCode != halEthernet_componentNone_c &&
		!halEthernet_componentConfigure (pComponent, u8HalOpCode, poEntry))
	{
		goto ieee8021BridgeBasePortRowStatus_update_cleanup;
	}
	
	bRetCode = true;
	
ieee8021BridgeBasePortRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeDot1dPortRowStatus_update (
	ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	bRetCode = true;
	
// ieee8021BridgeDot1dPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __ETHERNET_UTILS_C__
