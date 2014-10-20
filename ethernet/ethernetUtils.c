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
	ieee8021BridgePhyPortInfo_t oEthernetPhyPortInfo = ieee8021BridgePhyPortInfo_initInline (ieee8021BridgePhyPortInfo_ifToPortEntry_c);
	
	ieee8021BridgePhyPortInfo_rdLock ();
	
	if (!ieee8021BridgePhyPortInfo_getByIfIndex (poIfEntry->u32Index, &oEthernetPhyPortInfo))
	{
		goto ethernet_portEnableModify_cleanup;
	}
	oEthernetPhyPortInfo.poIfToPortEntry->u32IndexComponentId = 0;
	oEthernetPhyPortInfo.poIfToPortEntry->u32IndexPort = 0;
	
	if (oEthernetPhyPortInfo.poIfToPortEntry->u32IndexComponentId != 0 &&
		oEthernetPhyPortInfo.poIfToPortEntry->u32IndexPort != 0)
	{
		if (i32AdminStatus == xAdminStatus_up_c &&
			!halEthernet_ifConfig ())
		{
			goto ethernet_portEnableModify_cleanup;
		}
		
		if (!halEthernet_ifEnable (poIfEntry->u32Index, i32AdminStatus))
		{
			goto ethernet_portEnableModify_cleanup;
		}
	}
	
	bRetCode = true;
	
ethernet_portEnableModify_cleanup:
	
	ieee8021BridgePhyPortInfo_unLock ();
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
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		break;
		
	case xRowStatus_notInService_c:
		break;
		
	case xRowStatus_destroy_c:
		/* TODO */
		break;
	}
	
	bRetCode = true;
	
// ieee8021BridgeBaseRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ieee8021BridgeBasePortRowStatus_update (
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	bRetCode = true;
	
//ieee8021BridgeBasePortRowStatus_update_cleanup:
	
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
