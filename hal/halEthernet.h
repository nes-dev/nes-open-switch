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

#ifndef __HAL_ETHERNET_H__
#	define __HAL_ETHERNET_H__

#	ifdef __cplusplus
extern "C" {
#	endif


#include "lib/list.h"

#include <stdbool.h>
#include <stdint.h>


enum
{
	halEthernet_componentNone_c,
	halEthernet_componentCreate_c,
	halEthernet_componentEnable_c,
	halEthernet_componentPortAttach_c,
	halEthernet_componentPortDetach_c,
	halEthernet_componentDisable_c,
	halEthernet_componentDestroy_c,
	
	halEthernet_portNone_c,
	halEthernet_portEnable_c,
	halEthernet_portDisable_c,
	halEthernet_portDestroy_c,
	halEthernet_portQEnable_c,
	halEthernet_portQDisable_c,
	halEthernet_portQDestroy_c,
	
	halEthernet_ifAdminState_c,
	halEthernet_ifOperState_c,
	
	halEthernet_fdbOperState_c,
	
	halEthernet_vlanNone_c,
	halEthernet_vlanEnable_c,
	halEthernet_vlanOperState_c,
	halEthernet_vlanDisable_c,
	
	halEthernet_sidNone_c,
	halEthernet_sidEnable_c,
	halEthernet_sidDisable_c,
	
	halEthernet_if_bVlanNone,
	halEthernet_if_bVlanDisable,
	halEthernet_if_bVlanEnable,
	halEthernet_if_bVlanUntagged,
	
	halEthernet_if_bVlanMapIngressEnable,
	halEthernet_if_bVlanMapIngressDisable,
	halEthernet_if_bVlanMapIngressDestroy,
	halEthernet_if_bVlanMapEgressEnable,
	halEthernet_if_bVlanMapEgressDisable,
	halEthernet_if_bVlanMapEgressDestroy,
	
	halEthernet_if_bFdbNone_c,
	halEthernet_if_bFdbLearn_c,
	halEthernet_if_bFdbForward_c,
	halEthernet_if_bFdbDisable_c,
};

typedef struct halEthernet_ifEntry_t
{
	uint32_t u32IfIndex;
	
	uint8_t au8Flags[1];
	
	xSList_Node_t oNode;
} halEthernet_ifEntry_t;

extern bool
	halEthernet_componentConfigure ();
extern bool
	halEthernet_portConfigure ();
extern bool
	halEthernet_ifConfigure ();
extern bool
	halEthernet_ifFdbConfigure ();
extern bool
	halEthernet_vlanConfigure ();
extern bool
	halEthernet_ifVlanConfigure ();
extern bool
	halEthernet_cbpSidConfigure ();


#	ifdef __cplusplus
}
#	endif

#endif	// __HAL_ETHERNET_H__
