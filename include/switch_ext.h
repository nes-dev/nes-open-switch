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

#ifndef __SWITCH_EXT_H__
#	define __SWITCH_EXT_H__

#	ifdef __cplusplus
extern "C" {
#	endif


#include <stdint.h>

#define APP_NAME "SWITCH"

#define PKT_IP_ENC_USED 4
#define PKT_L2_ENC_USED
#undef PKT_L2_VLAN_ENC_USED

enum
{
	ModuleId_snmp_c				= 1,
	ModuleId_if_c,
	ModuleId_system_c,
	ModuleId_hal_c,
	ModuleId_ethernet_c,
	ModuleId_lag_c,
	ModuleId_bridge_c,
	ModuleId_cfm_c,
	ModuleId_isis_c,
	ModuleId_stp_c,
	ModuleId_spb_c,
	ModuleId_inet_c,
	ModuleId_tcpUdp_c,
};

typedef void *(ModuleRoutine_t) (void *);

typedef struct ModuleInfo_t
{
	uint32_t			u32ModuleId;
	ModuleRoutine_t	   *poStart;
} ModuleInfo_t;

#ifdef __SWITCH_MAIN_C__

#include "snmp_ext.h"
#include "if_ext.h"
#include "system_ext.h"
#include "hal_ext.h"
#include "ethernet_ext.h"
#include "lag_ext.h"
#include "bridge_ext.h"
#include "cfm_ext.h"
#include "isis_ext.h"
#include "stp_ext.h"
#include "spb_ext.h"
#include "inet_ext.h"
#include "tcpUdp_ext.h"

static ModuleInfo_t aoModuleList[] =
{
	{ModuleId_snmp_c,				&snmp_main},
	{ModuleId_if_c,					&if_main},
	{ModuleId_system_c,				&system_main},
	{ModuleId_hal_c,				&hal_main},
	{ModuleId_ethernet_c,			&ethernet_main},
	{ModuleId_lag_c,				&lag_main},
	{ModuleId_bridge_c,				&bridge_main},
	{ModuleId_cfm_c,				&cfm_main},
	{ModuleId_isis_c,				&isis_main},
	{ModuleId_stp_c,				&stp_main},
	{ModuleId_spb_c,				&spb_main},
	{ModuleId_inet_c,				&inet_main},
	{ModuleId_tcpUdp_c,				&tcpUdp_main},
};
#endif	// __SWITCH_MAIN_C__


#	ifdef __cplusplus
}
#	endif

#endif	// __SWITCH_EXT_H__
