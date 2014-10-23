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

#ifndef __HAL_ETHERNET_H__
#	define __HAL_ETHERNET_H__

#	ifdef __cplusplus
extern "C" {
#	endif


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
	
	halEthernet_portAdminState_c,
	halEthernet_portOperState_c,
};

extern bool
	halEthernet_componentConfigure ();
extern bool
	halEthernet_portConfigure ();


#	ifdef __cplusplus
}
#	endif

#endif	// __HAL_ETHERNET_H__
