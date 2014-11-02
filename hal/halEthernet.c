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

#ifndef __HAL_ETHERNET_C__
#	define __HAL_ETHERNET_C__


#include "halEthernet.h"
#include "if/ifUtils.h"

#include <stdbool.h>
#include <stdint.h>


/*static*/ bool
	halEthernet_ifNotify ();


bool
halEthernet_componentConfigure ()
{
	/* TODO */
	return false;
}

bool
halEthernet_portConfigure ()
{
	/* TODO */
	return false;
}

bool
halEthernet_vlanConfigure ()
{
	/* TODO */
	return false;
}

bool
halEthernet_ifNotify ()
{
	uint32_t u32IfIndex = 0;
	int32_t i32OperStatus = 0;
	
	/* TODO */
	
	if (!neIfStatus_modify (u32IfIndex, i32OperStatus, false, false))
	{
		return false;
	}
	
	return true;
}


#endif	// __HAL_ETHERNET_C__
