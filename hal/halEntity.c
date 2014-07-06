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

#ifndef __HAL_ENTITY_C__
#	define __HAL_ENTITY_C__


#include "hal_defines.h"
#include "system/entityMIB.h"

#include <stdbool.h>
#include <stdint.h>


bool
halEntityDetect ()
{
	uint32_t u32Index = 0;
	uint32_t u32ContainedIn = 0;
	int32_t i32Class = 0;
	uint8_t au8SerialNum[32] = {0};
	size_t u16SerialNum_len = 0;
	uint8_t u8RowStatus = 0;
	
	/* TODO */
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (!entPhysicalTable_createEntity (u32Index, i32Class, u32ContainedIn, au8SerialNum, u16SerialNum_len))
		{
			goto halEntityDetect_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
		if (!entPhysicalTable_removeEntity (u32Index))
		{
			goto halEntityDetect_cleanup;
		}
		break;
	}
	
	return true;
	
	
halEntityDetect_cleanup:
	
	return false;
}


#endif	// __HAL_ENTITY_C__
