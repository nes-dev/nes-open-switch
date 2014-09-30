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

#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>


bool
halEntityDetect ()
{
	bool bRetCode = false;
	entPhysicalEntry_t *poEntry = NULL;
	uint32_t u32ChassisIndex = 123;
	uint32_t u32PortIndex = 234;
	uint8_t u8RowStatus = 0;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		goto halEntityDetect_cleanup;
	}
	
	/* TODO */
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		*poEntry = (entPhysicalEntry_t)
		{
			.u32ContainedIn = 0,
			.i32Class = entPhysicalClass_chassis_c,
			.i32ParentRelPos = 0,
			.au8SerialNum = "ABCDKHG",
			.u16SerialNum_len = 7,
		};
		
		if (!entPhysicalTable_createEntity (u32ChassisIndex, poEntry))
		{
			goto halEntityDetect_cleanup;
		}
		
		*poEntry = (entPhysicalEntry_t)
		{
			.u32ContainedIn = u32ChassisIndex,
			.i32Class = entPhysicalClass_port_c,
			.i32ParentRelPos = 5,
			.au8SerialNum = "HJHTIBGP",
			.u16SerialNum_len = 8,
		};
		
		if (!entPhysicalTable_createEntity (u32PortIndex, poEntry))
		{
			goto halEntityDetect_cleanup;
		}
		break;
		
	case xRowStatus_destroy_c:
		if (!entPhysicalTable_removeEntity (u32PortIndex))
		{
			goto halEntityDetect_cleanup;
		}
		
		if (!entPhysicalTable_removeEntity (u32ChassisIndex))
		{
			goto halEntityDetect_cleanup;
		}
		break;
	}
	
	bRetCode = true;
	
halEntityDetect_cleanup:
	
	if (poEntry != NULL)
	{
		xBuffer_free (poEntry);
	}
	return bRetCode;
}


#endif	// __HAL_ENTITY_C__
