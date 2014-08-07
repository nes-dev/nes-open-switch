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

#ifndef __LAG_UTILS_C__
#	define __LAG_UTILS_C__



#include "lagUtils.h"
#include "if/ifUtils.h"

#include <stdbool.h>
#include <stdint.h>


static neIfTypeEnableHandler_t lag_aggEnableModify;


bool lagUtilsInit (void)
{
	register bool bRetCode = false;
	neIfTypeEntry_t *poNeIfTypeEntry = NULL;
	
	if ((poNeIfTypeEntry = neIfTypeTable_createExt (ifType_ieee8023adLag_c)) == NULL)
	{
		goto lagUtilsInit_cleanup;
	}
	
	poNeIfTypeEntry->pfEnableHandler = lag_aggEnableModify;
	
	bRetCode = true;
	
lagUtilsInit_cleanup:
	
	return bRetCode;
}

bool
lag_aggEnableModify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}


bool
neAggRowStatus_update (
	neAggEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	return false;
}

bool
neAggPortRowStatus_update (
	neAggPortEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	return false;
}



#endif	// __LAG_UTILS_C__
