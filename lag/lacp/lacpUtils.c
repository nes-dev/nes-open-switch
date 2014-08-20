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

#ifndef __LACP_UTILS_C__
#	define __LACP_UTILS_C__



#include "lacp_ext.h"
#include "lacpUtils.h"
#include "lag/lagMIB.h"
#include "if/ifMIB.h"

#include "lib/bitmap.h"

#include <stdbool.h>
#include <stdint.h>



bool
dot3adAggLacpStatus_update (
	dot3adAggData_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		/* TODO */
		break;
	}
	
	bRetCode = true;
	
// neAggRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
dot3adAggPortLacpStatus_update (
	dot3adAggPortData_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		
		if (xBitmap_getBit (poEntry->oNe.au8Flags, neAggPortFlags_lacp_c))
		{
			if (!ifRcvAddressTable_createRegister (poEntry->u32Index, poEntry->oPortX.au8ProtocolDA, poEntry->oPortX.u16ProtocolDA_len))
			{
				goto dot3adAggPortLacpStatus_update_cleanup;
			}
			
			/* TODO */
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		if (xBitmap_getBit (poEntry->oNe.au8Flags, neAggPortFlags_lacp_c))
		{
			/* TODO */
			
			if (!ifRcvAddressTable_removeRegister (poEntry->u32Index, poEntry->oPortX.au8ProtocolDA, poEntry->oPortX.u16ProtocolDA_len))
			{
				goto dot3adAggPortLacpStatus_update_cleanup;
			}
		}
		
		/* TODO */
		break;
	}
	
	bRetCode = true;
	
dot3adAggPortLacpStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __LACP_UTILS_C__
