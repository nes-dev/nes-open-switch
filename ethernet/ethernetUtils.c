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

#ifndef __ETHERNETUTILS_C__
#	define __ETHERNETUTILS_C__



#include "ieee8021BridgeMib.h"

#include "lib/lib.h"

#include <stdbool.h>
#include <stdint.h>


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
ieee8021BridgeDot1dPortRowStatus_update (
	ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus)
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
	
//ieee8021BridgeDot1dPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __ETHERNETUTILS_C__
