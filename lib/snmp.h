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

#ifndef __SNMP_H__
#	define __SNMP_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/lib.h"

#include <stdint.h>


enum
{
	/* enums for column xAdminStatus */
	xAdminStatus_up_c = 1,
	xAdminStatus_down_c = 2,
	xAdminStatus_testing_c = 3,
	
	xAdminStatus_mask_c = 0x07,
	xAdminStatus_fromChild_c = 0x08,
	xAdminStatus_fromParent_c = 0x10,
	
	/* enums for column xOperStatus */
	xOperStatus_up_c = 1,
	xOperStatus_down_c = 2,
	xOperStatus_testing_c = 3,
	xOperStatus_unknown_c = 4,
	xOperStatus_dormant_c = 5,
	xOperStatus_notPresent_c = 6,
	xOperStatus_lowerLayerDown_c = 7,
	
	xOperStatus_mask_c = 0x07,
	xOperStatus_fromChild_c = 0x08,
	xOperStatus_fromParent_c = 0x10,
	
	/* enums for column xRowStatus */
	xRowStatus_active_c = 1,
	xRowStatus_notInService_c = 2,
	xRowStatus_notReady_c = 3,
	xRowStatus_createAndGo_c = 4,
	xRowStatus_createAndWait_c = 5,
	xRowStatus_destroy_c = 6,
	
	xRowStatus_mask_c = 0x07,
	xRowStatus_fromChild_c = 0x08,
	xRowStatus_fromParent_c = 0x10,
	
	/* enums for column xStorageType */
	xStorageType_other_c = 1,
	xStorageType_volatile_c = 2,
	xStorageType_nonVolatile_c = 3,
	xStorageType_permanent_c = 4,
	xStorageType_readOnly_c = 5,
};

typedef unsigned long xOid_t;

typedef struct xObjectId_t
{
	void	    *pData;
	uint16_t	u16Len;
} xObjectId_t;

typedef struct xOctetString_t
{
	void	    *pData;
	uint16_t	u16Len;
} xOctetString_t;


inline int
xOidCmp (xOid_t *pOidA, xOid_t *pOidB, int iALen, int iBLen)
{
	int iResVal = 1;
	
	if (*((char*) &iResVal) == 0)
	{
		iResVal = xBinCmp (pOidA, pOidB, iALen * sizeof (*pOidA), iBLen * sizeof (*pOidB));
	}
	else
	{
		iResVal =
			iALen < iBLen ? -1:
			iALen > iBLen ? 1: 0;
			
		for (int iIdx = 0; iResVal == 0 && iIdx < iALen && iIdx < iBLen; iIdx++)
		{
			iResVal = pOidA[iIdx] - pOidB[iIdx];
		}
	}
	
	return iResVal;
}



#	ifdef __cplusplus
}
#	endif

#endif	// __SNMP_H__
