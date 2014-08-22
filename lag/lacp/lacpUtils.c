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
#include "lacpProtoConsts.h"
#include "lacpProtoObjects.h"
#include "lag/lagMIB.h"
#include "if/ifMIB.h"

#include "lib/bitmap.h"
#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>


static bool
	dot3adAggPortLacp_lacpPduTx (dot3adAggPortData_t *poEntry);
static bool
	dot3adAggPortLacp_rxInit (dot3adAggPortData_t *poEntry);


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

bool
dot3adAggPortLacp_lacpPduTx (dot3adAggPortData_t *poEntry)
{
	register bool bRetCode = false;
	register LacpPdu_Lacp_t *poPdu = NULL;
	register void *pvBuffer = NULL;
	
	if ((poPdu = xBuffer_cAlloc (sizeof (*poPdu))) == NULL)
	{
		goto dot3adAggPortLacp_lacpPduTx_cleanup;
	}
	if ((pvBuffer = xBuffer_cAlloc (LacpPdu_Lacp_size_c)) == NULL)
	{
		goto dot3adAggPortLacp_lacpPduTx_cleanup;
	}
	
	register void *pvBufferOffset = pvBuffer;
	
	poPdu->oHeader.u8Type = IeeeSlowProtocolsType_lacp_c;
	poPdu->oHeader.u8Version = Lacp_Version1_c;
	LacpPduHeader_serialize (pvBufferOffset, &poPdu->oActor);
	pvBufferOffset += LacpPduHeader_size_c;
	
	poPdu->oActor.oHeader.u8Type = LacpTlv_Actor_c;
	poPdu->oActor.oHeader.u8Length = LacpTlv_Actor_size_c;
	poPdu->oActor.u16SystemPriority = poEntry->oPort.i32ActorSystemPriority;
	memcpy (poPdu->oActor.oSystemAddress, poEntry->oPort.au8ActorSystemID, sizeof (poPdu->oActor.oSystemAddress));
	poPdu->oActor.u16Key = poEntry->oPort.i32ActorOperKey;
	poPdu->oActor.u16PortPriority = poEntry->oPort.i32ActorPortPriority;
	poPdu->oActor.u16PortNumber = poEntry->oPort.i32ActorPort;
	xBitmap_copyFromRev (poPdu->oActor.au8State, poEntry->oPort.au8ActorOperState, dot3adAggPortState_bitMin, dot3adAggPortState_bitMax_c);
	LacpTlv_Actor_serialize (pvBufferOffset, &poPdu->oActor);
	pvBufferOffset += LacpTlv_Actor_size_c;
	
	poPdu->oPartner.oHeader.u8Type = LacpTlv_Partner_c;
	poPdu->oPartner.oHeader.u8Length = LacpTlv_Partner_size_c;
	poPdu->oPartner.u16SystemPriority = poEntry->oPort.i32PartnerOperSystemPriority;
	memcpy (poPdu->oPartner.oSystemAddress, poEntry->oPort.au8PartnerOperSystemID, sizeof (poPdu->oPartner.oSystemAddress));
	poPdu->oPartner.u16Key = poEntry->oPort.i32PartnerOperKey;
	poPdu->oPartner.u16PortPriority = poEntry->oPort.i32PartnerOperPortPriority;
	poPdu->oPartner.u16PortNumber = poEntry->oPort.i32PartnerOperPort;
	xBitmap_copyFromRev (poPdu->oPartner.au8State, poEntry->oPort.au8PartnerOperState, dot3adAggPortState_bitMin, dot3adAggPortState_bitMax_c);
	LacpTlv_Partner_serialize (pvBufferOffset, &poPdu->oPartner);
	pvBufferOffset += LacpTlv_Partner_size_c;
	
	poPdu->oCollector.oHeader.u8Type = LacpTlv_Collector_c;
	poPdu->oCollector.oHeader.u8Length = LacpTlv_Collector_size_c;
	poPdu->oCollector.u16MaxDelay = poEntry->i32CollectorMaxDelay;
	LacpTlv_Collector_serialize (pvBufferOffset, &poPdu->oCollector);
	pvBufferOffset += LacpTlv_Collector_size_c;
	
	poPdu->oTerminator.oHeader.u8Type = LacpTlv_Terminator_c;
	poPdu->oTerminator.oHeader.u8Length = LacpTlv_Terminator_size_c;
	LacpTlv_Terminator_serialize (pvBufferOffset, &poPdu->oTerminator);
	pvBufferOffset += LacpTlv_Terminator_size_c;
	
	pvBufferOffset += LacpPduTrailer_Lacp_size_c;
	
// 	if (!ethernet_portTx (pvBuffer, poEntry->u32Index))
// 	{
// 		goto dot3adAggPortLacp_lacpPduTx_cleanup;
// 	}
	pvBuffer = NULL;
	
	bRetCode = true;
	
dot3adAggPortLacp_lacpPduTx_cleanup:
	
	if (poPdu != NULL)
	{
		xBuffer_free (poPdu);
	}
	return bRetCode;
}

bool
dot3adAggPortLacp_rxInit (dot3adAggPortData_t *poEntry)
{
	xBitmap_setBitRev (poEntry->oPort.au8ActorOperState, dot3adAggPortState_expired_c, 1);
	xBitmap_setBitRev (poEntry->oPort.au8PartnerOperState, dot3adAggPortState_synchronization_c, 0);
	xBitmap_setBitRev (poEntry->oPort.au8PartnerOperState, dot3adAggPortState_lacpTimeout_c, 0);
	
	/* TODO */
	
	return true;
}

void
dot3adAggPortLacp_processPduRx (lacpMessage_Pdu_t *pMessage)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if (pMessage == NULL ||
		(pMessage->u8Type != IeeeSlowProtocolsType_lacp_c && pMessage->u8Type != IeeeSlowProtocolsType_marker_c))
	{
		goto dot3adAggPortLacp_processPduRx_cleanup;
	}
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (pMessage->u32IfIndex)) == NULL)
	{
		goto dot3adAggPortLacp_processPduRx_cleanup;
	}
	
	if (poDot3adAggPortData->u8OperStatus != xOperStatus_up_c ||
		!poDot3adAggPortData->bFullDuplex)
	{
		goto dot3adAggPortLacp_processPduRx_cleanup;
	}
	
	
	switch (pMessage->u8Type)
	{
	default:
		poDot3adAggPortData->oStats.u32UnknownRx++;
		goto dot3adAggPortLacp_processPduRx_cleanup;
		
	case IeeeSlowProtocolsType_lacp_c:
		/* TODO */
		poDot3adAggPortData->oStats.u32LACPDUsRx++;
		break;
		
	case IeeeSlowProtocolsType_marker_c:
		/* TODO */
		poDot3adAggPortData->oStats.u32MarkerPDUsRx++;
// 		poDot3adAggPortData->oStats.u32MarkerResponsePDUsRx++;
		break;
	}
	
dot3adAggPortLacp_processPduRx_cleanup:
	
	if (pMessage->pvData != NULL)
	{
		free (pMessage->pvData);
	}
	return;
}


#endif	// __LACP_UTILS_C__
