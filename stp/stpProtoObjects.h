/*
 *  Copyright (c) 2008-2015
 *      NES Repo <nes.repo@gmail.com>
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

#ifndef __STP_PROTO_OBJECTS_H__
#	define __STP_PROTO_OBJECTS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/buffer.h"

#include <stdint.h>


/**
 *	PDU Definitions
 */
/**
 *	STP PDU
 */
enum
{
	StpPdu_StpBpdu_size_c			= 35,
	StpPdu_StpTcn_size_c			= 35,
};

typedef struct StpPdu_StpBpdu_t
{
	uint16_t		u16ProtocolIdentifier;
	uint8_t			u8ProtocolVersion;
	uint8_t			u8BpduType;
	uint8_t			u8CistFlags;
	uint8_t			au8CstRootId[8];
	uint32_t		u32CstPathCost;
	uint8_t			au8IstRootId[8];
	uint16_t		u16TxPortId;
	uint16_t		u16MessageAge;
	uint16_t		u16MaxAge;
	uint16_t		u16HelloTime;
	uint16_t		u16ForwardDelay;
} StpPdu_StpBpdu_t;

typedef struct StpPdu_StpTcn_t
{
	uint16_t		u16ProtocolIdentifier;
	uint8_t			u8ProtocolVersion;
	uint8_t			u8BpduType;
} StpPdu_StpTcn_t;


/**
 *	MST PDU
 */
enum
{
	StpPdu_MstBpdu_size_c			= 102,
};

typedef struct StpPdu_MstBpdu_t
{
	uint16_t		u16ProtocolIdentifier;
	uint8_t			u8ProtocolVersion;
	uint8_t			u8BpduType;
	uint8_t			u8CistFlags;
	uint8_t			au8CstRootId[8];
	uint32_t		u32CstPathCost;
	uint8_t			au8IstRootId[8];
	uint16_t		u16TxPortId;
	uint16_t		u16MessageAge;
	uint16_t		u16MaxAge;
	uint16_t		u16HelloTime;
	uint16_t		u16ForwardDelay;
	uint8_t			u8StpLength;
	uint16_t		u16MstLength;
	uint8_t			au8MstConfigId[51];
	uint32_t		u32IstPathCost;
	uint8_t			au8TxBridgeId[8];
	uint8_t			u8RemainingHops;
	uint8_t			au8MstConfig[0];
} StpPdu_MstBpdu_t;



#	ifdef __cplusplus
}
#	endif

#endif	// __STP_PROTO_OBJECTS_H__
