/*
 *  Copyright (c) 2008-2015
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

#ifndef __IEEE802_H__
#	define __IEEE802_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>


enum
{
	IeeeEui48_size_c		= 6,
	IeeeEui64_size_c		= 8,
};

typedef uint8_t IeeeEui48_t [IeeeEui48_size_c];
typedef uint8_t IeeeEui64_t [IeeeEui64_size_c];

typedef struct IeeeEui48Header_t
{
	IeeeEui48_t		oDestAddress;
	IeeeEui48_t		oSrcAddress;
	uint16_t			u16Type;
} IeeeEui48Header_t;

uint32_t xIeeeCrc32 (uint8_t *pu8Buf, uint16_t u16BufSize);
uint32_t xIeeeCrc16 (uint8_t *pu8Buf, uint16_t u16BufSize);


const IeeeEui48_t IeeeEui_slowProtocolsMulticast;

enum
{
	IeeeEtherType_slowProtocols_c		= 0x8809,
	
	IeeeSlowProtocolsType_unused_c		= 0x00,
	IeeeSlowProtocolsType_lacp_c		= 0x01,
	IeeeSlowProtocolsType_marker_c		= 0x02,
	IeeeSlowProtocolsType_oam_c			= 0x03,
	IeeeSlowProtocolsType_ossp_c		= 0x0A,
};



#	ifdef __cplusplus
}
#	endif

#endif	// __IEEE802_H__
