/*
 *  Copyright (c) 2008-2016
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

#ifndef __IP_H__
#	define __IP_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/iana_inet.h"


enum
{
	Ipv4Header_size_c						= 20,
	Ipv4Header_versionIpv4_c				= 4,
	Ipv4Header_flagsDontFragment_c			= 0x02,
	Ipv4Header_flagsMoreFragments_c			= 0x04,
};

typedef struct Ipv4Header_t
{
	uint8_t		ub4Version: 4;
	uint8_t		ub4HeaderLength: 4;
	uint8_t		u8TypeOfService;
	uint16_t	u16Length;
	uint16_t	u16Identification;
	uint16_t	ub3Flags: 3;
	uint16_t	ub13FragmentOffset: 13;
	uint8_t		u8TimeToLive;
	uint8_t		u8Protocol;
	uint16_t	u16CheckSum;
	InetAddressIPv4_t	oSrcAddress;
	InetAddressIPv4_t	oDestAddress;
} Ipv4Header_t;

#define Ipv4Header_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), Ipv4Header_size_c);\
	XBUFFER_ADDR (b)[0]						= ((h)->ub4Version & 0x0F) << 4;\
	XBUFFER_ADDR (b)[0]					   |= (h)->ub4HeaderLength & 0x0F;\
	*(uint16_t*) &XBUFFER_ADDR (b)[2]		= htons ((h)->u16Length);\
	*(uint16_t*) &XBUFFER_ADDR (b)[4]		= htons ((h)->u16Identification);\
	XBUFFER_ADDR (b)[6]						= ((h)->ub3Flags & 0x07) << 5;\
	XBUFFER_ADDR (b)[6]					   |= ((h)->ub13FragmentOffset & 0x1F00) >> 8;\
	XBUFFER_ADDR (b)[7]						= (h)->ub13FragmentOffset & 0x00FF;\
	*(uint16_t*) &XBUFFER_ADDR (b)[10]		= htons ((h)->u16CheckSum);\
}

#define Ipv4Header_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), Ipv4Header_size_c);\
	(h)->ub4Version							= (XBUFFER_ADDR (b)[0] & 0xF0) >> 4;\
	(h)->ub4HeaderLength					= XBUFFER_ADDR (b)[0] & 0x0F;\
	(h)->u16Length							= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[2]);\
	(h)->u16Identification					= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[4]);\
	(h)->ub3Flags							= (XBUFFER_ADDR (b)[6] & 0xE0) >> 5;\
	(h)->ub13FragmentOffset					= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[6] & 0x1FFF);\
	(h)->u16CheckSum						= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[10]);\
}


enum
{
	Ipv6Header_size_c						= 40,
	Ipv6Header_versionIpv6_c				= 6,
};

typedef struct Ipv6Header_t
{
	uint32_t	ub4Version: 4;
	uint32_t	ub8TrafficClass: 8;
	uint32_t	ub20FlowLabel: 20;
	uint16_t	u16Length;
	uint8_t		u8NextHeader;
	uint8_t		u8HopLimit;
	InetAddressIPv6_t	oSrcAddress;
	InetAddressIPv6_t	oDestAddress;
} Ipv6Header_t;

#define Ipv6Header_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), Ipv6Header_size_c);\
	XBUFFER_ADDR (b)[0]						= ((h)->ub4Version & 0x0F) << 4;\
	XBUFFER_ADDR (b)[0]					   |= ((h)->ub8TrafficClass & 0xF0) >> 4;\
	XBUFFER_ADDR (b)[1]						= ((h)->ub8TrafficClass & 0x0F) << 4;\
	XBUFFER_ADDR (b)[1]					   |= ((h)->ub20FlowLabel & 0xF0000) >> 16;\
	XBUFFER_ADDR (b)[2]						= ((h)->ub20FlowLabel & 0xFF00) >> 8;\
	XBUFFER_ADDR (b)[3]						= (h)->ub20FlowLabel & 0xFF;\
	*(uint16_t*) &XBUFFER_ADDR (b)[4]		= htons ((h)->u16Length);\
}

#define Ipv6Header_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), Ipv6Header_size_c);\
	(h)->ub4Version							= (XBUFFER_ADDR (b)[0] & 0xF0) >> 4;\
	(h)->ub8TrafficClass					= (XBUFFER_ADDR (b)[0] & 0x0F) << 4;\
	(h)->ub8TrafficClass				   |= (XBUFFER_ADDR (b)[1] & 0xF0) >> 4;\
	(h)->ub20FlowLabel						= (XBUFFER_ADDR (b)[1] & 0x0F) << 16;\
	(h)->ub20FlowLabel					   |= XBUFFER_ADDR (b)[2] << 8;\
	(h)->ub20FlowLabel					   |= XBUFFER_ADDR (b)[3];\
	(h)->u16Length							= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[4]);\
}

typedef struct Ipv6Header_HopByHopExt_t
{
	uint8_t		u8NextHeader;
	uint8_t		u8HeaderLength;
	uint8_t		au8Data[6];
} Ipv6Header_HopByHopExt_t;

typedef struct Ipv6Header_DestinationExt_t
{
	uint8_t		u8NextHeader;
	uint8_t		u8HeaderLength;
	uint8_t		au8Data[6];
} Ipv6Header_DestinationExt_t;

typedef struct Ipv6Header_RoutingExt_t
{
	uint8_t		u8NextHeader;
	uint8_t		u8HeaderLength;
	uint8_t		u8Type;
	uint8_t		u8SegmentsLeft;
	uint8_t		au8Data[4];
} Ipv6Header_RoutingExt_t;

typedef struct Ipv6Header_FragmentExt_t
{
	uint8_t		u8NextHeader;
	uint8_t		u8Reserved;
	uint16_t	ub1More: 1;
	uint16_t	ub2Reserved: 2;
	uint16_t	ub13Offset: 13;
	uint32_t	u32Identification;
} Ipv6Header_FragmentExt_t;

typedef struct Ipv6Header_AhExt_t
{
	uint8_t		u8NextHeader;
	uint8_t		u8HeaderLength;
	uint16_t	u16Reserved;
	uint32_t	u32Spi;
	uint32_t	u32SequenceNumber;
	uint32_t	au32Icv[1];
} Ipv6Header_AhExt_t;

typedef struct Ipv6Header_EspExt_t
{
	uint32_t	u32Spi;
	uint32_t	u32SequenceNumber;
	uint8_t		au8Data[2];
	uint8_t		u8PaddingLength;
	uint8_t		u8NextHeader;
	uint32_t	au32Icv[1];
} Ipv6Header_EspExt_t;



#	ifdef __cplusplus
}
#	endif

#endif	// __IP_H__
