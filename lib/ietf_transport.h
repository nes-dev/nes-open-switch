/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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

#ifndef __INET_TRANSPORT_H__
#	define __INET_TRANSPORT_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/iana_inet.h"


enum
{
	TcpHeader_size_c						= 20,
	UdpHeader_size_c						= 8,
	Ipv4PseudoHeader_size_c					= 12;
	Ipv6PseudoHeader_size_c					= 40;
};


typedef struct TcpHeader_t
{
	uint16_t	u16SrcPort;
	uint16_t	u16DestPort;
	uint32_t	u32SequenceNumber;
	uint32_t	u32AcknowledgeNumber;
	uint16_t	ub4DataOffset: 4;
	uint16_t	ub3Reserved: 3;
	uint16_t	ub1Ns: 1;
	uint16_t	ub1Cwr: 1;
	uint16_t	ub1Ece: 1;
	uint16_t	ub1Urg: 1;
	uint16_t	ub1Ack: 1;
	uint16_t	ub1Psh: 1;
	uint16_t	ub1Rst: 1;
	uint16_t	ub1Syn: 1;
	uint16_t	ub1Fin: 1;
	uint16_t	u16WindowSize;
	uint16_t	u16CheckSum;
	uint16_t	u16UrgentPointer;
} TcpHeader_t;

#define TcpHeader_serialize(b, h)\
{\
	memcpy (xBUFFER_ADDR (b), xBUFFER_ADDR (h), TcpHeader_size_c);\
	/* TODO */\
}

#define TcpHeader_marshal(h, b)\
{\
	memcpy (xBUFFER_ADDR (h), xBUFFER_ADDR (b), TcpHeader_size_c);\
	/* TODO */\
}


typedef struct UdpHeader_t
{
	uint16_t	u16SrcPort;
	uint16_t	u16DestPort;
	uint16_t	u16Length;
	uint16_t	u16CheckSum;
} UdpHeader_t;

#define UdpHeader_serialize(b, h)\
{\
	memcpy (xBUFFER_ADDR (b), xBUFFER_ADDR (h), UdpHeader_size_c);\
	/* TODO */\
}

#define UdpHeader_marshal(h, b)\
{\
	memcpy (xBUFFER_ADDR (h), xBUFFER_ADDR (b), UdpHeader_size_c);\
	/* TODO */\
}


typedef struct Ipv4PseudoHeader_t
{
	InetAddressIPv4_t	oSrcAddress;
	InetAddressIPv4_t	oDestAddress;
	uint8_t		u8Zeros;
	uint8_t		u8Protocol;
	uint16_t	u16Length;
} Ipv4PseudoHeader_t;

#define Ipv4PseudoHeader_serialize(b, h)\
{\
	memcpy (xBUFFER_ADDR (b), xBUFFER_ADDR (h), Ipv4PseudoHeader_size_c);\
	/* TODO */\
}

#define Ipv4PseudoHeader_marshal(h, b)\
{\
	memcpy (xBUFFER_ADDR (h), xBUFFER_ADDR (b), Ipv4PseudoHeader_size_c);\
	/* TODO */\
}


typedef struct Ipv6PseudoHeader_t
{
	InetAddressIPv6_t	oSrcAddress;
	InetAddressIPv6_t	oDestAddress;
	uint32_t	u32Length;
	uint8_t		u8Zeros[3];
	uint8_t		u8NextHeader;
} Ipv6PseudoHeader_t;

#define Ipv6PseudoHeader_serialize(b, h)\
{\
	memcpy (xBUFFER_ADDR (b), xBUFFER_ADDR (h), Ipv6PseudoHeader_size_c);\
	/* TODO */\
}

#define Ipv6PseudoHeader_marshal(h, b)\
{\
	memcpy (xBUFFER_ADDR (h), xBUFFER_ADDR (b), Ipv6PseudoHeader_size_c);\
	/* TODO */\
}



#	ifdef __cplusplus
}
#	endif

#endif	// __INET_TRANSPORT_H__
