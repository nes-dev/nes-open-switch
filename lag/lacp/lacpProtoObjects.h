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

#ifndef __LACP_PROTO_OBJECTS_H__
#	define __LACP_PROTO_OBJECTS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/ieee802.h"
#include "lib/buffer.h"

#include <stdint.h>


/**
 *	PDU Definitions
 */
/**
 *	PDU Header
 */
enum
{
	LacpPduHeader_size_c					= 2,
	LacpPduTrailer_Lacp_size_c				= 50,
	LacpPduTrailer_Marker_size_c			= 90,
};

typedef struct LacpPduHeader_t
{
	uint8_t		u8Type;
	uint8_t		u8Version;
} LacpPduHeader_t;

#define LacpPduHeader_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpPduHeader_size_c);\
}

#define LacpPduHeader_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpPduHeader_size_c);\
}

/**
 *	PDU Trailer
 */
typedef struct LacpPduTrailer_Lacp_t
{
	uint8_t		au8Reserved[50];
} LacpPduTrailer_Lacp_t;

#define LacpPduTrailer_Lacp_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpPduTrailer_Lacp_size_c);\
	/**(uint32_t*) &XBUFFER_ADDR (b)[50]		= htonl ((h)->u32Fcs);*/\
}

#define LacpPduTrailer_Lacp_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpPduTrailer_Lacp_size_c);\
	/*(h)->u32Fcs								= ntohl (*(uint32_t*) &XBUFFER_ADDR (b)[50]);*/\
}

typedef struct LacpPduTrailer_Marker_t
{
	uint8_t		au8Reserved[90];
} LacpPduTrailer_Marker_t;

#define LacpPduTrailer_Marker_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpPduTrailer_Marker_size_c);\
	/**(uint32_t*) &XBUFFER_ADDR (b)[80]		= htonl ((h)->u32Fcs);*/\
}

#define LacpPduTrailer_Marker_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpPduTrailer_Marker_size_c);\
	/*(h)->u32Fcs								= ntohl (*(uint32_t*) &XBUFFER_ADDR (b)[80]);*/\
}


/**
 *	TLV Header
 */
enum
{
	LacpTlvHeader_size_c					= 2,
};

typedef struct LacpTlvHeader_t
{
	uint8_t	u8Type;
	uint8_t	u8Length;
} LacpTlvHeader_t;

#define LacpTlvHeader_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpTlvHeader_size_c);\
}

#define LacpTlvHeader_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpTlvHeader_size_c);\
}


#if 0
/**
 *	Tlv
 */
typedef struct LacpTlv_t
{
	LacpTlvHeader_t		oHeader;
	/* xxxx */
} LacpTlv_t;
#endif


/**
 *	TLV Definitions
 */
/**
 *	TERMINATOR TLV
 */
enum
{
	LacpTlv_Terminator_size_c				= 2,
};

typedef struct LacpTlv_Terminator_t
{
	LacpTlvHeader_t		oHeader;
} LacpTlv_Terminator_t;

#define LacpTlv_Terminator_serialize(b, h)\
{\
	LacpTlvHeader_serialize (&XBUFFER_ADDR (b)[0], &(h)->oHeader);\
}

#define LacpTlv_Terminator_marshal(h, b)\
{\
	LacpTlvHeader_marshal (&(h)->oHeader, &XBUFFER_ADDR (b)[0]);\
}


/**
 *	ACTOR TLV
 */
enum
{
	LacpTlv_Actor_size_c					= 20,
};

typedef struct LacpTlv_Actor_t
{
	LacpTlvHeader_t		oHeader;
	uint16_t			u16SystemPriority;
	IeeeEui48_t			oSystemAddress;
	uint16_t			u16Key;
	uint16_t			u16PortPriority;
	uint16_t			u16PortNumber;
	uint8_t				au8State[1];
	uint8_t				au8Reserved[3];
} LacpTlv_Actor_t;

#define LacpTlv_Actor_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpTlv_Actor_size_c);\
	LacpTlvHeader_serialize (&XBUFFER_ADDR (b)[0], &(h)->oHeader);\
	*(uint16_t*) &XBUFFER_ADDR (b)[2]		= htons ((h)->u16SystemPriority);\
	*(uint16_t*) &XBUFFER_ADDR (b)[10]		= htons ((h)->u16Key);\
	*(uint16_t*) &XBUFFER_ADDR (b)[12]		= htons ((h)->u16PortPriority);\
	*(uint16_t*) &XBUFFER_ADDR (b)[14]		= htons ((h)->u16PortNumber);\
}

#define LacpTlv_Actor_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpTlv_Actor_size_c);\
	LacpTlvHeader_marshal (&(h)->oHeader, &XBUFFER_ADDR (b)[0]);\
	(h)->u16SystemPriority					= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[2]);\
	(h)->u16Key								= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[10]);\
	(h)->u16PortPriority					= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[12]);\
	(h)->u16PortNumber						= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[14]);\
}


/**
 *	PARTNER TLV
 */
enum
{
	LacpTlv_Partner_size_c					= LacpTlv_Actor_size_c,
};

typedef LacpTlv_Actor_t LacpTlv_Partner_t;

#define LacpTlv_Partner_serialize	LacpTlv_Actor_serialize
#define LacpTlv_Partner_marshal		LacpTlv_Actor_marshal


/**
 *	COLLECTOR TLV
 */
enum
{
	LacpTlv_Collector_size_c				= 16,
};

typedef struct LacpTlv_Collector_t
{
	LacpTlvHeader_t		oHeader;
	uint16_t			u16MaxDelay;
	uint8_t				au8Reserved[12];
} LacpTlv_Collector_t;

#define LacpTlv_Collector_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpTlv_Collector_size_c);\
	LacpTlvHeader_serialize (&XBUFFER_ADDR (b)[0], &(h)->oHeader);\
	*(uint16_t*) &XBUFFER_ADDR (b)[2]		= htons ((h)->u16MaxDelay);\
}

#define LacpTlv_Collector_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpTlv_Collector_size_c);\
	LacpTlvHeader_marshal (&(h)->oHeader, &XBUFFER_ADDR (b)[0]);\
	(h)->u16MaxDelay						= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[2]);\
}


/**
 *	LACP PDU
 */
enum
{
	LacpPdu_Lacp_size_c						= 110,
};

typedef struct LacpPdu_Lacp_t
{
	LacpPduHeader_t				oHeader;
	LacpTlv_Actor_t				oActor;
	LacpTlv_Partner_t			oPartner;
	LacpTlv_Collector_t			oCollector;
	LacpTlv_Terminator_t		oTerminator;
	LacpPduTrailer_Lacp_t		oTrailer;
} LacpPdu_Lacp_t;

#define LacpPdu_Lacp_serialize(b, h)\
{\
	LacpPduHeader_serialize (&XBUFFER_ADDR (b)[0], &(h)->oHeader);\
	LacpTlv_Actor_serialize (&XBUFFER_ADDR (b)[2], &(h)->oActor);\
	LacpTlv_Partner_serialize (&XBUFFER_ADDR (b)[22], &(h)->oPartner);\
	LacpTlv_Collector_serialize (&XBUFFER_ADDR (b)[42], &(h)->oCollector);\
	LacpTlv_Terminator_serialize (&XBUFFER_ADDR (b)[58], &(h)->oTerminator);\
	LacpPduTrailer_Lacp_serialize (&XBUFFER_ADDR (b)[60], &(h)->oTrailer);\
}

#define LacpPdu_Lacp_marshal(h, b)\
{\
	LacpPduHeader_marshal (&(h)->oHeader, &XBUFFER_ADDR (b)[0]);\
	LacpTlv_Actor_marshal (&(h)->oActor, &XBUFFER_ADDR (b)[2]);\
	LacpTlv_Partner_marshal (&(h)->oPartner, &XBUFFER_ADDR (b)[22]);\
	LacpTlv_Collector_marshal (&(h)->oCollector, &XBUFFER_ADDR (b)[42]);\
	LacpTlv_Terminator_marshal (&(h)->oTerminator, &XBUFFER_ADDR (b)[58]);\
	LacpPduTrailer_Lacp_marshal (&(h)->oTrailer, &XBUFFER_ADDR (b)[60]);\
}


/**
 *	MARKER TLV
 */
enum
{
	LacpTlv_Marker_size_c					= 16,
};

typedef struct LacpTlv_Marker_t
{
	LacpTlvHeader_t		oHeader;
	uint16_t			u16PortNumber;
	IeeeEui48_t			oSystemAddress;
	uint32_t			u32TransactionId;
	uint8_t				au8Reserved[2];
} LacpTlv_Marker_t;

#define LacpTlv_Marker_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), LacpTlv_Marker_size_c);\
	LacpTlvHeader_serialize (&XBUFFER_ADDR (b)[0], &(h)->oHeader);\
	*(uint16_t*) &XBUFFER_ADDR (b)[2]		= htons ((h)->u16MaxDelay);\
	*(uint32_t*) &XBUFFER_ADDR (b)[10]		= htonl ((h)->u32TransactionId);\
}

#define LacpTlv_Marker_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), LacpTlv_Marker_size_c);\
	LacpTlvHeader_marshal (&(h)->oHeader, &XBUFFER_ADDR (b)[0]);\
	(h)->u16MaxDelay						= ntohs (*(uint16_t*) &XBUFFER_ADDR (b)[2]);\
	(h)->u32TransactionId					= ntohl (*(uint32_t*) &XBUFFER_ADDR (b)[10]);\
}


/**
 *	LACP MARKER PDU
 */
enum
{
	LacpPdu_Marker_size_c					= 110,
};

typedef struct LacpPdu_Marker_t
{
	LacpPduHeader_t oHeader;
	LacpTlv_Marker_t oMarker;
	LacpPduTrailer_Marker_t oTrailer;
} LacpPdu_Marker_t;


/**
 *	MARKER RESPONSE TLV
 */
enum
{
	LacpTlv_MarkerResponse_size_c			= LacpTlv_Marker_size_c,
};

typedef LacpTlv_Marker_t LacpTlv_MarkerResponse_t;

#define LacpTlv_MarkerResponse_serialize	LacpTlv_Marker_serialize
#define LacpTlv_MarkerResponse_marshal		LacpTlv_Marker_marshal


/**
 *	LACP MARKER RESPONSE PDU
 */
enum
{
	LacpPdu_MarkerResponse_size_c			= 110,
};

typedef struct LacpPdu_MarkerResponse_t
{
	LacpPduHeader_t oHeader;
	LacpTlv_MarkerResponse_t oMarkerResponse;
	LacpPduTrailer_Marker_t oTrailer;
} LacpPdu_MarkerResponse_t;



#	ifdef __cplusplus
}
#	endif

#endif	// __LACP_PROTO_OBJECTS_H__
