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

#ifndef __NUMBER_H__
#	define __NUMBER_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdbool.h>
#include <stdint.h>


enum
{
	xNumber32_size_c				= 4,
	xNumber64_size_c				= 8,
	xNumber128_size_c				= 16,
};

typedef uint8_t xNumber32_t [4];
typedef uint8_t xNumber64_t [8];
typedef uint8_t xNumber128_t [16];

extern bool
	xNumber_toUint32 (
		void *pvNumber, uint16_t u16NumberSize,
		uint16_t u16StartByte, uint16_t u16StopByte,
		uint32_t *pu32Number);
extern bool
	xNumber_toUint64 (
		void *pvNumber, uint16_t u16NumberSize,
		uint16_t u16StartByte, uint16_t u16StopByte,
		uint64_t *pu64Number);
extern bool
	xNumber_checkUint32 (
		void *pvNumber, uint16_t u16NumberSize);
extern bool
	xNumber_checkUint64 (
		void *pvNumber, uint16_t u16NumberSize);

enum
{
	xIeee_Float32_size_c			= 4,
	xIeee_Float64_size_c			= 8,
	xIeee_Float128_size_c			= 16,
};

typedef struct xIeee_Float32_t
{
	uint32_t ub1Sign: 1;
	uint32_t ub8Exponent: 8;
	uint32_t ub23Fraction: 23;
} xIeee_Float32_t;

#define xIeee_Float32_serialize(b, h)\
{\
	XBUFFER_ADDR (b)[0]						= ((h)->ub1Sign & 0x01) << 7;\
	XBUFFER_ADDR (b)[0]					   |= (h)->ub8Exponent >> 1;\
	XBUFFER_ADDR (b)[1]						= (h)->ub8Exponent << 7;\
	XBUFFER_ADDR (b)[1]					   |= ((h)->ub23Fraction & 0x7F0000) >> 16;\
	XBUFFER_ADDR (b)[2]						= ((h)->ub23Fraction & 0x00FF00) >> 8;\
	XBUFFER_ADDR (b)[3]						= (h)->ub23Fraction & 0xFF;\
}

#define xIeee_Float32_marshal(h, b)\
{\
	(h)->ub1Sign							= (XBUFFER_ADDR (b)[0] & 0x80) >> 7;\
	(h)->ub8Exponent						= (XBUFFER_ADDR (b)[0] & 0x7F) << 1;\
	(h)->ub8Exponent					   |= (XBUFFER_ADDR (b)[1] & 0x80) >> 7;\
	(h)->ub23Fraction						= (XBUFFER_ADDR (b)[1] & 0x7F) << 16;\
	(h)->ub23Fraction					   |= XBUFFER_ADDR (b)[2] << 8;\
	(h)->ub23Fraction					   |= XBUFFER_ADDR (b)[3];\
}

typedef uint8_t xIeee_Float64_t [8];

#define xIeee_Float64_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), xIeee_Float64_size_c);\
}

#define xIeee_Float64_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), xIeee_Float64_size_c);\
}

typedef uint8_t xIeee_Float128_t [16];

#define xIeee_Float128_serialize(b, h)\
{\
	memcpy (XBUFFER_ADDR (b), XBUFFER_ADDR (h), xIeee_Float128_size_c);\
}

#define xIeee_Float128_marshal(h, b)\
{\
	memcpy (XBUFFER_ADDR (h), XBUFFER_ADDR (b), xIeee_Float128_size_c);\
}



#	ifdef __cplusplus
}
#	endif

#endif	// __NUMBER_H__
