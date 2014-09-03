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

#ifndef __BITMAP_H__
#	define __BITMAP_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#	include <stdbool.h>
#	include <stdint.h>


typedef uint8_t xBitmask_t;
typedef uint8_t *xBitmap_t;

#	define xBitmap_declare(_map, _bit_len) xBitmask_t _map[xBitmap_maskCount (_bit_len)]


#	define xBitmask_full_c		0xFF
#	define xBitmask_empty_c		0x00
#	define xBitmask_length_c	8

#	define xBitmask_bitIndex(_bit_offset) ((_bit_offset) & 0x07)
#	define xBitmask_bitIndexRev(_bit_offset) (~xBitmask_bitIndex (_bit_offset))
#	define xBitmask_bitRev(_bit_mask) (\
		(((_bit_mask) & 0x01) << 7) |\
		(((_bit_mask) & 0x02) << 6) |\
		(((_bit_mask) & 0x04) << 5) |\
		(((_bit_mask) & 0x08) << 4) |\
		(((_bit_mask) & 0x10) << 3) |\
		(((_bit_mask) & 0x20) << 2) |\
		(((_bit_mask) & 0x40) << 1) |\
		(((_bit_mask) & 0x80) << 0)\
	)
#	define xBitmap_maskIndex(_bit_offset) ((_bit_offset) >> 3)
#	define xBitmap_maskCount(_bit_len) (xBitmap_maskIndex (_bit_len) + xBitmask_bitIndex (_bit_len) != 0)

#	define xBitmask_bitMask(_bit_offset) (1 << xBitmask_bitIndex (_bit_offset))
#	define xBitmask_bitMaskRev(_bit_offset) (1 << xBitmask_bitIndexRev (_bit_offset))
#	define xBitmask_bitString(_bit_start, _bit_end) (\
	(~xBitmask_empty_c >> (_bit_start)) &\
	(~xBitmask_empty_c << (uint8_t) (xBitmask_length_c - _bit_end - 1)))

#	define xBitmap_bitLength(_mask_len) ((_mask_len) << 3)

#	define xBitmap_static(_map, _bit_len) uint8_t _map[xBitmap_maskCount (_bit_len)]
#	define xBitmap_alloc(_map, _bit_len) (_map) = malloc (xBitmap_maskCount (_bit_len))
#	define xBitmap_destroy(_map) free (_map)


#	define xBitmap_clearAll(_map, _bit_len) xBitmap_set(_map, 0, (_bit_len) - 1, 0)
#	define xBitmap_setAll(_map, _bit_len) xBitmap_set(_map, 0, (_bit_len) - 1, 1)

inline void
	xBitmap_set (
		xBitmask_t *poMap, uint32_t u32BitStart, uint32_t u32BitEnd, bool bFill)
{
	for (register uint16_t u16BitIdx = u32BitStart; u16BitIdx < u32BitEnd; u16BitIdx++)
	{
		if (xBitmask_bitIndex (u16BitIdx) == 0 && !bFill)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] = xBitmask_empty_c;
		}
		else if (
			xBitmask_bitIndex (u16BitIdx) == 0 && bFill)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] = xBitmask_full_c;
		}
		else if (
			xBitmask_bitIndex (u16BitIdx) != 0)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] =
				(poMap[xBitmap_maskIndex (u16BitIdx)] & ~xBitmask_bitMask (u16BitIdx)) |
				(bFill << xBitmask_bitIndex (u16BitIdx));
		}
		
		if (u32BitEnd - u16BitIdx >= xBitmask_length_c - 1)
		{
			u16BitIdx += xBitmask_length_c - 1;
		}
	}
	
	return;
}

inline void
	xBitmap_setRev (
		xBitmask_t *poMap, uint32_t u32BitStart, uint32_t u32BitEnd, bool bFill)
{
	for (register uint16_t u16BitIdx = u32BitStart; u16BitIdx < u32BitEnd; u16BitIdx++)
	{
		if (xBitmask_bitIndex (u16BitIdx) == 0 && !bFill)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] = xBitmask_empty_c;
		}
		else if (
			xBitmask_bitIndex (u16BitIdx) == 0 && bFill)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] = xBitmask_full_c;
		}
		else if (
			xBitmask_bitIndex (u16BitIdx) != 0)
		{
			poMap[xBitmap_maskIndex (u16BitIdx)] =
				(poMap[xBitmap_maskIndex (u16BitIdx)] & ~xBitmask_bitMaskRev (u16BitIdx)) |
				(bFill << xBitmask_bitIndexRev (u16BitIdx));
		}
		
		if (u32BitEnd - u16BitIdx >= xBitmask_length_c - 1)
		{
			u16BitIdx += xBitmask_length_c - 1;
		}
	}
	
	return;
}

inline uint8_t
	xBitmap_getBit (
		xBitmask_t *poMap, uint32_t u32Pos)
{
	return poMap[xBitmap_maskIndex (u32Pos)] & xBitmask_bitMask (u32Pos);
}

inline uint8_t
	xBitmap_getBitRev (
		xBitmask_t *poMap, uint32_t u32Pos)
{
	return poMap[xBitmap_maskIndex (u32Pos)] & xBitmask_bitMask (u32Pos);
}

inline uint8_t
	xBitmap_setBit (
		xBitmask_t *poMap, uint32_t u32Pos, bool bVal)
{
	register uint16_t u16Idx = xBitmap_maskIndex (u32Pos);
	
	return poMap[u16Idx] = (poMap[u16Idx] & ~xBitmask_bitMask (u32Pos)) | (bVal << xBitmask_bitIndex (u32Pos));
}

inline uint8_t
	xBitmap_setBitRev (
		xBitmask_t *poMap, uint32_t u32Pos, bool bVal)
{
	register uint16_t u16Idx = xBitmap_maskIndex (u32Pos);
	
	return poMap[u16Idx] = (poMap[u16Idx] & ~xBitmask_bitMaskRev (u32Pos)) | (bVal << xBitmask_bitIndexRev (u32Pos));
}

extern bool
	xBitmap_vSetBits (
		bool bIsRev, xBitmask_t *poMap, uint32_t u32Count, bool bVal, uint32_t u32Pos, ...);
		
#	define xBitmap_setBits(_map, _count, _val, _pos ...) xBitmap_vSetBits (0, _map, _count, _val, ## _pos)
#	define xBitmap_setBitsRev(_map, _count, _val, _pos ...) xBitmap_vSetBits (1, _map, _count, _val, ## _pos)


inline void
	xBitmap_or (
		xBitmask_t *poMapO1, xBitmask_t *poMapI1, xBitmask_t *poMapI2, uint32_t u32BitLen)
{
	for (register uint16_t u16BitIdx = 0; u16BitIdx < u32BitLen; u16BitIdx += xBitmask_length_c)
	{
		register uint16_t u16MaskIdx = xBitmap_maskIndex (u16BitIdx);
		
		poMapO1[u16MaskIdx] = poMapI1[u16MaskIdx] | poMapI2[u16MaskIdx];
	}
	
	return;
}

inline void
	xBitmap_and(
		xBitmask_t *poMapO1, xBitmask_t *poMapI1, xBitmask_t *poMapI2, uint32_t u32BitLen)
{
	for (register uint16_t u16BitIdx = 0; u16BitIdx < u32BitLen; u16BitIdx += xBitmask_length_c)
	{
		register uint16_t u16MaskIdx = xBitmap_maskIndex (u16BitIdx);
		
		poMapO1[u16MaskIdx] = poMapI1[u16MaskIdx] & poMapI2[u16MaskIdx];
	}
	
	return;
}

inline void
	xBitmap_xor (
		xBitmask_t *poMapO1, xBitmask_t *poMapI1, xBitmask_t *poMapI2, uint32_t u32BitLen)
{
	for (register uint16_t u16BitIdx = 0; u16BitIdx < u32BitLen; u16BitIdx += xBitmask_length_c)
	{
		register uint16_t u16MaskIdx = xBitmap_maskIndex (u16BitIdx);
		
		poMapO1[u16MaskIdx] = poMapI1[u16MaskIdx] ^ poMapI2[u16MaskIdx];
	}
	
	return;
}


extern void
	xBitmap_copyFromRev (
		xBitmask_t *poMapDst, xBitmask_t *poMapSrc, uint32_t u32BitStart, uint32_t u32BitEnd);
extern void
	xBitmap_copyToRev (
		xBitmask_t *poMapDst, xBitmask_t *poMapSrc, uint32_t u32BitStart, uint32_t u32BitEnd);


#	define xBitmap_scanEq(_map1, _map2, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map1[xBitmap_maskIndex (_bit_idx)] != _map2[xBitmap_maskIndex (_bit_idx)])\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map1[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)) ==\
			(_map2[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)))\


#	define xBitmap_scanEqRev(_map1, _map2, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map1[xBitmap_maskIndex (_bit_idx)] != _map2[xBitmap_maskIndex (_bit_idx)])\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map1[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)) ==\
			(_map2[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)))\


#	define xBitmap_scanNeq(_map1, _map2, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map1[xBitmap_maskIndex (_bit_idx)] == _map2[xBitmap_maskIndex (_bit_idx)])\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map1[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)) !=\
			(_map2[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)))\


#	define xBitmap_scanNeqRev(_map1, _map2, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map1[xBitmap_maskIndex (_bit_idx)] == _map2[xBitmap_maskIndex (_bit_idx)])\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map1[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)) !=\
			(_map2[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)))\


#	define xBitmap_scanSet(_map, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_empty_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx))\


#	define xBitmap_scanSetRev(_map, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_empty_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx))\


#	define xBitmap_scanSetRange(_map, _bit_start, _bit_end, _bit_idx) \
	for (_bit_idx = _bit_start; _bit_idx <= _bit_end; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_empty_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx))\


#	define xBitmap_scanSetRangeRev(_map, _bit_start, _bit_end, _bit_idx) \
	for (_bit_idx = _bit_start; _bit_idx <= _bit_end; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_empty_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx))\


#	define xBitmap_scanClear(_map, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_full_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)) == 0)\


#	define xBitmap_scanClearRev(_map, _bit_len, _bit_idx) \
	for (_bit_idx = 0; _bit_idx < _bit_len; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_full_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)) == 0)\


#	define xBitmap_scanClearRange(_map, _bit_start, _bit_end, _bit_idx) \
	for (_bit_idx = _bit_start; _bit_idx <= _bit_end; _bit_idx++)\
		if (\
			xBitmask_bitIndex (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_full_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMask (_bit_idx)) == 0)\


#	define xBitmap_scanClearRangeRev(_map, _bit_start, _bit_end, _bit_idx) \
	for (_bit_idx = _bit_start; _bit_idx <= _bit_end; _bit_idx++)\
		if (\
			xBitmask_bitIndexRev (_bit_idx) == 0 &&\
			_map[xBitmap_maskIndex (_bit_idx)] == xBitmask_full_c)\
		{\
			_bit_idx += (uint16_t) (xBitmask_length_c - 1);\
			continue;\
		}\
		else if (\
			(_map[xBitmap_maskIndex (_bit_idx)] & xBitmask_bitMaskRev (_bit_idx)) == 0)\



#	ifdef __cplusplus
}
#	endif

#endif	// __BITMAP_H__
