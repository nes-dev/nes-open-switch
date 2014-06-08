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

#ifndef __BITMAP_H__
#	define __BITMAP_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#	include <stdint.h>

#	define xBitmask_full_c		0xFF
#	define xBitmask_empty_c		0x00
#	define xBitmask_length_c	8

#	define xBitmask_bitIndex(_bit_offset) ((_bit_offset) & 0x07)
#	define xBitmask_bitIndexRev(_bit_offset) (~xBitmask_bitIndex (_bit_offset))
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

#	define xBitmap_set(_map, _bit_start, _bit_end, _fill) \
	for (register uint16_t _bit_idx = (_bit_start); _bit_idx < (_bit_end); _bit_idx++)\
	{\
		if (xBitmask_bitIndex (_bit_idx) == 0 && (_fill) == 0)\
		{\
			_map[xBitmap_maskIndex (_bit_idx)] = xBitmask_empty_c;\
		}\
		else if (\
			xBitmask_bitIndex (_bit_idx) == 0 && (_fill) != 0)\
		{\
			_map[xBitmap_maskIndex (_bit_idx)] = xBitmask_full_c;\
		}\
		else if (\
			xBitmask_bitIndex (_bit_idx) != 0)\
		{\
			_map[xBitmap_maskIndex (_bit_idx)] =\
				(_map[xBitmap_maskIndex (_bit_idx)] & ~xBitmask_bitMask (_bit_idx)) |\
				(((_fill) != 0) << xBitmask_bitIndex (_bit_idx));\
		}\
		\
		if ((_bit_end) - _bit_idx >= xBitmask_length_c - 1)\
		{\
			_bit_idx += xBitmask_length_c - 1;\
		}\
	}
	
	
#	define xBitmap_getBit(_map, _pos) (\
		_map[xBitmap_maskIndex (_pos)] & xBitmask_bitMask (_pos)\
	)
	
	
#	define xBitmap_getBitRev(_map, _pos) (\
		_map[xBitmap_maskIndex (_pos)] & xBitmask_bitMaskRev (_pos)\
	)
	
	
#	define xBitmap_setBit(_map, _pos, _val) ({\
		register uint16_t idx = xBitmap_maskIndex (_pos);\
		\
		_map[idx] = (_map[idx] & ~xBitmask_bitMask (_pos)) | (((_val) != 0) << xBitmask_bitIndex (_pos));\
	})
	
	
#	define xBitmap_setBitRev(_map, _pos, _val) ({\
		register uint16_t idx = xBitmap_maskIndex (_pos);\
		\
		_map[idx] = (_map[idx] & ~xBitmask_bitMaskRev (_pos)) | (((_val) != 0) << xBitmask_bitIndexRev (_pos));\
	})
	
	
#	define xBitmap_or(_map_o1, _map_i1, _map_i2, _bit_len) \
	for (register uint16_t _bit_idx = 0; _bit_idx < _bit_len; _bit_idx += xBitmask_length_c)\
	{\
		register uint16_t mask_idx = xBitmap_maskIndex (_bit_idx);\
		\
		_map_o1[mask_idx] = _map_i1[mask_idx] | _map_i2[mask_idx];\
	}
	
#	define xBitmap_and(_map_o1, _map_i1, _map_i2, _bit_len) \
	for (register uint16_t _bit_idx = 0; _bit_idx < _bit_len; _bit_idx += xBitmask_length_c)\
	{\
		register uint16_t mask_idx = xBitmap_maskIndex (_bit_idx);\
		\
		_map_o1[mask_idx] = _map_i1[mask_idx] & _map_i2[mask_idx];\
	}
	
#	define xBitmap_xor(_map_o1, _map_i1, _map_i2, _bit_len) \
	for (register uint16_t _bit_idx = 0; _bit_idx < _bit_len; _bit_idx += xBitmask_length_c)\
	{\
		register uint16_t mask_idx = xBitmap_maskIndex (_bit_idx);\
		\
		_map_o1[mask_idx] = _map_i1[mask_idx] ^ _map_i2[mask_idx];\
	}



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


typedef uint8_t xBitmask_t;
typedef uint8_t *xBitmap_t;
#	define xBitmap_declare(_map, _bit_len) xBitmask_t _map[xBitmap_maskCount (_bit_len)]



#	ifdef __cplusplus
}
#	endif

#endif	// __BITMAP_H__
