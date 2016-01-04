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

#ifndef __LIB_H__
#	define __LIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <string.h>


#define xOffsetOf(_type_t, _member_name) (\
	(size_t) ((void*) &((_type_t*) 0)->_member_name - (void*) 0)\
)

#define xMin(a, b) ((a) < (b) ? (a): (b))
#define xMax(a, b) ((a) > (b) ? (a): (b))

#define xGetParentByMemberPtr(_member_ptr, _type_t, _member_name) (\
	(_type_t*) ((void*) _member_ptr - xOffsetOf (_type_t, _member_name))\
)

#define xBinCmp(_pA, _pB, _u16ALen, _u16BLen) (\
	(_u16ALen) < (_u16BLen) ? -1:\
	(_u16ALen) == (_u16BLen) ? memcmp ((_pA), (_pB), (_u16ALen)): 1\
)

#define xUnused(_x) ((_x) = (_x))

#define xCallback_tryExec(_func, _args ...) ((_func) == NULL || (_func) (_args))



#	ifdef __cplusplus
}
#	endif

#endif	// __LIB_H__
