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

#ifndef __ETHERNET_EXT_H__
#	define __ETHERNET_EXT_H__

#	ifdef __cplusplus
extern "C" {
#	endif


#include <stdint.h>

#include "lib/buffer.h"


extern void *
ethernet_main (
	void *pvArgv);

extern void *
ethernet_start (
	void *pvArgv);


/**
 *	L2 TX
 */
void L2MsgSend (xBuffer_Vector_t *poBufferVector, uint16_t u16BufferCount);


#define PKT_IP_ENC_USED 4
#define PKT_L2_ENC_USED
#undef PKT_L2_VLAN_ENC_USED

#define ETHERNET_PORT_MAP_SIZE 64


#	ifdef __cplusplus
}
#	endif

#endif	// __ETHERNET_EXT_H__
