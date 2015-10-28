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

#ifndef __IEEE802_C__
#	define __IEEE802_C__



#include "ieee802.h"

#include <stdint.h>


const IeeeEui48_t IeeeEui_customerBridgeGroupAddress		= {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
const IeeeEui48_t IeeeEui_slowProtocolsMulticast			= {0x01, 0x80, 0xC2, 0x00, 0x00, 0x02};
const IeeeEui48_t IeeeEui_providerBridgeGroupAddress		= {0x01, 0x80, 0xC2, 0x00, 0x00, 0x08};



#endif	// __IEEE802_C__
