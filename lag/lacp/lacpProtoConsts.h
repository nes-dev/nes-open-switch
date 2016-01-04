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

#ifndef __LACP_PROTO_CONSTS_H__
#	define __LACP_PROTO_CONSTS_H__

#	ifdef __cplusplus
extern "C" {
#	endif


enum {
	Lacp_Version1_c			= 1,
};


/**
 *	TLVs
 */
enum
{
	LacpTlv_Terminator_c							= 0x00,
	
	LacpTlv_Actor_c									= 0x01,
	LacpTlv_Partner_c								= 0x02,
	LacpTlv_Collector_c								= 0x03,
	
	LacpTlv_Marker_c								= 0x01,
	LacpTlv_MarkerResponse_c						= 0x02,
};



#	ifdef __cplusplus
}
#	endif

#endif	// __LACP_PROTO_CONSTS_H__
