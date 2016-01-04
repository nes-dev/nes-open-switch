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

#ifndef ___IANA_INET_H__
#	define ___IANA_INET_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>


enum {
	AddressFamilyNumbers_other_c = 0,
	AddressFamilyNumbers_ipV4_c = 1,
	AddressFamilyNumbers_ipV6_c = 2,
	AddressFamilyNumbers_nsap_c = 3,
	AddressFamilyNumbers_hdlc_c = 4,
	AddressFamilyNumbers_bbn1822_c = 5,
	AddressFamilyNumbers_all802_c = 6,
	AddressFamilyNumbers_e163_c = 7,
	AddressFamilyNumbers_e164_c = 8,
	AddressFamilyNumbers_f69_c = 9,
	AddressFamilyNumbers_x121_c = 10,
	AddressFamilyNumbers_ipx_c = 11,
	AddressFamilyNumbers_appleTalk_c = 12,
	AddressFamilyNumbers_decnetIV_c = 13,
	AddressFamilyNumbers_banyanVines_c = 14,
	AddressFamilyNumbers_e164withNsap_c = 15,
	AddressFamilyNumbers_dns_c = 16,
	AddressFamilyNumbers_distinguishedName_c = 17,
	AddressFamilyNumbers_asNumber_c = 18,
	AddressFamilyNumbers_xtpOverIpv4_c = 19,
	AddressFamilyNumbers_xtpOverIpv6_c = 20,
	AddressFamilyNumbers_xtpNativeModeXTP_c = 21,
	AddressFamilyNumbers_fibreChannelWWPN_c = 22,
	AddressFamilyNumbers_fibreChannelWWNN_c = 23,
	AddressFamilyNumbers_gwid_c = 24,
	AddressFamilyNumbers_afi_c = 25,
	AddressFamilyNumbers_reserved_c = 65535,
};

enum
{
	InetAddressType_unknown_c		= 0,
	InetAddressType_ipv4_c			= 1,
	InetAddressType_ipv6_c			= 2,
	InetAddressType_ipv4z_c			= 3,
	InetAddressType_ipv6z_c			= 4,
	InetAddressType_dns_c			= 16,
	
	InetAddress_size_c				= 20,
	InetAddressIPv4_size_c 			= 4,
	InetAddressIPv6_size_c 			= 16,
	InetAddressIPv4z_size_c 		= 8,
	InetAddressIPv6z_size_c 		= 20,
	InetAddressVpnIPv4_size_c		= 12,
	InetAddressVpnIPv6_size_c		= 24,
	
	InetZoneIndex_size_c			= 4,
	
	InetVersion_unknown_c 			= 0,
	InetVersion_ipv4_c 				= 1,
	InetVersion_ipv6_c 				= 2,
};

typedef uint8_t InetAddress_t [InetAddress_size_c];
typedef uint8_t InetAddressIPv4_t [InetAddressIPv4_size_c];
typedef uint8_t InetAddressIPv6_t [InetAddressIPv6_size_c];
typedef uint8_t InetAddressIPv4z_t [InetAddressIPv4z_size_c];
typedef uint8_t InetAddressIPv6z_t [InetAddressIPv6z_size_c];
typedef uint8_t InetAddressVpnIPv4_t [InetAddressVpnIPv4_size_c];
typedef uint8_t InetAddressVpnIPv6_t [InetAddressVpnIPv6_size_c];

enum
{
	IpRouteProtocol_other_c = 1,
	IpRouteProtocol_local_c = 2,
	IpRouteProtocol_netmgmt_c = 3,
	IpRouteProtocol_icmp_c = 4,
	IpRouteProtocol_egp_c = 5,
	IpRouteProtocol_ggp_c = 6,
	IpRouteProtocol_hello_c = 7,
	IpRouteProtocol_rip_c = 8,
	IpRouteProtocol_isIs_c = 9,
	IpRouteProtocol_esIs_c = 10,
	IpRouteProtocol_ciscoIgrp_c = 11,
	IpRouteProtocol_bbnSpfIgp_c = 12,
	IpRouteProtocol_ospf_c = 13,
	IpRouteProtocol_bgp_c = 14,
	IpRouteProtocol_idpr_c = 15,
	IpRouteProtocol_ciscoEigrp_c = 16,
	IpRouteProtocol_dvmrp_c = 17,
};

enum
{
	IpMRouteProtocol_other_c = 1,
	IpMRouteProtocol_local_c = 2,
	IpMRouteProtocol_netmgmt_c = 3,
	IpMRouteProtocol_dvmrp_c = 4,
	IpMRouteProtocol_mospf_c = 5,
	IpMRouteProtocol_pimSparseDense_c = 6,
	IpMRouteProtocol_cbt_c = 7,
	IpMRouteProtocol_pimSparseMode_c = 8,
	IpMRouteProtocol_pimDenseMode_c = 9,
	IpMRouteProtocol_igmpOnly_c = 10,
	IpMRouteProtocol_bgmp_c = 11,
	IpMRouteProtocol_msdp_c = 12,
};



#	ifdef __cplusplus
}
#	endif

#endif	// ___IANA_INET_H__
