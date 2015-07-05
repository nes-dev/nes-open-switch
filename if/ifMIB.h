/*
 *  Copyright (c) 2008-2015
 *      NES Dev <nes.open.switch@gmail.com>
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

#ifndef __IFMIB_H__
#	define __IFMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/lib.h"
#include "lib/ieee802.h"
#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ifMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of interfaces **/
#define IFNUMBER 1

typedef struct interfaces_t
{
	int32_t i32IfNumber;
	
	xRwLock_t oIfLock;
	xRwLock_t oStackLock;
} interfaces_t;

extern interfaces_t oInterfaces;

#ifdef SNMP_SRC
Netsnmp_Node_Handler interfaces_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of ifMIBObjects **/
#define IFTABLELASTCHANGE 5
#define IFSTACKLASTCHANGE 6

typedef struct ifMIBObjects_t
{
	uint32_t u32TableLastChange;
	uint32_t u32StackLastChange;
} ifMIBObjects_t;

extern ifMIBObjects_t oIfMIBObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ifMIBObjects_mapper;
#endif	/* SNMP_SRC */

#define ifTable_wrLock() (xRwLock_wrLock (&oInterfaces.oIfLock))
#define ifTable_rdLock() (xRwLock_rdLock (&oInterfaces.oIfLock))
#define ifTable_unLock() (xRwLock_unlock (&oInterfaces.oIfLock))

#define ifStack_wrLock() (xRwLock_wrLock (&oInterfaces.oStackLock))
#define ifStack_rdLock() (xRwLock_rdLock (&oInterfaces.oStackLock))
#define ifStack_unLock() (xRwLock_unlock (&oInterfaces.oStackLock))



/**
 *	table mapper(s)
 */
/**
 *	table ifXTable definitions
 */
#define IFNAME 1
#define IFINMULTICASTPKTS 2
#define IFINBROADCASTPKTS 3
#define IFOUTMULTICASTPKTS 4
#define IFOUTBROADCASTPKTS 5
#define IFHCINOCTETS 6
#define IFHCINUCASTPKTS 7
#define IFHCINMULTICASTPKTS 8
#define IFHCINBROADCASTPKTS 9
#define IFHCOUTOCTETS 10
#define IFHCOUTUCASTPKTS 11
#define IFHCOUTMULTICASTPKTS 12
#define IFHCOUTBROADCASTPKTS 13
#define IFLINKUPDOWNTRAPENABLE 14
#define IFHIGHSPEED 15
#define IFPROMISCUOUSMODE 16
#define IFCONNECTORPRESENT 17
#define IFALIAS 18
#define IFCOUNTERDISCONTINUITYTIME 19

enum
{
	/* enums for column ifLinkUpDownTrapEnable */
	ifLinkUpDownTrapEnable_enabled_c = 1,
	ifLinkUpDownTrapEnable_disabled_c = 2,

	/* enums for column ifPromiscuousMode */
	ifPromiscuousMode_true_c = 1,
	ifPromiscuousMode_false_c = 2,

	/* enums for column ifConnectorPresent */
	ifConnectorPresent_true_c = 1,
	ifConnectorPresent_false_c = 2,
};

/* table ifXTable row entry data structure */
typedef struct ifXEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint32_t u32InMulticastPkts;
	uint32_t u32InBroadcastPkts;
	uint32_t u32OutMulticastPkts;
	uint32_t u32OutBroadcastPkts;
	uint64_t u64HCInOctets;
	uint64_t u64HCInUcastPkts;
	uint64_t u64HCInMulticastPkts;
	uint64_t u64HCInBroadcastPkts;
	uint64_t u64HCOutOctets;
	uint64_t u64HCOutUcastPkts;
	uint64_t u64HCOutMulticastPkts;
	uint64_t u64HCOutBroadcastPkts;
	int32_t i32LinkUpDownTrapEnable;
	uint32_t u32HighSpeed;
	uint8_t u8PromiscuousMode;
	uint8_t u8ConnectorPresent;
	uint8_t au8Alias[64];
	size_t u16Alias_len;	/* # of uint8_t elements */
	uint32_t u32CounterDiscontinuityTime;
	
// 	xBTree_Node_t oBTreeNode;
} ifXEntry_t;

// extern xBTree_t oIfXTable_BTree;

/* ifXTable table mapper */
void ifXTable_init (void);
ifXEntry_t * ifXTable_createEntry (
	uint32_t u32Index);
ifXEntry_t * ifXTable_getByIndex (
	uint32_t u32Index);
ifXEntry_t * ifXTable_getNextIndex (
	uint32_t u32Index);
void ifXTable_removeEntry (ifXEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ifXTable_getFirst;
Netsnmp_Next_Data_Point ifXTable_getNext;
Netsnmp_Get_Data_Point ifXTable_get;
Netsnmp_Node_Handler ifXTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ifStackTable definitions
 */
#define IFSTACKHIGHERLAYER 1
#define IFSTACKLOWERLAYER 2
#define IFSTACKSTATUS 3

enum
{
	/* enums for column ifStackStatus */
	ifStackStatus_active_c = 1,
	ifStackStatus_notInService_c = 2,
	ifStackStatus_notReady_c = 3,
	ifStackStatus_createAndGo_c = 4,
	ifStackStatus_createAndWait_c = 5,
	ifStackStatus_destroy_c = 6,
};

/* table ifStackTable row entry data structure */
typedef struct ifStackEntry_t
{
	/* Index values */
	uint32_t u32HigherLayer;
	uint32_t u32LowerLayer;
	
	/* Column values */
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oLToH_BTreeNode;
} ifStackEntry_t;

extern xBTree_t oIfStackTable_BTree;
extern xBTree_t oIfStackTable_LToH_BTree;

/* ifStackTable table mapper */
void ifStackTable_init (void);
ifStackEntry_t * ifStackTable_createEntry (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
ifStackEntry_t * ifStackTable_getByIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
ifStackEntry_t * ifStackTable_getNextIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
ifStackEntry_t * ifStackTable_LToH_getNextIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
void ifStackTable_removeEntry (ifStackEntry_t *poEntry);
bool ifStackTable_createRegister (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
bool ifStackTable_removeRegister (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
ifStackEntry_t * ifStackTable_createExt (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer);
bool ifStackTable_removeExt (ifStackEntry_t *poEntry);
bool ifStackTable_createHier (ifStackEntry_t *poEntry);
bool ifStackTable_removeHier (ifStackEntry_t *poEntry);
bool ifStackStatus_handler (
	ifStackEntry_t *poEntry, uint8_t u8Status);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ifStackTable_getFirst;
Netsnmp_Next_Data_Point ifStackTable_getNext;
Netsnmp_Get_Data_Point ifStackTable_get;
Netsnmp_Node_Handler ifStackTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ifRcvAddressTable definitions
 */
#define IFRCVADDRESSADDRESS 1
#define IFRCVADDRESSSTATUS 2
#define IFRCVADDRESSTYPE 3

enum
{
	/* enums for column ifRcvAddressStatus */
	ifRcvAddressStatus_active_c = 1,
	ifRcvAddressStatus_notInService_c = 2,
	ifRcvAddressStatus_notReady_c = 3,
	ifRcvAddressStatus_createAndGo_c = 4,
	ifRcvAddressStatus_createAndWait_c = 5,
	ifRcvAddressStatus_destroy_c = 6,

	/* enums for column ifRcvAddressType */
	ifRcvAddressType_other_c = 1,
	ifRcvAddressType_volatile_c = 2,
	ifRcvAddressType_nonVolatile_c = 3,
};

/* table ifRcvAddressTable row entry data structure */
typedef struct ifRcvAddressEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint8_t au8Address[IeeeEui64_size_c];
	size_t u16Address_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t u8Status;
	int32_t i32Type;
	
	uint32_t u32NumReferences;
	
	xBTree_Node_t oBTreeNode;
} ifRcvAddressEntry_t;

extern xBTree_t oIfRcvAddressTable_BTree;

/* ifRcvAddressTable table mapper */
void ifRcvAddressTable_init (void);
ifRcvAddressEntry_t * ifRcvAddressTable_createEntry (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len);
ifRcvAddressEntry_t * ifRcvAddressTable_getByIndex (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len);
ifRcvAddressEntry_t * ifRcvAddressTable_getNextIndex (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len);
void ifRcvAddressTable_removeEntry (ifRcvAddressEntry_t *poEntry);
bool ifRcvAddressTable_createRegister (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len);
bool ifRcvAddressTable_removeRegister (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ifRcvAddressTable_getFirst;
Netsnmp_Next_Data_Point ifRcvAddressTable_getNext;
Netsnmp_Get_Data_Point ifRcvAddressTable_get;
Netsnmp_Node_Handler ifRcvAddressTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIfTable definitions
 */
#define NEIFNAME 1
#define NEIFDESCR 2
#define NEIFTYPE 3
#define NEIFMTU 4
#define NEIFSPEED 5
#define NEIFPHYSADDRESS 6
#define NEIFADMINFLAGS 7
#define NEIFOPERFLAGS 8
#define NEIFROWSTATUS 9
#define NEIFSTORAGETYPE 10

enum
{
	/* enums for column neIfType */
	neIfType_other_c = 1,
	neIfType_regular1822_c = 2,
	neIfType_hdh1822_c = 3,
	neIfType_ddnX25_c = 4,
	neIfType_rfc877x25_c = 5,
	neIfType_ethernetCsmacd_c = 6,
	neIfType_iso88023Csmacd_c = 7,
	neIfType_iso88024TokenBus_c = 8,
	neIfType_iso88025TokenRing_c = 9,
	neIfType_iso88026Man_c = 10,
	neIfType_starLan_c = 11,
	neIfType_proteon10Mbit_c = 12,
	neIfType_proteon80Mbit_c = 13,
	neIfType_hyperchannel_c = 14,
	neIfType_fddi_c = 15,
	neIfType_lapb_c = 16,
	neIfType_sdlc_c = 17,
	neIfType_ds1_c = 18,
	neIfType_e1_c = 19,
	neIfType_basicISDN_c = 20,
	neIfType_primaryISDN_c = 21,
	neIfType_propPointToPointSerial_c = 22,
	neIfType_ppp_c = 23,
	neIfType_softwareLoopback_c = 24,
	neIfType_eon_c = 25,
	neIfType_ethernet3Mbit_c = 26,
	neIfType_nsip_c = 27,
	neIfType_slip_c = 28,
	neIfType_ultra_c = 29,
	neIfType_ds3_c = 30,
	neIfType_sip_c = 31,
	neIfType_frameRelay_c = 32,
	neIfType_rs232_c = 33,
	neIfType_para_c = 34,
	neIfType_arcnet_c = 35,
	neIfType_arcnetPlus_c = 36,
	neIfType_atm_c = 37,
	neIfType_miox25_c = 38,
	neIfType_sonet_c = 39,
	neIfType_x25ple_c = 40,
	neIfType_iso88022llc_c = 41,
	neIfType_localTalk_c = 42,
	neIfType_smdsDxi_c = 43,
	neIfType_frameRelayService_c = 44,
	neIfType_v35_c = 45,
	neIfType_hssi_c = 46,
	neIfType_hippi_c = 47,
	neIfType_modem_c = 48,
	neIfType_aal5_c = 49,
	neIfType_sonetPath_c = 50,
	neIfType_sonetVT_c = 51,
	neIfType_smdsIcip_c = 52,
	neIfType_propVirtual_c = 53,
	neIfType_propMultiplexor_c = 54,
	neIfType_ieee80212_c = 55,
	neIfType_fibreChannel_c = 56,
	neIfType_hippiInterface_c = 57,
	neIfType_frameRelayInterconnect_c = 58,
	neIfType_aflane8023_c = 59,
	neIfType_aflane8025_c = 60,
	neIfType_cctEmul_c = 61,
	neIfType_fastEther_c = 62,
	neIfType_isdn_c = 63,
	neIfType_v11_c = 64,
	neIfType_v36_c = 65,
	neIfType_g703at64k_c = 66,
	neIfType_g703at2mb_c = 67,
	neIfType_qllc_c = 68,
	neIfType_fastEtherFX_c = 69,
	neIfType_channel_c = 70,
	neIfType_ieee80211_c = 71,
	neIfType_ibm370parChan_c = 72,
	neIfType_escon_c = 73,
	neIfType_dlsw_c = 74,
	neIfType_isdns_c = 75,
	neIfType_isdnu_c = 76,
	neIfType_lapd_c = 77,
	neIfType_ipSwitch_c = 78,
	neIfType_rsrb_c = 79,
	neIfType_atmLogical_c = 80,
	neIfType_ds0_c = 81,
	neIfType_ds0Bundle_c = 82,
	neIfType_bsc_c = 83,
	neIfType_async_c = 84,
	neIfType_cnr_c = 85,
	neIfType_iso88025Dtr_c = 86,
	neIfType_eplrs_c = 87,
	neIfType_arap_c = 88,
	neIfType_propCnls_c = 89,
	neIfType_hostPad_c = 90,
	neIfType_termPad_c = 91,
	neIfType_frameRelayMPI_c = 92,
	neIfType_x213_c = 93,
	neIfType_adsl_c = 94,
	neIfType_radsl_c = 95,
	neIfType_sdsl_c = 96,
	neIfType_vdsl_c = 97,
	neIfType_iso88025CRFPInt_c = 98,
	neIfType_myrinet_c = 99,
	neIfType_voiceEM_c = 100,
	neIfType_voiceFXO_c = 101,
	neIfType_voiceFXS_c = 102,
	neIfType_voiceEncap_c = 103,
	neIfType_voiceOverIp_c = 104,
	neIfType_atmDxi_c = 105,
	neIfType_atmFuni_c = 106,
	neIfType_atmIma_c = 107,
	neIfType_pppMultilinkBundle_c = 108,
	neIfType_ipOverCdlc_c = 109,
	neIfType_ipOverClaw_c = 110,
	neIfType_stackToStack_c = 111,
	neIfType_virtualIpAddress_c = 112,
	neIfType_mpc_c = 113,
	neIfType_ipOverAtm_c = 114,
	neIfType_iso88025Fiber_c = 115,
	neIfType_tdlc_c = 116,
	neIfType_gigabitEthernet_c = 117,
	neIfType_hdlc_c = 118,
	neIfType_lapf_c = 119,
	neIfType_v37_c = 120,
	neIfType_x25mlp_c = 121,
	neIfType_x25huntGroup_c = 122,
	neIfType_transpHdlc_c = 123,
	neIfType_interleave_c = 124,
	neIfType_fast_c = 125,
	neIfType_ip_c = 126,
	neIfType_docsCableMaclayer_c = 127,
	neIfType_docsCableDownstream_c = 128,
	neIfType_docsCableUpstream_c = 129,
	neIfType_a12MppSwitch_c = 130,
	neIfType_tunnel_c = 131,
	neIfType_coffee_c = 132,
	neIfType_ces_c = 133,
	neIfType_atmSubInterface_c = 134,
	neIfType_l2vlan_c = 135,
	neIfType_l3ipvlan_c = 136,
	neIfType_l3ipxvlan_c = 137,
	neIfType_digitalPowerline_c = 138,
	neIfType_mediaMailOverIp_c = 139,
	neIfType_dtm_c = 140,
	neIfType_dcn_c = 141,
	neIfType_ipForward_c = 142,
	neIfType_msdsl_c = 143,
	neIfType_ieee1394_c = 144,
	neIfType_if_gsn_c = 145,
	neIfType_dvbRccMacLayer_c = 146,
	neIfType_dvbRccDownstream_c = 147,
	neIfType_dvbRccUpstream_c = 148,
	neIfType_atmVirtual_c = 149,
	neIfType_mplsTunnel_c = 150,
	neIfType_srp_c = 151,
	neIfType_voiceOverAtm_c = 152,
	neIfType_voiceOverFrameRelay_c = 153,
	neIfType_idsl_c = 154,
	neIfType_compositeLink_c = 155,
	neIfType_ss7SigLink_c = 156,
	neIfType_propWirelessP2P_c = 157,
	neIfType_frForward_c = 158,
	neIfType_rfc1483_c = 159,
	neIfType_usb_c = 160,
	neIfType_ieee8023adLag_c = 161,
	neIfType_bgppolicyaccounting_c = 162,
	neIfType_frf16MfrBundle_c = 163,
	neIfType_h323Gatekeeper_c = 164,
	neIfType_h323Proxy_c = 165,
	neIfType_mpls_c = 166,
	neIfType_mfSigLink_c = 167,
	neIfType_hdsl2_c = 168,
	neIfType_shdsl_c = 169,
	neIfType_ds1FDL_c = 170,
	neIfType_pos_c = 171,
	neIfType_dvbAsiIn_c = 172,
	neIfType_dvbAsiOut_c = 173,
	neIfType_plc_c = 174,
	neIfType_nfas_c = 175,
	neIfType_tr008_c = 176,
	neIfType_gr303RDT_c = 177,
	neIfType_gr303IDT_c = 178,
	neIfType_isup_c = 179,
	neIfType_propDocsWirelessMaclayer_c = 180,
	neIfType_propDocsWirelessDownstream_c = 181,
	neIfType_propDocsWirelessUpstream_c = 182,
	neIfType_hiperlan2_c = 183,
	neIfType_propBWAp2Mp_c = 184,
	neIfType_sonetOverheadChannel_c = 185,
	neIfType_digitalWrapperOverheadChannel_c = 186,
	neIfType_aal2_c = 187,
	neIfType_radioMAC_c = 188,
	neIfType_atmRadio_c = 189,
	neIfType_imt_c = 190,
	neIfType_mvl_c = 191,
	neIfType_reachDSL_c = 192,
	neIfType_frDlciEndPt_c = 193,
	neIfType_atmVciEndPt_c = 194,
	neIfType_opticalChannel_c = 195,
	neIfType_opticalTransport_c = 196,
	neIfType_propAtm_c = 197,
	neIfType_voiceOverCable_c = 198,
	neIfType_infiniband_c = 199,
	neIfType_teLink_c = 200,
	neIfType_q2931_c = 201,
	neIfType_virtualTg_c = 202,
	neIfType_sipTg_c = 203,
	neIfType_sipSig_c = 204,
	neIfType_docsCableUpstreamChannel_c = 205,
	neIfType_econet_c = 206,
	neIfType_pon155_c = 207,
	neIfType_pon622_c = 208,
	neIfType_bridge_c = 209,
	neIfType_linegroup_c = 210,
	neIfType_voiceEMFGD_c = 211,
	neIfType_voiceFGDEANA_c = 212,
	neIfType_voiceDID_c = 213,
	neIfType_mpegTransport_c = 214,
	neIfType_sixToFour_c = 215,
	neIfType_gtp_c = 216,
	neIfType_pdnEtherLoop1_c = 217,
	neIfType_pdnEtherLoop2_c = 218,
	neIfType_opticalChannelGroup_c = 219,
	neIfType_homepna_c = 220,
	neIfType_gfp_c = 221,
	neIfType_ciscoISLvlan_c = 222,
	neIfType_actelisMetaLOOP_c = 223,
	neIfType_fcipLink_c = 224,
	neIfType_rpr_c = 225,
	neIfType_qam_c = 226,
	neIfType_lmp_c = 227,
	neIfType_cblVectaStar_c = 228,
	neIfType_docsCableMCmtsDownstream_c = 229,
	neIfType_adsl2_c = 230,
	neIfType_macSecControlledIF_c = 231,
	neIfType_macSecUncontrolledIF_c = 232,
	neIfType_aviciOpticalEther_c = 233,
	neIfType_atmbond_c = 234,
	neIfType_voiceFGDOS_c = 235,
	neIfType_mocaVersion1_c = 236,
	neIfType_ieee80216WMAN_c = 237,
	neIfType_adsl2plus_c = 238,
	neIfType_dvbRcsMacLayer_c = 239,
	neIfType_dvbTdm_c = 240,
	neIfType_dvbRcsTdma_c = 241,
	neIfType_x86Laps_c = 242,
	neIfType_wwanPP_c = 243,
	neIfType_wwanPP2_c = 244,
	neIfType_voiceEBS_c = 245,
	neIfType_ifPwType_c = 246,
	neIfType_ilan_c = 247,
	neIfType_pip_c = 248,
	neIfType_aluELP_c = 249,
	neIfType_gpon_c = 250,
	neIfType_vdsl2_c = 251,
	neIfType_capwapDot11Profile_c = 252,
	neIfType_capwapDot11Bss_c = 253,
	neIfType_capwapWtpVirtualRadio_c = 254,
	neIfType_bits_c = 255,
	neIfType_docsCableUpstreamRfPort_c = 256,
	neIfType_cableDownstreamRfPort_c = 257,
	neIfType_vmwareVirtualNic_c = 258,
	neIfType_ieee802154_c = 259,
	neIfType_otnOdu_c = 260,
	neIfType_otnOtu_c = 261,
	neIfType_ifVfiType_c = 262,
	neIfType_g9981_c = 263,
	neIfType_g9982_c = 264,
	neIfType_g9983_c = 265,
	neIfType_aluEpon_c = 266,
	neIfType_aluEponOnu_c = 267,
	neIfType_aluEponPhysicalUni_c = 268,
	neIfType_aluEponLogicalLink_c = 269,
	neIfType_aluGponOnu_c = 270,
	neIfType_aluGponPhysicalUni_c = 271,
	neIfType_vmwareNicTeam_c = 272,

	/* enums for column neIfAdminFlags */
	neIfAdminFlags_speed10Mbps_c = 0,
	neIfAdminFlags_speed100Mbps_c = 1,
	neIfAdminFlags_speed1Gbps_c = 2,
	neIfAdminFlags_speed10Gbps_c = 3,
	neIfAdminFlags_speed40Gbps_c = 4,
	neIfAdminFlags_speed100Gbps_c = 5,
	neIfAdminFlags_speed1Tbps_c = 6,
	neIfAdminFlags_speedOther_c = 7,
	neIfAdminFlags_copper_c = 8,
	neIfAdminFlags_fiber_c = 9,
	neIfAdminFlags_autoNeg_c = 10,
	neIfAdminFlags_pause_c = 11,
	neIfAdminFlags_pauseAsym_c = 12,
	neIfAdminFlags_fullDuplex_c = 13,
	neIfAdminFlags_halfDuplex_c = 14,
	neIfAdminFlags_oam_c = 15,
	neIfAdminFlags_xCat_c = 16,
	neIfAdminFlags_xCatVc_c = 17,
	neIfAdminFlags_lag_c = 18,
	neIfAdminFlags_macLearn_c = 19,
	neIfAdminFlags_macFwd_c = 20,
	neIfAdminFlags_vlanFwd_c = 21,
	neIfAdminFlags_pbbFwd_c = 22,
	neIfAdminFlags_mplsFwd_c = 23,
	neIfAdminFlags_ipFwd_c = 24,
	neIfAdminFlags_te_c = 25,

	/* enums for column neIfOperFlags */
	neIfOperFlags_speed10Mbps_c = 0,
	neIfOperFlags_speed100Mbps_c = 1,
	neIfOperFlags_speed1Gbps_c = 2,
	neIfOperFlags_speed10Gbps_c = 3,
	neIfOperFlags_speed40Gbps_c = 4,
	neIfOperFlags_speed100Gbps_c = 5,
	neIfOperFlags_speed1Tbps_c = 6,
	neIfOperFlags_speedOther_c = 7,
	neIfOperFlags_copper_c = 8,
	neIfOperFlags_fiber_c = 9,
	neIfOperFlags_autoNeg_c = 10,
	neIfOperFlags_pause_c = 11,
	neIfOperFlags_pauseAsym_c = 12,
	neIfOperFlags_fullDuplex_c = 13,
	neIfOperFlags_halfDuplex_c = 14,
	neIfOperFlags_oam_c = 15,
	neIfOperFlags_xCat_c = 16,
	neIfOperFlags_xCatVc_c = 17,
	neIfOperFlags_lag_c = 18,
	neIfOperFlags_macLearn_c = 19,
	neIfOperFlags_macFwd_c = 20,
	neIfOperFlags_vlanFwd_c = 21,
	neIfOperFlags_pbbFwd_c = 22,
	neIfOperFlags_mplsFwd_c = 23,
	neIfOperFlags_ipFwd_c = 24,
	neIfOperFlags_te_c = 25,

	/* enums for column neIfRowStatus */
	neIfRowStatus_active_c = 1,
	neIfRowStatus_notInService_c = 2,
	neIfRowStatus_notReady_c = 3,
	neIfRowStatus_createAndGo_c = 4,
	neIfRowStatus_createAndWait_c = 5,
	neIfRowStatus_destroy_c = 6,

	/* enums for column neIfStorageType */
	neIfStorageType_other_c = 1,
	neIfStorageType_volatile_c = 2,
	neIfStorageType_nonVolatile_c = 3,
	neIfStorageType_permanent_c = 4,
	neIfStorageType_readOnly_c = 5,
};

/* table neIfTable row entry data structure */
typedef struct neIfEntry_t
{
	/* Index values */
// 	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8Descr[32];
	size_t u16Descr_len;	/* # of uint8_t elements */
	int32_t i32Type;
	int32_t i32Mtu;
	uint8_t au8Speed[8];
	size_t u16Speed_len;	/* # of uint8_t elements */
	uint8_t au8PhysAddress[8];
	size_t u16PhysAddress_len;	/* # of uint8_t elements */
	uint8_t au8AdminFlags[3];
	size_t u16AdminFlags_len;	/* # of uint8_t elements */
	uint8_t au8OperFlags[3];
	size_t u16OperFlags_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	struct neIfEntry_t *poOldEntry;
	
// 	xBTree_Node_t oBTreeNode;
} neIfEntry_t;

// extern xBTree_t oNeIfTable_BTree;

/* neIfTable table mapper */
void neIfTable_init (void);
neIfEntry_t * neIfTable_createEntry (
	uint32_t u32IfIndex);
neIfEntry_t * neIfTable_getByIndex (
	uint32_t u32IfIndex);
neIfEntry_t * neIfTable_getNextIndex (
	uint32_t u32IfIndex);
void neIfTable_removeEntry (neIfEntry_t *poEntry);
neIfEntry_t * neIfTable_createExt (
	uint32_t u32IfIndex);
bool neIfTable_removeExt (neIfEntry_t *poEntry);
bool neIfTable_createHier (neIfEntry_t *poEntry);
bool neIfTable_removeHier (neIfEntry_t *poEntry);
bool neIfRowStatus_handler (
	neIfEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIfTable_getFirst;
Netsnmp_Next_Data_Point neIfTable_getNext;
Netsnmp_Get_Data_Point neIfTable_get;
Netsnmp_Node_Handler neIfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ifTable definitions
 */
#define IFINDEX 1
#define IFDESCR 2
#define IFTYPE 3
#define IFMTU 4
#define IFSPEED 5
#define IFPHYSADDRESS 6
#define IFADMINSTATUS 7
#define IFOPERSTATUS 8
#define IFLASTCHANGE 9
#define IFINOCTETS 10
#define IFINUCASTPKTS 11
#define IFINDISCARDS 13
#define IFINERRORS 14
#define IFINUNKNOWNPROTOS 15
#define IFOUTOCTETS 16
#define IFOUTUCASTPKTS 17
#define IFOUTDISCARDS 19
#define IFOUTERRORS 20

enum
{
	ifIndex_zero_c = 0,
	
	/* enums for column ifType */
	ifType_other_c = 1,
	ifType_regular1822_c = 2,
	ifType_hdh1822_c = 3,
	ifType_ddnX25_c = 4,
	ifType_rfc877x25_c = 5,
	ifType_ethernetCsmacd_c = 6,
	ifType_iso88023Csmacd_c = 7,
	ifType_iso88024TokenBus_c = 8,
	ifType_iso88025TokenRing_c = 9,
	ifType_iso88026Man_c = 10,
	ifType_starLan_c = 11,
	ifType_proteon10Mbit_c = 12,
	ifType_proteon80Mbit_c = 13,
	ifType_hyperchannel_c = 14,
	ifType_fddi_c = 15,
	ifType_lapb_c = 16,
	ifType_sdlc_c = 17,
	ifType_ds1_c = 18,
	ifType_e1_c = 19,
	ifType_basicISDN_c = 20,
	ifType_primaryISDN_c = 21,
	ifType_propPointToPointSerial_c = 22,
	ifType_ppp_c = 23,
	ifType_softwareLoopback_c = 24,
	ifType_eon_c = 25,
	ifType_ethernet3Mbit_c = 26,
	ifType_nsip_c = 27,
	ifType_slip_c = 28,
	ifType_ultra_c = 29,
	ifType_ds3_c = 30,
	ifType_sip_c = 31,
	ifType_frameRelay_c = 32,
	ifType_rs232_c = 33,
	ifType_para_c = 34,
	ifType_arcnet_c = 35,
	ifType_arcnetPlus_c = 36,
	ifType_atm_c = 37,
	ifType_miox25_c = 38,
	ifType_sonet_c = 39,
	ifType_x25ple_c = 40,
	ifType_iso88022llc_c = 41,
	ifType_localTalk_c = 42,
	ifType_smdsDxi_c = 43,
	ifType_frameRelayService_c = 44,
	ifType_v35_c = 45,
	ifType_hssi_c = 46,
	ifType_hippi_c = 47,
	ifType_modem_c = 48,
	ifType_aal5_c = 49,
	ifType_sonetPath_c = 50,
	ifType_sonetVT_c = 51,
	ifType_smdsIcip_c = 52,
	ifType_propVirtual_c = 53,
	ifType_propMultiplexor_c = 54,
	ifType_ieee80212_c = 55,
	ifType_fibreChannel_c = 56,
	ifType_hippiInterface_c = 57,
	ifType_frameRelayInterconnect_c = 58,
	ifType_aflane8023_c = 59,
	ifType_aflane8025_c = 60,
	ifType_cctEmul_c = 61,
	ifType_fastEther_c = 62,
	ifType_isdn_c = 63,
	ifType_v11_c = 64,
	ifType_v36_c = 65,
	ifType_g703at64k_c = 66,
	ifType_g703at2mb_c = 67,
	ifType_qllc_c = 68,
	ifType_fastEtherFX_c = 69,
	ifType_channel_c = 70,
	ifType_ieee80211_c = 71,
	ifType_ibm370parChan_c = 72,
	ifType_escon_c = 73,
	ifType_dlsw_c = 74,
	ifType_isdns_c = 75,
	ifType_isdnu_c = 76,
	ifType_lapd_c = 77,
	ifType_ipSwitch_c = 78,
	ifType_rsrb_c = 79,
	ifType_atmLogical_c = 80,
	ifType_ds0_c = 81,
	ifType_ds0Bundle_c = 82,
	ifType_bsc_c = 83,
	ifType_async_c = 84,
	ifType_cnr_c = 85,
	ifType_iso88025Dtr_c = 86,
	ifType_eplrs_c = 87,
	ifType_arap_c = 88,
	ifType_propCnls_c = 89,
	ifType_hostPad_c = 90,
	ifType_termPad_c = 91,
	ifType_frameRelayMPI_c = 92,
	ifType_x213_c = 93,
	ifType_adsl_c = 94,
	ifType_radsl_c = 95,
	ifType_sdsl_c = 96,
	ifType_vdsl_c = 97,
	ifType_iso88025CRFPInt_c = 98,
	ifType_myrinet_c = 99,
	ifType_voiceEM_c = 100,
	ifType_voiceFXO_c = 101,
	ifType_voiceFXS_c = 102,
	ifType_voiceEncap_c = 103,
	ifType_voiceOverIp_c = 104,
	ifType_atmDxi_c = 105,
	ifType_atmFuni_c = 106,
	ifType_atmIma_c = 107,
	ifType_pppMultilinkBundle_c = 108,
	ifType_ipOverCdlc_c = 109,
	ifType_ipOverClaw_c = 110,
	ifType_stackToStack_c = 111,
	ifType_virtualIpAddress_c = 112,
	ifType_mpc_c = 113,
	ifType_ipOverAtm_c = 114,
	ifType_iso88025Fiber_c = 115,
	ifType_tdlc_c = 116,
	ifType_gigabitEthernet_c = 117,
	ifType_hdlc_c = 118,
	ifType_lapf_c = 119,
	ifType_v37_c = 120,
	ifType_x25mlp_c = 121,
	ifType_x25huntGroup_c = 122,
	ifType_transpHdlc_c = 123,
	ifType_interleave_c = 124,
	ifType_fast_c = 125,
	ifType_ip_c = 126,
	ifType_docsCableMaclayer_c = 127,
	ifType_docsCableDownstream_c = 128,
	ifType_docsCableUpstream_c = 129,
	ifType_a12MppSwitch_c = 130,
	ifType_tunnel_c = 131,
	ifType_coffee_c = 132,
	ifType_ces_c = 133,
	ifType_atmSubInterface_c = 134,
	ifType_l2vlan_c = 135,
	ifType_l3ipvlan_c = 136,
	ifType_l3ipxvlan_c = 137,
	ifType_digitalPowerline_c = 138,
	ifType_mediaMailOverIp_c = 139,
	ifType_dtm_c = 140,
	ifType_dcn_c = 141,
	ifType_ipForward_c = 142,
	ifType_msdsl_c = 143,
	ifType_ieee1394_c = 144,
	ifType_if_gsn_c = 145,
	ifType_dvbRccMacLayer_c = 146,
	ifType_dvbRccDownstream_c = 147,
	ifType_dvbRccUpstream_c = 148,
	ifType_atmVirtual_c = 149,
	ifType_mplsTunnel_c = 150,
	ifType_srp_c = 151,
	ifType_voiceOverAtm_c = 152,
	ifType_voiceOverFrameRelay_c = 153,
	ifType_idsl_c = 154,
	ifType_compositeLink_c = 155,
	ifType_ss7SigLink_c = 156,
	ifType_propWirelessP2P_c = 157,
	ifType_frForward_c = 158,
	ifType_rfc1483_c = 159,
	ifType_usb_c = 160,
	ifType_ieee8023adLag_c = 161,
	ifType_bgppolicyaccounting_c = 162,
	ifType_frf16MfrBundle_c = 163,
	ifType_h323Gatekeeper_c = 164,
	ifType_h323Proxy_c = 165,
	ifType_mpls_c = 166,
	ifType_mfSigLink_c = 167,
	ifType_hdsl2_c = 168,
	ifType_shdsl_c = 169,
	ifType_ds1FDL_c = 170,
	ifType_pos_c = 171,
	ifType_dvbAsiIn_c = 172,
	ifType_dvbAsiOut_c = 173,
	ifType_plc_c = 174,
	ifType_nfas_c = 175,
	ifType_tr008_c = 176,
	ifType_gr303RDT_c = 177,
	ifType_gr303IDT_c = 178,
	ifType_isup_c = 179,
	ifType_propDocsWirelessMaclayer_c = 180,
	ifType_propDocsWirelessDownstream_c = 181,
	ifType_propDocsWirelessUpstream_c = 182,
	ifType_hiperlan2_c = 183,
	ifType_propBWAp2Mp_c = 184,
	ifType_sonetOverheadChannel_c = 185,
	ifType_digitalWrapperOverheadChannel_c = 186,
	ifType_aal2_c = 187,
	ifType_radioMAC_c = 188,
	ifType_atmRadio_c = 189,
	ifType_imt_c = 190,
	ifType_mvl_c = 191,
	ifType_reachDSL_c = 192,
	ifType_frDlciEndPt_c = 193,
	ifType_atmVciEndPt_c = 194,
	ifType_opticalChannel_c = 195,
	ifType_opticalTransport_c = 196,
	ifType_propAtm_c = 197,
	ifType_voiceOverCable_c = 198,
	ifType_infiniband_c = 199,
	ifType_teLink_c = 200,
	ifType_q2931_c = 201,
	ifType_virtualTg_c = 202,
	ifType_sipTg_c = 203,
	ifType_sipSig_c = 204,
	ifType_docsCableUpstreamChannel_c = 205,
	ifType_econet_c = 206,
	ifType_pon155_c = 207,
	ifType_pon622_c = 208,
	ifType_bridge_c = 209,
	ifType_linegroup_c = 210,
	ifType_voiceEMFGD_c = 211,
	ifType_voiceFGDEANA_c = 212,
	ifType_voiceDID_c = 213,
	ifType_mpegTransport_c = 214,
	ifType_sixToFour_c = 215,
	ifType_gtp_c = 216,
	ifType_pdnEtherLoop1_c = 217,
	ifType_pdnEtherLoop2_c = 218,
	ifType_opticalChannelGroup_c = 219,
	ifType_homepna_c = 220,
	ifType_gfp_c = 221,
	ifType_ciscoISLvlan_c = 222,
	ifType_actelisMetaLOOP_c = 223,
	ifType_fcipLink_c = 224,
	ifType_rpr_c = 225,
	ifType_qam_c = 226,
	ifType_lmp_c = 227,
	ifType_cblVectaStar_c = 228,
	ifType_docsCableMCmtsDownstream_c = 229,
	ifType_adsl2_c = 230,
	ifType_macSecControlledIF_c = 231,
	ifType_macSecUncontrolledIF_c = 232,
	ifType_aviciOpticalEther_c = 233,
	ifType_atmbond_c = 234,
	ifType_voiceFGDOS_c = 235,
	ifType_mocaVersion1_c = 236,
	ifType_ieee80216WMAN_c = 237,
	ifType_adsl2plus_c = 238,
	ifType_dvbRcsMacLayer_c = 239,
	ifType_dvbTdm_c = 240,
	ifType_dvbRcsTdma_c = 241,
	ifType_x86Laps_c = 242,
	ifType_wwanPP_c = 243,
	ifType_wwanPP2_c = 244,
	ifType_voiceEBS_c = 245,
	ifType_ifPwType_c = 246,
	ifType_ilan_c = 247,
	ifType_pip_c = 248,
	ifType_aluELP_c = 249,
	ifType_gpon_c = 250,
	ifType_vdsl2_c = 251,
	ifType_capwapDot11Profile_c = 252,
	ifType_capwapDot11Bss_c = 253,
	ifType_capwapWtpVirtualRadio_c = 254,
	ifType_bits_c = 255,
	ifType_docsCableUpstreamRfPort_c = 256,
	ifType_cableDownstreamRfPort_c = 257,
	ifType_vmwareVirtualNic_c = 258,
	ifType_ieee802154_c = 259,
	ifType_otnOdu_c = 260,
	ifType_otnOtu_c = 261,
	ifType_ifVfiType_c = 262,
	ifType_g9981_c = 263,
	ifType_g9982_c = 264,
	ifType_g9983_c = 265,
	ifType_aluEpon_c = 266,
	ifType_aluEponOnu_c = 267,
	ifType_aluEponPhysicalUni_c = 268,
	ifType_aluEponLogicalLink_c = 269,
	ifType_aluGponOnu_c = 270,
	ifType_aluGponPhysicalUni_c = 271,
	ifType_vmwareNicTeam_c = 272,

	/* enums for column ifAdminStatus */
	ifAdminStatus_up_c = 1,
	ifAdminStatus_down_c = 2,
	ifAdminStatus_testing_c = 3,

	/* enums for column ifOperStatus */
	ifOperStatus_up_c = 1,
	ifOperStatus_down_c = 2,
	ifOperStatus_testing_c = 3,
	ifOperStatus_unknown_c = 4,
	ifOperStatus_dormant_c = 5,
	ifOperStatus_notPresent_c = 6,
	ifOperStatus_lowerLayerDown_c = 7,
};

/* table ifTable row entry data structure */
typedef struct ifEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Descr[32];
	size_t u16Descr_len;	/* # of uint8_t elements */
	int32_t i32Type;
	int32_t i32Mtu;
	uint32_t u32Speed;
	uint8_t au8PhysAddress[8];
	size_t u16PhysAddress_len;	/* # of uint8_t elements */
	int32_t i32AdminStatus;
	int32_t i32OperStatus;
	uint32_t u32LastChange;
	uint32_t u32InOctets;
	uint32_t u32InUcastPkts;
	uint32_t u32InDiscards;
	uint32_t u32InErrors;
	uint32_t u32InUnknownProtos;
	uint32_t u32OutOctets;
	uint32_t u32OutUcastPkts;
	uint32_t u32OutDiscards;
	uint32_t u32OutErrors;
	
	ifXEntry_t oX;
	neIfEntry_t oNe;
	
	uint32_t u32NumReferences;
	
	xBTree_Node_t oBTreeNode;
	xRwLock_t oLock;
} ifEntry_t;

extern xBTree_t oIfTable_BTree;

#define ifEntry_rdLock(poEntry) (xRwLock_rdLock (&(poEntry)->oLock))
#define ifEntry_wrLock(poEntry) (xRwLock_wrLock (&(poEntry)->oLock))
#define ifEntry_unLock(poEntry) (xRwLock_unlock (&(poEntry)->oLock))

/* ifTable table mapper */
void ifTable_init (void);
ifEntry_t * ifTable_createEntry (
	uint32_t u32Index);
ifEntry_t * ifTable_getByIndex (
	uint32_t u32Index);
ifEntry_t * ifTable_getNextIndex (
	uint32_t u32Index);
#define ifTable_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ifEntry_t, oNe))
#define ifTable_getByIfXEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ifEntry_t, oX))
void ifTable_removeEntry (ifEntry_t *poEntry);
ifEntry_t * ifTable_createExt (
	uint32_t u32Index);
bool ifTable_removeExt (ifEntry_t *poEntry);
bool ifTable_createHier (ifEntry_t *poEntry);
bool ifTable_removeHier (ifEntry_t *poEntry);
bool ifTable_getByIndexExt (
	uint32_t u32Index, bool bWrLock,
	ifEntry_t **ppoIfEntry);
bool ifTable_createReference (
	uint32_t u32IfIndex,
	int32_t i32Type,
	int32_t i32AdminStatus,
	bool bCreate, bool bReference, bool bActivate,
	ifEntry_t **ppoIfEntry);
bool ifTable_removeReference (
	uint32_t u32IfIndex,
	bool bCreate, bool bReference, bool bActivate);
bool ifAdminStatus_handler (
	ifEntry_t *poEntry,
	int32_t i32AdminStatus, bool bForce);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ifTable_getFirst;
Netsnmp_Next_Data_Point ifTable_getNext;
Netsnmp_Get_Data_Point ifTable_get;
Netsnmp_Node_Handler ifTable_mapper;
#endif	/* SNMP_SRC */


enum
{
	ifFlags_neCreated_c = 0,
	ifFlags_ifCreated_c = 1,
	ifFlags_ifXCreated_c = 2,
	ifFlags_count_c,
};

typedef struct ifData_t
{
	uint32_t u32Index;
	
	neIfEntry_t oNe;
	ifEntry_t oIf;
	ifXEntry_t oIfX;
	
	uint8_t au8Flags[1];
	uint32_t u32NumReferences;
	
	xBTree_Node_t oBTreeNode;
	xRwLock_t oLock;
} ifData_t;

// extern xBTree_t oIfData_BTree;

ifData_t * ifData_createEntry (
	uint32_t u32Index);
ifData_t * ifData_getByIndex (
	uint32_t u32Index);
ifData_t * ifData_getNextIndex (
	uint32_t u32Index);
#define ifData_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ifData_t, oNe))
#define ifData_getByIfEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ifData_t, oIf))
#define ifData_getByIfXEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ifData_t, oIfX))
void ifData_removeEntry (ifData_t *poEntry);
bool ifData_getByIndexExt (
	uint32_t u32Index, bool bWrLock,
	ifData_t **ppoIfData);
bool ifData_createReference (
	uint32_t u32IfIndex,
	int32_t i32Type,
	int32_t i32AdminStatus,
	bool bCreate, bool bReference, bool bActivate,
	ifData_t **ppoIfData);
bool ifData_removeReference (
	uint32_t u32IfIndex,
	bool bCreate, bool bReference, bool bActivate);
#define ifData_rdLock(poEntry) (xRwLock_rdLock (&(poEntry)->oLock))
#define ifData_wrLock(poEntry) (xRwLock_wrLock (&(poEntry)->oLock))
#define ifData_unLock(poEntry) (xRwLock_unlock (&(poEntry)->oLock))


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of snmpTraps */
#	define LINKDOWN 3
#	define LINKUP 4

/* snmpTraps mapper(s) */
int linkDown_trap (void);
int linkUp_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __IFMIB_H__ */
