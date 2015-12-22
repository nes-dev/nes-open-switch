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

#ifndef __NEXCMIB_H__
#	define __NEXCMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void neXcMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table neXcTable definitions
 */
#define NEXCINDEX 1
#define NEXCDESCR 2
#define NEXCTYPE 3
#define NEXCIFINDEX 4
#define NEXCADMINSTATUS 5
#define NEXCOPERSTATUS 6
#define NEXCROWSTATUS 7
#define NEXCSTORAGETYPE 8

enum
{
	/* enums for column neXcType */
	neXcType_other_c = 1,
	neXcType_regular1822_c = 2,
	neXcType_hdh1822_c = 3,
	neXcType_ddnX25_c = 4,
	neXcType_rfc877x25_c = 5,
	neXcType_ethernetCsmacd_c = 6,
	neXcType_iso88023Csmacd_c = 7,
	neXcType_iso88024TokenBus_c = 8,
	neXcType_iso88025TokenRing_c = 9,
	neXcType_iso88026Man_c = 10,
	neXcType_starLan_c = 11,
	neXcType_proteon10Mbit_c = 12,
	neXcType_proteon80Mbit_c = 13,
	neXcType_hyperchannel_c = 14,
	neXcType_fddi_c = 15,
	neXcType_lapb_c = 16,
	neXcType_sdlc_c = 17,
	neXcType_ds1_c = 18,
	neXcType_e1_c = 19,
	neXcType_basicISDN_c = 20,
	neXcType_primaryISDN_c = 21,
	neXcType_propPointToPointSerial_c = 22,
	neXcType_ppp_c = 23,
	neXcType_softwareLoopback_c = 24,
	neXcType_eon_c = 25,
	neXcType_ethernet3Mbit_c = 26,
	neXcType_nsip_c = 27,
	neXcType_slip_c = 28,
	neXcType_ultra_c = 29,
	neXcType_ds3_c = 30,
	neXcType_sip_c = 31,
	neXcType_frameRelay_c = 32,
	neXcType_rs232_c = 33,
	neXcType_para_c = 34,
	neXcType_arcnet_c = 35,
	neXcType_arcnetPlus_c = 36,
	neXcType_atm_c = 37,
	neXcType_miox25_c = 38,
	neXcType_sonet_c = 39,
	neXcType_x25ple_c = 40,
	neXcType_iso88022llc_c = 41,
	neXcType_localTalk_c = 42,
	neXcType_smdsDxi_c = 43,
	neXcType_frameRelayService_c = 44,
	neXcType_v35_c = 45,
	neXcType_hssi_c = 46,
	neXcType_hippi_c = 47,
	neXcType_modem_c = 48,
	neXcType_aal5_c = 49,
	neXcType_sonetPath_c = 50,
	neXcType_sonetVT_c = 51,
	neXcType_smdsIcip_c = 52,
	neXcType_propVirtual_c = 53,
	neXcType_propMultiplexor_c = 54,
	neXcType_ieee80212_c = 55,
	neXcType_fibreChannel_c = 56,
	neXcType_hippiInterface_c = 57,
	neXcType_frameRelayInterconnect_c = 58,
	neXcType_aflane8023_c = 59,
	neXcType_aflane8025_c = 60,
	neXcType_cctEmul_c = 61,
	neXcType_fastEther_c = 62,
	neXcType_isdn_c = 63,
	neXcType_v11_c = 64,
	neXcType_v36_c = 65,
	neXcType_g703at64k_c = 66,
	neXcType_g703at2mb_c = 67,
	neXcType_qllc_c = 68,
	neXcType_fastEtherFX_c = 69,
	neXcType_channel_c = 70,
	neXcType_ieee80211_c = 71,
	neXcType_ibm370parChan_c = 72,
	neXcType_escon_c = 73,
	neXcType_dlsw_c = 74,
	neXcType_isdns_c = 75,
	neXcType_isdnu_c = 76,
	neXcType_lapd_c = 77,
	neXcType_ipSwitch_c = 78,
	neXcType_rsrb_c = 79,
	neXcType_atmLogical_c = 80,
	neXcType_ds0_c = 81,
	neXcType_ds0Bundle_c = 82,
	neXcType_bsc_c = 83,
	neXcType_async_c = 84,
	neXcType_cnr_c = 85,
	neXcType_iso88025Dtr_c = 86,
	neXcType_eplrs_c = 87,
	neXcType_arap_c = 88,
	neXcType_propCnls_c = 89,
	neXcType_hostPad_c = 90,
	neXcType_termPad_c = 91,
	neXcType_frameRelayMPI_c = 92,
	neXcType_x213_c = 93,
	neXcType_adsl_c = 94,
	neXcType_radsl_c = 95,
	neXcType_sdsl_c = 96,
	neXcType_vdsl_c = 97,
	neXcType_iso88025CRFPInt_c = 98,
	neXcType_myrinet_c = 99,
	neXcType_voiceEM_c = 100,
	neXcType_voiceFXO_c = 101,
	neXcType_voiceFXS_c = 102,
	neXcType_voiceEncap_c = 103,
	neXcType_voiceOverIp_c = 104,
	neXcType_atmDxi_c = 105,
	neXcType_atmFuni_c = 106,
	neXcType_atmIma_c = 107,
	neXcType_pppMultilinkBundle_c = 108,
	neXcType_ipOverCdlc_c = 109,
	neXcType_ipOverClaw_c = 110,
	neXcType_stackToStack_c = 111,
	neXcType_virtualIpAddress_c = 112,
	neXcType_mpc_c = 113,
	neXcType_ipOverAtm_c = 114,
	neXcType_iso88025Fiber_c = 115,
	neXcType_tdlc_c = 116,
	neXcType_gigabitEthernet_c = 117,
	neXcType_hdlc_c = 118,
	neXcType_lapf_c = 119,
	neXcType_v37_c = 120,
	neXcType_x25mlp_c = 121,
	neXcType_x25huntGroup_c = 122,
	neXcType_transpHdlc_c = 123,
	neXcType_interleave_c = 124,
	neXcType_fast_c = 125,
	neXcType_ip_c = 126,
	neXcType_docsCableMaclayer_c = 127,
	neXcType_docsCableDownstream_c = 128,
	neXcType_docsCableUpstream_c = 129,
	neXcType_a12MppSwitch_c = 130,
	neXcType_tunnel_c = 131,
	neXcType_coffee_c = 132,
	neXcType_ces_c = 133,
	neXcType_atmSubInterface_c = 134,
	neXcType_l2vlan_c = 135,
	neXcType_l3ipvlan_c = 136,
	neXcType_l3ipxvlan_c = 137,
	neXcType_digitalPowerline_c = 138,
	neXcType_mediaMailOverIp_c = 139,
	neXcType_dtm_c = 140,
	neXcType_dcn_c = 141,
	neXcType_ipForward_c = 142,
	neXcType_msdsl_c = 143,
	neXcType_ieee1394_c = 144,
	neXcType_if_gsn_c = 145,
	neXcType_dvbRccMacLayer_c = 146,
	neXcType_dvbRccDownstream_c = 147,
	neXcType_dvbRccUpstream_c = 148,
	neXcType_atmVirtual_c = 149,
	neXcType_mplsTunnel_c = 150,
	neXcType_srp_c = 151,
	neXcType_voiceOverAtm_c = 152,
	neXcType_voiceOverFrameRelay_c = 153,
	neXcType_idsl_c = 154,
	neXcType_compositeLink_c = 155,
	neXcType_ss7SigLink_c = 156,
	neXcType_propWirelessP2P_c = 157,
	neXcType_frForward_c = 158,
	neXcType_rfc1483_c = 159,
	neXcType_usb_c = 160,
	neXcType_ieee8023adLag_c = 161,
	neXcType_bgppolicyaccounting_c = 162,
	neXcType_frf16MfrBundle_c = 163,
	neXcType_h323Gatekeeper_c = 164,
	neXcType_h323Proxy_c = 165,
	neXcType_mpls_c = 166,
	neXcType_mfSigLink_c = 167,
	neXcType_hdsl2_c = 168,
	neXcType_shdsl_c = 169,
	neXcType_ds1FDL_c = 170,
	neXcType_pos_c = 171,
	neXcType_dvbAsiIn_c = 172,
	neXcType_dvbAsiOut_c = 173,
	neXcType_plc_c = 174,
	neXcType_nfas_c = 175,
	neXcType_tr008_c = 176,
	neXcType_gr303RDT_c = 177,
	neXcType_gr303IDT_c = 178,
	neXcType_isup_c = 179,
	neXcType_propDocsWirelessMaclayer_c = 180,
	neXcType_propDocsWirelessDownstream_c = 181,
	neXcType_propDocsWirelessUpstream_c = 182,
	neXcType_hiperlan2_c = 183,
	neXcType_propBWAp2Mp_c = 184,
	neXcType_sonetOverheadChannel_c = 185,
	neXcType_digitalWrapperOverheadChannel_c = 186,
	neXcType_aal2_c = 187,
	neXcType_radioMAC_c = 188,
	neXcType_atmRadio_c = 189,
	neXcType_imt_c = 190,
	neXcType_mvl_c = 191,
	neXcType_reachDSL_c = 192,
	neXcType_frDlciEndPt_c = 193,
	neXcType_atmVciEndPt_c = 194,
	neXcType_opticalChannel_c = 195,
	neXcType_opticalTransport_c = 196,
	neXcType_propAtm_c = 197,
	neXcType_voiceOverCable_c = 198,
	neXcType_infiniband_c = 199,
	neXcType_teLink_c = 200,
	neXcType_q2931_c = 201,
	neXcType_virtualTg_c = 202,
	neXcType_sipTg_c = 203,
	neXcType_sipSig_c = 204,
	neXcType_docsCableUpstreamChannel_c = 205,
	neXcType_econet_c = 206,
	neXcType_pon155_c = 207,
	neXcType_pon622_c = 208,
	neXcType_bridge_c = 209,
	neXcType_linegroup_c = 210,
	neXcType_voiceEMFGD_c = 211,
	neXcType_voiceFGDEANA_c = 212,
	neXcType_voiceDID_c = 213,
	neXcType_mpegTransport_c = 214,
	neXcType_sixToFour_c = 215,
	neXcType_gtp_c = 216,
	neXcType_pdnEtherLoop1_c = 217,
	neXcType_pdnEtherLoop2_c = 218,
	neXcType_opticalChannelGroup_c = 219,
	neXcType_homepna_c = 220,
	neXcType_gfp_c = 221,
	neXcType_ciscoISLvlan_c = 222,
	neXcType_actelisMetaLOOP_c = 223,
	neXcType_fcipLink_c = 224,
	neXcType_rpr_c = 225,
	neXcType_qam_c = 226,
	neXcType_lmp_c = 227,
	neXcType_cblVectaStar_c = 228,
	neXcType_docsCableMCmtsDownstream_c = 229,
	neXcType_adsl2_c = 230,
	neXcType_macSecControlledIF_c = 231,
	neXcType_macSecUncontrolledIF_c = 232,
	neXcType_aviciOpticalEther_c = 233,
	neXcType_atmbond_c = 234,
	neXcType_voiceFGDOS_c = 235,
	neXcType_mocaVersion1_c = 236,
	neXcType_ieee80216WMAN_c = 237,
	neXcType_adsl2plus_c = 238,
	neXcType_dvbRcsMacLayer_c = 239,
	neXcType_dvbTdm_c = 240,
	neXcType_dvbRcsTdma_c = 241,
	neXcType_x86Laps_c = 242,
	neXcType_wwanPP_c = 243,
	neXcType_wwanPP2_c = 244,
	neXcType_voiceEBS_c = 245,
	neXcType_ifPwType_c = 246,
	neXcType_ilan_c = 247,
	neXcType_pip_c = 248,
	neXcType_aluELP_c = 249,
	neXcType_gpon_c = 250,
	neXcType_vdsl2_c = 251,
	neXcType_capwapDot11Profile_c = 252,
	neXcType_capwapDot11Bss_c = 253,
	neXcType_capwapWtpVirtualRadio_c = 254,
	neXcType_bits_c = 255,
	neXcType_docsCableUpstreamRfPort_c = 256,
	neXcType_cableDownstreamRfPort_c = 257,
	neXcType_vmwareVirtualNic_c = 258,
	neXcType_ieee802154_c = 259,
	neXcType_otnOdu_c = 260,
	neXcType_otnOtu_c = 261,
	neXcType_ifVfiType_c = 262,
	neXcType_g9981_c = 263,
	neXcType_g9982_c = 264,
	neXcType_g9983_c = 265,
	neXcType_aluEpon_c = 266,
	neXcType_aluEponOnu_c = 267,
	neXcType_aluEponPhysicalUni_c = 268,
	neXcType_aluEponLogicalLink_c = 269,
	neXcType_aluGponOnu_c = 270,
	neXcType_aluGponPhysicalUni_c = 271,
	neXcType_vmwareNicTeam_c = 272,

	/* enums for column neXcAdminStatus */
	neXcAdminStatus_up_c = 1,
	neXcAdminStatus_down_c = 2,
	neXcAdminStatus_testing_c = 3,

	/* enums for column neXcOperStatus */
	neXcOperStatus_up_c = 1,
	neXcOperStatus_down_c = 2,
	neXcOperStatus_testing_c = 3,
	neXcOperStatus_unknown_c = 4,
	neXcOperStatus_dormant_c = 5,
	neXcOperStatus_notPresent_c = 6,
	neXcOperStatus_lowerLayerDown_c = 7,

	/* enums for column neXcRowStatus */
	neXcRowStatus_active_c = 1,
	neXcRowStatus_notInService_c = 2,
	neXcRowStatus_notReady_c = 3,
	neXcRowStatus_createAndGo_c = 4,
	neXcRowStatus_createAndWait_c = 5,
	neXcRowStatus_destroy_c = 6,

	/* enums for column neXcStorageType */
	neXcStorageType_other_c = 1,
	neXcStorageType_volatile_c = 2,
	neXcStorageType_nonVolatile_c = 3,
	neXcStorageType_permanent_c = 4,
	neXcStorageType_readOnly_c = 5,
};

/* table neXcTable row entry data structure */
typedef struct neXcEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Descr[32];
	size_t u16Descr_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint32_t u32IfIndex;
	int32_t i32AdminStatus;
	int32_t i32OperStatus;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neXcEntry_t;

extern xBTree_t oNeXcTable_BTree;

/* neXcTable table mapper */
void neXcTable_init (void);
neXcEntry_t * neXcTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
neXcEntry_t * neXcTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
neXcEntry_t * neXcTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void neXcTable_removeEntry (neXcEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neXcTable_getFirst;
Netsnmp_Next_Data_Point neXcTable_getNext;
Netsnmp_Get_Data_Point neXcTable_get;
Netsnmp_Node_Handler neXcTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neXcIfTable definitions
 */
#define NEXCIFDIRECTION 1
#define NEXCIFDATA 2
#define NEXCIFROWSTATUS 3
#define NEXCIFSTORAGETYPE 4

enum
{
	/* enums for column neXcIfDirection */
	neXcIfDirection_egress_c = 1,
	neXcIfDirection_ingress_c = 2,
	neXcIfDirection_duplex_c = 3,

	/* enums for column neXcIfRowStatus */
	neXcIfRowStatus_active_c = 1,
	neXcIfRowStatus_notInService_c = 2,
	neXcIfRowStatus_notReady_c = 3,
	neXcIfRowStatus_createAndGo_c = 4,
	neXcIfRowStatus_createAndWait_c = 5,
	neXcIfRowStatus_destroy_c = 6,

	/* enums for column neXcIfStorageType */
	neXcIfStorageType_other_c = 1,
	neXcIfStorageType_volatile_c = 2,
	neXcIfStorageType_nonVolatile_c = 3,
	neXcIfStorageType_permanent_c = 4,
	neXcIfStorageType_readOnly_c = 5,
};

/* table neXcIfTable row entry data structure */
typedef struct neXcIfEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	int32_t i32Direction;
	
	/* Column values */
	uint8_t au8Data[8];
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neXcIfEntry_t;

extern xBTree_t oNeXcIfTable_BTree;

/* neXcIfTable table mapper */
void neXcIfTable_init (void);
neXcIfEntry_t * neXcIfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32IfIndex,
	int32_t i32Direction);
neXcIfEntry_t * neXcIfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32IfIndex,
	int32_t i32Direction);
neXcIfEntry_t * neXcIfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32IfIndex,
	int32_t i32Direction);
void neXcIfTable_removeEntry (neXcIfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neXcIfTable_getFirst;
Netsnmp_Next_Data_Point neXcIfTable_getNext;
Netsnmp_Get_Data_Point neXcIfTable_get;
Netsnmp_Node_Handler neXcIfTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEXCMIB_H__ */
