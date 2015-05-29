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
//set ts=4 sw=4

#ifndef __STP_PROTO_CONSTS_H__
#	define __STP_PROTO_CONSTS_H__

#	ifdef __cplusplus
extern "C" {
#	endif


enum {
	Stp_ProtocolIdentifier_c		= 0,
	
	Stp_BpduType_StpBpdu_c			= 0,
	Stp_BpduType_StpTcn_c			= 0x80,
	Stp_BpduType_RstBpdu_c			= 0x02,
	
	Stp_Version_Stp_c				= 0,
	Stp_Version_Rstp_c				= 2,
	Stp_Version_Mstp_c				= 3,
	Stp_Version_Spb_c				= 4,
	
	Stp_CistFlag_bTopologyChange_c			= 0,
	Stp_CistFlag_bProposal_c				= 1,
	Stp_CistFlag_PortRoleMask_c				= 0x06,
	Stp_CistFlag_bLearning_c				= 4,
	Stp_CistFlag_bForwarding_c				= 5,
	Stp_CistFlag_bAgreement_c				= 6,
	Stp_CistFlag_bTcAcknowledge_c			= 7,
	
	Stp_MstiFlag_bTopologyChange_c			= 0,
	Stp_MstiFlag_bProposal_c				= 1,
	Stp_MstiFlag_PortRoleMask_c				= 0x06,
	Stp_MstiFlag_bLearning_c				= 4,
	Stp_MstiFlag_bForwarding_c				= 5,
	Stp_MstiFlag_bAgreement_c				= 6,
	Stp_MstiFlag_bMaster_c					= 7,
};



#	ifdef __cplusplus
}
#	endif

#endif	// __STP_PROTO_CONSTS_H__
