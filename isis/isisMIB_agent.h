/*
 *  Copyright (c) 2008-2015
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

#ifndef __ISISMIB_AGENT_H__
#	define __ISISMIB_AGENT_H__

#	ifdef __cplusplus
extern "C" {
#	endif



/**
 *	agent MIB function
 */
void isisMIB_init (void);


/**
 *	notification mapper(s)
 */
int isisDatabaseOverload_trap (void);
int isisManualAddressDrops_trap (void);
int isisCorruptedLSPDetected_trap (void);
int isisAttemptToExceedMaxSequence_trap (void);
int isisIDLenMismatch_trap (void);
int isisMaxAreaAddressesMismatch_trap (void);
int isisOwnLSPPurge_trap (void);
int isisSequenceNumberSkip_trap (void);
int isisAuthenticationTypeFailure_trap (void);
int isisAuthenticationFailure_trap (void);
int isisVersionSkew_trap (void);
int isisAreaMismatch_trap (void);
int isisRejectedAdjacency_trap (void);
int isisLSPTooLargeToPropagate_trap (void);
int isisOrigLSPBuffSizeMismatch_trap (void);
int isisProtocolsSupportedMismatch_trap (void);
int isisAdjacencyChange_trap (void);
int isisLSPErrorDetected_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __ISISMIB_AGENT_H__ */
