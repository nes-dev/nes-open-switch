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

#define SNMP_SRC

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "isisMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid isisMIB_oid[] = {1,3,6,1,2,1,138};

static oid isisSysObject_oid[] = {1,3,6,1,2,1,138,1,1,1};
static oid isisCirc_oid[] = {1,3,6,1,2,1,138,1,3};

static oid isisManAreaAddrTable_oid[] = {1,3,6,1,2,1,138,1,1,2};
static oid isisAreaAddrTable_oid[] = {1,3,6,1,2,1,138,1,1,3};
static oid isisSummAddrTable_oid[] = {1,3,6,1,2,1,138,1,1,4};
static oid isisRedistributeAddrTable_oid[] = {1,3,6,1,2,1,138,1,1,5};
static oid isisRouterTable_oid[] = {1,3,6,1,2,1,138,1,1,6};
static oid isisSysLevelTable_oid[] = {1,3,6,1,2,1,138,1,2,1};
static oid isisCircTable_oid[] = {1,3,6,1,2,1,138,1,3,2};
static oid isisCircLevelTable_oid[] = {1,3,6,1,2,1,138,1,4,1};
static oid isisSystemCounterTable_oid[] = {1,3,6,1,2,1,138,1,5,1};
static oid isisCircuitCounterTable_oid[] = {1,3,6,1,2,1,138,1,5,2};
static oid isisPacketCounterTable_oid[] = {1,3,6,1,2,1,138,1,5,3};
static oid isisISAdjTable_oid[] = {1,3,6,1,2,1,138,1,6,1};
static oid isisISAdjAreaAddrTable_oid[] = {1,3,6,1,2,1,138,1,6,2};
static oid isisISAdjIPAddrTable_oid[] = {1,3,6,1,2,1,138,1,6,3};
static oid isisISAdjProtSuppTable_oid[] = {1,3,6,1,2,1,138,1,6,4};
static oid isisRATable_oid[] = {1,3,6,1,2,1,138,1,7,1};
static oid isisIPRATable_oid[] = {1,3,6,1,2,1,138,1,8,1};
static oid isisLSPSummaryTable_oid[] = {1,3,6,1,2,1,138,1,9,1};
static oid isisLSPTLVTable_oid[] = {1,3,6,1,2,1,138,1,9,2};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid isisDatabaseOverload_oid[] = {1,3,6,1,2,1,138,0,1};
static oid isisManualAddressDrops_oid[] = {1,3,6,1,2,1,138,0,2};
static oid isisCorruptedLSPDetected_oid[] = {1,3,6,1,2,1,138,0,3};
static oid isisAttemptToExceedMaxSequence_oid[] = {1,3,6,1,2,1,138,0,4};
static oid isisIDLenMismatch_oid[] = {1,3,6,1,2,1,138,0,5};
static oid isisMaxAreaAddressesMismatch_oid[] = {1,3,6,1,2,1,138,0,6};
static oid isisOwnLSPPurge_oid[] = {1,3,6,1,2,1,138,0,7};
static oid isisSequenceNumberSkip_oid[] = {1,3,6,1,2,1,138,0,8};
static oid isisAuthenticationTypeFailure_oid[] = {1,3,6,1,2,1,138,0,9};
static oid isisAuthenticationFailure_oid[] = {1,3,6,1,2,1,138,0,10};
static oid isisVersionSkew_oid[] = {1,3,6,1,2,1,138,0,11};
static oid isisAreaMismatch_oid[] = {1,3,6,1,2,1,138,0,12};
static oid isisRejectedAdjacency_oid[] = {1,3,6,1,2,1,138,0,13};
static oid isisLSPTooLargeToPropagate_oid[] = {1,3,6,1,2,1,138,0,14};
static oid isisOrigLSPBuffSizeMismatch_oid[] = {1,3,6,1,2,1,138,0,15};
static oid isisProtocolsSupportedMismatch_oid[] = {1,3,6,1,2,1,138,0,16};
static oid isisAdjacencyChange_oid[] = {1,3,6,1,2,1,138,0,17};
static oid isisLSPErrorDetected_oid[] = {1,3,6,1,2,1,138,0,18};



/**
 *	initialize isisMIB group mapper
 */
void
isisMIB_init (void)
{
	extern oid isisMIB_oid[];
	extern oid isisSysObject_oid[];
	extern oid isisCirc_oid[];
	
	DEBUGMSGTL (("isisMIB", "Initializing\n"));
	
	/* register isisSysObject scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"isisSysObject_mapper", &isisSysObject_mapper,
			isisSysObject_oid, OID_LENGTH (isisSysObject_oid),
			HANDLER_CAN_RWRITE
		),
		ISISSYSVERSION,
		ISISSYSNOTIFICATIONENABLE
	);
	
	/* register isisCirc scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"isisCirc_mapper", &isisCirc_mapper,
			isisCirc_oid, OID_LENGTH (isisCirc_oid),
			HANDLER_CAN_RONLY
		),
		ISISNEXTCIRCINDEX,
		ISISNEXTCIRCINDEX
	);
	
	
	/* register isisMIB group table mappers */
	isisManAreaAddrTable_init ();
	isisAreaAddrTable_init ();
	isisSummAddrTable_init ();
	isisRedistributeAddrTable_init ();
	isisRouterTable_init ();
	isisSysLevelTable_init ();
	isisCircTable_init ();
	isisCircLevelTable_init ();
	isisSystemCounterTable_init ();
	isisCircuitCounterTable_init ();
	isisPacketCounterTable_init ();
	isisISAdjTable_init ();
	isisISAdjAreaAddrTable_init ();
	isisISAdjIPAddrTable_init ();
	isisISAdjProtSuppTable_init ();
	isisRATable_init ();
	isisIPRATable_init ();
	isisLSPSummaryTable_init ();
	isisLSPTLVTable_init ();
	
	/* register isisMIB modules */
	sysORTable_createRegister ("isisMIB", isisMIB_oid, OID_LENGTH (isisMIB_oid));
}


/**
 *	scalar mapper(s)
 */
isisSysObject_t oIsisSysObject;

/** isisSysObject scalar mapper **/
int
isisSysObject_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid isisSysObject_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (isisSysObject_oid) - 1])
			{
			case ISISSYSVERSION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIsisSysObject.i32Version);
				break;
			case ISISSYSLEVELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIsisSysObject.i32LevelType);
				break;
			case ISISSYSID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIsisSysObject.au8ID, oIsisSysObject.u16ID_len);
				break;
			case ISISSYSMAXPATHSPLITS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32MaxPathSplits);
				break;
			case ISISSYSMAXLSPGENINT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32MaxLSPGenInt);
				break;
			case ISISSYSPOLLESHELLORATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32PollESHelloRate);
				break;
			case ISISSYSWAITTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32WaitTime);
				break;
			case ISISSYSADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIsisSysObject.i32AdminState);
				break;
			case ISISSYSL2TOL1LEAKING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIsisSysObject.i32L2toL1Leaking);
				break;
			case ISISSYSMAXAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32MaxAge);
				break;
			case ISISSYSRECEIVELSPBUFFERSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisSysObject.u32ReceiveLSPBufferSize);
				break;
			case ISISSYSPROTSUPPORTED:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIsisSysObject.au8ProtSupported, oIsisSysObject.u16ProtSupported_len);
				break;
			case ISISSYSNOTIFICATIONENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIsisSysObject.i32NotificationEnable);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				continue;
			}
		}
		break;
		
	/*
	 * SET REQUEST
	 *
	 * multiple states in the transaction.  See:
	 * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (isisSysObject_oid) - 1])
			{
			case ISISSYSLEVELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSMAXPATHSPLITS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSMAXLSPGENINT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSPOLLESHELLORATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSWAITTIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSL2TOL1LEAKING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSMAXAGE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSRECEIVELSPBUFFERSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case ISISSYSNOTIFICATIONENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				continue;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (isisSysObject_oid) - 1])
			{
			case ISISSYSLEVELTYPE:
				/* XXX: perform the value change here */
				oIsisSysObject.i32LevelType = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSID:
				/* XXX: perform the value change here */
				memset (oIsisSysObject.au8ID, 0, sizeof (oIsisSysObject.au8ID));
				memcpy (oIsisSysObject.au8ID, request->requestvb->val.string, request->requestvb->val_len);
				oIsisSysObject.u16ID_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSMAXPATHSPLITS:
				/* XXX: perform the value change here */
				oIsisSysObject.u32MaxPathSplits = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSMAXLSPGENINT:
				/* XXX: perform the value change here */
				oIsisSysObject.u32MaxLSPGenInt = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSPOLLESHELLORATE:
				/* XXX: perform the value change here */
				oIsisSysObject.u32PollESHelloRate = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSWAITTIME:
				/* XXX: perform the value change here */
				oIsisSysObject.u32WaitTime = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSADMINSTATE:
				/* XXX: perform the value change here */
				oIsisSysObject.i32AdminState = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSL2TOL1LEAKING:
				/* XXX: perform the value change here */
				oIsisSysObject.i32L2toL1Leaking = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSMAXAGE:
				/* XXX: perform the value change here */
				oIsisSysObject.u32MaxAge = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSRECEIVELSPBUFFERSIZE:
				/* XXX: perform the value change here */
				oIsisSysObject.u32ReceiveLSPBufferSize = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case ISISSYSNOTIFICATIONENABLE:
				/* XXX: perform the value change here */
				oIsisSysObject.i32NotificationEnable = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (isisSysObject_oid) - 1])
			{
			case ISISSYSLEVELTYPE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSID:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSMAXPATHSPLITS:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSMAXLSPGENINT:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSPOLLESHELLORATE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSWAITTIME:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSADMINSTATE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSL2TOL1LEAKING:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSMAXAGE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSRECEIVELSPBUFFERSIZE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case ISISSYSNOTIFICATIONENABLE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			}
		}
		break;
		
	default:
		/* we should never get here, so this is a really bad error */
		snmp_log (LOG_ERR, "unknown mode (%d) in handle_\n", reqinfo->mode);
		return SNMP_ERR_GENERR;
	}
	
	return SNMP_ERR_NOERROR;
}

isisCirc_t oIsisCirc;

/** isisCirc scalar mapper **/
int
isisCirc_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid isisCirc_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (isisCirc_oid) - 1])
			{
			case ISISNEXTCIRCINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIsisCirc.u32NextCircIndex);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				continue;
			}
		}
		break;
		
		
	default:
		/* we should never get here, so this is a really bad error */
		snmp_log (LOG_ERR, "unknown mode (%d) in handle_\n", reqinfo->mode);
		return SNMP_ERR_GENERR;
	}
	
	return SNMP_ERR_NOERROR;
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize isisManAreaAddrTable table mapper **/
void
isisManAreaAddrTable_init (void)
{
	extern oid isisManAreaAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisManAreaAddrTable", &isisManAreaAddrTable_mapper,
		isisManAreaAddrTable_oid, OID_LENGTH (isisManAreaAddrTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: isisManAreaAddr */,
		0);
	table_info->min_column = ISISMANAREAADDREXISTSTATE;
	table_info->max_column = ISISMANAREAADDREXISTSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisManAreaAddrTable_getFirst;
	iinfo->get_next_data_point = &isisManAreaAddrTable_getNext;
	iinfo->get_data_point = &isisManAreaAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisManAreaAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisManAreaAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisManAreaAddrEntry_t, oBTreeNode);
	register isisManAreaAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisManAreaAddrEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0) ? 0: 1;
}

xBTree_t oIsisManAreaAddrTable_BTree = xBTree_initInline (&isisManAreaAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisManAreaAddrEntry_t *
isisManAreaAddrTable_createEntry (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisManAreaAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Addr, pau8Addr, u16Addr_len);
	poEntry->u16Addr_len = u16Addr_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8ExistState = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree);
	return poEntry;
}

isisManAreaAddrEntry_t *
isisManAreaAddrTable_getByIndex (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisManAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisManAreaAddrEntry_t, oBTreeNode);
}

isisManAreaAddrEntry_t *
isisManAreaAddrTable_getNextIndex (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisManAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisManAreaAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisManAreaAddrTable_removeEntry (isisManAreaAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisManAreaAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisManAreaAddrTable_BTree);
	return isisManAreaAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisManAreaAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisManAreaAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisManAreaAddrEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Addr, poEntry->u16Addr_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisManAreaAddrTable_BTree);
	return put_index_data;
}

bool
isisManAreaAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisManAreaAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = isisManAreaAddrTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisManAreaAddrTable table mapper */
int
isisManAreaAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisManAreaAddrEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisManAreaAddrTable_createEntry (
						(void*) idx1->val.string, idx1->val_len);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisManAreaAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisManAreaAddrTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisManAreaAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisManAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISMANAREAADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisManAreaAddrTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisAreaAddrTable table mapper **/
void
isisAreaAddrTable_init (void)
{
	extern oid isisAreaAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisAreaAddrTable", &isisAreaAddrTable_mapper,
		isisAreaAddrTable_oid, OID_LENGTH (isisAreaAddrTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: isisAreaAddr */,
		0);
	table_info->min_column = ISISAREAADDR;
	table_info->max_column = ISISAREAADDR;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisAreaAddrTable_getFirst;
	iinfo->get_next_data_point = &isisAreaAddrTable_getNext;
	iinfo->get_data_point = &isisAreaAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisAreaAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisAreaAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisAreaAddrEntry_t, oBTreeNode);
	register isisAreaAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisAreaAddrEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0) ? 0: 1;
}

xBTree_t oIsisAreaAddrTable_BTree = xBTree_initInline (&isisAreaAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisAreaAddrEntry_t *
isisAreaAddrTable_createEntry (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisAreaAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Addr, pau8Addr, u16Addr_len);
	poEntry->u16Addr_len = u16Addr_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisAreaAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisAreaAddrTable_BTree);
	return poEntry;
}

isisAreaAddrEntry_t *
isisAreaAddrTable_getByIndex (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisAreaAddrEntry_t, oBTreeNode);
}

isisAreaAddrEntry_t *
isisAreaAddrTable_getNextIndex (
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register isisAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisAreaAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisAreaAddrTable_removeEntry (isisAreaAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisAreaAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisAreaAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisAreaAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisAreaAddrTable_BTree);
	return isisAreaAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisAreaAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisAreaAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisAreaAddrEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Addr, poEntry->u16Addr_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisAreaAddrTable_BTree);
	return put_index_data;
}

bool
isisAreaAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisAreaAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = isisAreaAddrTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisAreaAddrTable table mapper */
int
isisAreaAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisAreaAddrEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISAREAADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Addr, table_entry->u16Addr_len);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisSummAddrTable table mapper **/
void
isisSummAddrTable_init (void)
{
	extern oid isisSummAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisSummAddrTable", &isisSummAddrTable_mapper,
		isisSummAddrTable_oid, OID_LENGTH (isisSummAddrTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisSummAddressType */,
		ASN_OCTET_STR /* index: isisSummAddress */,
		ASN_UNSIGNED /* index: isisSummAddrPrefixLen */,
		0);
	table_info->min_column = ISISSUMMADDREXISTSTATE;
	table_info->max_column = ISISSUMMADDRFULLMETRIC;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisSummAddrTable_getFirst;
	iinfo->get_next_data_point = &isisSummAddrTable_getNext;
	iinfo->get_data_point = &isisSummAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisSummAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisSummAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisSummAddrEntry_t, oBTreeNode);
	register isisSummAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisSummAddrEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32AddressType < pEntry2->i32AddressType) ||
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32PrefixLen < pEntry2->u32PrefixLen) ? -1:
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32PrefixLen == pEntry2->u32PrefixLen) ? 0: 1;
}

xBTree_t oIsisSummAddrTable_BTree = xBTree_initInline (&isisSummAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisSummAddrEntry_t *
isisSummAddrTable_createEntry (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisSummAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32AddressType = i32AddressType;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32PrefixLen = u32PrefixLen;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSummAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8ExistState = xRowStatus_notInService_c;
	poEntry->u32Metric = 20;
	poEntry->u32FullMetric = 20;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisSummAddrTable_BTree);
	return poEntry;
}

isisSummAddrEntry_t *
isisSummAddrTable_getByIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisSummAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32PrefixLen = u32PrefixLen;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisSummAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSummAddrEntry_t, oBTreeNode);
}

isisSummAddrEntry_t *
isisSummAddrTable_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisSummAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32PrefixLen = u32PrefixLen;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisSummAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSummAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisSummAddrTable_removeEntry (isisSummAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSummAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisSummAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisSummAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisSummAddrTable_BTree);
	return isisSummAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisSummAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSummAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisSummAddrEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32AddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PrefixLen);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisSummAddrTable_BTree);
	return put_index_data;
}

bool
isisSummAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSummAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisSummAddrTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisSummAddrTable table mapper */
int
isisSummAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisSummAddrEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
			case ISISSUMMADDRMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Metric);
				break;
			case ISISSUMMADDRFULLMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32FullMetric);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSUMMADDRMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSUMMADDRFULLMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisSummAddrTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len,
						*idx3->val.integer);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisSummAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDRMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Metric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Metric, sizeof (table_entry->u32Metric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Metric = *request->requestvb->val.integer;
				break;
			case ISISSUMMADDRFULLMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32FullMetric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32FullMetric, sizeof (table_entry->u32FullMetric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32FullMetric = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisSummAddrTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisSummAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case ISISSUMMADDRMETRIC:
				memcpy (&table_entry->u32Metric, pvOldDdata, sizeof (table_entry->u32Metric));
				break;
			case ISISSUMMADDRFULLMETRIC:
				memcpy (&table_entry->u32FullMetric, pvOldDdata, sizeof (table_entry->u32FullMetric));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSummAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSUMMADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisSummAddrTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisRedistributeAddrTable table mapper **/
void
isisRedistributeAddrTable_init (void)
{
	extern oid isisRedistributeAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisRedistributeAddrTable", &isisRedistributeAddrTable_mapper,
		isisRedistributeAddrTable_oid, OID_LENGTH (isisRedistributeAddrTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisRedistributeAddrType */,
		ASN_OCTET_STR /* index: isisRedistributeAddrAddress */,
		ASN_UNSIGNED /* index: isisRedistributeAddrPrefixLen */,
		0);
	table_info->min_column = ISISREDISTRIBUTEADDREXISTSTATE;
	table_info->max_column = ISISREDISTRIBUTEADDREXISTSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisRedistributeAddrTable_getFirst;
	iinfo->get_next_data_point = &isisRedistributeAddrTable_getNext;
	iinfo->get_data_point = &isisRedistributeAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisRedistributeAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisRedistributeAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisRedistributeAddrEntry_t, oBTreeNode);
	register isisRedistributeAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisRedistributeAddrEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32PrefixLen < pEntry2->u32PrefixLen) ? -1:
		(pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32PrefixLen == pEntry2->u32PrefixLen) ? 0: 1;
}

xBTree_t oIsisRedistributeAddrTable_BTree = xBTree_initInline (&isisRedistributeAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisRedistributeAddrEntry_t *
isisRedistributeAddrTable_createEntry (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisRedistributeAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Type = i32Type;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32PrefixLen = u32PrefixLen;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8ExistState = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree);
	return poEntry;
}

isisRedistributeAddrEntry_t *
isisRedistributeAddrTable_getByIndex (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisRedistributeAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32PrefixLen = u32PrefixLen;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRedistributeAddrEntry_t, oBTreeNode);
}

isisRedistributeAddrEntry_t *
isisRedistributeAddrTable_getNextIndex (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen)
{
	register isisRedistributeAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32PrefixLen = u32PrefixLen;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRedistributeAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisRedistributeAddrTable_removeEntry (isisRedistributeAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisRedistributeAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisRedistributeAddrTable_BTree);
	return isisRedistributeAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisRedistributeAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRedistributeAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisRedistributeAddrEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Type);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PrefixLen);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisRedistributeAddrTable_BTree);
	return put_index_data;
}

bool
isisRedistributeAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRedistributeAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisRedistributeAddrTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisRedistributeAddrTable table mapper */
int
isisRedistributeAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisRedistributeAddrEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisRedistributeAddrTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len,
						*idx3->val.integer);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisRedistributeAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisRedistributeAddrTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisRedistributeAddrTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRedistributeAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISREDISTRIBUTEADDREXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisRedistributeAddrTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisRouterTable table mapper **/
void
isisRouterTable_init (void)
{
	extern oid isisRouterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisRouterTable", &isisRouterTable_mapper,
		isisRouterTable_oid, OID_LENGTH (isisRouterTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: isisRouterSysID */,
		ASN_INTEGER /* index: isisRouterLevel */,
		0);
	table_info->min_column = ISISROUTERHOSTNAME;
	table_info->max_column = ISISROUTERID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisRouterTable_getFirst;
	iinfo->get_next_data_point = &isisRouterTable_getNext;
	iinfo->get_data_point = &isisRouterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisRouterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisRouterEntry_t *pEntry1 = xBTree_entry (pNode1, isisRouterEntry_t, oBTreeNode);
	register isisRouterEntry_t *pEntry2 = xBTree_entry (pNode2, isisRouterEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8SysID, pEntry2->au8SysID, pEntry1->u16SysID_len, pEntry2->u16SysID_len) == -1) ||
		(xBinCmp (pEntry1->au8SysID, pEntry2->au8SysID, pEntry1->u16SysID_len, pEntry2->u16SysID_len) == 0 && pEntry1->i32Level < pEntry2->i32Level) ? -1:
		(xBinCmp (pEntry1->au8SysID, pEntry2->au8SysID, pEntry1->u16SysID_len, pEntry2->u16SysID_len) == 0 && pEntry1->i32Level == pEntry2->i32Level) ? 0: 1;
}

xBTree_t oIsisRouterTable_BTree = xBTree_initInline (&isisRouterTable_BTreeNodeCmp);

/* create a new row in the table */
isisRouterEntry_t *
isisRouterTable_createEntry (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level)
{
	register isisRouterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8SysID, pau8SysID, u16SysID_len);
	poEntry->u16SysID_len = u16SysID_len;
	poEntry->i32Level = i32Level;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRouterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisRouterTable_BTree);
	return poEntry;
}

isisRouterEntry_t *
isisRouterTable_getByIndex (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level)
{
	register isisRouterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8SysID, pau8SysID, u16SysID_len);
	poTmpEntry->u16SysID_len = u16SysID_len;
	poTmpEntry->i32Level = i32Level;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisRouterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRouterEntry_t, oBTreeNode);
}

isisRouterEntry_t *
isisRouterTable_getNextIndex (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level)
{
	register isisRouterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8SysID, pau8SysID, u16SysID_len);
	poTmpEntry->u16SysID_len = u16SysID_len;
	poTmpEntry->i32Level = i32Level;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisRouterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRouterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisRouterTable_removeEntry (isisRouterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRouterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisRouterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisRouterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisRouterTable_BTree);
	return isisRouterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisRouterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRouterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisRouterEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8SysID, poEntry->u16SysID_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Level);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisRouterTable_BTree);
	return put_index_data;
}

bool
isisRouterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRouterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisRouterTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisRouterTable table mapper */
int
isisRouterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisRouterEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRouterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISROUTERHOSTNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8HostName, table_entry->u16HostName_len);
				break;
			case ISISROUTERID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ID);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisSysLevelTable table mapper **/
void
isisSysLevelTable_init (void)
{
	extern oid isisSysLevelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisSysLevelTable", &isisSysLevelTable_mapper,
		isisSysLevelTable_oid, OID_LENGTH (isisSysLevelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisSysLevelIndex */,
		0);
	table_info->min_column = ISISSYSLEVELORIGLSPBUFFSIZE;
	table_info->max_column = ISISSYSLEVELTEENABLED;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisSysLevelTable_getFirst;
	iinfo->get_next_data_point = &isisSysLevelTable_getNext;
	iinfo->get_data_point = &isisSysLevelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisSysLevelTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisSysLevelEntry_t *pEntry1 = xBTree_entry (pNode1, isisSysLevelEntry_t, oBTreeNode);
	register isisSysLevelEntry_t *pEntry2 = xBTree_entry (pNode2, isisSysLevelEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Index < pEntry2->i32Index) ? -1:
		(pEntry1->i32Index == pEntry2->i32Index) ? 0: 1;
}

xBTree_t oIsisSysLevelTable_BTree = xBTree_initInline (&isisSysLevelTable_BTreeNodeCmp);

/* create a new row in the table */
isisSysLevelEntry_t *
isisSysLevelTable_createEntry (
	int32_t i32Index)
{
	register isisSysLevelEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Index = i32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSysLevelTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32OrigLSPBuffSize = 1492;
	poEntry->u32MinLSPGenInt = 30;
	poEntry->i32SetOverload = isisSysLevelSetOverload_false_c;
	poEntry->i32MetricStyle = isisSysLevelMetricStyle_narrow_c;
	poEntry->i32SPFConsiders = isisSysLevelSPFConsiders_narrow_c;
	poEntry->i32TEEnabled = isisSysLevelTEEnabled_false_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisSysLevelTable_BTree);
	return poEntry;
}

isisSysLevelEntry_t *
isisSysLevelTable_getByIndex (
	int32_t i32Index)
{
	register isisSysLevelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisSysLevelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSysLevelEntry_t, oBTreeNode);
}

isisSysLevelEntry_t *
isisSysLevelTable_getNextIndex (
	int32_t i32Index)
{
	register isisSysLevelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisSysLevelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSysLevelEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisSysLevelTable_removeEntry (isisSysLevelEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSysLevelTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisSysLevelTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisSysLevelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisSysLevelTable_BTree);
	return isisSysLevelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisSysLevelTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSysLevelEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisSysLevelEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisSysLevelTable_BTree);
	return put_index_data;
}

bool
isisSysLevelTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSysLevelEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = isisSysLevelTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisSysLevelTable table mapper */
int
isisSysLevelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisSysLevelEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSysLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSYSLEVELORIGLSPBUFFSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32OrigLSPBuffSize);
				break;
			case ISISSYSLEVELMINLSPGENINT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MinLSPGenInt);
				break;
			case ISISSYSLEVELSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case ISISSYSLEVELSETOVERLOAD:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SetOverload);
				break;
			case ISISSYSLEVELSETOVERLOADUNTIL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SetOverloadUntil);
				break;
			case ISISSYSLEVELMETRICSTYLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MetricStyle);
				break;
			case ISISSYSLEVELSPFCONSIDERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SPFConsiders);
				break;
			case ISISSYSLEVELTEENABLED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TEEnabled);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSysLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSYSLEVELORIGLSPBUFFSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELMINLSPGENINT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELSETOVERLOAD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELSETOVERLOADUNTIL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELMETRICSTYLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELSPFCONSIDERS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISSYSLEVELTEENABLED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSysLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisSysLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISSYSLEVELORIGLSPBUFFSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32OrigLSPBuffSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32OrigLSPBuffSize, sizeof (table_entry->u32OrigLSPBuffSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32OrigLSPBuffSize = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELMINLSPGENINT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MinLSPGenInt))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MinLSPGenInt, sizeof (table_entry->u32MinLSPGenInt));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MinLSPGenInt = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELSETOVERLOAD:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SetOverload))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SetOverload, sizeof (table_entry->i32SetOverload));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SetOverload = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELSETOVERLOADUNTIL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32SetOverloadUntil))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32SetOverloadUntil, sizeof (table_entry->u32SetOverloadUntil));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32SetOverloadUntil = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELMETRICSTYLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MetricStyle))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MetricStyle, sizeof (table_entry->i32MetricStyle));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MetricStyle = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELSPFCONSIDERS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SPFConsiders))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SPFConsiders, sizeof (table_entry->i32SPFConsiders));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SPFConsiders = *request->requestvb->val.integer;
				break;
			case ISISSYSLEVELTEENABLED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TEEnabled))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TEEnabled, sizeof (table_entry->i32TEEnabled));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TEEnabled = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisSysLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSYSLEVELORIGLSPBUFFSIZE:
				memcpy (&table_entry->u32OrigLSPBuffSize, pvOldDdata, sizeof (table_entry->u32OrigLSPBuffSize));
				break;
			case ISISSYSLEVELMINLSPGENINT:
				memcpy (&table_entry->u32MinLSPGenInt, pvOldDdata, sizeof (table_entry->u32MinLSPGenInt));
				break;
			case ISISSYSLEVELSETOVERLOAD:
				memcpy (&table_entry->i32SetOverload, pvOldDdata, sizeof (table_entry->i32SetOverload));
				break;
			case ISISSYSLEVELSETOVERLOADUNTIL:
				memcpy (&table_entry->u32SetOverloadUntil, pvOldDdata, sizeof (table_entry->u32SetOverloadUntil));
				break;
			case ISISSYSLEVELMETRICSTYLE:
				memcpy (&table_entry->i32MetricStyle, pvOldDdata, sizeof (table_entry->i32MetricStyle));
				break;
			case ISISSYSLEVELSPFCONSIDERS:
				memcpy (&table_entry->i32SPFConsiders, pvOldDdata, sizeof (table_entry->i32SPFConsiders));
				break;
			case ISISSYSLEVELTEENABLED:
				memcpy (&table_entry->i32TEEnabled, pvOldDdata, sizeof (table_entry->i32TEEnabled));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisCircTable table mapper **/
void
isisCircTable_init (void)
{
	extern oid isisCircTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisCircTable", &isisCircTable_mapper,
		isisCircTable_oid, OID_LENGTH (isisCircTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		0);
	table_info->min_column = ISISCIRCIFINDEX;
	table_info->max_column = ISISCIRCEXTENDEDCIRCID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisCircTable_getFirst;
	iinfo->get_next_data_point = &isisCircTable_getNext;
	iinfo->get_data_point = &isisCircTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisCircTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisCircEntry_t *pEntry1 = xBTree_entry (pNode1, isisCircEntry_t, oBTreeNode);
	register isisCircEntry_t *pEntry2 = xBTree_entry (pNode2, isisCircEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisCircTable_BTree = xBTree_initInline (&isisCircTable_BTreeNodeCmp);

/* create a new row in the table */
isisCircEntry_t *
isisCircTable_createEntry (
	uint32_t u32Index)
{
	register isisCircEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AdminState = isisCircAdminState_off_c;
	poEntry->u8ExistState = xRowStatus_notInService_c;
	poEntry->i32ExtDomain = isisCircExtDomain_false_c;
	poEntry->i32LevelType = isisCircLevelType_level1and2_c;
	poEntry->i32PassiveCircuit = isisCircPassiveCircuit_false_c;
	poEntry->i32MeshGroupEnabled = isisCircMeshGroupEnabled_inactive_c;
	poEntry->i32SmallHellos = isisCircSmallHellos_false_c;
	poEntry->i32Circ3WayEnabled = isisCirc3WayEnabled_true_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisCircTable_BTree);
	return poEntry;
}

isisCircEntry_t *
isisCircTable_getByIndex (
	uint32_t u32Index)
{
	register isisCircEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisCircTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircEntry_t, oBTreeNode);
}

isisCircEntry_t *
isisCircTable_getNextIndex (
	uint32_t u32Index)
{
	register isisCircEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisCircTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisCircTable_removeEntry (isisCircEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisCircTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisCircTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisCircTable_BTree);
	return isisCircTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisCircTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisCircEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisCircTable_BTree);
	return put_index_data;
}

bool
isisCircTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = isisCircTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisCircTable table mapper */
int
isisCircTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisCircEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case ISISCIRCADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminState);
				break;
			case ISISCIRCEXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
			case ISISCIRCTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case ISISCIRCEXTDOMAIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ExtDomain);
				break;
			case ISISCIRCLEVELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LevelType);
				break;
			case ISISCIRCPASSIVECIRCUIT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PassiveCircuit);
				break;
			case ISISCIRCMESHGROUPENABLED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MeshGroupEnabled);
				break;
			case ISISCIRCMESHGROUP:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MeshGroup);
				break;
			case ISISCIRCSMALLHELLOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SmallHellos);
				break;
			case ISISCIRCLASTUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastUpTime);
				break;
			case ISISCIRC3WAYENABLED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Circ3WayEnabled);
				break;
			case ISISCIRCEXTENDEDCIRCID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ExtendedCircID);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCEXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCEXTDOMAIN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCPASSIVECIRCUIT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCMESHGROUPENABLED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCMESHGROUP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCSMALLHELLOS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRC3WAYENABLED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCEXTENDEDCIRCID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case ISISCIRCEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisCircTable_createEntry (
						*idx1->val.integer);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisCircTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IfIndex, sizeof (table_entry->u32IfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IfIndex = *request->requestvb->val.integer;
				break;
			case ISISCIRCADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminState, sizeof (table_entry->i32AdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminState = *request->requestvb->val.integer;
				break;
			case ISISCIRCTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Type))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Type, sizeof (table_entry->i32Type));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Type = *request->requestvb->val.integer;
				break;
			case ISISCIRCEXTDOMAIN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ExtDomain))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ExtDomain, sizeof (table_entry->i32ExtDomain));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ExtDomain = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LevelType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LevelType, sizeof (table_entry->i32LevelType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LevelType = *request->requestvb->val.integer;
				break;
			case ISISCIRCPASSIVECIRCUIT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PassiveCircuit))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PassiveCircuit, sizeof (table_entry->i32PassiveCircuit));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PassiveCircuit = *request->requestvb->val.integer;
				break;
			case ISISCIRCMESHGROUPENABLED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MeshGroupEnabled))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MeshGroupEnabled, sizeof (table_entry->i32MeshGroupEnabled));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MeshGroupEnabled = *request->requestvb->val.integer;
				break;
			case ISISCIRCMESHGROUP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MeshGroup))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MeshGroup, sizeof (table_entry->u32MeshGroup));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MeshGroup = *request->requestvb->val.integer;
				break;
			case ISISCIRCSMALLHELLOS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SmallHellos))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SmallHellos, sizeof (table_entry->i32SmallHellos));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SmallHellos = *request->requestvb->val.integer;
				break;
			case ISISCIRC3WAYENABLED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Circ3WayEnabled))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Circ3WayEnabled, sizeof (table_entry->i32Circ3WayEnabled));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Circ3WayEnabled = *request->requestvb->val.integer;
				break;
			case ISISCIRCEXTENDEDCIRCID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ExtendedCircID))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ExtendedCircID, sizeof (table_entry->u32ExtendedCircID));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ExtendedCircID = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisCircTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case ISISCIRCADMINSTATE:
				memcpy (&table_entry->i32AdminState, pvOldDdata, sizeof (table_entry->i32AdminState));
				break;
			case ISISCIRCEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisCircTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case ISISCIRCTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case ISISCIRCEXTDOMAIN:
				memcpy (&table_entry->i32ExtDomain, pvOldDdata, sizeof (table_entry->i32ExtDomain));
				break;
			case ISISCIRCLEVELTYPE:
				memcpy (&table_entry->i32LevelType, pvOldDdata, sizeof (table_entry->i32LevelType));
				break;
			case ISISCIRCPASSIVECIRCUIT:
				memcpy (&table_entry->i32PassiveCircuit, pvOldDdata, sizeof (table_entry->i32PassiveCircuit));
				break;
			case ISISCIRCMESHGROUPENABLED:
				memcpy (&table_entry->i32MeshGroupEnabled, pvOldDdata, sizeof (table_entry->i32MeshGroupEnabled));
				break;
			case ISISCIRCMESHGROUP:
				memcpy (&table_entry->u32MeshGroup, pvOldDdata, sizeof (table_entry->u32MeshGroup));
				break;
			case ISISCIRCSMALLHELLOS:
				memcpy (&table_entry->i32SmallHellos, pvOldDdata, sizeof (table_entry->i32SmallHellos));
				break;
			case ISISCIRC3WAYENABLED:
				memcpy (&table_entry->i32Circ3WayEnabled, pvOldDdata, sizeof (table_entry->i32Circ3WayEnabled));
				break;
			case ISISCIRCEXTENDEDCIRCID:
				memcpy (&table_entry->u32ExtendedCircID, pvOldDdata, sizeof (table_entry->u32ExtendedCircID));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisCircTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisCircLevelTable table mapper **/
void
isisCircLevelTable_init (void)
{
	extern oid isisCircLevelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisCircLevelTable", &isisCircLevelTable_mapper,
		isisCircLevelTable_oid, OID_LENGTH (isisCircLevelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_INTEGER /* index: isisCircLevelIndex */,
		0);
	table_info->min_column = ISISCIRCLEVELMETRIC;
	table_info->max_column = ISISCIRCLEVELPARTSNPINTERVAL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisCircLevelTable_getFirst;
	iinfo->get_next_data_point = &isisCircLevelTable_getNext;
	iinfo->get_data_point = &isisCircLevelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisCircLevelTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisCircLevelEntry_t *pEntry1 = xBTree_entry (pNode1, isisCircLevelEntry_t, oBTreeNode);
	register isisCircLevelEntry_t *pEntry2 = xBTree_entry (pNode2, isisCircLevelEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->i32Index < pEntry2->i32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->i32Index == pEntry2->i32Index) ? 0: 1;
}

xBTree_t oIsisCircLevelTable_BTree = xBTree_initInline (&isisCircLevelTable_BTreeNodeCmp);

/* create a new row in the table */
isisCircLevelEntry_t *
isisCircLevelTable_createEntry (
	uint32_t u32Index,
	int32_t i32Index)
{
	register isisCircLevelEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->i32Index = i32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircLevelTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32Metric = 10;
	poEntry->u32WideMetric = 10;
	poEntry->u32ISPriority = 64;
	poEntry->u32HelloMultiplier = 10;
	poEntry->u32HelloTimer = 3000;
	poEntry->u32DRHelloTimer = 1000;
	poEntry->u32LSPThrottle = 30;
	poEntry->u32MinLSPRetransInt = 5;
	poEntry->u32CSNPInterval = 10;
	poEntry->u32PartSNPInterval = 2;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisCircLevelTable_BTree);
	return poEntry;
}

isisCircLevelEntry_t *
isisCircLevelTable_getByIndex (
	uint32_t u32Index,
	int32_t i32Index)
{
	register isisCircLevelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisCircLevelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircLevelEntry_t, oBTreeNode);
}

isisCircLevelEntry_t *
isisCircLevelTable_getNextIndex (
	uint32_t u32Index,
	int32_t i32Index)
{
	register isisCircLevelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisCircLevelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircLevelEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisCircLevelTable_removeEntry (isisCircLevelEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircLevelTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisCircLevelTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisCircLevelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisCircLevelTable_BTree);
	return isisCircLevelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisCircLevelTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircLevelEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisCircLevelEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisCircLevelTable_BTree);
	return put_index_data;
}

bool
isisCircLevelTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircLevelEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisCircLevelTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisCircLevelTable table mapper */
int
isisCircLevelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisCircLevelEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCLEVELMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Metric);
				break;
			case ISISCIRCLEVELWIDEMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WideMetric);
				break;
			case ISISCIRCLEVELISPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ISPriority);
				break;
			case ISISCIRCLEVELIDOCTET:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IDOctet);
				break;
			case ISISCIRCLEVELID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ID, table_entry->u16ID_len);
				break;
			case ISISCIRCLEVELDESIS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DesIS, table_entry->u16DesIS_len);
				break;
			case ISISCIRCLEVELHELLOMULTIPLIER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32HelloMultiplier);
				break;
			case ISISCIRCLEVELHELLOTIMER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32HelloTimer);
				break;
			case ISISCIRCLEVELDRHELLOTIMER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DRHelloTimer);
				break;
			case ISISCIRCLEVELLSPTHROTTLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LSPThrottle);
				break;
			case ISISCIRCLEVELMINLSPRETRANSINT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MinLSPRetransInt);
				break;
			case ISISCIRCLEVELCSNPINTERVAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CSNPInterval);
				break;
			case ISISCIRCLEVELPARTSNPINTERVAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PartSNPInterval);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCLEVELMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELWIDEMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELISPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELHELLOMULTIPLIER:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELHELLOTIMER:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELDRHELLOTIMER:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELLSPTHROTTLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELMINLSPRETRANSINT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELCSNPINTERVAL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISCIRCLEVELPARTSNPINTERVAL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisCircLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISCIRCLEVELMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Metric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Metric, sizeof (table_entry->u32Metric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Metric = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELWIDEMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WideMetric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WideMetric, sizeof (table_entry->u32WideMetric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WideMetric = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELISPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ISPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ISPriority, sizeof (table_entry->u32ISPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ISPriority = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELHELLOMULTIPLIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32HelloMultiplier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32HelloMultiplier, sizeof (table_entry->u32HelloMultiplier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32HelloMultiplier = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELHELLOTIMER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32HelloTimer))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32HelloTimer, sizeof (table_entry->u32HelloTimer));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32HelloTimer = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELDRHELLOTIMER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32DRHelloTimer))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32DRHelloTimer, sizeof (table_entry->u32DRHelloTimer));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32DRHelloTimer = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELLSPTHROTTLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LSPThrottle))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LSPThrottle, sizeof (table_entry->u32LSPThrottle));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LSPThrottle = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELMINLSPRETRANSINT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MinLSPRetransInt))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MinLSPRetransInt, sizeof (table_entry->u32MinLSPRetransInt));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MinLSPRetransInt = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELCSNPINTERVAL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CSNPInterval))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CSNPInterval, sizeof (table_entry->u32CSNPInterval));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CSNPInterval = *request->requestvb->val.integer;
				break;
			case ISISCIRCLEVELPARTSNPINTERVAL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PartSNPInterval))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PartSNPInterval, sizeof (table_entry->u32PartSNPInterval));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PartSNPInterval = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisCircLevelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCLEVELMETRIC:
				memcpy (&table_entry->u32Metric, pvOldDdata, sizeof (table_entry->u32Metric));
				break;
			case ISISCIRCLEVELWIDEMETRIC:
				memcpy (&table_entry->u32WideMetric, pvOldDdata, sizeof (table_entry->u32WideMetric));
				break;
			case ISISCIRCLEVELISPRIORITY:
				memcpy (&table_entry->u32ISPriority, pvOldDdata, sizeof (table_entry->u32ISPriority));
				break;
			case ISISCIRCLEVELHELLOMULTIPLIER:
				memcpy (&table_entry->u32HelloMultiplier, pvOldDdata, sizeof (table_entry->u32HelloMultiplier));
				break;
			case ISISCIRCLEVELHELLOTIMER:
				memcpy (&table_entry->u32HelloTimer, pvOldDdata, sizeof (table_entry->u32HelloTimer));
				break;
			case ISISCIRCLEVELDRHELLOTIMER:
				memcpy (&table_entry->u32DRHelloTimer, pvOldDdata, sizeof (table_entry->u32DRHelloTimer));
				break;
			case ISISCIRCLEVELLSPTHROTTLE:
				memcpy (&table_entry->u32LSPThrottle, pvOldDdata, sizeof (table_entry->u32LSPThrottle));
				break;
			case ISISCIRCLEVELMINLSPRETRANSINT:
				memcpy (&table_entry->u32MinLSPRetransInt, pvOldDdata, sizeof (table_entry->u32MinLSPRetransInt));
				break;
			case ISISCIRCLEVELCSNPINTERVAL:
				memcpy (&table_entry->u32CSNPInterval, pvOldDdata, sizeof (table_entry->u32CSNPInterval));
				break;
			case ISISCIRCLEVELPARTSNPINTERVAL:
				memcpy (&table_entry->u32PartSNPInterval, pvOldDdata, sizeof (table_entry->u32PartSNPInterval));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisSystemCounterTable table mapper **/
void
isisSystemCounterTable_init (void)
{
	extern oid isisSystemCounterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisSystemCounterTable", &isisSystemCounterTable_mapper,
		isisSystemCounterTable_oid, OID_LENGTH (isisSystemCounterTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisSysStatLevel */,
		0);
	table_info->min_column = ISISSYSSTATCORRLSPS;
	table_info->max_column = ISISSYSSTATLSPERRORS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisSystemCounterTable_getFirst;
	iinfo->get_next_data_point = &isisSystemCounterTable_getNext;
	iinfo->get_data_point = &isisSystemCounterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisSystemCounterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisSystemCounterEntry_t *pEntry1 = xBTree_entry (pNode1, isisSystemCounterEntry_t, oBTreeNode);
	register isisSystemCounterEntry_t *pEntry2 = xBTree_entry (pNode2, isisSystemCounterEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32StatLevel < pEntry2->i32StatLevel) ? -1:
		(pEntry1->i32StatLevel == pEntry2->i32StatLevel) ? 0: 1;
}

xBTree_t oIsisSystemCounterTable_BTree = xBTree_initInline (&isisSystemCounterTable_BTreeNodeCmp);

/* create a new row in the table */
isisSystemCounterEntry_t *
isisSystemCounterTable_createEntry (
	int32_t i32StatLevel)
{
	register isisSystemCounterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32StatLevel = i32StatLevel;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSystemCounterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisSystemCounterTable_BTree);
	return poEntry;
}

isisSystemCounterEntry_t *
isisSystemCounterTable_getByIndex (
	int32_t i32StatLevel)
{
	register isisSystemCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32StatLevel = i32StatLevel;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisSystemCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSystemCounterEntry_t, oBTreeNode);
}

isisSystemCounterEntry_t *
isisSystemCounterTable_getNextIndex (
	int32_t i32StatLevel)
{
	register isisSystemCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32StatLevel = i32StatLevel;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisSystemCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisSystemCounterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisSystemCounterTable_removeEntry (isisSystemCounterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisSystemCounterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisSystemCounterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisSystemCounterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisSystemCounterTable_BTree);
	return isisSystemCounterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisSystemCounterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSystemCounterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisSystemCounterEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32StatLevel);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisSystemCounterTable_BTree);
	return put_index_data;
}

bool
isisSystemCounterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisSystemCounterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = isisSystemCounterTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisSystemCounterTable table mapper */
int
isisSystemCounterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisSystemCounterEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisSystemCounterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISSYSSTATCORRLSPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatCorrLSPs);
				break;
			case ISISSYSSTATAUTHTYPEFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatAuthTypeFails);
				break;
			case ISISSYSSTATAUTHFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatAuthFails);
				break;
			case ISISSYSSTATLSPDBASEOLOADS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatLSPDbaseOloads);
				break;
			case ISISSYSSTATMANADDRDROPFROMAREAS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatManAddrDropFromAreas);
				break;
			case ISISSYSSTATATTMPTTOEXMAXSEQNUMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatAttmptToExMaxSeqNums);
				break;
			case ISISSYSSTATSEQNUMSKIPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatSeqNumSkips);
				break;
			case ISISSYSSTATOWNLSPPURGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatOwnLSPPurges);
				break;
			case ISISSYSSTATIDFIELDLENMISMATCHES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatIDFieldLenMismatches);
				break;
			case ISISSYSSTATPARTCHANGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatPartChanges);
				break;
			case ISISSYSSTATSPFRUNS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatSPFRuns);
				break;
			case ISISSYSSTATLSPERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StatLSPErrors);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisCircuitCounterTable table mapper **/
void
isisCircuitCounterTable_init (void)
{
	extern oid isisCircuitCounterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisCircuitCounterTable", &isisCircuitCounterTable_mapper,
		isisCircuitCounterTable_oid, OID_LENGTH (isisCircuitCounterTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_INTEGER /* index: isisCircuitType */,
		0);
	table_info->min_column = ISISCIRCADJCHANGES;
	table_info->max_column = ISISCIRCLANDESISCHANGES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisCircuitCounterTable_getFirst;
	iinfo->get_next_data_point = &isisCircuitCounterTable_getNext;
	iinfo->get_data_point = &isisCircuitCounterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisCircuitCounterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisCircuitCounterEntry_t *pEntry1 = xBTree_entry (pNode1, isisCircuitCounterEntry_t, oBTreeNode);
	register isisCircuitCounterEntry_t *pEntry2 = xBTree_entry (pNode2, isisCircuitCounterEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->i32IsisCircuitType < pEntry2->i32IsisCircuitType) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->i32IsisCircuitType == pEntry2->i32IsisCircuitType) ? 0: 1;
}

xBTree_t oIsisCircuitCounterTable_BTree = xBTree_initInline (&isisCircuitCounterTable_BTreeNodeCmp);

/* create a new row in the table */
isisCircuitCounterEntry_t *
isisCircuitCounterTable_createEntry (
	uint32_t u32Index,
	int32_t i32IsisCircuitType)
{
	register isisCircuitCounterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->i32IsisCircuitType = i32IsisCircuitType;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree);
	return poEntry;
}

isisCircuitCounterEntry_t *
isisCircuitCounterTable_getByIndex (
	uint32_t u32Index,
	int32_t i32IsisCircuitType)
{
	register isisCircuitCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->i32IsisCircuitType = i32IsisCircuitType;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircuitCounterEntry_t, oBTreeNode);
}

isisCircuitCounterEntry_t *
isisCircuitCounterTable_getNextIndex (
	uint32_t u32Index,
	int32_t i32IsisCircuitType)
{
	register isisCircuitCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->i32IsisCircuitType = i32IsisCircuitType;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisCircuitCounterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisCircuitCounterTable_removeEntry (isisCircuitCounterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisCircuitCounterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisCircuitCounterTable_BTree);
	return isisCircuitCounterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisCircuitCounterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircuitCounterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisCircuitCounterEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IsisCircuitType);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisCircuitCounterTable_BTree);
	return put_index_data;
}

bool
isisCircuitCounterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisCircuitCounterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisCircuitCounterTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisCircuitCounterTable table mapper */
int
isisCircuitCounterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisCircuitCounterEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisCircuitCounterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISCIRCADJCHANGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32AdjChanges);
				break;
			case ISISCIRCNUMADJ:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NumAdj);
				break;
			case ISISCIRCINITFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InitFails);
				break;
			case ISISCIRCREJADJS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32RejAdjs);
				break;
			case ISISCIRCIDFIELDLENMISMATCHES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IDFieldLenMismatches);
				break;
			case ISISCIRCMAXAREAADDRMISMATCHES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32MaxAreaAddrMismatches);
				break;
			case ISISCIRCAUTHTYPEFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32AuthTypeFails);
				break;
			case ISISCIRCAUTHFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32AuthFails);
				break;
			case ISISCIRCLANDESISCHANGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LANDesISChanges);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisPacketCounterTable table mapper **/
void
isisPacketCounterTable_init (void)
{
	extern oid isisPacketCounterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisPacketCounterTable", &isisPacketCounterTable_mapper,
		isisPacketCounterTable_oid, OID_LENGTH (isisPacketCounterTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_INTEGER /* index: isisPacketCountLevel */,
		ASN_INTEGER /* index: isisPacketCountDirection */,
		0);
	table_info->min_column = ISISPACKETCOUNTIIHELLO;
	table_info->max_column = ISISPACKETCOUNTUNKNOWN;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisPacketCounterTable_getFirst;
	iinfo->get_next_data_point = &isisPacketCounterTable_getNext;
	iinfo->get_data_point = &isisPacketCounterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisPacketCounterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisPacketCounterEntry_t *pEntry1 = xBTree_entry (pNode1, isisPacketCounterEntry_t, oBTreeNode);
	register isisPacketCounterEntry_t *pEntry2 = xBTree_entry (pNode2, isisPacketCounterEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->i32PacketCountLevel < pEntry2->i32PacketCountLevel) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->i32PacketCountLevel == pEntry2->i32PacketCountLevel && pEntry1->i32PacketCountDirection < pEntry2->i32PacketCountDirection) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->i32PacketCountLevel == pEntry2->i32PacketCountLevel && pEntry1->i32PacketCountDirection == pEntry2->i32PacketCountDirection) ? 0: 1;
}

xBTree_t oIsisPacketCounterTable_BTree = xBTree_initInline (&isisPacketCounterTable_BTreeNodeCmp);

/* create a new row in the table */
isisPacketCounterEntry_t *
isisPacketCounterTable_createEntry (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection)
{
	register isisPacketCounterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->i32PacketCountLevel = i32PacketCountLevel;
	poEntry->i32PacketCountDirection = i32PacketCountDirection;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisPacketCounterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisPacketCounterTable_BTree);
	return poEntry;
}

isisPacketCounterEntry_t *
isisPacketCounterTable_getByIndex (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection)
{
	register isisPacketCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->i32PacketCountLevel = i32PacketCountLevel;
	poTmpEntry->i32PacketCountDirection = i32PacketCountDirection;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisPacketCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisPacketCounterEntry_t, oBTreeNode);
}

isisPacketCounterEntry_t *
isisPacketCounterTable_getNextIndex (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection)
{
	register isisPacketCounterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->i32PacketCountLevel = i32PacketCountLevel;
	poTmpEntry->i32PacketCountDirection = i32PacketCountDirection;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisPacketCounterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisPacketCounterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisPacketCounterTable_removeEntry (isisPacketCounterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisPacketCounterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisPacketCounterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisPacketCounterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisPacketCounterTable_BTree);
	return isisPacketCounterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisPacketCounterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisPacketCounterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisPacketCounterEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PacketCountLevel);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PacketCountDirection);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisPacketCounterTable_BTree);
	return put_index_data;
}

bool
isisPacketCounterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisPacketCounterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisPacketCounterTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisPacketCounterTable table mapper */
int
isisPacketCounterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisPacketCounterEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisPacketCounterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISPACKETCOUNTIIHELLO:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountIIHello);
				break;
			case ISISPACKETCOUNTISHELLO:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountISHello);
				break;
			case ISISPACKETCOUNTESHELLO:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountESHello);
				break;
			case ISISPACKETCOUNTLSP:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountLSP);
				break;
			case ISISPACKETCOUNTCSNP:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountCSNP);
				break;
			case ISISPACKETCOUNTPSNP:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountPSNP);
				break;
			case ISISPACKETCOUNTUNKNOWN:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PacketCountUnknown);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisISAdjTable table mapper **/
void
isisISAdjTable_init (void)
{
	extern oid isisISAdjTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisISAdjTable", &isisISAdjTable_mapper,
		isisISAdjTable_oid, OID_LENGTH (isisISAdjTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_UNSIGNED /* index: isisISAdjIndex */,
		0);
	table_info->min_column = ISISISADJSTATE;
	table_info->max_column = ISISISADJLASTUPTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisISAdjTable_getFirst;
	iinfo->get_next_data_point = &isisISAdjTable_getNext;
	iinfo->get_data_point = &isisISAdjTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisISAdjTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisISAdjEntry_t *pEntry1 = xBTree_entry (pNode1, isisISAdjEntry_t, oBTreeNode);
	register isisISAdjEntry_t *pEntry2 = xBTree_entry (pNode2, isisISAdjEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisISAdjTable_BTree = xBTree_initInline (&isisISAdjTable_BTreeNodeCmp);

/* create a new row in the table */
isisISAdjEntry_t *
isisISAdjTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisISAdjEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisISAdjTable_BTree);
	return poEntry;
}

isisISAdjEntry_t *
isisISAdjTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisISAdjEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisISAdjTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjEntry_t, oBTreeNode);
}

isisISAdjEntry_t *
isisISAdjTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisISAdjEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisISAdjTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisISAdjTable_removeEntry (isisISAdjEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisISAdjTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisISAdjTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisISAdjTable_BTree);
	return isisISAdjTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisISAdjTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisISAdjEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisISAdjTable_BTree);
	return put_index_data;
}

bool
isisISAdjTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisISAdjTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisISAdjTable table mapper */
int
isisISAdjTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisISAdjEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisISAdjEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISISADJSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case ISISISADJ3WAYSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ISAdj3WayState);
				break;
			case ISISISADJNEIGHSNPAADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NeighSNPAAddress, table_entry->u16NeighSNPAAddress_len);
				break;
			case ISISISADJNEIGHSYSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NeighSysType);
				break;
			case ISISISADJNEIGHSYSID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NeighSysID, table_entry->u16NeighSysID_len);
				break;
			case ISISISADJNBREXTENDEDCIRCID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NbrExtendedCircID);
				break;
			case ISISISADJUSAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Usage);
				break;
			case ISISISADJHOLDTIMER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32HoldTimer);
				break;
			case ISISISADJNEIGHPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NeighPriority);
				break;
			case ISISISADJLASTUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastUpTime);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisISAdjAreaAddrTable table mapper **/
void
isisISAdjAreaAddrTable_init (void)
{
	extern oid isisISAdjAreaAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisISAdjAreaAddrTable", &isisISAdjAreaAddrTable_mapper,
		isisISAdjAreaAddrTable_oid, OID_LENGTH (isisISAdjAreaAddrTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_UNSIGNED /* index: isisISAdjIndex */,
		ASN_UNSIGNED /* index: isisISAdjAreaAddrIndex */,
		0);
	table_info->min_column = ISISISADJAREAADDRESS;
	table_info->max_column = ISISISADJAREAADDRESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisISAdjAreaAddrTable_getFirst;
	iinfo->get_next_data_point = &isisISAdjAreaAddrTable_getNext;
	iinfo->get_data_point = &isisISAdjAreaAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisISAdjAreaAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisISAdjAreaAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisISAdjAreaAddrEntry_t, oBTreeNode);
	register isisISAdjAreaAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisISAdjAreaAddrEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex < pEntry2->u32ISAdjIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisISAdjAreaAddrTable_BTree = xBTree_initInline (&isisISAdjAreaAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisISAdjAreaAddrEntry_t *
isisISAdjAreaAddrTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjAreaAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->u32ISAdjIndex = u32ISAdjIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree);
	return poEntry;
}

isisISAdjAreaAddrEntry_t *
isisISAdjAreaAddrTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjAreaAddrEntry_t, oBTreeNode);
}

isisISAdjAreaAddrEntry_t *
isisISAdjAreaAddrTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjAreaAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjAreaAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisISAdjAreaAddrTable_removeEntry (isisISAdjAreaAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisISAdjAreaAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisISAdjAreaAddrTable_BTree);
	return isisISAdjAreaAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisISAdjAreaAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjAreaAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisISAdjAreaAddrEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ISAdjIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisISAdjAreaAddrTable_BTree);
	return put_index_data;
}

bool
isisISAdjAreaAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjAreaAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisISAdjAreaAddrTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisISAdjAreaAddrTable table mapper */
int
isisISAdjAreaAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisISAdjAreaAddrEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisISAdjAreaAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISISADJAREAADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ISAdjAreaAddress, table_entry->u16ISAdjAreaAddress_len);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisISAdjIPAddrTable table mapper **/
void
isisISAdjIPAddrTable_init (void)
{
	extern oid isisISAdjIPAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisISAdjIPAddrTable", &isisISAdjIPAddrTable_mapper,
		isisISAdjIPAddrTable_oid, OID_LENGTH (isisISAdjIPAddrTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_UNSIGNED /* index: isisISAdjIndex */,
		ASN_UNSIGNED /* index: isisISAdjIPAddrIndex */,
		0);
	table_info->min_column = ISISISADJIPADDRTYPE;
	table_info->max_column = ISISISADJIPADDRADDRESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisISAdjIPAddrTable_getFirst;
	iinfo->get_next_data_point = &isisISAdjIPAddrTable_getNext;
	iinfo->get_data_point = &isisISAdjIPAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisISAdjIPAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisISAdjIPAddrEntry_t *pEntry1 = xBTree_entry (pNode1, isisISAdjIPAddrEntry_t, oBTreeNode);
	register isisISAdjIPAddrEntry_t *pEntry2 = xBTree_entry (pNode2, isisISAdjIPAddrEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex < pEntry2->u32ISAdjIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisISAdjIPAddrTable_BTree = xBTree_initInline (&isisISAdjIPAddrTable_BTreeNodeCmp);

/* create a new row in the table */
isisISAdjIPAddrEntry_t *
isisISAdjIPAddrTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjIPAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->u32ISAdjIndex = u32ISAdjIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree);
	return poEntry;
}

isisISAdjIPAddrEntry_t *
isisISAdjIPAddrTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjIPAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjIPAddrEntry_t, oBTreeNode);
}

isisISAdjIPAddrEntry_t *
isisISAdjIPAddrTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index)
{
	register isisISAdjIPAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjIPAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisISAdjIPAddrTable_removeEntry (isisISAdjIPAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisISAdjIPAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisISAdjIPAddrTable_BTree);
	return isisISAdjIPAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisISAdjIPAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjIPAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisISAdjIPAddrEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ISAdjIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisISAdjIPAddrTable_BTree);
	return put_index_data;
}

bool
isisISAdjIPAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjIPAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisISAdjIPAddrTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisISAdjIPAddrTable table mapper */
int
isisISAdjIPAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisISAdjIPAddrEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisISAdjIPAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISISADJIPADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case ISISISADJIPADDRADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Address, table_entry->u16Address_len);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisISAdjProtSuppTable table mapper **/
void
isisISAdjProtSuppTable_init (void)
{
	extern oid isisISAdjProtSuppTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisISAdjProtSuppTable", &isisISAdjProtSuppTable_mapper,
		isisISAdjProtSuppTable_oid, OID_LENGTH (isisISAdjProtSuppTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_UNSIGNED /* index: isisISAdjIndex */,
		ASN_INTEGER /* index: isisISAdjProtSuppProtocol */,
		0);
	table_info->min_column = ISISISADJPROTSUPPPROTOCOL;
	table_info->max_column = ISISISADJPROTSUPPPROTOCOL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisISAdjProtSuppTable_getFirst;
	iinfo->get_next_data_point = &isisISAdjProtSuppTable_getNext;
	iinfo->get_data_point = &isisISAdjProtSuppTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisISAdjProtSuppTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisISAdjProtSuppEntry_t *pEntry1 = xBTree_entry (pNode1, isisISAdjProtSuppEntry_t, oBTreeNode);
	register isisISAdjProtSuppEntry_t *pEntry2 = xBTree_entry (pNode2, isisISAdjProtSuppEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex < pEntry2->u32ISAdjIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->i32Protocol < pEntry2->i32Protocol) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32ISAdjIndex == pEntry2->u32ISAdjIndex && pEntry1->i32Protocol == pEntry2->i32Protocol) ? 0: 1;
}

xBTree_t oIsisISAdjProtSuppTable_BTree = xBTree_initInline (&isisISAdjProtSuppTable_BTreeNodeCmp);

/* create a new row in the table */
isisISAdjProtSuppEntry_t *
isisISAdjProtSuppTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol)
{
	register isisISAdjProtSuppEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->u32ISAdjIndex = u32ISAdjIndex;
	poEntry->i32Protocol = i32Protocol;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree);
	return poEntry;
}

isisISAdjProtSuppEntry_t *
isisISAdjProtSuppTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol)
{
	register isisISAdjProtSuppEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->i32Protocol = i32Protocol;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjProtSuppEntry_t, oBTreeNode);
}

isisISAdjProtSuppEntry_t *
isisISAdjProtSuppTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol)
{
	register isisISAdjProtSuppEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32ISAdjIndex = u32ISAdjIndex;
	poTmpEntry->i32Protocol = i32Protocol;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisISAdjProtSuppEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisISAdjProtSuppTable_removeEntry (isisISAdjProtSuppEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisISAdjProtSuppTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisISAdjProtSuppTable_BTree);
	return isisISAdjProtSuppTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisISAdjProtSuppTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjProtSuppEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisISAdjProtSuppEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ISAdjIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Protocol);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisISAdjProtSuppTable_BTree);
	return put_index_data;
}

bool
isisISAdjProtSuppTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisISAdjProtSuppEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisISAdjProtSuppTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisISAdjProtSuppTable table mapper */
int
isisISAdjProtSuppTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisISAdjProtSuppEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisISAdjProtSuppEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISISADJPROTSUPPPROTOCOL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Protocol);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisRATable table mapper **/
void
isisRATable_init (void)
{
	extern oid isisRATable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisRATable", &isisRATable_mapper,
		isisRATable_oid, OID_LENGTH (isisRATable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: isisCircIndex */,
		ASN_UNSIGNED /* index: isisRAIndex */,
		0);
	table_info->min_column = ISISRAEXISTSTATE;
	table_info->max_column = ISISRATYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisRATable_getFirst;
	iinfo->get_next_data_point = &isisRATable_getNext;
	iinfo->get_data_point = &isisRATable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisRATable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisRAEntry_t *pEntry1 = xBTree_entry (pNode1, isisRAEntry_t, oBTreeNode);
	register isisRAEntry_t *pEntry2 = xBTree_entry (pNode2, isisRAEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CircIndex < pEntry2->u32CircIndex) ||
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32CircIndex == pEntry2->u32CircIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisRATable_BTree = xBTree_initInline (&isisRATable_BTreeNodeCmp);

/* create a new row in the table */
isisRAEntry_t *
isisRATable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisRAEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CircIndex = u32CircIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRATable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8ExistState = xRowStatus_notInService_c;
	poEntry->i32AdminState = isisRAAdminState_off_c;
	poEntry->u32Metric = 20;
	poEntry->i32MetricType = isisRAMetricType_internal_c;
	/*poEntry->au8SNPAAddress = 0*/;
	/*poEntry->au8SNPAMask = 0*/;
	/*poEntry->au8SNPAPrefix = 0*/;
	poEntry->i32Type = isisRAType_manual_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisRATable_BTree);
	return poEntry;
}

isisRAEntry_t *
isisRATable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisRAEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisRATable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRAEntry_t, oBTreeNode);
}

isisRAEntry_t *
isisRATable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index)
{
	register isisRAEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CircIndex = u32CircIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisRATable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisRAEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisRATable_removeEntry (isisRAEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisRATable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisRATable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisRATable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisRATable_BTree);
	return isisRATable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisRATable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRAEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisRAEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CircIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisRATable_BTree);
	return put_index_data;
}

bool
isisRATable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisRAEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisRATable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisRATable table mapper */
int
isisRATable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisRAEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
			case ISISRAADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminState);
				break;
			case ISISRAADDRPREFIX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AddrPrefix, table_entry->u16AddrPrefix_len);
				break;
			case ISISRAMAPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MapType);
				break;
			case ISISRAMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Metric);
				break;
			case ISISRAMETRICTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MetricType);
				break;
			case ISISRASNPAADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SNPAAddress, table_entry->u16SNPAAddress_len);
				break;
			case ISISRASNPAMASK:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SNPAMask, table_entry->u16SNPAMask_len);
				break;
			case ISISRASNPAPREFIX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SNPAPrefix, table_entry->u16SNPAPrefix_len);
				break;
			case ISISRATYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRAADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRAADDRPREFIX:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AddrPrefix));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRAMAPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRAMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRAMETRICTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRASNPAADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SNPAAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRASNPAMASK:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SNPAMask));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRASNPAPREFIX:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SNPAPrefix));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISRATYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisRATable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisRATable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISRAADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminState, sizeof (table_entry->i32AdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminState = *request->requestvb->val.integer;
				break;
			case ISISRAADDRPREFIX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AddrPrefix))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AddrPrefix_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AddrPrefix, sizeof (table_entry->au8AddrPrefix));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AddrPrefix, 0, sizeof (table_entry->au8AddrPrefix));
				memcpy (table_entry->au8AddrPrefix, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AddrPrefix_len = request->requestvb->val_len;
				break;
			case ISISRAMAPTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MapType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MapType, sizeof (table_entry->i32MapType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MapType = *request->requestvb->val.integer;
				break;
			case ISISRAMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Metric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Metric, sizeof (table_entry->u32Metric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Metric = *request->requestvb->val.integer;
				break;
			case ISISRAMETRICTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MetricType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MetricType, sizeof (table_entry->i32MetricType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MetricType = *request->requestvb->val.integer;
				break;
			case ISISRASNPAADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SNPAAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SNPAAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SNPAAddress, sizeof (table_entry->au8SNPAAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SNPAAddress, 0, sizeof (table_entry->au8SNPAAddress));
				memcpy (table_entry->au8SNPAAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SNPAAddress_len = request->requestvb->val_len;
				break;
			case ISISRASNPAMASK:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SNPAMask))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SNPAMask_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SNPAMask, sizeof (table_entry->au8SNPAMask));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SNPAMask, 0, sizeof (table_entry->au8SNPAMask));
				memcpy (table_entry->au8SNPAMask, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SNPAMask_len = request->requestvb->val_len;
				break;
			case ISISRASNPAPREFIX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SNPAPrefix))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SNPAPrefix_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SNPAPrefix, sizeof (table_entry->au8SNPAPrefix));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SNPAPrefix, 0, sizeof (table_entry->au8SNPAPrefix));
				memcpy (table_entry->au8SNPAPrefix, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SNPAPrefix_len = request->requestvb->val_len;
				break;
			case ISISRATYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Type))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Type, sizeof (table_entry->i32Type));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Type = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisRATable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisRATable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case ISISRAADMINSTATE:
				memcpy (&table_entry->i32AdminState, pvOldDdata, sizeof (table_entry->i32AdminState));
				break;
			case ISISRAADDRPREFIX:
				memcpy (table_entry->au8AddrPrefix, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AddrPrefix_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ISISRAMAPTYPE:
				memcpy (&table_entry->i32MapType, pvOldDdata, sizeof (table_entry->i32MapType));
				break;
			case ISISRAMETRIC:
				memcpy (&table_entry->u32Metric, pvOldDdata, sizeof (table_entry->u32Metric));
				break;
			case ISISRAMETRICTYPE:
				memcpy (&table_entry->i32MetricType, pvOldDdata, sizeof (table_entry->i32MetricType));
				break;
			case ISISRASNPAADDRESS:
				memcpy (table_entry->au8SNPAAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SNPAAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ISISRASNPAMASK:
				memcpy (table_entry->au8SNPAMask, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SNPAMask_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ISISRASNPAPREFIX:
				memcpy (table_entry->au8SNPAPrefix, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SNPAPrefix_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ISISRATYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisRATable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisIPRATable table mapper **/
void
isisIPRATable_init (void)
{
	extern oid isisIPRATable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisIPRATable", &isisIPRATable_mapper,
		isisIPRATable_oid, OID_LENGTH (isisIPRATable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisSysLevelIndex */,
		ASN_INTEGER /* index: isisIPRADestType */,
		ASN_OCTET_STR /* index: isisIPRADest */,
		ASN_UNSIGNED /* index: isisIPRADestPrefixLen */,
		ASN_UNSIGNED /* index: isisIPRANextHopIndex */,
		0);
	table_info->min_column = ISISIPRANEXTHOPTYPE;
	table_info->max_column = ISISIPRASOURCETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisIPRATable_getFirst;
	iinfo->get_next_data_point = &isisIPRATable_getNext;
	iinfo->get_data_point = &isisIPRATable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisIPRATable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisIPRAEntry_t *pEntry1 = xBTree_entry (pNode1, isisIPRAEntry_t, oBTreeNode);
	register isisIPRAEntry_t *pEntry2 = xBTree_entry (pNode2, isisIPRAEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32SysLevelIndex < pEntry2->i32SysLevelIndex) ||
		(pEntry1->i32SysLevelIndex == pEntry2->i32SysLevelIndex && pEntry1->i32DestType < pEntry2->i32DestType) ||
		(pEntry1->i32SysLevelIndex == pEntry2->i32SysLevelIndex && pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == -1) ||
		(pEntry1->i32SysLevelIndex == pEntry2->i32SysLevelIndex && pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen < pEntry2->u32DestPrefixLen) ||
		(pEntry1->i32SysLevelIndex == pEntry2->i32SysLevelIndex && pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32NextHopIndex < pEntry2->u32NextHopIndex) ? -1:
		(pEntry1->i32SysLevelIndex == pEntry2->i32SysLevelIndex && pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32NextHopIndex == pEntry2->u32NextHopIndex) ? 0: 1;
}

xBTree_t oIsisIPRATable_BTree = xBTree_initInline (&isisIPRATable_BTreeNodeCmp);

/* create a new row in the table */
isisIPRAEntry_t *
isisIPRATable_createEntry (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex)
{
	register isisIPRAEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32SysLevelIndex = i32SysLevelIndex;
	poEntry->i32DestType = i32DestType;
	memcpy (poEntry->au8Dest, pau8Dest, u16Dest_len);
	poEntry->u16Dest_len = u16Dest_len;
	poEntry->u32DestPrefixLen = u32DestPrefixLen;
	poEntry->u32NextHopIndex = u32NextHopIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisIPRATable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8ExistState = xRowStatus_notInService_c;
	poEntry->i32AdminState = isisIPRAAdminState_off_c;
	poEntry->u32Metric = 10;
	poEntry->i32MetricType = isisIPRAMetricType_internal_c;
	poEntry->u32FullMetric = 10;
	/*poEntry->au8SNPAAddress = 0*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisIPRATable_BTree);
	return poEntry;
}

isisIPRAEntry_t *
isisIPRATable_getByIndex (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex)
{
	register isisIPRAEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SysLevelIndex = i32SysLevelIndex;
	poTmpEntry->i32DestType = i32DestType;
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32NextHopIndex = u32NextHopIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisIPRATable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisIPRAEntry_t, oBTreeNode);
}

isisIPRAEntry_t *
isisIPRATable_getNextIndex (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex)
{
	register isisIPRAEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SysLevelIndex = i32SysLevelIndex;
	poTmpEntry->i32DestType = i32DestType;
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32NextHopIndex = u32NextHopIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisIPRATable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisIPRAEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisIPRATable_removeEntry (isisIPRAEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisIPRATable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisIPRATable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisIPRATable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisIPRATable_BTree);
	return isisIPRATable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisIPRATable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisIPRAEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisIPRAEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32SysLevelIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32DestType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Dest, poEntry->u16Dest_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32DestPrefixLen);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32NextHopIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisIPRATable_BTree);
	return put_index_data;
}

bool
isisIPRATable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisIPRAEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = isisIPRATable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		(void*) idx3->val.string, idx3->val_len,
		*idx4->val.integer,
		*idx5->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisIPRATable table mapper */
int
isisIPRATable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisIPRAEntry_t *table_entry;
	void *pvOldDdata = NULL;
	int ret;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISIPRANEXTHOPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NextHopType);
				break;
			case ISISIPRANEXTHOP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NextHop, table_entry->u16NextHop_len);
				break;
			case ISISIPRATYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case ISISIPRAEXISTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ExistState);
				break;
			case ISISIPRAADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminState);
				break;
			case ISISIPRAMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Metric);
				break;
			case ISISIPRAMETRICTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MetricType);
				break;
			case ISISIPRAFULLMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32FullMetric);
				break;
			case ISISIPRASNPAADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SNPAAddress, table_entry->u16SNPAAddress_len);
				break;
			case ISISIPRASOURCETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SourceType);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	/*
	 * Write-support
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISIPRANEXTHOPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRANEXTHOP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NextHop));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRATYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRAEXISTSTATE:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRAADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRAMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRAMETRICTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRAFULLMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ISISIPRASNPAADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SNPAAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			register netsnmp_variable_list *idx5 = idx4->next_variable;
			
			switch (table_info->colnum)
			{
			case ISISIPRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = isisIPRATable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						(void*) idx3->val.string, idx3->val_len,
						*idx4->val.integer,
						*idx5->val.integer);
					if (table_entry != NULL)
					{
						netsnmp_insert_iterator_context (request, table_entry);
						netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, table_entry, &xBuffer_free));
					}
					else
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
						return SNMP_ERR_NOERROR;
					}
					break;
					
				case RS_DESTROY:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISIPRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisIPRATable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISIPRANEXTHOPTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32NextHopType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32NextHopType, sizeof (table_entry->i32NextHopType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32NextHopType = *request->requestvb->val.integer;
				break;
			case ISISIPRANEXTHOP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NextHop))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NextHop_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NextHop, sizeof (table_entry->au8NextHop));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NextHop, 0, sizeof (table_entry->au8NextHop));
				memcpy (table_entry->au8NextHop, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NextHop_len = request->requestvb->val_len;
				break;
			case ISISIPRATYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Type))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Type, sizeof (table_entry->i32Type));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Type = *request->requestvb->val.integer;
				break;
			case ISISIPRAADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminState, sizeof (table_entry->i32AdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminState = *request->requestvb->val.integer;
				break;
			case ISISIPRAMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Metric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Metric, sizeof (table_entry->u32Metric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Metric = *request->requestvb->val.integer;
				break;
			case ISISIPRAMETRICTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MetricType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MetricType, sizeof (table_entry->i32MetricType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MetricType = *request->requestvb->val.integer;
				break;
			case ISISIPRAFULLMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32FullMetric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32FullMetric, sizeof (table_entry->u32FullMetric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32FullMetric = *request->requestvb->val.integer;
				break;
			case ISISIPRASNPAADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SNPAAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SNPAAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SNPAAddress, sizeof (table_entry->au8SNPAAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SNPAAddress, 0, sizeof (table_entry->au8SNPAAddress));
				memcpy (table_entry->au8SNPAAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SNPAAddress_len = request->requestvb->val_len;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISIPRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int isisIPRATable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					break;
				}
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISIPRANEXTHOPTYPE:
				memcpy (&table_entry->i32NextHopType, pvOldDdata, sizeof (table_entry->i32NextHopType));
				break;
			case ISISIPRANEXTHOP:
				memcpy (table_entry->au8NextHop, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NextHop_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ISISIPRATYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case ISISIPRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					isisIPRATable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case ISISIPRAADMINSTATE:
				memcpy (&table_entry->i32AdminState, pvOldDdata, sizeof (table_entry->i32AdminState));
				break;
			case ISISIPRAMETRIC:
				memcpy (&table_entry->u32Metric, pvOldDdata, sizeof (table_entry->u32Metric));
				break;
			case ISISIPRAMETRICTYPE:
				memcpy (&table_entry->i32MetricType, pvOldDdata, sizeof (table_entry->i32MetricType));
				break;
			case ISISIPRAFULLMETRIC:
				memcpy (&table_entry->u32FullMetric, pvOldDdata, sizeof (table_entry->u32FullMetric));
				break;
			case ISISIPRASNPAADDRESS:
				memcpy (table_entry->au8SNPAAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SNPAAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisIPRAEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ISISIPRAEXISTSTATE:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8ExistState = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8ExistState = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					isisIPRATable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisLSPSummaryTable table mapper **/
void
isisLSPSummaryTable_init (void)
{
	extern oid isisLSPSummaryTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisLSPSummaryTable", &isisLSPSummaryTable_mapper,
		isisLSPSummaryTable_oid, OID_LENGTH (isisLSPSummaryTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisLSPLevel */,
		ASN_OCTET_STR /* index: isisLSPID */,
		0);
	table_info->min_column = ISISLSPSEQ;
	table_info->max_column = ISISLSPATTRIBUTES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisLSPSummaryTable_getFirst;
	iinfo->get_next_data_point = &isisLSPSummaryTable_getNext;
	iinfo->get_data_point = &isisLSPSummaryTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisLSPSummaryTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisLSPSummaryEntry_t *pEntry1 = xBTree_entry (pNode1, isisLSPSummaryEntry_t, oBTreeNode);
	register isisLSPSummaryEntry_t *pEntry2 = xBTree_entry (pNode2, isisLSPSummaryEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Level < pEntry2->i32Level) ||
		(pEntry1->i32Level == pEntry2->i32Level && xBinCmp (pEntry1->au8ID, pEntry2->au8ID, pEntry1->u16ID_len, pEntry2->u16ID_len) == -1) ? -1:
		(pEntry1->i32Level == pEntry2->i32Level && xBinCmp (pEntry1->au8ID, pEntry2->au8ID, pEntry1->u16ID_len, pEntry2->u16ID_len) == 0) ? 0: 1;
}

xBTree_t oIsisLSPSummaryTable_BTree = xBTree_initInline (&isisLSPSummaryTable_BTreeNodeCmp);

/* create a new row in the table */
isisLSPSummaryEntry_t *
isisLSPSummaryTable_createEntry (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len)
{
	register isisLSPSummaryEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Level = i32Level;
	memcpy (poEntry->au8ID, pau8ID, u16ID_len);
	poEntry->u16ID_len = u16ID_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree);
	return poEntry;
}

isisLSPSummaryEntry_t *
isisLSPSummaryTable_getByIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len)
{
	register isisLSPSummaryEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Level = i32Level;
	memcpy (poTmpEntry->au8ID, pau8ID, u16ID_len);
	poTmpEntry->u16ID_len = u16ID_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisLSPSummaryEntry_t, oBTreeNode);
}

isisLSPSummaryEntry_t *
isisLSPSummaryTable_getNextIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len)
{
	register isisLSPSummaryEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Level = i32Level;
	memcpy (poTmpEntry->au8ID, pau8ID, u16ID_len);
	poTmpEntry->u16ID_len = u16ID_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisLSPSummaryEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisLSPSummaryTable_removeEntry (isisLSPSummaryEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisLSPSummaryTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisLSPSummaryTable_BTree);
	return isisLSPSummaryTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisLSPSummaryTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisLSPSummaryEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisLSPSummaryEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Level);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8ID, poEntry->u16ID_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisLSPSummaryTable_BTree);
	return put_index_data;
}

bool
isisLSPSummaryTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisLSPSummaryEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = isisLSPSummaryTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisLSPSummaryTable table mapper */
int
isisLSPSummaryTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisLSPSummaryEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisLSPSummaryEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISLSPSEQ:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Seq);
				break;
			case ISISLSPZEROLIFE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ZeroLife);
				break;
			case ISISLSPCHECKSUM:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Checksum);
				break;
			case ISISLSPLIFETIMEREMAIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LifetimeRemain);
				break;
			case ISISLSPPDULENGTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PDULength);
				break;
			case ISISLSPATTRIBUTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Attributes);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize isisLSPTLVTable table mapper **/
void
isisLSPTLVTable_init (void)
{
	extern oid isisLSPTLVTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"isisLSPTLVTable", &isisLSPTLVTable_mapper,
		isisLSPTLVTable_oid, OID_LENGTH (isisLSPTLVTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: isisLSPLevel */,
		ASN_OCTET_STR /* index: isisLSPID */,
		ASN_UNSIGNED /* index: isisLSPTLVIndex */,
		0);
	table_info->min_column = ISISLSPTLVSEQ;
	table_info->max_column = ISISLSPTLVVALUE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &isisLSPTLVTable_getFirst;
	iinfo->get_next_data_point = &isisLSPTLVTable_getNext;
	iinfo->get_data_point = &isisLSPTLVTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
isisLSPTLVTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register isisLSPTLVEntry_t *pEntry1 = xBTree_entry (pNode1, isisLSPTLVEntry_t, oBTreeNode);
	register isisLSPTLVEntry_t *pEntry2 = xBTree_entry (pNode2, isisLSPTLVEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Level < pEntry2->i32Level) ||
		(pEntry1->i32Level == pEntry2->i32Level && xBinCmp (pEntry1->au8ID, pEntry2->au8ID, pEntry1->u16ID_len, pEntry2->u16ID_len) == -1) ||
		(pEntry1->i32Level == pEntry2->i32Level && xBinCmp (pEntry1->au8ID, pEntry2->au8ID, pEntry1->u16ID_len, pEntry2->u16ID_len) == 0 && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->i32Level == pEntry2->i32Level && xBinCmp (pEntry1->au8ID, pEntry2->au8ID, pEntry1->u16ID_len, pEntry2->u16ID_len) == 0 && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIsisLSPTLVTable_BTree = xBTree_initInline (&isisLSPTLVTable_BTreeNodeCmp);

/* create a new row in the table */
isisLSPTLVEntry_t *
isisLSPTLVTable_createEntry (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index)
{
	register isisLSPTLVEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Level = i32Level;
	memcpy (poEntry->au8ID, pau8ID, u16ID_len);
	poEntry->u16ID_len = u16ID_len;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisLSPTLVTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIsisLSPTLVTable_BTree);
	return poEntry;
}

isisLSPTLVEntry_t *
isisLSPTLVTable_getByIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index)
{
	register isisLSPTLVEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Level = i32Level;
	memcpy (poTmpEntry->au8ID, pau8ID, u16ID_len);
	poTmpEntry->u16ID_len = u16ID_len;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIsisLSPTLVTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisLSPTLVEntry_t, oBTreeNode);
}

isisLSPTLVEntry_t *
isisLSPTLVTable_getNextIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index)
{
	register isisLSPTLVEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Level = i32Level;
	memcpy (poTmpEntry->au8ID, pau8ID, u16ID_len);
	poTmpEntry->u16ID_len = u16ID_len;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIsisLSPTLVTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, isisLSPTLVEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
isisLSPTLVTable_removeEntry (isisLSPTLVEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIsisLSPTLVTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIsisLSPTLVTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
isisLSPTLVTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIsisLSPTLVTable_BTree);
	return isisLSPTLVTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
isisLSPTLVTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisLSPTLVEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, isisLSPTLVEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Level);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8ID, poEntry->u16ID_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIsisLSPTLVTable_BTree);
	return put_index_data;
}

bool
isisLSPTLVTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	isisLSPTLVEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = isisLSPTLVTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* isisLSPTLVTable table mapper */
int
isisLSPTLVTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	isisLSPTLVEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (isisLSPTLVEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ISISLSPTLVSEQ:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Seq);
				break;
			case ISISLSPTLVCHECKSUM:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Checksum);
				break;
			case ISISLSPTLVTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Type);
				break;
			case ISISLSPTLVLEN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Len);
				break;
			case ISISLSPTLVVALUE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Value, table_entry->u16Value_len);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
			}
		}
		break;
		
	}
	
	return SNMP_ERR_NOERROR;
}


/**
 *	notification mapper(s)
 */
int
isisDatabaseOverload_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisDatabaseOverload_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisSysLevelState_oid[] = {1,3,6,1,2,1,138,1,2,1,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisDatabaseOverload_oid, sizeof (isisDatabaseOverload_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisSysLevelState_oid, OID_LENGTH (isisSysLevelState_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisSysLevelState */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisManualAddressDrops_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisManualAddressDrops_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationAreaAddress_oid[] = {1,3,6,1,2,1,138,1,10,1,15, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisManualAddressDrops_oid, sizeof (isisManualAddressDrops_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationAreaAddress_oid, OID_LENGTH (isisNotificationAreaAddress_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisNotificationAreaAddress */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisCorruptedLSPDetected_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisCorruptedLSPDetected_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisCorruptedLSPDetected_oid, sizeof (isisCorruptedLSPDetected_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisAttemptToExceedMaxSequence_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisAttemptToExceedMaxSequence_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisAttemptToExceedMaxSequence_oid, sizeof (isisAttemptToExceedMaxSequence_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisIDLenMismatch_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisIDLenMismatch_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisPduFieldLen_oid[] = {1,3,6,1,2,1,138,1,10,1,5, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisIDLenMismatch_oid, sizeof (isisIDLenMismatch_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFieldLen_oid, OID_LENGTH (isisPduFieldLen_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduFieldLen */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisMaxAreaAddressesMismatch_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisMaxAreaAddressesMismatch_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisPduMaxAreaAddress_oid[] = {1,3,6,1,2,1,138,1,10,1,6, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisMaxAreaAddressesMismatch_oid, sizeof (isisMaxAreaAddressesMismatch_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduMaxAreaAddress_oid, OID_LENGTH (isisPduMaxAreaAddress_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduMaxAreaAddress */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisOwnLSPPurge_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisOwnLSPPurge_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisOwnLSPPurge_oid, sizeof (isisOwnLSPPurge_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisSequenceNumberSkip_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisSequenceNumberSkip_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisSequenceNumberSkip_oid, sizeof (isisSequenceNumberSkip_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisAuthenticationTypeFailure_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisAuthenticationTypeFailure_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisAuthenticationTypeFailure_oid, sizeof (isisAuthenticationTypeFailure_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisAuthenticationFailure_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisAuthenticationFailure_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisAuthenticationFailure_oid, sizeof (isisAuthenticationFailure_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisVersionSkew_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisVersionSkew_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduProtocolVersion_oid[] = {1,3,6,1,2,1,138,1,10,1,7, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisVersionSkew_oid, sizeof (isisVersionSkew_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduProtocolVersion_oid, OID_LENGTH (isisPduProtocolVersion_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduProtocolVersion */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisAreaMismatch_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisAreaMismatch_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisAreaMismatch_oid, sizeof (isisAreaMismatch_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisRejectedAdjacency_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisRejectedAdjacency_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisRejectedAdjacency_oid, sizeof (isisRejectedAdjacency_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisLSPTooLargeToPropagate_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisLSPTooLargeToPropagate_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduLspSize_oid[] = {1,3,6,1,2,1,138,1,10,1,8, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisLSPTooLargeToPropagate_oid, sizeof (isisLSPTooLargeToPropagate_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspSize_oid, OID_LENGTH (isisPduLspSize_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduLspSize */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisOrigLSPBuffSizeMismatch_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisOrigLSPBuffSizeMismatch_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	oid isisPduOriginatingBufferSize_oid[] = {1,3,6,1,2,1,138,1,10,1,9, /* insert index here */};
	oid isisPduBufferSize_oid[] = {1,3,6,1,2,1,138,1,10,1,10, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisOrigLSPBuffSizeMismatch_oid, sizeof (isisOrigLSPBuffSizeMismatch_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduOriginatingBufferSize_oid, OID_LENGTH (isisPduOriginatingBufferSize_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduOriginatingBufferSize */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduBufferSize_oid, OID_LENGTH (isisPduBufferSize_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisPduBufferSize */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisProtocolsSupportedMismatch_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisProtocolsSupportedMismatch_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduProtocolsSupported_oid[] = {1,3,6,1,2,1,138,1,10,1,11, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisProtocolsSupportedMismatch_oid, sizeof (isisProtocolsSupportedMismatch_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduProtocolsSupported_oid, OID_LENGTH (isisPduProtocolsSupported_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduProtocolsSupported */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisAdjacencyChange_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisAdjacencyChange_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	oid isisAdjState_oid[] = {1,3,6,1,2,1,138,1,10,1,12, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisAdjacencyChange_oid, sizeof (isisAdjacencyChange_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisAdjState_oid, OID_LENGTH (isisAdjState_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisAdjState */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}

int
isisLSPErrorDetected_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid isisLSPErrorDetected_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid isisNotificationSysLevelIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,1, /* insert index here */};
	oid isisPduLspId_oid[] = {1,3,6,1,2,1,138,1,10,1,3, /* insert index here */};
	oid isisNotificationCircIfIndex_oid[] = {1,3,6,1,2,1,138,1,10,1,2, /* insert index here */};
	oid isisPduFragment_oid[] = {1,3,6,1,2,1,138,1,10,1,4, /* insert index here */};
	oid isisErrorOffset_oid[] = {1,3,6,1,2,1,138,1,10,1,13, /* insert index here */};
	oid isisErrorTLVType_oid[] = {1,3,6,1,2,1,138,1,10,1,14, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) isisLSPErrorDetected_oid, sizeof (isisLSPErrorDetected_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		isisNotificationSysLevelIndex_oid, OID_LENGTH (isisNotificationSysLevelIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for isisNotificationSysLevelIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduLspId_oid, OID_LENGTH (isisPduLspId_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduLspId */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisNotificationCircIfIndex_oid, OID_LENGTH (isisNotificationCircIfIndex_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisNotificationCircIfIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisPduFragment_oid, OID_LENGTH (isisPduFragment_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for isisPduFragment */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisErrorOffset_oid, OID_LENGTH (isisErrorOffset_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisErrorOffset */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		isisErrorTLVType_oid, OID_LENGTH (isisErrorTLVType_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for isisErrorTLVType */
		NULL, 0);
		
	/*
	 * Add any extra (optional) objects here
	 */
	
	/*
	 * Send the trap to the list of configured destinations
	 *  and clean up
	 */
	send_v2trap (var_list);
	snmp_free_varbind (var_list);
	
	return SNMP_ERR_NOERROR;
}
