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

#define SNMP_SRC

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "system/systemMIB.h"
#include "snmpMIB.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid snmpMIB_oid[] = {1,3,6,1,6,3,1};
static oid snmpTargetMIB_oid[] = {1,3,6,1,6,3,12};
static oid snmpNotificationMIB_oid[] = {1,3,6,1,6,3,13};
static oid snmpUsmMIB_oid[] = {1,3,6,1,6,3,15};
static oid snmpVacmMIB_oid[] = {1,3,6,1,6,3,16};
static oid snmpCommunityMIB_oid[] = {1,3,6,1,6,3,18};

static oid snmpSet_oid[] = {1,3,6,1,6,3,1,1,6};
static oid snmpTargetObjects_oid[] = {1,3,6,1,6,3,12,1};
static oid usmStats_oid[] = {1,3,6,1,6,3,15,1,1};
static oid usmUser_oid[] = {1,3,6,1,6,3,15,1,2};
static oid vacmMIBViews_oid[] = {1,3,6,1,6,3,16,1,5};

static oid snmpTargetAddrTable_oid[] = {1,3,6,1,6,3,12,1,2};
static oid snmpTargetParamsTable_oid[] = {1,3,6,1,6,3,12,1,3};
static oid snmpNotifyTable_oid[] = {1,3,6,1,6,3,13,1,1};
static oid snmpNotifyFilterProfileTable_oid[] = {1,3,6,1,6,3,13,1,2};
static oid snmpNotifyFilterTable_oid[] = {1,3,6,1,6,3,13,1,3};
static oid usmUserTable_oid[] = {1,3,6,1,6,3,15,1,2,2};
static oid vacmContextTable_oid[] = {1,3,6,1,6,3,16,1,1};
static oid vacmSecurityToGroupTable_oid[] = {1,3,6,1,6,3,16,1,2};
static oid vacmAccessTable_oid[] = {1,3,6,1,6,3,16,1,4};
static oid vacmViewTreeFamilyTable_oid[] = {1,3,6,1,6,3,16,1,5,2};
static oid snmpCommunityTable_oid[] = {1,3,6,1,6,3,18,1,1};
static oid snmpTargetAddrExtTable_oid[] = {1,3,6,1,6,3,18,1,2};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid coldStart_oid[] = {1,3,6,1,6,3,1,1,5,1};
static oid warmStart_oid[] = {1,3,6,1,6,3,1,1,5,2};
static oid authenticationFailure_oid[] = {1,3,6,1,6,3,1,1,5,5};



/**
 *	initialize snmpMIB group mapper
 */
void
snmpMIB_init (void)
{
	extern oid snmpMIB_oid[];
	extern oid snmpTargetMIB_oid[];
	extern oid snmpNotificationMIB_oid[];
	extern oid snmpUsmMIB_oid[];
	extern oid snmpVacmMIB_oid[];
	extern oid snmpCommunityMIB_oid[];
	extern oid snmpSet_oid[];
	extern oid snmpTargetObjects_oid[];
	extern oid usmStats_oid[];
	extern oid usmUser_oid[];
	extern oid vacmMIBViews_oid[];
	
	DEBUGMSGTL (("snmpMIB", "Initializing\n"));
	
	/* register snmpSet scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"snmpSet_mapper", &snmpSet_mapper,
			snmpSet_oid, OID_LENGTH (snmpSet_oid),
			HANDLER_CAN_RWRITE
		),
		SNMPSETSERIALNO,
		SNMPSETSERIALNO
	);
	
	/* register snmpTargetObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"snmpTargetObjects_mapper", &snmpTargetObjects_mapper,
			snmpTargetObjects_oid, OID_LENGTH (snmpTargetObjects_oid),
			HANDLER_CAN_RWRITE
		),
		SNMPTARGETSPINLOCK,
		SNMPUNKNOWNCONTEXTS
	);
	
	/* register usmStats scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"usmStats_mapper", &usmStats_mapper,
			usmStats_oid, OID_LENGTH (usmStats_oid),
			HANDLER_CAN_RONLY
		),
		USMSTATSUNSUPPORTEDSECLEVELS,
		USMSTATSDECRYPTIONERRORS
	);
	
	/* register usmUser scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"usmUser_mapper", &usmUser_mapper,
			usmUser_oid, OID_LENGTH (usmUser_oid),
			HANDLER_CAN_RWRITE
		),
		USMUSERSPINLOCK,
		USMUSERSPINLOCK
	);
	
	/* register vacmMIBViews scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"vacmMIBViews_mapper", &vacmMIBViews_mapper,
			vacmMIBViews_oid, OID_LENGTH (vacmMIBViews_oid),
			HANDLER_CAN_RWRITE
		),
		VACMVIEWSPINLOCK,
		VACMVIEWSPINLOCK
	);
	
	
	/* register snmpMIB group table mappers */
	snmpTargetAddrTable_init ();
	snmpTargetParamsTable_init ();
	snmpNotifyTable_init ();
	snmpNotifyFilterProfileTable_init ();
	snmpNotifyFilterTable_init ();
	usmUserTable_init ();
	vacmContextTable_init ();
	vacmSecurityToGroupTable_init ();
	vacmAccessTable_init ();
	vacmViewTreeFamilyTable_init ();
	snmpCommunityTable_init ();
	snmpTargetAddrExtTable_init ();
	
	/* register snmpMIB modules */
	sysORTable_createRegister ("snmpMIB", snmpMIB_oid, OID_LENGTH (snmpMIB_oid));
	sysORTable_createRegister ("snmpTargetMIB", snmpTargetMIB_oid, OID_LENGTH (snmpTargetMIB_oid));
	sysORTable_createRegister ("snmpNotificationMIB", snmpNotificationMIB_oid, OID_LENGTH (snmpNotificationMIB_oid));
	sysORTable_createRegister ("snmpUsmMIB", snmpUsmMIB_oid, OID_LENGTH (snmpUsmMIB_oid));
	sysORTable_createRegister ("snmpVacmMIB", snmpVacmMIB_oid, OID_LENGTH (snmpVacmMIB_oid));
	sysORTable_createRegister ("snmpCommunityMIB", snmpCommunityMIB_oid, OID_LENGTH (snmpCommunityMIB_oid));
}


/**
 *	scalar mapper(s)
 */
snmpSet_t oSnmpSet;

/** snmpSet scalar mapper **/
int
snmpSet_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid snmpSet_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (snmpSet_oid) - 1])
			{
			case SNMPSETSERIALNO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oSnmpSet.i32SerialNo);
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
			switch (request->requestvb->name[OID_LENGTH (snmpSet_oid) - 1])
			{
			case SNMPSETSERIALNO:
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
			switch (request->requestvb->name[OID_LENGTH (snmpSet_oid) - 1])
			{
			case SNMPSETSERIALNO:
				/* XXX: perform the value change here */
				oSnmpSet.i32SerialNo = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (snmpSet_oid) - 1])
			{
			case SNMPSETSERIALNO:
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

snmpTargetObjects_t oSnmpTargetObjects;

/** snmpTargetObjects scalar mapper **/
int
snmpTargetObjects_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid snmpTargetObjects_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (snmpTargetObjects_oid) - 1])
			{
			case SNMPTARGETSPINLOCK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oSnmpTargetObjects.i32TargetSpinLock);
				break;
			case SNMPUNAVAILABLECONTEXTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oSnmpTargetObjects.u32UnavailableContexts);
				break;
			case SNMPUNKNOWNCONTEXTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oSnmpTargetObjects.u32UnknownContexts);
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
			switch (request->requestvb->name[OID_LENGTH (snmpTargetObjects_oid) - 1])
			{
			case SNMPTARGETSPINLOCK:
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
			switch (request->requestvb->name[OID_LENGTH (snmpTargetObjects_oid) - 1])
			{
			case SNMPTARGETSPINLOCK:
				/* XXX: perform the value change here */
				oSnmpTargetObjects.i32TargetSpinLock = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (snmpTargetObjects_oid) - 1])
			{
			case SNMPTARGETSPINLOCK:
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

usmStats_t oUsmStats;

/** usmStats scalar mapper **/
int
usmStats_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid usmStats_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (usmStats_oid) - 1])
			{
			case USMSTATSUNSUPPORTEDSECLEVELS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32UnsupportedSecLevels);
				break;
			case USMSTATSNOTINTIMEWINDOWS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32NotInTimeWindows);
				break;
			case USMSTATSUNKNOWNUSERNAMES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32UnknownUserNames);
				break;
			case USMSTATSUNKNOWNENGINEIDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32UnknownEngineIDs);
				break;
			case USMSTATSWRONGDIGESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32WrongDigests);
				break;
			case USMSTATSDECRYPTIONERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUsmStats.u32DecryptionErrors);
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

usmUser_t oUsmUser;

/** usmUser scalar mapper **/
int
usmUser_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid usmUser_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (usmUser_oid) - 1])
			{
			case USMUSERSPINLOCK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oUsmUser.i32SpinLock);
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
			switch (request->requestvb->name[OID_LENGTH (usmUser_oid) - 1])
			{
			case USMUSERSPINLOCK:
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
			switch (request->requestvb->name[OID_LENGTH (usmUser_oid) - 1])
			{
			case USMUSERSPINLOCK:
				/* XXX: perform the value change here */
				oUsmUser.i32SpinLock = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (usmUser_oid) - 1])
			{
			case USMUSERSPINLOCK:
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

vacmMIBViews_t oVacmMIBViews;

/** vacmMIBViews scalar mapper **/
int
vacmMIBViews_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid vacmMIBViews_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (vacmMIBViews_oid) - 1])
			{
			case VACMVIEWSPINLOCK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oVacmMIBViews.i32ViewSpinLock);
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
			switch (request->requestvb->name[OID_LENGTH (vacmMIBViews_oid) - 1])
			{
			case VACMVIEWSPINLOCK:
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
			switch (request->requestvb->name[OID_LENGTH (vacmMIBViews_oid) - 1])
			{
			case VACMVIEWSPINLOCK:
				/* XXX: perform the value change here */
				oVacmMIBViews.i32ViewSpinLock = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (vacmMIBViews_oid) - 1])
			{
			case VACMVIEWSPINLOCK:
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


/**
 *	table mapper(s) & helper(s)
 */
/** initialize snmpTargetAddrTable table mapper **/
void
snmpTargetAddrTable_init (void)
{
	extern oid snmpTargetAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpTargetAddrTable", &snmpTargetAddrTable_mapper,
		snmpTargetAddrTable_oid, OID_LENGTH (snmpTargetAddrTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpTargetAddrName */,
		0);
	table_info->min_column = SNMPTARGETADDRTDOMAIN;
	table_info->max_column = SNMPTARGETADDRROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpTargetAddrTable_getFirst;
	iinfo->get_next_data_point = &snmpTargetAddrTable_getNext;
	iinfo->get_data_point = &snmpTargetAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpTargetAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpTargetAddrEntry_t *pEntry1 = xBTree_entry (pNode1, snmpTargetAddrEntry_t, oBTreeNode);
	register snmpTargetAddrEntry_t *pEntry2 = xBTree_entry (pNode2, snmpTargetAddrEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oSnmpTargetAddrTable_BTree = xBTree_initInline (&snmpTargetAddrTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpTargetAddrEntry_t *
snmpTargetAddrTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Timeout = 1500;
	poEntry->i32RetryCount = 3;
	/*poEntry->au8TagList = ""*/;
	poEntry->u8StorageType = snmpTargetAddrStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree);
	return poEntry;
}

snmpTargetAddrEntry_t *
snmpTargetAddrTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetAddrEntry_t, oBTreeNode);
}

snmpTargetAddrEntry_t *
snmpTargetAddrTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpTargetAddrTable_removeEntry (snmpTargetAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpTargetAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpTargetAddrTable_BTree);
	return snmpTargetAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpTargetAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpTargetAddrEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpTargetAddrTable_BTree);
	return put_index_data;
}

bool
snmpTargetAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpTargetAddrTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpTargetAddrTable table mapper */
int
snmpTargetAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpTargetAddrEntry_t *table_entry;
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTDOMAIN:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoTDomain, table_entry->u16TDomain_len);
				break;
			case SNMPTARGETADDRTADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TAddress, table_entry->u16TAddress_len);
				break;
			case SNMPTARGETADDRTIMEOUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Timeout);
				break;
			case SNMPTARGETADDRRETRYCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RetryCount);
				break;
			case SNMPTARGETADDRTAGLIST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TagList, table_entry->u16TagList_len);
				break;
			case SNMPTARGETADDRPARAMS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Params, table_entry->u16Params_len);
				break;
			case SNMPTARGETADDRSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case SNMPTARGETADDRROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTDOMAIN:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoTDomain));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRTADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRTIMEOUT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRRETRYCOUNT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRTAGLIST:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TagList));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRPARAMS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Params));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRROWSTATUS:
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpTargetAddrTable_createEntry (
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpTargetAddrTable_removeEntry (table_entry);
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTDOMAIN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoTDomain))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TDomain_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoTDomain, sizeof (table_entry->aoTDomain));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoTDomain, 0, sizeof (table_entry->aoTDomain));
				memcpy (table_entry->aoTDomain, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TDomain_len = request->requestvb->val_len;
				break;
			case SNMPTARGETADDRTADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TAddress, sizeof (table_entry->au8TAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TAddress, 0, sizeof (table_entry->au8TAddress));
				memcpy (table_entry->au8TAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TAddress_len = request->requestvb->val_len;
				break;
			case SNMPTARGETADDRTIMEOUT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Timeout))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Timeout, sizeof (table_entry->i32Timeout));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Timeout = *request->requestvb->val.integer;
				break;
			case SNMPTARGETADDRRETRYCOUNT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RetryCount))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RetryCount, sizeof (table_entry->i32RetryCount));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RetryCount = *request->requestvb->val.integer;
				break;
			case SNMPTARGETADDRTAGLIST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TagList))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TagList_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TagList, sizeof (table_entry->au8TagList));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TagList, 0, sizeof (table_entry->au8TagList));
				memcpy (table_entry->au8TagList, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TagList_len = request->requestvb->val_len;
				break;
			case SNMPTARGETADDRPARAMS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Params))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Params_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Params, sizeof (table_entry->au8Params));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Params, 0, sizeof (table_entry->au8Params));
				memcpy (table_entry->au8Params, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Params_len = request->requestvb->val_len;
				break;
			case SNMPTARGETADDRSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpTargetAddrTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTDOMAIN:
				memcpy (table_entry->aoTDomain, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TDomain_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPTARGETADDRTADDRESS:
				memcpy (table_entry->au8TAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPTARGETADDRTIMEOUT:
				memcpy (&table_entry->i32Timeout, pvOldDdata, sizeof (table_entry->i32Timeout));
				break;
			case SNMPTARGETADDRRETRYCOUNT:
				memcpy (&table_entry->i32RetryCount, pvOldDdata, sizeof (table_entry->i32RetryCount));
				break;
			case SNMPTARGETADDRTAGLIST:
				memcpy (table_entry->au8TagList, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TagList_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPTARGETADDRPARAMS:
				memcpy (table_entry->au8Params, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Params_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPTARGETADDRSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case SNMPTARGETADDRROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpTargetAddrTable_removeEntry (table_entry);
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
			table_entry = (snmpTargetAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpTargetAddrTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpTargetParamsTable table mapper **/
void
snmpTargetParamsTable_init (void)
{
	extern oid snmpTargetParamsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpTargetParamsTable", &snmpTargetParamsTable_mapper,
		snmpTargetParamsTable_oid, OID_LENGTH (snmpTargetParamsTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpTargetParamsName */,
		0);
	table_info->min_column = SNMPTARGETPARAMSMPMODEL;
	table_info->max_column = SNMPTARGETPARAMSROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpTargetParamsTable_getFirst;
	iinfo->get_next_data_point = &snmpTargetParamsTable_getNext;
	iinfo->get_data_point = &snmpTargetParamsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpTargetParamsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpTargetParamsEntry_t *pEntry1 = xBTree_entry (pNode1, snmpTargetParamsEntry_t, oBTreeNode);
	register snmpTargetParamsEntry_t *pEntry2 = xBTree_entry (pNode2, snmpTargetParamsEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oSnmpTargetParamsTable_BTree = xBTree_initInline (&snmpTargetParamsTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpTargetParamsEntry_t *
snmpTargetParamsTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetParamsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = snmpTargetParamsStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree);
	return poEntry;
}

snmpTargetParamsEntry_t *
snmpTargetParamsTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetParamsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetParamsEntry_t, oBTreeNode);
}

snmpTargetParamsEntry_t *
snmpTargetParamsTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetParamsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetParamsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpTargetParamsTable_removeEntry (snmpTargetParamsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpTargetParamsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpTargetParamsTable_BTree);
	return snmpTargetParamsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpTargetParamsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetParamsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpTargetParamsEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpTargetParamsTable_BTree);
	return put_index_data;
}

bool
snmpTargetParamsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetParamsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpTargetParamsTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpTargetParamsTable table mapper */
int
snmpTargetParamsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpTargetParamsEntry_t *table_entry;
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSMPMODEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MPModel);
				break;
			case SNMPTARGETPARAMSSECURITYMODEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SecurityModel);
				break;
			case SNMPTARGETPARAMSSECURITYNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SecurityName, table_entry->u16SecurityName_len);
				break;
			case SNMPTARGETPARAMSSECURITYLEVEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SecurityLevel);
				break;
			case SNMPTARGETPARAMSSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case SNMPTARGETPARAMSROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSMPMODEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETPARAMSSECURITYMODEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETPARAMSSECURITYNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SecurityName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETPARAMSSECURITYLEVEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETPARAMSSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETPARAMSROWSTATUS:
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpTargetParamsTable_createEntry (
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpTargetParamsTable_removeEntry (table_entry);
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSMPMODEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MPModel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MPModel, sizeof (table_entry->i32MPModel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MPModel = *request->requestvb->val.integer;
				break;
			case SNMPTARGETPARAMSSECURITYMODEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SecurityModel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SecurityModel, sizeof (table_entry->i32SecurityModel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SecurityModel = *request->requestvb->val.integer;
				break;
			case SNMPTARGETPARAMSSECURITYNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SecurityName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SecurityName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SecurityName, sizeof (table_entry->au8SecurityName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SecurityName, 0, sizeof (table_entry->au8SecurityName));
				memcpy (table_entry->au8SecurityName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SecurityName_len = request->requestvb->val_len;
				break;
			case SNMPTARGETPARAMSSECURITYLEVEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SecurityLevel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SecurityLevel, sizeof (table_entry->i32SecurityLevel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SecurityLevel = *request->requestvb->val.integer;
				break;
			case SNMPTARGETPARAMSSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpTargetParamsTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSMPMODEL:
				memcpy (&table_entry->i32MPModel, pvOldDdata, sizeof (table_entry->i32MPModel));
				break;
			case SNMPTARGETPARAMSSECURITYMODEL:
				memcpy (&table_entry->i32SecurityModel, pvOldDdata, sizeof (table_entry->i32SecurityModel));
				break;
			case SNMPTARGETPARAMSSECURITYNAME:
				memcpy (table_entry->au8SecurityName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SecurityName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPTARGETPARAMSSECURITYLEVEL:
				memcpy (&table_entry->i32SecurityLevel, pvOldDdata, sizeof (table_entry->i32SecurityLevel));
				break;
			case SNMPTARGETPARAMSSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case SNMPTARGETPARAMSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpTargetParamsTable_removeEntry (table_entry);
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
			table_entry = (snmpTargetParamsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETPARAMSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpTargetParamsTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpNotifyTable table mapper **/
void
snmpNotifyTable_init (void)
{
	extern oid snmpNotifyTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpNotifyTable", &snmpNotifyTable_mapper,
		snmpNotifyTable_oid, OID_LENGTH (snmpNotifyTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpNotifyName */,
		0);
	table_info->min_column = SNMPNOTIFYTAG;
	table_info->max_column = SNMPNOTIFYROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpNotifyTable_getFirst;
	iinfo->get_next_data_point = &snmpNotifyTable_getNext;
	iinfo->get_data_point = &snmpNotifyTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpNotifyTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpNotifyEntry_t *pEntry1 = xBTree_entry (pNode1, snmpNotifyEntry_t, oBTreeNode);
	register snmpNotifyEntry_t *pEntry2 = xBTree_entry (pNode2, snmpNotifyEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oSnmpNotifyTable_BTree = xBTree_initInline (&snmpNotifyTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpNotifyEntry_t *
snmpNotifyTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpNotifyEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Tag = ""*/;
	poEntry->i32Type = snmpNotifyType_trap_c;
	poEntry->u8StorageType = snmpNotifyStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpNotifyTable_BTree);
	return poEntry;
}

snmpNotifyEntry_t *
snmpNotifyTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpNotifyEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpNotifyTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyEntry_t, oBTreeNode);
}

snmpNotifyEntry_t *
snmpNotifyTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpNotifyEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpNotifyTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpNotifyTable_removeEntry (snmpNotifyEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpNotifyTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpNotifyTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpNotifyTable_BTree);
	return snmpNotifyTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpNotifyTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpNotifyEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpNotifyTable_BTree);
	return put_index_data;
}

bool
snmpNotifyTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpNotifyTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpNotifyTable table mapper */
int
snmpNotifyTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpNotifyEntry_t *table_entry;
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYTAG:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Tag, table_entry->u16Tag_len);
				break;
			case SNMPNOTIFYTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case SNMPNOTIFYSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case SNMPNOTIFYROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYTAG:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Tag));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYROWSTATUS:
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpNotifyTable_createEntry (
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYTAG:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Tag))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Tag_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Tag, sizeof (table_entry->au8Tag));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Tag, 0, sizeof (table_entry->au8Tag));
				memcpy (table_entry->au8Tag, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Tag_len = request->requestvb->val_len;
				break;
			case SNMPNOTIFYTYPE:
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
			case SNMPNOTIFYSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpNotifyTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYTAG:
				memcpy (table_entry->au8Tag, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Tag_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPNOTIFYTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case SNMPNOTIFYSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case SNMPNOTIFYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpNotifyTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpNotifyFilterProfileTable table mapper **/
void
snmpNotifyFilterProfileTable_init (void)
{
	extern oid snmpNotifyFilterProfileTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpNotifyFilterProfileTable", &snmpNotifyFilterProfileTable_mapper,
		snmpNotifyFilterProfileTable_oid, OID_LENGTH (snmpNotifyFilterProfileTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpTargetParamsName */,
		0);
	table_info->min_column = SNMPNOTIFYFILTERPROFILENAME;
	table_info->max_column = SNMPNOTIFYFILTERPROFILEROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpNotifyFilterProfileTable_getFirst;
	iinfo->get_next_data_point = &snmpNotifyFilterProfileTable_getNext;
	iinfo->get_data_point = &snmpNotifyFilterProfileTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpNotifyFilterProfileTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpNotifyFilterProfileEntry_t *pEntry1 = xBTree_entry (pNode1, snmpNotifyFilterProfileEntry_t, oBTreeNode);
	register snmpNotifyFilterProfileEntry_t *pEntry2 = xBTree_entry (pNode2, snmpNotifyFilterProfileEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8TargetParamsName, pEntry2->au8TargetParamsName, pEntry1->u16TargetParamsName_len, pEntry2->u16TargetParamsName_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8TargetParamsName, pEntry2->au8TargetParamsName, pEntry1->u16TargetParamsName_len, pEntry2->u16TargetParamsName_len) == 0) ? 0: 1;
}

xBTree_t oSnmpNotifyFilterProfileTable_BTree = xBTree_initInline (&snmpNotifyFilterProfileTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpNotifyFilterProfileEntry_t *
snmpNotifyFilterProfileTable_createEntry (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len)
{
	register snmpNotifyFilterProfileEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8TargetParamsName, pau8TargetParamsName, u16TargetParamsName_len);
	poEntry->u16TargetParamsName_len = u16TargetParamsName_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorType = snmpNotifyFilterProfileStorType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree);
	return poEntry;
}

snmpNotifyFilterProfileEntry_t *
snmpNotifyFilterProfileTable_getByIndex (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len)
{
	register snmpNotifyFilterProfileEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8TargetParamsName, pau8TargetParamsName, u16TargetParamsName_len);
	poTmpEntry->u16TargetParamsName_len = u16TargetParamsName_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyFilterProfileEntry_t, oBTreeNode);
}

snmpNotifyFilterProfileEntry_t *
snmpNotifyFilterProfileTable_getNextIndex (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len)
{
	register snmpNotifyFilterProfileEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8TargetParamsName, pau8TargetParamsName, u16TargetParamsName_len);
	poTmpEntry->u16TargetParamsName_len = u16TargetParamsName_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyFilterProfileEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpNotifyFilterProfileTable_removeEntry (snmpNotifyFilterProfileEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpNotifyFilterProfileTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpNotifyFilterProfileTable_BTree);
	return snmpNotifyFilterProfileTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpNotifyFilterProfileTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyFilterProfileEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpNotifyFilterProfileEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8TargetParamsName, poEntry->u16TargetParamsName_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpNotifyFilterProfileTable_BTree);
	return put_index_data;
}

bool
snmpNotifyFilterProfileTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyFilterProfileEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpNotifyFilterProfileTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpNotifyFilterProfileTable table mapper */
int
snmpNotifyFilterProfileTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpNotifyFilterProfileEntry_t *table_entry;
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILENAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case SNMPNOTIFYFILTERPROFILESTORTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorType);
				break;
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILENAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYFILTERPROFILESTORTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpNotifyFilterProfileTable_createEntry (
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyFilterProfileTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILENAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Name))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Name_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Name, sizeof (table_entry->au8Name));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Name, 0, sizeof (table_entry->au8Name));
				memcpy (table_entry->au8Name, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Name_len = request->requestvb->val_len;
				break;
			case SNMPNOTIFYFILTERPROFILESTORTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorType, sizeof (table_entry->u8StorType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpNotifyFilterProfileTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILENAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPNOTIFYFILTERPROFILESTORTYPE:
				memcpy (&table_entry->u8StorType, pvOldDdata, sizeof (table_entry->u8StorType));
				break;
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyFilterProfileTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyFilterProfileEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERPROFILEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpNotifyFilterProfileTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpNotifyFilterTable table mapper **/
void
snmpNotifyFilterTable_init (void)
{
	extern oid snmpNotifyFilterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpNotifyFilterTable", &snmpNotifyFilterTable_mapper,
		snmpNotifyFilterTable_oid, OID_LENGTH (snmpNotifyFilterTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpNotifyFilterProfileName */,
		ASN_OBJECT_ID /* index: snmpNotifyFilterSubtree */,
		0);
	table_info->min_column = SNMPNOTIFYFILTERMASK;
	table_info->max_column = SNMPNOTIFYFILTERROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpNotifyFilterTable_getFirst;
	iinfo->get_next_data_point = &snmpNotifyFilterTable_getNext;
	iinfo->get_data_point = &snmpNotifyFilterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpNotifyFilterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpNotifyFilterEntry_t *pEntry1 = xBTree_entry (pNode1, snmpNotifyFilterEntry_t, oBTreeNode);
	register snmpNotifyFilterEntry_t *pEntry2 = xBTree_entry (pNode2, snmpNotifyFilterEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8ProfileName, pEntry2->au8ProfileName, pEntry1->u16ProfileName_len, pEntry2->u16ProfileName_len) == -1) ||
		(xBinCmp (pEntry1->au8ProfileName, pEntry2->au8ProfileName, pEntry1->u16ProfileName_len, pEntry2->u16ProfileName_len) == 0 && xOidCmp (pEntry1->aoSubtree, pEntry2->aoSubtree, pEntry1->u16Subtree_len, pEntry2->u16Subtree_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8ProfileName, pEntry2->au8ProfileName, pEntry1->u16ProfileName_len, pEntry2->u16ProfileName_len) == 0 && xOidCmp (pEntry1->aoSubtree, pEntry2->aoSubtree, pEntry1->u16Subtree_len, pEntry2->u16Subtree_len) == 0) ? 0: 1;
}

xBTree_t oSnmpNotifyFilterTable_BTree = xBTree_initInline (&snmpNotifyFilterTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpNotifyFilterEntry_t *
snmpNotifyFilterTable_createEntry (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register snmpNotifyFilterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8ProfileName, pau8ProfileName, u16ProfileName_len);
	poEntry->u16ProfileName_len = u16ProfileName_len;
	memcpy (poEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poEntry->u16Subtree_len = u16Subtree_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Mask = 0*/;
	poEntry->i32Type = snmpNotifyFilterType_included_c;
	poEntry->u8StorageType = snmpNotifyFilterStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree);
	return poEntry;
}

snmpNotifyFilterEntry_t *
snmpNotifyFilterTable_getByIndex (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register snmpNotifyFilterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8ProfileName, pau8ProfileName, u16ProfileName_len);
	poTmpEntry->u16ProfileName_len = u16ProfileName_len;
	memcpy (poTmpEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poTmpEntry->u16Subtree_len = u16Subtree_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyFilterEntry_t, oBTreeNode);
}

snmpNotifyFilterEntry_t *
snmpNotifyFilterTable_getNextIndex (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register snmpNotifyFilterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8ProfileName, pau8ProfileName, u16ProfileName_len);
	poTmpEntry->u16ProfileName_len = u16ProfileName_len;
	memcpy (poTmpEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poTmpEntry->u16Subtree_len = u16Subtree_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpNotifyFilterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpNotifyFilterTable_removeEntry (snmpNotifyFilterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpNotifyFilterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpNotifyFilterTable_BTree);
	return snmpNotifyFilterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpNotifyFilterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyFilterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpNotifyFilterEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8ProfileName, poEntry->u16ProfileName_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->aoSubtree, poEntry->u16Subtree_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpNotifyFilterTable_BTree);
	return put_index_data;
}

bool
snmpNotifyFilterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpNotifyFilterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = snmpNotifyFilterTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpNotifyFilterTable table mapper */
int
snmpNotifyFilterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpNotifyFilterEntry_t *table_entry;
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERMASK:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Mask, table_entry->u16Mask_len);
				break;
			case SNMPNOTIFYFILTERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case SNMPNOTIFYFILTERSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case SNMPNOTIFYFILTERROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERMASK:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Mask));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYFILTERTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYFILTERSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPNOTIFYFILTERROWSTATUS:
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpNotifyFilterTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
						(void*) idx2->val.string, idx2->val_len);
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyFilterTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERMASK:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Mask))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Mask_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Mask, sizeof (table_entry->au8Mask));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Mask, 0, sizeof (table_entry->au8Mask));
				memcpy (table_entry->au8Mask, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Mask_len = request->requestvb->val_len;
				break;
			case SNMPNOTIFYFILTERTYPE:
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
			case SNMPNOTIFYFILTERSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpNotifyFilterTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERMASK:
				memcpy (table_entry->au8Mask, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Mask_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPNOTIFYFILTERTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case SNMPNOTIFYFILTERSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case SNMPNOTIFYFILTERROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpNotifyFilterTable_removeEntry (table_entry);
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
			table_entry = (snmpNotifyFilterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPNOTIFYFILTERROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpNotifyFilterTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize usmUserTable table mapper **/
void
usmUserTable_init (void)
{
	extern oid usmUserTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"usmUserTable", &usmUserTable_mapper,
		usmUserTable_oid, OID_LENGTH (usmUserTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: usmUserEngineID */,
		ASN_OCTET_STR /* index: usmUserName */,
		0);
	table_info->min_column = USMUSERSECURITYNAME;
	table_info->max_column = USMUSERSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &usmUserTable_getFirst;
	iinfo->get_next_data_point = &usmUserTable_getNext;
	iinfo->get_data_point = &usmUserTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
usmUserTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register usmUserEntry_t *pEntry1 = xBTree_entry (pNode1, usmUserEntry_t, oBTreeNode);
	register usmUserEntry_t *pEntry2 = xBTree_entry (pNode2, usmUserEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8EngineID, pEntry2->au8EngineID, pEntry1->u16EngineID_len, pEntry2->u16EngineID_len) == -1) ||
		(xBinCmp (pEntry1->au8EngineID, pEntry2->au8EngineID, pEntry1->u16EngineID_len, pEntry2->u16EngineID_len) == 0 && xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8EngineID, pEntry2->au8EngineID, pEntry1->u16EngineID_len, pEntry2->u16EngineID_len) == 0 && xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oUsmUserTable_BTree = xBTree_initInline (&usmUserTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
usmUserEntry_t *
usmUserTable_createEntry (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len)
{
	register usmUserEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8EngineID, pau8EngineID, u16EngineID_len);
	poEntry->u16EngineID_len = u16EngineID_len;
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oUsmUserTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->aoAuthProtocol = usmNoAuthProtocol*/;
	/*poEntry->au8AuthKeyChange = 0*/;
	/*poEntry->au8OwnAuthKeyChange = 0*/;
	/*poEntry->aoPrivProtocol = usmNoPrivProtocol*/;
	/*poEntry->au8PrivKeyChange = 0*/;
	/*poEntry->au8OwnPrivKeyChange = 0*/;
	/*poEntry->au8Public = 0*/;
	poEntry->u8StorageType = usmUserStorageType_nonVolatile_c;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oUsmUserTable_BTree);
	return poEntry;
}

usmUserEntry_t *
usmUserTable_getByIndex (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len)
{
	register usmUserEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8EngineID, pau8EngineID, u16EngineID_len);
	poTmpEntry->u16EngineID_len = u16EngineID_len;
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oUsmUserTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, usmUserEntry_t, oBTreeNode);
}

usmUserEntry_t *
usmUserTable_getNextIndex (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len)
{
	register usmUserEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8EngineID, pau8EngineID, u16EngineID_len);
	poTmpEntry->u16EngineID_len = u16EngineID_len;
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oUsmUserTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, usmUserEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
usmUserTable_removeEntry (usmUserEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oUsmUserTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oUsmUserTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
usmUserTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oUsmUserTable_BTree);
	return usmUserTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
usmUserTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	usmUserEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, usmUserEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8EngineID, poEntry->u16EngineID_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oUsmUserTable_BTree);
	return put_index_data;
}

bool
usmUserTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	usmUserEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = usmUserTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* usmUserTable table mapper */
int
usmUserTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	usmUserEntry_t *table_entry;
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case USMUSERSECURITYNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SecurityName, table_entry->u16SecurityName_len);
				break;
			case USMUSERCLONEFROM:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoCloneFrom, table_entry->u16CloneFrom_len);
				break;
			case USMUSERAUTHPROTOCOL:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoAuthProtocol, table_entry->u16AuthProtocol_len);
				break;
			case USMUSERAUTHKEYCHANGE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AuthKeyChange, table_entry->u16AuthKeyChange_len);
				break;
			case USMUSEROWNAUTHKEYCHANGE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8OwnAuthKeyChange, table_entry->u16OwnAuthKeyChange_len);
				break;
			case USMUSERPRIVPROTOCOL:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoPrivProtocol, table_entry->u16PrivProtocol_len);
				break;
			case USMUSERPRIVKEYCHANGE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PrivKeyChange, table_entry->u16PrivKeyChange_len);
				break;
			case USMUSEROWNPRIVKEYCHANGE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8OwnPrivKeyChange, table_entry->u16OwnPrivKeyChange_len);
				break;
			case USMUSERPUBLIC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Public, table_entry->u16Public_len);
				break;
			case USMUSERSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case USMUSERSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case USMUSERCLONEFROM:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoCloneFrom));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERAUTHPROTOCOL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoAuthProtocol));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERAUTHKEYCHANGE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AuthKeyChange));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSEROWNAUTHKEYCHANGE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8OwnAuthKeyChange));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERPRIVPROTOCOL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoPrivProtocol));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERPRIVKEYCHANGE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PrivKeyChange));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSEROWNPRIVKEYCHANGE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8OwnPrivKeyChange));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERPUBLIC:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Public));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case USMUSERSTATUS:
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case USMUSERSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = usmUserTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
						(void*) idx2->val.string, idx2->val_len);
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case USMUSERSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					usmUserTable_removeEntry (table_entry);
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case USMUSERCLONEFROM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoCloneFrom))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16CloneFrom_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoCloneFrom, sizeof (table_entry->aoCloneFrom));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoCloneFrom, 0, sizeof (table_entry->aoCloneFrom));
				memcpy (table_entry->aoCloneFrom, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16CloneFrom_len = request->requestvb->val_len;
				break;
			case USMUSERAUTHPROTOCOL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoAuthProtocol))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AuthProtocol_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoAuthProtocol, sizeof (table_entry->aoAuthProtocol));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoAuthProtocol, 0, sizeof (table_entry->aoAuthProtocol));
				memcpy (table_entry->aoAuthProtocol, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AuthProtocol_len = request->requestvb->val_len;
				break;
			case USMUSERAUTHKEYCHANGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AuthKeyChange))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AuthKeyChange_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AuthKeyChange, sizeof (table_entry->au8AuthKeyChange));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AuthKeyChange, 0, sizeof (table_entry->au8AuthKeyChange));
				memcpy (table_entry->au8AuthKeyChange, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AuthKeyChange_len = request->requestvb->val_len;
				break;
			case USMUSEROWNAUTHKEYCHANGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8OwnAuthKeyChange))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16OwnAuthKeyChange_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8OwnAuthKeyChange, sizeof (table_entry->au8OwnAuthKeyChange));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8OwnAuthKeyChange, 0, sizeof (table_entry->au8OwnAuthKeyChange));
				memcpy (table_entry->au8OwnAuthKeyChange, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16OwnAuthKeyChange_len = request->requestvb->val_len;
				break;
			case USMUSERPRIVPROTOCOL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoPrivProtocol))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PrivProtocol_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoPrivProtocol, sizeof (table_entry->aoPrivProtocol));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoPrivProtocol, 0, sizeof (table_entry->aoPrivProtocol));
				memcpy (table_entry->aoPrivProtocol, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PrivProtocol_len = request->requestvb->val_len;
				break;
			case USMUSERPRIVKEYCHANGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PrivKeyChange))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PrivKeyChange_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PrivKeyChange, sizeof (table_entry->au8PrivKeyChange));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PrivKeyChange, 0, sizeof (table_entry->au8PrivKeyChange));
				memcpy (table_entry->au8PrivKeyChange, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PrivKeyChange_len = request->requestvb->val_len;
				break;
			case USMUSEROWNPRIVKEYCHANGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8OwnPrivKeyChange))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16OwnPrivKeyChange_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8OwnPrivKeyChange, sizeof (table_entry->au8OwnPrivKeyChange));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8OwnPrivKeyChange, 0, sizeof (table_entry->au8OwnPrivKeyChange));
				memcpy (table_entry->au8OwnPrivKeyChange, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16OwnPrivKeyChange_len = request->requestvb->val_len;
				break;
			case USMUSERPUBLIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Public))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Public_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Public, sizeof (table_entry->au8Public));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Public, 0, sizeof (table_entry->au8Public));
				memcpy (table_entry->au8Public, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Public_len = request->requestvb->val_len;
				break;
			case USMUSERSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case USMUSERSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int usmUserTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case USMUSERCLONEFROM:
				memcpy (table_entry->aoCloneFrom, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16CloneFrom_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERAUTHPROTOCOL:
				memcpy (table_entry->aoAuthProtocol, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AuthProtocol_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERAUTHKEYCHANGE:
				memcpy (table_entry->au8AuthKeyChange, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AuthKeyChange_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSEROWNAUTHKEYCHANGE:
				memcpy (table_entry->au8OwnAuthKeyChange, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16OwnAuthKeyChange_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERPRIVPROTOCOL:
				memcpy (table_entry->aoPrivProtocol, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PrivProtocol_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERPRIVKEYCHANGE:
				memcpy (table_entry->au8PrivKeyChange, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PrivKeyChange_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSEROWNPRIVKEYCHANGE:
				memcpy (table_entry->au8OwnPrivKeyChange, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16OwnPrivKeyChange_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERPUBLIC:
				memcpy (table_entry->au8Public, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Public_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case USMUSERSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case USMUSERSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					usmUserTable_removeEntry (table_entry);
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
			table_entry = (usmUserEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case USMUSERSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					usmUserTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize vacmContextTable table mapper **/
void
vacmContextTable_init (void)
{
	extern oid vacmContextTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"vacmContextTable", &vacmContextTable_mapper,
		vacmContextTable_oid, OID_LENGTH (vacmContextTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: vacmContextName */,
		0);
	table_info->min_column = VACMCONTEXTNAME;
	table_info->max_column = VACMCONTEXTNAME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &vacmContextTable_getFirst;
	iinfo->get_next_data_point = &vacmContextTable_getNext;
	iinfo->get_data_point = &vacmContextTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
vacmContextTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register vacmContextEntry_t *pEntry1 = xBTree_entry (pNode1, vacmContextEntry_t, oBTreeNode);
	register vacmContextEntry_t *pEntry2 = xBTree_entry (pNode2, vacmContextEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oVacmContextTable_BTree = xBTree_initInline (&vacmContextTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
vacmContextEntry_t *
vacmContextTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register vacmContextEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmContextTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oVacmContextTable_BTree);
	return poEntry;
}

vacmContextEntry_t *
vacmContextTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register vacmContextEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oVacmContextTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmContextEntry_t, oBTreeNode);
}

vacmContextEntry_t *
vacmContextTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register vacmContextEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oVacmContextTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmContextEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
vacmContextTable_removeEntry (vacmContextEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmContextTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oVacmContextTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
vacmContextTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oVacmContextTable_BTree);
	return vacmContextTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
vacmContextTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmContextEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, vacmContextEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oVacmContextTable_BTree);
	return put_index_data;
}

bool
vacmContextTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmContextEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = vacmContextTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* vacmContextTable table mapper */
int
vacmContextTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	vacmContextEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (vacmContextEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMCONTEXTNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
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

/** initialize vacmSecurityToGroupTable table mapper **/
void
vacmSecurityToGroupTable_init (void)
{
	extern oid vacmSecurityToGroupTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"vacmSecurityToGroupTable", &vacmSecurityToGroupTable_mapper,
		vacmSecurityToGroupTable_oid, OID_LENGTH (vacmSecurityToGroupTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: vacmSecurityModel */,
		ASN_OCTET_STR /* index: vacmSecurityName */,
		0);
	table_info->min_column = VACMGROUPNAME;
	table_info->max_column = VACMSECURITYTOGROUPSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &vacmSecurityToGroupTable_getFirst;
	iinfo->get_next_data_point = &vacmSecurityToGroupTable_getNext;
	iinfo->get_data_point = &vacmSecurityToGroupTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
vacmSecurityToGroupTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register vacmSecurityToGroupEntry_t *pEntry1 = xBTree_entry (pNode1, vacmSecurityToGroupEntry_t, oBTreeNode);
	register vacmSecurityToGroupEntry_t *pEntry2 = xBTree_entry (pNode2, vacmSecurityToGroupEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32SecurityModel < pEntry2->i32SecurityModel) ||
		(pEntry1->i32SecurityModel == pEntry2->i32SecurityModel && xBinCmp (pEntry1->au8SecurityName, pEntry2->au8SecurityName, pEntry1->u16SecurityName_len, pEntry2->u16SecurityName_len) == -1) ? -1:
		(pEntry1->i32SecurityModel == pEntry2->i32SecurityModel && xBinCmp (pEntry1->au8SecurityName, pEntry2->au8SecurityName, pEntry1->u16SecurityName_len, pEntry2->u16SecurityName_len) == 0) ? 0: 1;
}

xBTree_t oVacmSecurityToGroupTable_BTree = xBTree_initInline (&vacmSecurityToGroupTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
vacmSecurityToGroupEntry_t *
vacmSecurityToGroupTable_createEntry (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len)
{
	register vacmSecurityToGroupEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32SecurityModel = i32SecurityModel;
	memcpy (poEntry->au8SecurityName, pau8SecurityName, u16SecurityName_len);
	poEntry->u16SecurityName_len = u16SecurityName_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = vacmSecurityToGroupStorageType_nonVolatile_c;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree);
	return poEntry;
}

vacmSecurityToGroupEntry_t *
vacmSecurityToGroupTable_getByIndex (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len)
{
	register vacmSecurityToGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SecurityModel = i32SecurityModel;
	memcpy (poTmpEntry->au8SecurityName, pau8SecurityName, u16SecurityName_len);
	poTmpEntry->u16SecurityName_len = u16SecurityName_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmSecurityToGroupEntry_t, oBTreeNode);
}

vacmSecurityToGroupEntry_t *
vacmSecurityToGroupTable_getNextIndex (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len)
{
	register vacmSecurityToGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SecurityModel = i32SecurityModel;
	memcpy (poTmpEntry->au8SecurityName, pau8SecurityName, u16SecurityName_len);
	poTmpEntry->u16SecurityName_len = u16SecurityName_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmSecurityToGroupEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
vacmSecurityToGroupTable_removeEntry (vacmSecurityToGroupEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
vacmSecurityToGroupTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oVacmSecurityToGroupTable_BTree);
	return vacmSecurityToGroupTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
vacmSecurityToGroupTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmSecurityToGroupEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, vacmSecurityToGroupEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32SecurityModel);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8SecurityName, poEntry->u16SecurityName_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oVacmSecurityToGroupTable_BTree);
	return put_index_data;
}

bool
vacmSecurityToGroupTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmSecurityToGroupEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = vacmSecurityToGroupTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* vacmSecurityToGroupTable table mapper */
int
vacmSecurityToGroupTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	vacmSecurityToGroupEntry_t *table_entry;
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMGROUPNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8GroupName, table_entry->u16GroupName_len);
				break;
			case VACMSECURITYTOGROUPSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case VACMSECURITYTOGROUPSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMGROUPNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8GroupName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMSECURITYTOGROUPSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMSECURITYTOGROUPSTATUS:
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case VACMSECURITYTOGROUPSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = vacmSecurityToGroupTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len);
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMSECURITYTOGROUPSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmSecurityToGroupTable_removeEntry (table_entry);
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMGROUPNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8GroupName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16GroupName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8GroupName, sizeof (table_entry->au8GroupName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8GroupName, 0, sizeof (table_entry->au8GroupName));
				memcpy (table_entry->au8GroupName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16GroupName_len = request->requestvb->val_len;
				break;
			case VACMSECURITYTOGROUPSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMSECURITYTOGROUPSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int vacmSecurityToGroupTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMGROUPNAME:
				memcpy (table_entry->au8GroupName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16GroupName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case VACMSECURITYTOGROUPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case VACMSECURITYTOGROUPSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmSecurityToGroupTable_removeEntry (table_entry);
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
			table_entry = (vacmSecurityToGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMSECURITYTOGROUPSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					vacmSecurityToGroupTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize vacmAccessTable table mapper **/
void
vacmAccessTable_init (void)
{
	extern oid vacmAccessTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"vacmAccessTable", &vacmAccessTable_mapper,
		vacmAccessTable_oid, OID_LENGTH (vacmAccessTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: vacmGroupName */,
		ASN_OCTET_STR /* index: vacmAccessContextPrefix */,
		ASN_INTEGER /* index: vacmAccessSecurityModel */,
		ASN_INTEGER /* index: vacmAccessSecurityLevel */,
		0);
	table_info->min_column = VACMACCESSCONTEXTMATCH;
	table_info->max_column = VACMACCESSSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &vacmAccessTable_getFirst;
	iinfo->get_next_data_point = &vacmAccessTable_getNext;
	iinfo->get_data_point = &vacmAccessTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
vacmAccessTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register vacmAccessEntry_t *pEntry1 = xBTree_entry (pNode1, vacmAccessEntry_t, oBTreeNode);
	register vacmAccessEntry_t *pEntry2 = xBTree_entry (pNode2, vacmAccessEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8GroupName, pEntry2->au8GroupName, pEntry1->u16GroupName_len, pEntry2->u16GroupName_len) == -1) ||
		(xBinCmp (pEntry1->au8GroupName, pEntry2->au8GroupName, pEntry1->u16GroupName_len, pEntry2->u16GroupName_len) == 0 && xBinCmp (pEntry1->au8ContextPrefix, pEntry2->au8ContextPrefix, pEntry1->u16ContextPrefix_len, pEntry2->u16ContextPrefix_len) == -1) ||
		(xBinCmp (pEntry1->au8GroupName, pEntry2->au8GroupName, pEntry1->u16GroupName_len, pEntry2->u16GroupName_len) == 0 && xBinCmp (pEntry1->au8ContextPrefix, pEntry2->au8ContextPrefix, pEntry1->u16ContextPrefix_len, pEntry2->u16ContextPrefix_len) == 0 && pEntry1->i32SecurityModel < pEntry2->i32SecurityModel) ||
		(xBinCmp (pEntry1->au8GroupName, pEntry2->au8GroupName, pEntry1->u16GroupName_len, pEntry2->u16GroupName_len) == 0 && xBinCmp (pEntry1->au8ContextPrefix, pEntry2->au8ContextPrefix, pEntry1->u16ContextPrefix_len, pEntry2->u16ContextPrefix_len) == 0 && pEntry1->i32SecurityModel == pEntry2->i32SecurityModel && pEntry1->i32SecurityLevel < pEntry2->i32SecurityLevel) ? -1:
		(xBinCmp (pEntry1->au8GroupName, pEntry2->au8GroupName, pEntry1->u16GroupName_len, pEntry2->u16GroupName_len) == 0 && xBinCmp (pEntry1->au8ContextPrefix, pEntry2->au8ContextPrefix, pEntry1->u16ContextPrefix_len, pEntry2->u16ContextPrefix_len) == 0 && pEntry1->i32SecurityModel == pEntry2->i32SecurityModel && pEntry1->i32SecurityLevel == pEntry2->i32SecurityLevel) ? 0: 1;
}

xBTree_t oVacmAccessTable_BTree = xBTree_initInline (&vacmAccessTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
vacmAccessEntry_t *
vacmAccessTable_createEntry (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel)
{
	register vacmAccessEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8GroupName, pau8GroupName, u16GroupName_len);
	poEntry->u16GroupName_len = u16GroupName_len;
	memcpy (poEntry->au8ContextPrefix, pau8ContextPrefix, u16ContextPrefix_len);
	poEntry->u16ContextPrefix_len = u16ContextPrefix_len;
	poEntry->i32SecurityModel = i32SecurityModel;
	poEntry->i32SecurityLevel = i32SecurityLevel;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmAccessTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32ContextMatch = vacmAccessContextMatch_exact_c;
	/*poEntry->au8ReadViewName = 0*/;
	/*poEntry->au8WriteViewName = 0*/;
	/*poEntry->au8NotifyViewName = 0*/;
	poEntry->u8StorageType = vacmAccessStorageType_nonVolatile_c;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oVacmAccessTable_BTree);
	return poEntry;
}

vacmAccessEntry_t *
vacmAccessTable_getByIndex (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel)
{
	register vacmAccessEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8GroupName, pau8GroupName, u16GroupName_len);
	poTmpEntry->u16GroupName_len = u16GroupName_len;
	memcpy (poTmpEntry->au8ContextPrefix, pau8ContextPrefix, u16ContextPrefix_len);
	poTmpEntry->u16ContextPrefix_len = u16ContextPrefix_len;
	poTmpEntry->i32SecurityModel = i32SecurityModel;
	poTmpEntry->i32SecurityLevel = i32SecurityLevel;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oVacmAccessTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmAccessEntry_t, oBTreeNode);
}

vacmAccessEntry_t *
vacmAccessTable_getNextIndex (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel)
{
	register vacmAccessEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8GroupName, pau8GroupName, u16GroupName_len);
	poTmpEntry->u16GroupName_len = u16GroupName_len;
	memcpy (poTmpEntry->au8ContextPrefix, pau8ContextPrefix, u16ContextPrefix_len);
	poTmpEntry->u16ContextPrefix_len = u16ContextPrefix_len;
	poTmpEntry->i32SecurityModel = i32SecurityModel;
	poTmpEntry->i32SecurityLevel = i32SecurityLevel;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oVacmAccessTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmAccessEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
vacmAccessTable_removeEntry (vacmAccessEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmAccessTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oVacmAccessTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
vacmAccessTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oVacmAccessTable_BTree);
	return vacmAccessTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
vacmAccessTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmAccessEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, vacmAccessEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8GroupName, poEntry->u16GroupName_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8ContextPrefix, poEntry->u16ContextPrefix_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32SecurityModel);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32SecurityLevel);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oVacmAccessTable_BTree);
	return put_index_data;
}

bool
vacmAccessTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmAccessEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = vacmAccessTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer,
		*idx4->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* vacmAccessTable table mapper */
int
vacmAccessTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	vacmAccessEntry_t *table_entry;
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMACCESSCONTEXTMATCH:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ContextMatch);
				break;
			case VACMACCESSREADVIEWNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ReadViewName, table_entry->u16ReadViewName_len);
				break;
			case VACMACCESSWRITEVIEWNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8WriteViewName, table_entry->u16WriteViewName_len);
				break;
			case VACMACCESSNOTIFYVIEWNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NotifyViewName, table_entry->u16NotifyViewName_len);
				break;
			case VACMACCESSSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case VACMACCESSSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMACCESSCONTEXTMATCH:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMACCESSREADVIEWNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ReadViewName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMACCESSWRITEVIEWNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8WriteViewName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMACCESSNOTIFYVIEWNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NotifyViewName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMACCESSSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMACCESSSTATUS:
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case VACMACCESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = vacmAccessTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
						(void*) idx2->val.string, idx2->val_len,
						*idx3->val.integer,
						*idx4->val.integer);
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMACCESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmAccessTable_removeEntry (table_entry);
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMACCESSCONTEXTMATCH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ContextMatch))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ContextMatch, sizeof (table_entry->i32ContextMatch));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ContextMatch = *request->requestvb->val.integer;
				break;
			case VACMACCESSREADVIEWNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ReadViewName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ReadViewName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ReadViewName, sizeof (table_entry->au8ReadViewName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ReadViewName, 0, sizeof (table_entry->au8ReadViewName));
				memcpy (table_entry->au8ReadViewName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ReadViewName_len = request->requestvb->val_len;
				break;
			case VACMACCESSWRITEVIEWNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8WriteViewName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16WriteViewName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8WriteViewName, sizeof (table_entry->au8WriteViewName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8WriteViewName, 0, sizeof (table_entry->au8WriteViewName));
				memcpy (table_entry->au8WriteViewName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16WriteViewName_len = request->requestvb->val_len;
				break;
			case VACMACCESSNOTIFYVIEWNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NotifyViewName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NotifyViewName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NotifyViewName, sizeof (table_entry->au8NotifyViewName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NotifyViewName, 0, sizeof (table_entry->au8NotifyViewName));
				memcpy (table_entry->au8NotifyViewName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NotifyViewName_len = request->requestvb->val_len;
				break;
			case VACMACCESSSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMACCESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int vacmAccessTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMACCESSCONTEXTMATCH:
				memcpy (&table_entry->i32ContextMatch, pvOldDdata, sizeof (table_entry->i32ContextMatch));
				break;
			case VACMACCESSREADVIEWNAME:
				memcpy (table_entry->au8ReadViewName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ReadViewName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case VACMACCESSWRITEVIEWNAME:
				memcpy (table_entry->au8WriteViewName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16WriteViewName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case VACMACCESSNOTIFYVIEWNAME:
				memcpy (table_entry->au8NotifyViewName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NotifyViewName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case VACMACCESSSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case VACMACCESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmAccessTable_removeEntry (table_entry);
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
			table_entry = (vacmAccessEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMACCESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					vacmAccessTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize vacmViewTreeFamilyTable table mapper **/
void
vacmViewTreeFamilyTable_init (void)
{
	extern oid vacmViewTreeFamilyTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"vacmViewTreeFamilyTable", &vacmViewTreeFamilyTable_mapper,
		vacmViewTreeFamilyTable_oid, OID_LENGTH (vacmViewTreeFamilyTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: vacmViewTreeFamilyViewName */,
		ASN_OBJECT_ID /* index: vacmViewTreeFamilySubtree */,
		0);
	table_info->min_column = VACMVIEWTREEFAMILYMASK;
	table_info->max_column = VACMVIEWTREEFAMILYSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &vacmViewTreeFamilyTable_getFirst;
	iinfo->get_next_data_point = &vacmViewTreeFamilyTable_getNext;
	iinfo->get_data_point = &vacmViewTreeFamilyTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
vacmViewTreeFamilyTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register vacmViewTreeFamilyEntry_t *pEntry1 = xBTree_entry (pNode1, vacmViewTreeFamilyEntry_t, oBTreeNode);
	register vacmViewTreeFamilyEntry_t *pEntry2 = xBTree_entry (pNode2, vacmViewTreeFamilyEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8ViewName, pEntry2->au8ViewName, pEntry1->u16ViewName_len, pEntry2->u16ViewName_len) == -1) ||
		(xBinCmp (pEntry1->au8ViewName, pEntry2->au8ViewName, pEntry1->u16ViewName_len, pEntry2->u16ViewName_len) == 0 && xOidCmp (pEntry1->aoSubtree, pEntry2->aoSubtree, pEntry1->u16Subtree_len, pEntry2->u16Subtree_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8ViewName, pEntry2->au8ViewName, pEntry1->u16ViewName_len, pEntry2->u16ViewName_len) == 0 && xOidCmp (pEntry1->aoSubtree, pEntry2->aoSubtree, pEntry1->u16Subtree_len, pEntry2->u16Subtree_len) == 0) ? 0: 1;
}

xBTree_t oVacmViewTreeFamilyTable_BTree = xBTree_initInline (&vacmViewTreeFamilyTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
vacmViewTreeFamilyEntry_t *
vacmViewTreeFamilyTable_createEntry (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register vacmViewTreeFamilyEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8ViewName, pau8ViewName, u16ViewName_len);
	poEntry->u16ViewName_len = u16ViewName_len;
	memcpy (poEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poEntry->u16Subtree_len = u16Subtree_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Mask = 0*/;
	poEntry->i32Type = vacmViewTreeFamilyType_included_c;
	poEntry->u8StorageType = vacmViewTreeFamilyStorageType_nonVolatile_c;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree);
	return poEntry;
}

vacmViewTreeFamilyEntry_t *
vacmViewTreeFamilyTable_getByIndex (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register vacmViewTreeFamilyEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8ViewName, pau8ViewName, u16ViewName_len);
	poTmpEntry->u16ViewName_len = u16ViewName_len;
	memcpy (poTmpEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poTmpEntry->u16Subtree_len = u16Subtree_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmViewTreeFamilyEntry_t, oBTreeNode);
}

vacmViewTreeFamilyEntry_t *
vacmViewTreeFamilyTable_getNextIndex (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len)
{
	register vacmViewTreeFamilyEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8ViewName, pau8ViewName, u16ViewName_len);
	poTmpEntry->u16ViewName_len = u16ViewName_len;
	memcpy (poTmpEntry->aoSubtree, paoSubtree, u16Subtree_len);
	poTmpEntry->u16Subtree_len = u16Subtree_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, vacmViewTreeFamilyEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
vacmViewTreeFamilyTable_removeEntry (vacmViewTreeFamilyEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
vacmViewTreeFamilyTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oVacmViewTreeFamilyTable_BTree);
	return vacmViewTreeFamilyTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
vacmViewTreeFamilyTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmViewTreeFamilyEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, vacmViewTreeFamilyEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8ViewName, poEntry->u16ViewName_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->aoSubtree, poEntry->u16Subtree_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oVacmViewTreeFamilyTable_BTree);
	return put_index_data;
}

bool
vacmViewTreeFamilyTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	vacmViewTreeFamilyEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = vacmViewTreeFamilyTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* vacmViewTreeFamilyTable table mapper */
int
vacmViewTreeFamilyTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	vacmViewTreeFamilyEntry_t *table_entry;
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYMASK:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Mask, table_entry->u16Mask_len);
				break;
			case VACMVIEWTREEFAMILYTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case VACMVIEWTREEFAMILYSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case VACMVIEWTREEFAMILYSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYMASK:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Mask));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMVIEWTREEFAMILYTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMVIEWTREEFAMILYSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case VACMVIEWTREEFAMILYSTATUS:
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = vacmViewTreeFamilyTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
						(void*) idx2->val.string, idx2->val_len);
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmViewTreeFamilyTable_removeEntry (table_entry);
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYMASK:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Mask))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Mask_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Mask, sizeof (table_entry->au8Mask));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Mask, 0, sizeof (table_entry->au8Mask));
				memcpy (table_entry->au8Mask, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Mask_len = request->requestvb->val_len;
				break;
			case VACMVIEWTREEFAMILYTYPE:
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
			case VACMVIEWTREEFAMILYSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int vacmViewTreeFamilyTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYMASK:
				memcpy (table_entry->au8Mask, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Mask_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case VACMVIEWTREEFAMILYTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case VACMVIEWTREEFAMILYSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case VACMVIEWTREEFAMILYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					vacmViewTreeFamilyTable_removeEntry (table_entry);
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
			table_entry = (vacmViewTreeFamilyEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case VACMVIEWTREEFAMILYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					vacmViewTreeFamilyTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpCommunityTable table mapper **/
void
snmpCommunityTable_init (void)
{
	extern oid snmpCommunityTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpCommunityTable", &snmpCommunityTable_mapper,
		snmpCommunityTable_oid, OID_LENGTH (snmpCommunityTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpCommunityIndex */,
		0);
	table_info->min_column = SNMPCOMMUNITYNAME;
	table_info->max_column = SNMPCOMMUNITYSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpCommunityTable_getFirst;
	iinfo->get_next_data_point = &snmpCommunityTable_getNext;
	iinfo->get_data_point = &snmpCommunityTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpCommunityTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpCommunityEntry_t *pEntry1 = xBTree_entry (pNode1, snmpCommunityEntry_t, oBTreeNode);
	register snmpCommunityEntry_t *pEntry2 = xBTree_entry (pNode2, snmpCommunityEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oSnmpCommunityTable_BTree = xBTree_initInline (&snmpCommunityTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpCommunityEntry_t *
snmpCommunityTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register snmpCommunityEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpCommunityTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8ContextName = 0*/;
	/*poEntry->au8TransportTag = 0*/;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpCommunityTable_BTree);
	return poEntry;
}

snmpCommunityEntry_t *
snmpCommunityTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register snmpCommunityEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpCommunityTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpCommunityEntry_t, oBTreeNode);
}

snmpCommunityEntry_t *
snmpCommunityTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register snmpCommunityEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpCommunityTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpCommunityEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpCommunityTable_removeEntry (snmpCommunityEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpCommunityTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpCommunityTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpCommunityTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpCommunityTable_BTree);
	return snmpCommunityTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpCommunityTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpCommunityEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpCommunityEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpCommunityTable_BTree);
	return put_index_data;
}

bool
snmpCommunityTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpCommunityEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpCommunityTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpCommunityTable table mapper */
int
snmpCommunityTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpCommunityEntry_t *table_entry;
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case SNMPCOMMUNITYSECURITYNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SecurityName, table_entry->u16SecurityName_len);
				break;
			case SNMPCOMMUNITYCONTEXTENGINEID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ContextEngineID, table_entry->u16ContextEngineID_len);
				break;
			case SNMPCOMMUNITYCONTEXTNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ContextName, table_entry->u16ContextName_len);
				break;
			case SNMPCOMMUNITYTRANSPORTTAG:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransportTag, table_entry->u16TransportTag_len);
				break;
			case SNMPCOMMUNITYSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case SNMPCOMMUNITYSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYSECURITYNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SecurityName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYCONTEXTENGINEID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ContextEngineID));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYCONTEXTNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ContextName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYTRANSPORTTAG:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransportTag));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPCOMMUNITYSTATUS:
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpCommunityTable_createEntry (
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpCommunityTable_removeEntry (table_entry);
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Name))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Name_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Name, sizeof (table_entry->au8Name));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Name, 0, sizeof (table_entry->au8Name));
				memcpy (table_entry->au8Name, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Name_len = request->requestvb->val_len;
				break;
			case SNMPCOMMUNITYSECURITYNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SecurityName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SecurityName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SecurityName, sizeof (table_entry->au8SecurityName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SecurityName, 0, sizeof (table_entry->au8SecurityName));
				memcpy (table_entry->au8SecurityName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SecurityName_len = request->requestvb->val_len;
				break;
			case SNMPCOMMUNITYCONTEXTENGINEID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ContextEngineID))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ContextEngineID_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ContextEngineID, sizeof (table_entry->au8ContextEngineID));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ContextEngineID, 0, sizeof (table_entry->au8ContextEngineID));
				memcpy (table_entry->au8ContextEngineID, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ContextEngineID_len = request->requestvb->val_len;
				break;
			case SNMPCOMMUNITYCONTEXTNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ContextName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ContextName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ContextName, sizeof (table_entry->au8ContextName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ContextName, 0, sizeof (table_entry->au8ContextName));
				memcpy (table_entry->au8ContextName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ContextName_len = request->requestvb->val_len;
				break;
			case SNMPCOMMUNITYTRANSPORTTAG:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransportTag))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransportTag_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransportTag, sizeof (table_entry->au8TransportTag));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransportTag, 0, sizeof (table_entry->au8TransportTag));
				memcpy (table_entry->au8TransportTag, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransportTag_len = request->requestvb->val_len;
				break;
			case SNMPCOMMUNITYSTORAGETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8StorageType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8StorageType, sizeof (table_entry->u8StorageType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8StorageType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int snmpCommunityTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPCOMMUNITYSECURITYNAME:
				memcpy (table_entry->au8SecurityName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SecurityName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPCOMMUNITYCONTEXTENGINEID:
				memcpy (table_entry->au8ContextEngineID, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ContextEngineID_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPCOMMUNITYCONTEXTNAME:
				memcpy (table_entry->au8ContextName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ContextName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPCOMMUNITYTRANSPORTTAG:
				memcpy (table_entry->au8TransportTag, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransportTag_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case SNMPCOMMUNITYSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case SNMPCOMMUNITYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					snmpCommunityTable_removeEntry (table_entry);
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
			table_entry = (snmpCommunityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPCOMMUNITYSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					snmpCommunityTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize snmpTargetAddrExtTable table mapper **/
void
snmpTargetAddrExtTable_init (void)
{
	extern oid snmpTargetAddrExtTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"snmpTargetAddrExtTable", &snmpTargetAddrExtTable_mapper,
		snmpTargetAddrExtTable_oid, OID_LENGTH (snmpTargetAddrExtTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: snmpTargetAddrName */,
		0);
	table_info->min_column = SNMPTARGETADDRTMASK;
	table_info->max_column = SNMPTARGETADDRMMS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &snmpTargetAddrExtTable_getFirst;
	iinfo->get_next_data_point = &snmpTargetAddrExtTable_getNext;
	iinfo->get_data_point = &snmpTargetAddrExtTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
snmpTargetAddrExtTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register snmpTargetAddrExtEntry_t *pEntry1 = xBTree_entry (pNode1, snmpTargetAddrExtEntry_t, oBTreeNode);
	register snmpTargetAddrExtEntry_t *pEntry2 = xBTree_entry (pNode2, snmpTargetAddrExtEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Name, pEntry2->au8Name, pEntry1->u16Name_len, pEntry2->u16Name_len) == 0) ? 0: 1;
}

xBTree_t oSnmpTargetAddrExtTable_BTree = xBTree_initInline (&snmpTargetAddrExtTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
snmpTargetAddrExtEntry_t *
snmpTargetAddrExtTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrExtEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Name, pau8Name, u16Name_len);
	poEntry->u16Name_len = u16Name_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8TMask = 0*/;
	poEntry->i32MMS = 484;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree);
	return poEntry;
}

snmpTargetAddrExtEntry_t *
snmpTargetAddrExtTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrExtEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetAddrExtEntry_t, oBTreeNode);
}

snmpTargetAddrExtEntry_t *
snmpTargetAddrExtTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len)
{
	register snmpTargetAddrExtEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Name, pau8Name, u16Name_len);
	poTmpEntry->u16Name_len = u16Name_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, snmpTargetAddrExtEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
snmpTargetAddrExtTable_removeEntry (snmpTargetAddrExtEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
snmpTargetAddrExtTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oSnmpTargetAddrExtTable_BTree);
	return snmpTargetAddrExtTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
snmpTargetAddrExtTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetAddrExtEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, snmpTargetAddrExtEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Name, poEntry->u16Name_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oSnmpTargetAddrExtTable_BTree);
	return put_index_data;
}

bool
snmpTargetAddrExtTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	snmpTargetAddrExtEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = snmpTargetAddrExtTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* snmpTargetAddrExtTable table mapper */
int
snmpTargetAddrExtTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	snmpTargetAddrExtEntry_t *table_entry;
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
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TMask, table_entry->u16TMask_len);
				break;
			case SNMPTARGETADDRMMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MMS);
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
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TMask));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case SNMPTARGETADDRMMS:
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
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
			case SNMPTARGETADDRMMS:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = snmpTargetAddrExtTable_createEntry (
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
				}
				break;
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
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
			case SNMPTARGETADDRMMS:
				snmpTargetAddrExtTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TMask))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TMask_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TMask, sizeof (table_entry->au8TMask));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TMask, 0, sizeof (table_entry->au8TMask));
				memcpy (table_entry->au8TMask, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TMask_len = request->requestvb->val_len;
				break;
			case SNMPTARGETADDRMMS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MMS))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MMS, sizeof (table_entry->i32MMS));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MMS = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (snmpTargetAddrExtEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case SNMPTARGETADDRTMASK:
				if (pvOldDdata == table_entry)
				{
					snmpTargetAddrExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8TMask, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16TMask_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case SNMPTARGETADDRMMS:
				if (pvOldDdata == table_entry)
				{
					snmpTargetAddrExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32MMS, pvOldDdata, sizeof (table_entry->i32MMS));
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}


/**
 *	notification mapper(s)
 */
int
coldStart_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid coldStart_oid[];
	netsnmp_variable_list *var_list = NULL;
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) coldStart_oid, sizeof (coldStart_oid));
		
		
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
warmStart_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid warmStart_oid[];
	netsnmp_variable_list *var_list = NULL;
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) warmStart_oid, sizeof (warmStart_oid));
		
		
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
authenticationFailure_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid authenticationFailure_oid[];
	netsnmp_variable_list *var_list = NULL;
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) authenticationFailure_oid, sizeof (authenticationFailure_oid));
		
		
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
