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

#define SNMP_SRC

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "clnsMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid clns_oid[] = {1,3,6,1,3,1};

static oid clnp_oid[] = {1,3,6,1,3,1,1};
static oid error_oid[] = {1,3,6,1,3,1,2};
static oid esis_oid[] = {1,3,6,1,3,1,4};

static oid clnpAddrTable_oid[] = {1,3,6,1,3,1,1,21};
static oid clnpRoutingTable_oid[] = {1,3,6,1,3,1,1,22};
static oid clnpNetToMediaTable_oid[] = {1,3,6,1,3,1,1,23};
static oid clnpMediaToNetTable_oid[] = {1,3,6,1,3,1,1,24};



/**
 *	initialize clnsMIB group mapper
 */
void
clnsMIB_init (void)
{
	extern oid clns_oid[];
	extern oid clnp_oid[];
	extern oid error_oid[];
	extern oid esis_oid[];
	
	DEBUGMSGTL (("clnsMIB", "Initializing\n"));
	
	/* register clnp scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"clnp_mapper", &clnp_mapper,
			clnp_oid, OID_LENGTH (clnp_oid),
			HANDLER_CAN_RWRITE
		),
		CLNPFORWARDING,
		CLNPROUTINGDISCARDS
	);
	
	/* register error scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"error_mapper", &error_mapper,
			error_oid, OID_LENGTH (error_oid),
			HANDLER_CAN_RONLY
		),
		CLNPINERRORS,
		CLNPOUTERRINTERFERENCES
	);
	
	/* register esis scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"esis_mapper", &esis_mapper,
			esis_oid, OID_LENGTH (esis_oid),
			HANDLER_CAN_RONLY
		),
		ESISESHINS,
		ESISRDUOUTS
	);
	
	
	/* register clnsMIB group table mappers */
	clnpAddrTable_init ();
	clnpRoutingTable_init ();
	clnpNetToMediaTable_init ();
	clnpMediaToNetTable_init ();
	
	/* register clnsMIB modules */
	sysORTable_createRegister ("clns", clns_oid, OID_LENGTH (clns_oid));
}


/**
 *	scalar mapper(s)
 */
clnp_t oClnp;

/** clnp scalar mapper **/
int
clnp_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid clnp_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (clnp_oid) - 1])
			{
			case CLNPFORWARDING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oClnp.i32Forwarding);
				break;
			case CLNPDEFAULTLIFETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oClnp.i32DefaultLifeTime);
				break;
			case CLNPINRECEIVES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InReceives);
				break;
			case CLNPINHDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InHdrErrors);
				break;
			case CLNPINADDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InAddrErrors);
				break;
			case CLNPFORWPDUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32ForwPDUs);
				break;
			case CLNPINUNKNOWNNLPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InUnknownNLPs);
				break;
			case CLNPINUNKNOWNULPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InUnknownULPs);
				break;
			case CLNPINDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InDiscards);
				break;
			case CLNPINDELIVERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InDelivers);
				break;
			case CLNPOUTREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32OutRequests);
				break;
			case CLNPOUTDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32OutDiscards);
				break;
			case CLNPOUTNOROUTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32OutNoRoutes);
				break;
			case CLNPREASMTIMEOUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oClnp.i32ReasmTimeout);
				break;
			case CLNPREASMREQDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32ReasmReqds);
				break;
			case CLNPREASMOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32ReasmOKs);
				break;
			case CLNPREASMFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32ReasmFails);
				break;
			case CLNPSEGOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32SegOKs);
				break;
			case CLNPSEGFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32SegFails);
				break;
			case CLNPSEGCREATES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32SegCreates);
				break;
			case CLNPINOPTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32InOpts);
				break;
			case CLNPOUTOPTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32OutOpts);
				break;
			case CLNPROUTINGDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oClnp.u32RoutingDiscards);
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
			switch (request->requestvb->name[OID_LENGTH (clnp_oid) - 1])
			{
			case CLNPFORWARDING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case CLNPDEFAULTLIFETIME:
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
			switch (request->requestvb->name[OID_LENGTH (clnp_oid) - 1])
			{
			case CLNPFORWARDING:
				/* XXX: perform the value change here */
				oClnp.i32Forwarding = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case CLNPDEFAULTLIFETIME:
				/* XXX: perform the value change here */
				oClnp.i32DefaultLifeTime = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (clnp_oid) - 1])
			{
			case CLNPFORWARDING:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case CLNPDEFAULTLIFETIME:
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

error_t oError;

/** error scalar mapper **/
int
error_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid error_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (error_oid) - 1])
			{
			case CLNPINERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrors);
				break;
			case CLNPOUTERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrors);
				break;
			case CLNPINERRUNSPECS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnspecs);
				break;
			case CLNPINERRPROCS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrProcs);
				break;
			case CLNPINERRCKSUMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrCksums);
				break;
			case CLNPINERRCONGESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrCongests);
				break;
			case CLNPINERRHDRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrHdrs);
				break;
			case CLNPINERRSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrSegs);
				break;
			case CLNPINERRINCOMPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrIncomps);
				break;
			case CLNPINERRDUPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrDups);
				break;
			case CLNPINERRUNREACHDSTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnreachDsts);
				break;
			case CLNPINERRUNKNOWNDSTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnknownDsts);
				break;
			case CLNPINERRSRUNSPECS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrSRUnspecs);
				break;
			case CLNPINERRSRSYNTAXES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrSRSyntaxes);
				break;
			case CLNPINERRSRUNKADDRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrSRUnkAddrs);
				break;
			case CLNPINERRSRBADPATHS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrSRBadPaths);
				break;
			case CLNPINERRHOPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrHops);
				break;
			case CLNPINERRHOPREASSMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrHopReassms);
				break;
			case CLNPINERRUNSOPTIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnsOptions);
				break;
			case CLNPINERRUNSVERSIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnsVersions);
				break;
			case CLNPINERRUNSSECURITIES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnsSecurities);
				break;
			case CLNPINERRUNSSRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnsSRs);
				break;
			case CLNPINERRUNSRRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrUnsRRs);
				break;
			case CLNPINERRINTERFERENCES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpInErrInterferences);
				break;
			case CLNPOUTERRUNSPECS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnspecs);
				break;
			case CLNPOUTERRPROCS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrProcs);
				break;
			case CLNPOUTERRCKSUMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrCksums);
				break;
			case CLNPOUTERRCONGESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrCongests);
				break;
			case CLNPOUTERRHDRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrHdrs);
				break;
			case CLNPOUTERRSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrSegs);
				break;
			case CLNPOUTERRINCOMPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrIncomps);
				break;
			case CLNPOUTERRDUPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrDups);
				break;
			case CLNPOUTERRUNREACHDSTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnreachDsts);
				break;
			case CLNPOUTERRUNKNOWNDSTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnknownDsts);
				break;
			case CLNPOUTERRSRUNSPECS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrSRUnspecs);
				break;
			case CLNPOUTERRSRSYNTAXES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrSRSyntaxes);
				break;
			case CLNPOUTERRSRUNKADDRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrSRUnkAddrs);
				break;
			case CLNPOUTERRSRBADPATHS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrSRBadPaths);
				break;
			case CLNPOUTERRHOPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrHops);
				break;
			case CLNPOUTERRHOPREASSMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrHopReassms);
				break;
			case CLNPOUTERRUNSOPTIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnsOptions);
				break;
			case CLNPOUTERRUNSVERSIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnsVersions);
				break;
			case CLNPOUTERRUNSSECURITIES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnsSecurities);
				break;
			case CLNPOUTERRUNSSRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnsSRs);
				break;
			case CLNPOUTERRUNSRRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrUnsRRs);
				break;
			case CLNPOUTERRINTERFERENCES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oError.u32ClnpOutErrInterferences);
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

esis_t oEsis;

/** esis scalar mapper **/
int
esis_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid esis_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (esis_oid) - 1])
			{
			case ESISESHINS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32ESHins);
				break;
			case ESISESHOUTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32ESHouts);
				break;
			case ESISISHINS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32ISHins);
				break;
			case ESISISHOUTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32ISHouts);
				break;
			case ESISRDUINS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32RDUins);
				break;
			case ESISRDUOUTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oEsis.u32RDUouts);
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
/** initialize clnpAddrTable table mapper **/
void
clnpAddrTable_init (void)
{
	extern oid clnpAddrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"clnpAddrTable", &clnpAddrTable_mapper,
		clnpAddrTable_oid, OID_LENGTH (clnpAddrTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: clnpAdEntAddr */,
		0);
	table_info->min_column = CLNPADENTADDR;
	table_info->max_column = CLNPADENTREASMMAXSIZE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &clnpAddrTable_getFirst;
	iinfo->get_next_data_point = &clnpAddrTable_getNext;
	iinfo->get_data_point = &clnpAddrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
clnpAddrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register clnpAddrEntry_t *pEntry1 = xBTree_entry (pNode1, clnpAddrEntry_t, oBTreeNode);
	register clnpAddrEntry_t *pEntry2 = xBTree_entry (pNode2, clnpAddrEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8EntAddr, pEntry2->au8EntAddr, pEntry1->u16EntAddr_len, pEntry2->u16EntAddr_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8EntAddr, pEntry2->au8EntAddr, pEntry1->u16EntAddr_len, pEntry2->u16EntAddr_len) == 0) ? 0: 1;
}

xBTree_t oClnpAddrTable_BTree = xBTree_initInline (&clnpAddrTable_BTreeNodeCmp);

/* create a new row in the table */
clnpAddrEntry_t *
clnpAddrTable_createEntry (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len)
{
	clnpAddrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (clnpAddrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8EntAddr, pau8EntAddr, u16EntAddr_len);
	poEntry->u16EntAddr_len = u16EntAddr_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpAddrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oClnpAddrTable_BTree);
	return poEntry;
}

clnpAddrEntry_t *
clnpAddrTable_getByIndex (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len)
{
	register clnpAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpAddrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8EntAddr, pau8EntAddr, u16EntAddr_len);
	poTmpEntry->u16EntAddr_len = u16EntAddr_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oClnpAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpAddrEntry_t, oBTreeNode);
}

clnpAddrEntry_t *
clnpAddrTable_getNextIndex (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len)
{
	register clnpAddrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpAddrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8EntAddr, pau8EntAddr, u16EntAddr_len);
	poTmpEntry->u16EntAddr_len = u16EntAddr_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oClnpAddrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpAddrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
clnpAddrTable_removeEntry (clnpAddrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpAddrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oClnpAddrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
clnpAddrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oClnpAddrTable_BTree);
	return clnpAddrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
clnpAddrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpAddrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, clnpAddrEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8EntAddr, poEntry->u16EntAddr_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oClnpAddrTable_BTree);
	return put_index_data;
}

bool
clnpAddrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpAddrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = clnpAddrTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* clnpAddrTable table mapper */
int
clnpAddrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	clnpAddrEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (clnpAddrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPADENTADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntAddr, table_entry->u16EntAddr_len);
				break;
			case CLNPADENTIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntIfIndex);
				break;
			case CLNPADENTREASMMAXSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntReasmMaxSize);
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

/** initialize clnpRoutingTable table mapper **/
void
clnpRoutingTable_init (void)
{
	extern oid clnpRoutingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"clnpRoutingTable", &clnpRoutingTable_mapper,
		clnpRoutingTable_oid, OID_LENGTH (clnpRoutingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: clnpRouteDest */,
		0);
	table_info->min_column = CLNPROUTEDEST;
	table_info->max_column = CLNPROUTEINFO;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &clnpRoutingTable_getFirst;
	iinfo->get_next_data_point = &clnpRoutingTable_getNext;
	iinfo->get_data_point = &clnpRoutingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
clnpRoutingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register clnpRoutingEntry_t *pEntry1 = xBTree_entry (pNode1, clnpRoutingEntry_t, oBTreeNode);
	register clnpRoutingEntry_t *pEntry2 = xBTree_entry (pNode2, clnpRoutingEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8RouteDest, pEntry2->au8RouteDest, pEntry1->u16RouteDest_len, pEntry2->u16RouteDest_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8RouteDest, pEntry2->au8RouteDest, pEntry1->u16RouteDest_len, pEntry2->u16RouteDest_len) == 0) ? 0: 1;
}

xBTree_t oClnpRoutingTable_BTree = xBTree_initInline (&clnpRoutingTable_BTreeNodeCmp);

/* create a new row in the table */
clnpRoutingEntry_t *
clnpRoutingTable_createEntry (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len)
{
	clnpRoutingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (clnpRoutingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8RouteDest, pau8RouteDest, u16RouteDest_len);
	poEntry->u16RouteDest_len = u16RouteDest_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpRoutingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oClnpRoutingTable_BTree);
	return poEntry;
}

clnpRoutingEntry_t *
clnpRoutingTable_getByIndex (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len)
{
	register clnpRoutingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpRoutingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8RouteDest, pau8RouteDest, u16RouteDest_len);
	poTmpEntry->u16RouteDest_len = u16RouteDest_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oClnpRoutingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpRoutingEntry_t, oBTreeNode);
}

clnpRoutingEntry_t *
clnpRoutingTable_getNextIndex (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len)
{
	register clnpRoutingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpRoutingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8RouteDest, pau8RouteDest, u16RouteDest_len);
	poTmpEntry->u16RouteDest_len = u16RouteDest_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oClnpRoutingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpRoutingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
clnpRoutingTable_removeEntry (clnpRoutingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpRoutingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oClnpRoutingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
clnpRoutingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oClnpRoutingTable_BTree);
	return clnpRoutingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
clnpRoutingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpRoutingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, clnpRoutingEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8RouteDest, poEntry->u16RouteDest_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oClnpRoutingTable_BTree);
	return put_index_data;
}

bool
clnpRoutingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpRoutingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = clnpRoutingTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* clnpRoutingTable table mapper */
int
clnpRoutingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	clnpRoutingEntry_t *table_entry;
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
			table_entry = (clnpRoutingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPROUTEDEST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RouteDest, table_entry->u16RouteDest_len);
				break;
			case CLNPROUTEIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteIfIndex);
				break;
			case CLNPROUTEMETRIC1:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteMetric1);
				break;
			case CLNPROUTEMETRIC2:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteMetric2);
				break;
			case CLNPROUTEMETRIC3:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteMetric3);
				break;
			case CLNPROUTEMETRIC4:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteMetric4);
				break;
			case CLNPROUTENEXTHOP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RouteNextHop, table_entry->u16RouteNextHop_len);
				break;
			case CLNPROUTETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteType);
				break;
			case CLNPROUTEPROTO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteProto);
				break;
			case CLNPROUTEAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteAge);
				break;
			case CLNPROUTEMETRIC5:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RouteMetric5);
				break;
			case CLNPROUTEINFO:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoRouteInfo, table_entry->u16RouteInfo_len);
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
			table_entry = (clnpRoutingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPROUTEDEST:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8RouteDest));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEMETRIC1:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEMETRIC2:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEMETRIC3:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEMETRIC4:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTENEXTHOP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8RouteNextHop));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEAGE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPROUTEMETRIC5:
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
			table_entry = (clnpRoutingEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (clnpRoutingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPROUTEDEST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8RouteDest))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16RouteDest_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8RouteDest, sizeof (table_entry->au8RouteDest));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8RouteDest, 0, sizeof (table_entry->au8RouteDest));
				memcpy (table_entry->au8RouteDest, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16RouteDest_len = request->requestvb->val_len;
				break;
			case CLNPROUTEIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteIfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteIfIndex, sizeof (table_entry->i32RouteIfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteIfIndex = *request->requestvb->val.integer;
				break;
			case CLNPROUTEMETRIC1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteMetric1))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteMetric1, sizeof (table_entry->i32RouteMetric1));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteMetric1 = *request->requestvb->val.integer;
				break;
			case CLNPROUTEMETRIC2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteMetric2))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteMetric2, sizeof (table_entry->i32RouteMetric2));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteMetric2 = *request->requestvb->val.integer;
				break;
			case CLNPROUTEMETRIC3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteMetric3))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteMetric3, sizeof (table_entry->i32RouteMetric3));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteMetric3 = *request->requestvb->val.integer;
				break;
			case CLNPROUTEMETRIC4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteMetric4))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteMetric4, sizeof (table_entry->i32RouteMetric4));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteMetric4 = *request->requestvb->val.integer;
				break;
			case CLNPROUTENEXTHOP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8RouteNextHop))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16RouteNextHop_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8RouteNextHop, sizeof (table_entry->au8RouteNextHop));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8RouteNextHop, 0, sizeof (table_entry->au8RouteNextHop));
				memcpy (table_entry->au8RouteNextHop, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16RouteNextHop_len = request->requestvb->val_len;
				break;
			case CLNPROUTETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteType, sizeof (table_entry->i32RouteType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteType = *request->requestvb->val.integer;
				break;
			case CLNPROUTEAGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteAge))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteAge, sizeof (table_entry->i32RouteAge));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteAge = *request->requestvb->val.integer;
				break;
			case CLNPROUTEMETRIC5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RouteMetric5))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RouteMetric5, sizeof (table_entry->i32RouteMetric5));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RouteMetric5 = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (clnpRoutingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPROUTEDEST:
				memcpy (table_entry->au8RouteDest, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16RouteDest_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPROUTEIFINDEX:
				memcpy (&table_entry->i32RouteIfIndex, pvOldDdata, sizeof (table_entry->i32RouteIfIndex));
				break;
			case CLNPROUTEMETRIC1:
				memcpy (&table_entry->i32RouteMetric1, pvOldDdata, sizeof (table_entry->i32RouteMetric1));
				break;
			case CLNPROUTEMETRIC2:
				memcpy (&table_entry->i32RouteMetric2, pvOldDdata, sizeof (table_entry->i32RouteMetric2));
				break;
			case CLNPROUTEMETRIC3:
				memcpy (&table_entry->i32RouteMetric3, pvOldDdata, sizeof (table_entry->i32RouteMetric3));
				break;
			case CLNPROUTEMETRIC4:
				memcpy (&table_entry->i32RouteMetric4, pvOldDdata, sizeof (table_entry->i32RouteMetric4));
				break;
			case CLNPROUTENEXTHOP:
				memcpy (table_entry->au8RouteNextHop, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16RouteNextHop_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPROUTETYPE:
				memcpy (&table_entry->i32RouteType, pvOldDdata, sizeof (table_entry->i32RouteType));
				break;
			case CLNPROUTEAGE:
				memcpy (&table_entry->i32RouteAge, pvOldDdata, sizeof (table_entry->i32RouteAge));
				break;
			case CLNPROUTEMETRIC5:
				memcpy (&table_entry->i32RouteMetric5, pvOldDdata, sizeof (table_entry->i32RouteMetric5));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize clnpNetToMediaTable table mapper **/
void
clnpNetToMediaTable_init (void)
{
	extern oid clnpNetToMediaTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"clnpNetToMediaTable", &clnpNetToMediaTable_mapper,
		clnpNetToMediaTable_oid, OID_LENGTH (clnpNetToMediaTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: clnpNetToMediaIfIndex */,
		ASN_OCTET_STR /* index: clnpNetToMediaNetAddress */,
		0);
	table_info->min_column = CLNPNETTOMEDIAIFINDEX;
	table_info->max_column = CLNPNETTOMEDIAHOLDTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &clnpNetToMediaTable_getFirst;
	iinfo->get_next_data_point = &clnpNetToMediaTable_getNext;
	iinfo->get_data_point = &clnpNetToMediaTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
clnpNetToMediaTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register clnpNetToMediaEntry_t *pEntry1 = xBTree_entry (pNode1, clnpNetToMediaEntry_t, oBTreeNode);
	register clnpNetToMediaEntry_t *pEntry2 = xBTree_entry (pNode2, clnpNetToMediaEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IfIndex < pEntry2->i32IfIndex) ||
		(pEntry1->i32IfIndex == pEntry2->i32IfIndex && xBinCmp (pEntry1->au8NetAddress, pEntry2->au8NetAddress, pEntry1->u16NetAddress_len, pEntry2->u16NetAddress_len) == -1) ? -1:
		(pEntry1->i32IfIndex == pEntry2->i32IfIndex && xBinCmp (pEntry1->au8NetAddress, pEntry2->au8NetAddress, pEntry1->u16NetAddress_len, pEntry2->u16NetAddress_len) == 0) ? 0: 1;
}

xBTree_t oClnpNetToMediaTable_BTree = xBTree_initInline (&clnpNetToMediaTable_BTreeNodeCmp);

/* create a new row in the table */
clnpNetToMediaEntry_t *
clnpNetToMediaTable_createEntry (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	clnpNetToMediaEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (clnpNetToMediaEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IfIndex = i32IfIndex;
	memcpy (poEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poEntry->u16NetAddress_len = u16NetAddress_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpNetToMediaTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oClnpNetToMediaTable_BTree);
	return poEntry;
}

clnpNetToMediaEntry_t *
clnpNetToMediaTable_getByIndex (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	register clnpNetToMediaEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpNetToMediaEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IfIndex = i32IfIndex;
	memcpy (poTmpEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poTmpEntry->u16NetAddress_len = u16NetAddress_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oClnpNetToMediaTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpNetToMediaEntry_t, oBTreeNode);
}

clnpNetToMediaEntry_t *
clnpNetToMediaTable_getNextIndex (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	register clnpNetToMediaEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpNetToMediaEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IfIndex = i32IfIndex;
	memcpy (poTmpEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poTmpEntry->u16NetAddress_len = u16NetAddress_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oClnpNetToMediaTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpNetToMediaEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
clnpNetToMediaTable_removeEntry (clnpNetToMediaEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpNetToMediaTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oClnpNetToMediaTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
clnpNetToMediaTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oClnpNetToMediaTable_BTree);
	return clnpNetToMediaTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
clnpNetToMediaTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpNetToMediaEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, clnpNetToMediaEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8NetAddress, poEntry->u16NetAddress_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oClnpNetToMediaTable_BTree);
	return put_index_data;
}

bool
clnpNetToMediaTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpNetToMediaEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = clnpNetToMediaTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* clnpNetToMediaTable table mapper */
int
clnpNetToMediaTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	clnpNetToMediaEntry_t *table_entry;
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
			table_entry = (clnpNetToMediaEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPNETTOMEDIAIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IfIndex);
				break;
			case CLNPNETTOMEDIAPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PhysAddress, table_entry->u16PhysAddress_len);
				break;
			case CLNPNETTOMEDIANETADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NetAddress, table_entry->u16NetAddress_len);
				break;
			case CLNPNETTOMEDIATYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case CLNPNETTOMEDIAAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Age);
				break;
			case CLNPNETTOMEDIAHOLDTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32HoldTime);
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
			table_entry = (clnpNetToMediaEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPNETTOMEDIAIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPNETTOMEDIAPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PhysAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPNETTOMEDIANETADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NetAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPNETTOMEDIATYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPNETTOMEDIAAGE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPNETTOMEDIAHOLDTIME:
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
			table_entry = (clnpNetToMediaEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (clnpNetToMediaEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPNETTOMEDIAIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IfIndex, sizeof (table_entry->i32IfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IfIndex = *request->requestvb->val.integer;
				break;
			case CLNPNETTOMEDIAPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PhysAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PhysAddress, 0, sizeof (table_entry->au8PhysAddress));
				memcpy (table_entry->au8PhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PhysAddress_len = request->requestvb->val_len;
				break;
			case CLNPNETTOMEDIANETADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NetAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NetAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NetAddress, sizeof (table_entry->au8NetAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NetAddress, 0, sizeof (table_entry->au8NetAddress));
				memcpy (table_entry->au8NetAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NetAddress_len = request->requestvb->val_len;
				break;
			case CLNPNETTOMEDIATYPE:
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
			case CLNPNETTOMEDIAAGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Age))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Age, sizeof (table_entry->i32Age));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Age = *request->requestvb->val.integer;
				break;
			case CLNPNETTOMEDIAHOLDTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32HoldTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32HoldTime, sizeof (table_entry->i32HoldTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32HoldTime = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (clnpNetToMediaEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPNETTOMEDIAIFINDEX:
				memcpy (&table_entry->i32IfIndex, pvOldDdata, sizeof (table_entry->i32IfIndex));
				break;
			case CLNPNETTOMEDIAPHYSADDRESS:
				memcpy (table_entry->au8PhysAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PhysAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPNETTOMEDIANETADDRESS:
				memcpy (table_entry->au8NetAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NetAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPNETTOMEDIATYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case CLNPNETTOMEDIAAGE:
				memcpy (&table_entry->i32Age, pvOldDdata, sizeof (table_entry->i32Age));
				break;
			case CLNPNETTOMEDIAHOLDTIME:
				memcpy (&table_entry->i32HoldTime, pvOldDdata, sizeof (table_entry->i32HoldTime));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize clnpMediaToNetTable table mapper **/
void
clnpMediaToNetTable_init (void)
{
	extern oid clnpMediaToNetTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"clnpMediaToNetTable", &clnpMediaToNetTable_mapper,
		clnpMediaToNetTable_oid, OID_LENGTH (clnpMediaToNetTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: clnpMediaToNetIfIndex */,
		ASN_OCTET_STR /* index: clnpMediaToNetPhysAddress */,
		0);
	table_info->min_column = CLNPMEDIATONETIFINDEX;
	table_info->max_column = CLNPMEDIATONETHOLDTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &clnpMediaToNetTable_getFirst;
	iinfo->get_next_data_point = &clnpMediaToNetTable_getNext;
	iinfo->get_data_point = &clnpMediaToNetTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
clnpMediaToNetTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register clnpMediaToNetEntry_t *pEntry1 = xBTree_entry (pNode1, clnpMediaToNetEntry_t, oBTreeNode);
	register clnpMediaToNetEntry_t *pEntry2 = xBTree_entry (pNode2, clnpMediaToNetEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IfIndex < pEntry2->i32IfIndex) ||
		(pEntry1->i32IfIndex == pEntry2->i32IfIndex && xBinCmp (pEntry1->au8PhysAddress, pEntry2->au8PhysAddress, pEntry1->u16PhysAddress_len, pEntry2->u16PhysAddress_len) == -1) ? -1:
		(pEntry1->i32IfIndex == pEntry2->i32IfIndex && xBinCmp (pEntry1->au8PhysAddress, pEntry2->au8PhysAddress, pEntry1->u16PhysAddress_len, pEntry2->u16PhysAddress_len) == 0) ? 0: 1;
}

xBTree_t oClnpMediaToNetTable_BTree = xBTree_initInline (&clnpMediaToNetTable_BTreeNodeCmp);

/* create a new row in the table */
clnpMediaToNetEntry_t *
clnpMediaToNetTable_createEntry (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len)
{
	clnpMediaToNetEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (clnpMediaToNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IfIndex = i32IfIndex;
	memcpy (poEntry->au8PhysAddress, pau8PhysAddress, u16PhysAddress_len);
	poEntry->u16PhysAddress_len = u16PhysAddress_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpMediaToNetTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oClnpMediaToNetTable_BTree);
	return poEntry;
}

clnpMediaToNetEntry_t *
clnpMediaToNetTable_getByIndex (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len)
{
	register clnpMediaToNetEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpMediaToNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IfIndex = i32IfIndex;
	memcpy (poTmpEntry->au8PhysAddress, pau8PhysAddress, u16PhysAddress_len);
	poTmpEntry->u16PhysAddress_len = u16PhysAddress_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oClnpMediaToNetTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpMediaToNetEntry_t, oBTreeNode);
}

clnpMediaToNetEntry_t *
clnpMediaToNetTable_getNextIndex (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len)
{
	register clnpMediaToNetEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (clnpMediaToNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IfIndex = i32IfIndex;
	memcpy (poTmpEntry->au8PhysAddress, pau8PhysAddress, u16PhysAddress_len);
	poTmpEntry->u16PhysAddress_len = u16PhysAddress_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oClnpMediaToNetTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, clnpMediaToNetEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
clnpMediaToNetTable_removeEntry (clnpMediaToNetEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oClnpMediaToNetTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oClnpMediaToNetTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
clnpMediaToNetTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oClnpMediaToNetTable_BTree);
	return clnpMediaToNetTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
clnpMediaToNetTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpMediaToNetEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, clnpMediaToNetEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8PhysAddress, poEntry->u16PhysAddress_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oClnpMediaToNetTable_BTree);
	return put_index_data;
}

bool
clnpMediaToNetTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	clnpMediaToNetEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = clnpMediaToNetTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* clnpMediaToNetTable table mapper */
int
clnpMediaToNetTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	clnpMediaToNetEntry_t *table_entry;
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
			table_entry = (clnpMediaToNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPMEDIATONETIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IfIndex);
				break;
			case CLNPMEDIATONETADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Address, table_entry->u16Address_len);
				break;
			case CLNPMEDIATONETPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PhysAddress, table_entry->u16PhysAddress_len);
				break;
			case CLNPMEDIATONETTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case CLNPMEDIATONETAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Age);
				break;
			case CLNPMEDIATONETHOLDTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32HoldTime);
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
			table_entry = (clnpMediaToNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPMEDIATONETIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPMEDIATONETADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Address));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPMEDIATONETPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PhysAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPMEDIATONETTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPMEDIATONETAGE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case CLNPMEDIATONETHOLDTIME:
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
			table_entry = (clnpMediaToNetEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (clnpMediaToNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case CLNPMEDIATONETIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IfIndex, sizeof (table_entry->i32IfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IfIndex = *request->requestvb->val.integer;
				break;
			case CLNPMEDIATONETADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Address))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Address_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Address, sizeof (table_entry->au8Address));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Address, 0, sizeof (table_entry->au8Address));
				memcpy (table_entry->au8Address, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Address_len = request->requestvb->val_len;
				break;
			case CLNPMEDIATONETPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PhysAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PhysAddress, 0, sizeof (table_entry->au8PhysAddress));
				memcpy (table_entry->au8PhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PhysAddress_len = request->requestvb->val_len;
				break;
			case CLNPMEDIATONETTYPE:
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
			case CLNPMEDIATONETAGE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Age))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Age, sizeof (table_entry->i32Age));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Age = *request->requestvb->val.integer;
				break;
			case CLNPMEDIATONETHOLDTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32HoldTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32HoldTime, sizeof (table_entry->i32HoldTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32HoldTime = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (clnpMediaToNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case CLNPMEDIATONETIFINDEX:
				memcpy (&table_entry->i32IfIndex, pvOldDdata, sizeof (table_entry->i32IfIndex));
				break;
			case CLNPMEDIATONETADDRESS:
				memcpy (table_entry->au8Address, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Address_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPMEDIATONETPHYSADDRESS:
				memcpy (table_entry->au8PhysAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PhysAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case CLNPMEDIATONETTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case CLNPMEDIATONETAGE:
				memcpy (&table_entry->i32Age, pvOldDdata, sizeof (table_entry->i32Age));
				break;
			case CLNPMEDIATONETHOLDTIME:
				memcpy (&table_entry->i32HoldTime, pvOldDdata, sizeof (table_entry->i32HoldTime));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
