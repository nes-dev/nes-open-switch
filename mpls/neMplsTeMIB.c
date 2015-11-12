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
#include "mplsTeStdMIB.h"
#include "neMplsTeMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid neMplsTeMIB_oid[] = {1,3,6,1,4,1,36969,64};

static oid neMplsTeScalars_oid[] = {1,3,6,1,4,1,36969,64,1,1};

static oid neMplsTunnelTable_oid[] = {1,3,6,1,4,1,36969,64,1,2};
static oid neMplsTunnelHopTable_oid[] = {1,3,6,1,4,1,36969,64,1,4};
static oid neMplsTunnelARHopTable_oid[] = {1,3,6,1,4,1,36969,64,1,5};
static oid neMplsTunnelCHopTable_oid[] = {1,3,6,1,4,1,36969,64,1,6};
static oid neMplsTunnelPathTable_oid[] = {1,3,6,1,4,1,36969,64,1,7};
static oid neMplsCallTable_oid[] = {1,3,6,1,4,1,36969,64,1,13};
static oid neMplsCallLinkTable_oid[] = {1,3,6,1,4,1,36969,64,1,14};



/**
 *	initialize neMplsTeMIB group mapper
 */
void
neMplsTeMIB_init (void)
{
	extern oid neMplsTeMIB_oid[];
	extern oid neMplsTeScalars_oid[];
	
	DEBUGMSGTL (("neMplsTeMIB", "Initializing\n"));
	
	/* register neMplsTeScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"neMplsTeScalars_mapper", &neMplsTeScalars_mapper,
			neMplsTeScalars_oid, OID_LENGTH (neMplsTeScalars_oid),
			HANDLER_CAN_RWRITE
		),
		NEMPLSTEUNDERLAYENABLE,
		NEMPLSTEHLSPHOPMERGEENABLE
	);
	
	
	/* register neMplsTeMIB group table mappers */
	neMplsTunnelTable_init ();
	neMplsTunnelHopTable_init ();
	neMplsTunnelARHopTable_init ();
	neMplsTunnelCHopTable_init ();
	neMplsTunnelPathTable_init ();
	neMplsCallTable_init ();
	neMplsCallLinkTable_init ();
	
	/* register neMplsTeMIB modules */
	sysORTable_createRegister ("neMplsTeMIB", neMplsTeMIB_oid, OID_LENGTH (neMplsTeMIB_oid));
}


/**
 *	scalar mapper(s)
 */
neMplsTeScalars_t oNeMplsTeScalars;

/** neMplsTeScalars scalar mapper **/
int
neMplsTeScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid neMplsTeScalars_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (neMplsTeScalars_oid)])
			{
			case NEMPLSTEUNDERLAYENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oNeMplsTeScalars.u8UnderlayEnable);
				break;
			case NEMPLSTELOOSEHOPEXPANDENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oNeMplsTeScalars.u8LooseHopExpandEnable);
				break;
			case NEMPLSTESETUPRETRYPERIOD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeMplsTeScalars.u32SetupRetryPeriod);
				break;
			case NEMPLSTESOFTPREEMPTIONPERIOD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeMplsTeScalars.u32SoftPreemptionPeriod);
				break;
			case NEMPLSTEREOPTIMIZATIONPERIOD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeMplsTeScalars.u32ReoptimizationPeriod);
				break;
			case NEMPLSTEFRRPROTECTIONMETHOD:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oNeMplsTeScalars.au8FrrProtectionMethod, oNeMplsTeScalars.u16FrrProtectionMethod_len);
				break;
			case NEMPLSTEFRRREVERTIVEMODE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oNeMplsTeScalars.au8FrrRevertiveMode, oNeMplsTeScalars.u16FrrRevertiveMode_len);
				break;
			case NEMPLSTECRANKBACKMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oNeMplsTeScalars.i32CrankbackMode);
				break;
			case NEMPLSTEREROUTEUPSTREAMHOLDPERIOD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeMplsTeScalars.u32RerouteUpstreamHoldPeriod);
				break;
			case NEMPLSTEHLSPHOPMERGEENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oNeMplsTeScalars.u8HlspHopMergeEnable);
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
			switch (request->requestvb->name[OID_LENGTH (neMplsTeScalars_oid)])
			{
			case NEMPLSTEUNDERLAYENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTELOOSEHOPEXPANDENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTESETUPRETRYPERIOD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTESOFTPREEMPTIONPERIOD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTEREOPTIMIZATIONPERIOD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTEFRRPROTECTIONMETHOD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTEFRRREVERTIVEMODE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTECRANKBACKMODE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTEREROUTEUPSTREAMHOLDPERIOD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEMPLSTEHLSPHOPMERGEENABLE:
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
			switch (request->requestvb->name[OID_LENGTH (neMplsTeScalars_oid)])
			{
			case NEMPLSTEUNDERLAYENABLE:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u8UnderlayEnable = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTELOOSEHOPEXPANDENABLE:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u8LooseHopExpandEnable = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTESETUPRETRYPERIOD:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u32SetupRetryPeriod = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTESOFTPREEMPTIONPERIOD:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u32SoftPreemptionPeriod = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTEREOPTIMIZATIONPERIOD:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u32ReoptimizationPeriod = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTEFRRPROTECTIONMETHOD:
				/* XXX: perform the value change here */
				memset (oNeMplsTeScalars.au8FrrProtectionMethod, 0, sizeof (oNeMplsTeScalars.au8FrrProtectionMethod));
				memcpy (oNeMplsTeScalars.au8FrrProtectionMethod, request->requestvb->val.string, request->requestvb->val_len);
				oNeMplsTeScalars.u16FrrProtectionMethod_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTEFRRREVERTIVEMODE:
				/* XXX: perform the value change here */
				memset (oNeMplsTeScalars.au8FrrRevertiveMode, 0, sizeof (oNeMplsTeScalars.au8FrrRevertiveMode));
				memcpy (oNeMplsTeScalars.au8FrrRevertiveMode, request->requestvb->val.string, request->requestvb->val_len);
				oNeMplsTeScalars.u16FrrRevertiveMode_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTECRANKBACKMODE:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.i32CrankbackMode = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTEREROUTEUPSTREAMHOLDPERIOD:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u32RerouteUpstreamHoldPeriod = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEMPLSTEHLSPHOPMERGEENABLE:
				/* XXX: perform the value change here */
				oNeMplsTeScalars.u8HlspHopMergeEnable = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (neMplsTeScalars_oid)])
			{
			case NEMPLSTEUNDERLAYENABLE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTELOOSEHOPEXPANDENABLE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTESETUPRETRYPERIOD:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTESOFTPREEMPTIONPERIOD:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTEREOPTIMIZATIONPERIOD:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTEFRRPROTECTIONMETHOD:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTEFRRREVERTIVEMODE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTECRANKBACKMODE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTEREROUTEUPSTREAMHOLDPERIOD:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEMPLSTEHLSPHOPMERGEENABLE:
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
/** initialize neMplsTunnelTable table mapper **/
void
neMplsTunnelTable_init (void)
{
	extern oid neMplsTunnelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsTunnelTable", &neMplsTunnelTable_mapper,
		neMplsTunnelTable_oid, OID_LENGTH (neMplsTunnelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = NEMPLSTUNNELCALLID;
	table_info->max_column = NEMPLSTUNNELDIFFSERVTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsTunnelTable_getFirst;
	iinfo->get_next_data_point = &neMplsTunnelTable_getNext;
	iinfo->get_data_point = &neMplsTunnelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neMplsTunnelEntry_t *
neMplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register neMplsTunnelEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oNe;
	
	poEntry->u32ResourceIndex = 0;
	poEntry->u32ReverseResourceIndex = 0;
	xBitmap_setBitsRev (poEntry->au8PathCompModel, 2, 1, neMplsTunnelPathCompModel_bContiguous_c, neMplsTunnelPathCompModel_bNested_c);
	poEntry->u32PeerIfIndex = 0;
	poEntry->i32ReoptimizationEnable = neMplsTunnelReoptimizationEnable_auto_c;
	poEntry->i32DiffServType = neMplsTunnelDiffServType_uniform_c;
	
	return poEntry;
}

neMplsTunnelEntry_t *
neMplsTunnelTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnel->oNe;
}

neMplsTunnelEntry_t *
neMplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getNextIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnel->oNe;
}

/* remove a row from the table */
void
neMplsTunnelTable_removeEntry (neMplsTunnelEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsTunnelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return neMplsTunnelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsTunnelTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Instance);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32IngressLSRId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EgressLSRId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return put_index_data;
}

bool
neMplsTunnelTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = mplsTunnelTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		*idx4->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsTunnelTable table mapper */
int
neMplsTunnelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsTunnelEntry_t *table_entry;
	register mplsTunnelEntry_t *poEntry = NULL;
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCALLID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CallId);
				break;
			case NEMPLSTUNNELTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
				break;
			case NEMPLSTUNNELXCINDEX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8XCIndex, table_entry->u16XCIndex_len);
				break;
			case NEMPLSTUNNELRESOURCEINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ResourceIndex);
				break;
			case NEMPLSTUNNELREVERSERESOURCEINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ReverseResourceIndex);
				break;
			case NEMPLSTUNNELPATHCOMPMODEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PathCompModel, table_entry->u16PathCompModel_len);
				break;
			case NEMPLSTUNNELPEERIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32PeerIfIndex);
				break;
			case NEMPLSTUNNELLASTACTION:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LastAction, table_entry->u16LastAction_len);
				break;
			case NEMPLSTUNNELREOPTIMIZATIONENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ReoptimizationEnable);
				break;
			case NEMPLSTUNNELREOPTIMIZATIONSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ReoptimizationStatus);
				break;
			case NEMPLSTUNNELACTIVEINSTANCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ActiveInstance);
				break;
			case NEMPLSTUNNELSHAREDPARENTINSTANCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SharedParentInstance);
				break;
			case NEMPLSTUNNELPROTECTIONSTATUS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ProtectionStatus, table_entry->u16ProtectionStatus_len);
				break;
			case NEMPLSTUNNELDIFFSERVTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32DiffServType);
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCALLID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELRESOURCEINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELREVERSERESOURCEINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELPATHCOMPMODEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PathCompModel));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELPEERIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELREOPTIMIZATIONENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELDIFFSERVTYPE:
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCALLID:
			case NEMPLSTUNNELRESOURCEINDEX:
			case NEMPLSTUNNELREVERSERESOURCEINDEX:
			case NEMPLSTUNNELPATHCOMPMODEL:
			case NEMPLSTUNNELPEERIFINDEX:
			case NEMPLSTUNNELDIFFSERVTYPE:
				if (poEntry->u8RowStatus == xRowStatus_active_c || poEntry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCALLID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CallId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CallId, sizeof (table_entry->u32CallId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CallId = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELRESOURCEINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ResourceIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ResourceIndex, sizeof (table_entry->u32ResourceIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ResourceIndex = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELREVERSERESOURCEINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ReverseResourceIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ReverseResourceIndex, sizeof (table_entry->u32ReverseResourceIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ReverseResourceIndex = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELPATHCOMPMODEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PathCompModel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PathCompModel_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PathCompModel, sizeof (table_entry->au8PathCompModel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PathCompModel, 0, sizeof (table_entry->au8PathCompModel));
				memcpy (table_entry->au8PathCompModel, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PathCompModel_len = request->requestvb->val_len;
				break;
			case NEMPLSTUNNELPEERIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PeerIfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PeerIfIndex, sizeof (table_entry->u32PeerIfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PeerIfIndex = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELREOPTIMIZATIONENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ReoptimizationEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ReoptimizationEnable, sizeof (table_entry->i32ReoptimizationEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ReoptimizationEnable = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELDIFFSERVTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32DiffServType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32DiffServType, sizeof (table_entry->i32DiffServType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32DiffServType = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCALLID:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32CallId, pvOldDdata, sizeof (table_entry->u32CallId));
				}
				break;
			case NEMPLSTUNNELRESOURCEINDEX:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32ResourceIndex, pvOldDdata, sizeof (table_entry->u32ResourceIndex));
				}
				break;
			case NEMPLSTUNNELREVERSERESOURCEINDEX:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32ReverseResourceIndex, pvOldDdata, sizeof (table_entry->u32ReverseResourceIndex));
				}
				break;
			case NEMPLSTUNNELPATHCOMPMODEL:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8PathCompModel, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16PathCompModel_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEMPLSTUNNELPEERIFINDEX:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32PeerIfIndex, pvOldDdata, sizeof (table_entry->u32PeerIfIndex));
				}
				break;
			case NEMPLSTUNNELREOPTIMIZATIONENABLE:
				memcpy (&table_entry->i32ReoptimizationEnable, pvOldDdata, sizeof (table_entry->i32ReoptimizationEnable));
				break;
			case NEMPLSTUNNELDIFFSERVTYPE:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32DiffServType, pvOldDdata, sizeof (table_entry->i32DiffServType));
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

/** initialize neMplsTunnelHopTable table mapper **/
void
neMplsTunnelHopTable_init (void)
{
	extern oid neMplsTunnelHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsTunnelHopTable", &neMplsTunnelHopTable_mapper,
		neMplsTunnelHopTable_oid, OID_LENGTH (neMplsTunnelHopTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopPathOptionIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopIndex */,
		0);
	table_info->min_column = NEMPLSTUNNELHOPNODEID;
	table_info->max_column = NEMPLSTUNNELHOPREVERSELABEL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsTunnelHopTable_getFirst;
	iinfo->get_next_data_point = &neMplsTunnelHopTable_getNext;
	iinfo->get_data_point = &neMplsTunnelHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neMplsTunnelHopEntry_t *
neMplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register neMplsTunnelHopEntry_t *poEntry = NULL;
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getByIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnelHop->oNe;
	
	return poEntry;
}

neMplsTunnelHopEntry_t *
neMplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getByIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelHop->oNe;
}

neMplsTunnelHopEntry_t *
neMplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getNextIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelHop->oNe;
}

/* remove a row from the table */
void
neMplsTunnelHopTable_removeEntry (neMplsTunnelHopEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsTunnelHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelHopTable_BTree);
	return neMplsTunnelHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsTunnelHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PathOptionIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree);
	return put_index_data;
}

bool
neMplsTunnelHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = mplsTunnelHopTable_getByIndex (
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

/* neMplsTunnelHopTable table mapper */
int
neMplsTunnelHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsTunnelHopEntry_t *table_entry;
	register mplsTunnelHopEntry_t *poEntry = NULL;
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
			poEntry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELHOPNODEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NodeId);
				break;
			case NEMPLSTUNNELHOPLINKID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LinkId);
				break;
			case NEMPLSTUNNELHOPLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSTUNNELHOPFORWARDLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForwardLabel, table_entry->u16ForwardLabel_len);
				break;
			case NEMPLSTUNNELHOPREVERSELABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ReverseLabel, table_entry->u16ReverseLabel_len);
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
			poEntry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELHOPNODEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELHOPLINKID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELHOPLABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELHOPFORWARDLABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ForwardLabel));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELHOPREVERSELABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ReverseLabel));
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
			poEntry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELHOPNODEID:
			case NEMPLSTUNNELHOPLINKID:
			case NEMPLSTUNNELHOPLABELTYPE:
			case NEMPLSTUNNELHOPFORWARDLABEL:
			case NEMPLSTUNNELHOPREVERSELABEL:
				if (poEntry->u8RowStatus == xRowStatus_active_c || poEntry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELHOPNODEID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32NodeId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32NodeId, sizeof (table_entry->u32NodeId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32NodeId = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELHOPLINKID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LinkId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LinkId, sizeof (table_entry->u32LinkId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LinkId = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELHOPLABELTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LabelType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LabelType, sizeof (table_entry->i32LabelType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LabelType = *request->requestvb->val.integer;
				break;
			case NEMPLSTUNNELHOPFORWARDLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ForwardLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForwardLabel_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ForwardLabel, sizeof (table_entry->au8ForwardLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ForwardLabel, 0, sizeof (table_entry->au8ForwardLabel));
				memcpy (table_entry->au8ForwardLabel, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForwardLabel_len = request->requestvb->val_len;
				break;
			case NEMPLSTUNNELHOPREVERSELABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ReverseLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ReverseLabel_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ReverseLabel, sizeof (table_entry->au8ReverseLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ReverseLabel, 0, sizeof (table_entry->au8ReverseLabel));
				memcpy (table_entry->au8ReverseLabel, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ReverseLabel_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELHOPNODEID:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32NodeId, pvOldDdata, sizeof (table_entry->u32NodeId));
				}
				break;
			case NEMPLSTUNNELHOPLINKID:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32LinkId, pvOldDdata, sizeof (table_entry->u32LinkId));
				}
				break;
			case NEMPLSTUNNELHOPLABELTYPE:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32LabelType, pvOldDdata, sizeof (table_entry->i32LabelType));
				}
				break;
			case NEMPLSTUNNELHOPFORWARDLABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8ForwardLabel, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16ForwardLabel_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEMPLSTUNNELHOPREVERSELABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8ReverseLabel, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16ReverseLabel_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize neMplsTunnelARHopTable table mapper **/
void
neMplsTunnelARHopTable_init (void)
{
	extern oid neMplsTunnelARHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsTunnelARHopTable", &neMplsTunnelARHopTable_mapper,
		neMplsTunnelARHopTable_oid, OID_LENGTH (neMplsTunnelARHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelARHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelARHopIndex */,
		0);
	table_info->min_column = NEMPLSTUNNELARHOPNODEID;
	table_info->max_column = NEMPLSTUNNELARHOPREVERSELABEL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsTunnelARHopTable_getFirst;
	iinfo->get_next_data_point = &neMplsTunnelARHopTable_getNext;
	iinfo->get_data_point = &neMplsTunnelARHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsTunnelARHopTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsTunnelARHopEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsTunnelARHopEntry_t, oBTreeNode);
	register neMplsTunnelARHopEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsTunnelARHopEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ListIndex < pEntry2->u32ListIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeMplsTunnelARHopTable_BTree = xBTree_initInline (&neMplsTunnelARHopTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsTunnelARHopEntry_t *
neMplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register neMplsTunnelARHopEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ListIndex = u32ListIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree);
	return poEntry;
}

neMplsTunnelARHopEntry_t *
neMplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register neMplsTunnelARHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsTunnelARHopEntry_t, oBTreeNode);
}

neMplsTunnelARHopEntry_t *
neMplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register neMplsTunnelARHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsTunnelARHopEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsTunnelARHopTable_removeEntry (neMplsTunnelARHopEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsTunnelARHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsTunnelARHopTable_BTree);
	return neMplsTunnelARHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsTunnelARHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsTunnelARHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsTunnelARHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsTunnelARHopTable_BTree);
	return put_index_data;
}

bool
neMplsTunnelARHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsTunnelARHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neMplsTunnelARHopTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsTunnelARHopTable table mapper */
int
neMplsTunnelARHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsTunnelARHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsTunnelARHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELARHOPNODEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NodeId);
				break;
			case NEMPLSTUNNELARHOPLINKID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LinkId);
				break;
			case NEMPLSTUNNELARHOPLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSTUNNELARHOPFORWARDLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForwardLabel, table_entry->u16ForwardLabel_len);
				break;
			case NEMPLSTUNNELARHOPREVERSELABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ReverseLabel, table_entry->u16ReverseLabel_len);
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

/** initialize neMplsTunnelCHopTable table mapper **/
void
neMplsTunnelCHopTable_init (void)
{
	extern oid neMplsTunnelCHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsTunnelCHopTable", &neMplsTunnelCHopTable_mapper,
		neMplsTunnelCHopTable_oid, OID_LENGTH (neMplsTunnelCHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelCHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelCHopIndex */,
		0);
	table_info->min_column = NEMPLSTUNNELCHOPLABELTYPE;
	table_info->max_column = NEMPLSTUNNELCHOPREVERSELABEL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsTunnelCHopTable_getFirst;
	iinfo->get_next_data_point = &neMplsTunnelCHopTable_getNext;
	iinfo->get_data_point = &neMplsTunnelCHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neMplsTunnelCHopEntry_t *
neMplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register neMplsTunnelCHopEntry_t *poEntry = NULL;
	register mplsTunnelCHopEntry_t *poTunnelCHop = NULL;
	
	if ((poTunnelCHop = mplsTunnelCHopTable_getByIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnelCHop->oNe;
	
	return poEntry;
}

neMplsTunnelCHopEntry_t *
neMplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelCHopEntry_t *poTunnelCHop = NULL;
	
	if ((poTunnelCHop = mplsTunnelCHopTable_getByIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelCHop->oNe;
}

neMplsTunnelCHopEntry_t *
neMplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelCHopEntry_t *poTunnelCHop = NULL;
	
	if ((poTunnelCHop = mplsTunnelCHopTable_getNextIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelCHop->oNe;
}

/* remove a row from the table */
void
neMplsTunnelCHopTable_removeEntry (neMplsTunnelCHopEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsTunnelCHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelCHopTable_BTree);
	return neMplsTunnelCHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsTunnelCHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelCHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelCHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) &poEntry->oNe;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree);
	return put_index_data;
}

bool
neMplsTunnelCHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelCHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mplsTunnelCHopTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) &poEntry->oNe;
	return true;
}

/* neMplsTunnelCHopTable table mapper */
int
neMplsTunnelCHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsTunnelCHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsTunnelCHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELCHOPLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSTUNNELCHOPFORWARDLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForwardLabel, table_entry->u16ForwardLabel_len);
				break;
			case NEMPLSTUNNELCHOPREVERSELABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ReverseLabel, table_entry->u16ReverseLabel_len);
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

/** initialize neMplsTunnelPathTable table mapper **/
void
neMplsTunnelPathTable_init (void)
{
	extern oid neMplsTunnelPathTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsTunnelPathTable", &neMplsTunnelPathTable_mapper,
		neMplsTunnelPathTable_oid, OID_LENGTH (neMplsTunnelPathTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		ASN_UNSIGNED /* index: neMplsTunnelPathOptionIndex */,
		0);
	table_info->min_column = NEMPLSTUNNELPATHTYPE;
	table_info->max_column = NEMPLSTUNNELPATHSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsTunnelPathTable_getFirst;
	iinfo->get_next_data_point = &neMplsTunnelPathTable_getNext;
	iinfo->get_data_point = &neMplsTunnelPathTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsTunnelPathTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsTunnelPathEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsTunnelPathEntry_t, oBTreeNode);
	register neMplsTunnelPathEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsTunnelPathEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance < pEntry2->u32Instance) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId < pEntry2->u32IngressLSRId) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId == pEntry2->u32IngressLSRId && pEntry1->u32EgressLSRId < pEntry2->u32EgressLSRId) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId == pEntry2->u32IngressLSRId && pEntry1->u32EgressLSRId == pEntry2->u32EgressLSRId && pEntry1->u32OptionIndex < pEntry2->u32OptionIndex) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId == pEntry2->u32IngressLSRId && pEntry1->u32EgressLSRId == pEntry2->u32EgressLSRId && pEntry1->u32OptionIndex == pEntry2->u32OptionIndex) ? 0: 1;
}

xBTree_t oNeMplsTunnelPathTable_BTree = xBTree_initInline (&neMplsTunnelPathTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsTunnelPathEntry_t *
neMplsTunnelPathTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex)
{
	register neMplsTunnelPathEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->u32Instance = u32Instance;
	poEntry->u32IngressLSRId = u32IngressLSRId;
	poEntry->u32EgressLSRId = u32EgressLSRId;
	poEntry->u32OptionIndex = u32OptionIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree);
	return poEntry;
}

neMplsTunnelPathEntry_t *
neMplsTunnelPathTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex)
{
	register neMplsTunnelPathEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Instance = u32Instance;
	poTmpEntry->u32IngressLSRId = u32IngressLSRId;
	poTmpEntry->u32EgressLSRId = u32EgressLSRId;
	poTmpEntry->u32OptionIndex = u32OptionIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsTunnelPathEntry_t, oBTreeNode);
}

neMplsTunnelPathEntry_t *
neMplsTunnelPathTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex)
{
	register neMplsTunnelPathEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Instance = u32Instance;
	poTmpEntry->u32IngressLSRId = u32IngressLSRId;
	poTmpEntry->u32EgressLSRId = u32EgressLSRId;
	poTmpEntry->u32OptionIndex = u32OptionIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsTunnelPathEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsTunnelPathTable_removeEntry (neMplsTunnelPathEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsTunnelPathTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsTunnelPathTable_BTree);
	return neMplsTunnelPathTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsTunnelPathTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsTunnelPathEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsTunnelPathEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Instance);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32IngressLSRId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EgressLSRId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32OptionIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsTunnelPathTable_BTree);
	return put_index_data;
}

bool
neMplsTunnelPathTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsTunnelPathEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = neMplsTunnelPathTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		*idx4->val.integer,
		*idx5->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsTunnelPathTable table mapper */
int
neMplsTunnelPathTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsTunnelPathEntry_t *table_entry;
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case NEMPLSTUNNELPATHROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEMPLSTUNNELPATHSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELPATHROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSTUNNELPATHSTORAGETYPE:
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			register netsnmp_variable_list *idx5 = idx4->next_variable;
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsTunnelPathTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						*idx3->val.integer,
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsTunnelPathTable_removeEntry (table_entry);
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHTYPE:
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
			case NEMPLSTUNNELPATHSTORAGETYPE:
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neMplsTunnelPathTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case NEMPLSTUNNELPATHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsTunnelPathTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEMPLSTUNNELPATHSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsTunnelPathEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSTUNNELPATHROWSTATUS:
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
					neMplsTunnelPathTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neMplsCallTable table mapper **/
void
neMplsCallTable_init (void)
{
	extern oid neMplsCallTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsCallTable", &neMplsCallTable_mapper,
		neMplsCallTable_oid, OID_LENGTH (neMplsCallTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neMplsCallIngressLsrId */,
		ASN_UNSIGNED /* index: neMplsCallEgressLsrId */,
		ASN_UNSIGNED /* index: neMplsCallId */,
		0);
	table_info->min_column = NEMPLSCALLLONGID;
	table_info->max_column = NEMPLSCALLSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsCallTable_getFirst;
	iinfo->get_next_data_point = &neMplsCallTable_getNext;
	iinfo->get_data_point = &neMplsCallTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsCallTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsCallEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsCallEntry_t, oBTreeNode);
	register neMplsCallEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsCallEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IngressLsrId < pEntry2->u32IngressLsrId) ||
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId < pEntry2->u32EgressLsrId) ||
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId == pEntry2->u32EgressLsrId && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId == pEntry2->u32EgressLsrId && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oNeMplsCallTable_BTree = xBTree_initInline (&neMplsCallTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsCallEntry_t *
neMplsCallTable_createEntry (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id)
{
	register neMplsCallEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IngressLsrId = u32IngressLsrId;
	poEntry->u32EgressLsrId = u32EgressLsrId;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsCallTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsCallTable_BTree);
	return poEntry;
}

neMplsCallEntry_t *
neMplsCallTable_getByIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id)
{
	register neMplsCallEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IngressLsrId = u32IngressLsrId;
	poTmpEntry->u32EgressLsrId = u32EgressLsrId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsCallTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsCallEntry_t, oBTreeNode);
}

neMplsCallEntry_t *
neMplsCallTable_getNextIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id)
{
	register neMplsCallEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IngressLsrId = u32IngressLsrId;
	poTmpEntry->u32EgressLsrId = u32EgressLsrId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsCallTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsCallEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsCallTable_removeEntry (neMplsCallEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsCallTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsCallTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsCallTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsCallTable_BTree);
	return neMplsCallTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsCallTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsCallEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsCallEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32IngressLsrId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EgressLsrId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsCallTable_BTree);
	return put_index_data;
}

bool
neMplsCallTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsCallEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = neMplsCallTable_getByIndex (
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

/* neMplsCallTable table mapper */
int
neMplsCallTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsCallEntry_t *table_entry;
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLONGID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LongId, table_entry->u16LongId_len);
				break;
			case NEMPLSCALLROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEMPLSCALLSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLONGID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LongId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLSTORAGETYPE:
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsCallTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsCallTable_removeEntry (table_entry);
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLONGID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LongId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LongId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LongId, sizeof (table_entry->au8LongId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LongId, 0, sizeof (table_entry->au8LongId));
				memcpy (table_entry->au8LongId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LongId_len = request->requestvb->val_len;
				break;
			case NEMPLSCALLSTORAGETYPE:
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neMplsCallTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLONGID:
				memcpy (table_entry->au8LongId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LongId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEMPLSCALLROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsCallTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEMPLSCALLSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsCallEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLROWSTATUS:
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
					neMplsCallTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neMplsCallLinkTable table mapper **/
void
neMplsCallLinkTable_init (void)
{
	extern oid neMplsCallLinkTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsCallLinkTable", &neMplsCallLinkTable_mapper,
		neMplsCallLinkTable_oid, OID_LENGTH (neMplsCallLinkTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neMplsCallIngressLsrId */,
		ASN_UNSIGNED /* index: neMplsCallEgressLsrId */,
		ASN_UNSIGNED /* index: neMplsCallId */,
		ASN_UNSIGNED /* index: neMplsCallLinkIndex */,
		0);
	table_info->min_column = NEMPLSCALLLINKTYPE;
	table_info->max_column = NEMPLSCALLLINKSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsCallLinkTable_getFirst;
	iinfo->get_next_data_point = &neMplsCallLinkTable_getNext;
	iinfo->get_data_point = &neMplsCallLinkTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsCallLinkTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsCallLinkEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsCallLinkEntry_t, oBTreeNode);
	register neMplsCallLinkEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsCallLinkEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IngressLsrId < pEntry2->u32IngressLsrId) ||
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId < pEntry2->u32EgressLsrId) ||
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId == pEntry2->u32EgressLsrId && pEntry1->u32Id < pEntry2->u32Id) ||
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId == pEntry2->u32EgressLsrId && pEntry1->u32Id == pEntry2->u32Id && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32IngressLsrId == pEntry2->u32IngressLsrId && pEntry1->u32EgressLsrId == pEntry2->u32EgressLsrId && pEntry1->u32Id == pEntry2->u32Id && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeMplsCallLinkTable_BTree = xBTree_initInline (&neMplsCallLinkTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsCallLinkEntry_t *
neMplsCallLinkTable_createEntry (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index)
{
	register neMplsCallLinkEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IngressLsrId = u32IngressLsrId;
	poEntry->u32EgressLsrId = u32EgressLsrId;
	poEntry->u32Id = u32Id;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree);
	return poEntry;
}

neMplsCallLinkEntry_t *
neMplsCallLinkTable_getByIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index)
{
	register neMplsCallLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IngressLsrId = u32IngressLsrId;
	poTmpEntry->u32EgressLsrId = u32EgressLsrId;
	poTmpEntry->u32Id = u32Id;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsCallLinkEntry_t, oBTreeNode);
}

neMplsCallLinkEntry_t *
neMplsCallLinkTable_getNextIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index)
{
	register neMplsCallLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IngressLsrId = u32IngressLsrId;
	poTmpEntry->u32EgressLsrId = u32EgressLsrId;
	poTmpEntry->u32Id = u32Id;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsCallLinkEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsCallLinkTable_removeEntry (neMplsCallLinkEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsCallLinkTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsCallLinkTable_BTree);
	return neMplsCallLinkTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsCallLinkTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsCallLinkEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsCallLinkEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32IngressLsrId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EgressLsrId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsCallLinkTable_BTree);
	return put_index_data;
}

bool
neMplsCallLinkTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsCallLinkEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = neMplsCallLinkTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		*idx4->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsCallLinkTable table mapper */
int
neMplsCallLinkTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsCallLinkEntry_t *table_entry;
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case NEMPLSCALLLINKADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Address, table_entry->u16Address_len);
				break;
			case NEMPLSCALLLINKADDRESSUNNUMBERED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32AddressUnnumbered);
				break;
			case NEMPLSCALLLINKRESERVABLEBANDWIDTH:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ReservableBandwidth, table_entry->u16ReservableBandwidth_len);
				break;
			case NEMPLSCALLLINKROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEMPLSCALLLINKSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLLINKADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Address));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLLINKADDRESSUNNUMBERED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLLINKRESERVABLEBANDWIDTH:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ReservableBandwidth));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLLINKROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSCALLLINKSTORAGETYPE:
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsCallLinkTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsCallLinkTable_removeEntry (table_entry);
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKTYPE:
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
			case NEMPLSCALLLINKADDRESS:
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
			case NEMPLSCALLLINKADDRESSUNNUMBERED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32AddressUnnumbered))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32AddressUnnumbered, sizeof (table_entry->u32AddressUnnumbered));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32AddressUnnumbered = *request->requestvb->val.integer;
				break;
			case NEMPLSCALLLINKRESERVABLEBANDWIDTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ReservableBandwidth))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ReservableBandwidth_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ReservableBandwidth, sizeof (table_entry->au8ReservableBandwidth));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ReservableBandwidth, 0, sizeof (table_entry->au8ReservableBandwidth));
				memcpy (table_entry->au8ReservableBandwidth, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ReservableBandwidth_len = request->requestvb->val_len;
				break;
			case NEMPLSCALLLINKSTORAGETYPE:
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neMplsCallLinkTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case NEMPLSCALLLINKADDRESS:
				memcpy (table_entry->au8Address, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Address_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEMPLSCALLLINKADDRESSUNNUMBERED:
				memcpy (&table_entry->u32AddressUnnumbered, pvOldDdata, sizeof (table_entry->u32AddressUnnumbered));
				break;
			case NEMPLSCALLLINKRESERVABLEBANDWIDTH:
				memcpy (table_entry->au8ReservableBandwidth, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ReservableBandwidth_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEMPLSCALLLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsCallLinkTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEMPLSCALLLINKSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsCallLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSCALLLINKROWSTATUS:
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
					neMplsCallLinkTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
