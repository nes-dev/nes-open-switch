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

#define SNMP_SRC

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "mplsTeStdMIB.h"
#include "mplsTeExtStdMIB.h"
#include "neMplsTeMIB.h"
#include "ted/neTedMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mplsTeStdMIB_oid[] = {1,3,6,1,2,1,10,166,3};
static oid gmplsTeStdMIB_oid[] = {1,3,6,1,2,1,10,166,13};

static oid mplsTeScalars_oid[] = {1,3,6,1,2,1,10,166,3,1};
static oid mplsTeObjects_oid[] = {1,3,6,1,2,1,10,166,3,2};
static oid gmplsTeScalars_oid[] = {1,3,6,1,2,1,10,166,13,1};

static oid mplsTunnelTable_oid[] = {1,3,6,1,2,1,10,166,3,2,2};
static oid mplsTunnelHopTable_oid[] = {1,3,6,1,2,1,10,166,3,2,4};
static oid mplsTunnelResourceTable_oid[] = {1,3,6,1,2,1,10,166,3,2,6};
static oid mplsTunnelARHopTable_oid[] = {1,3,6,1,2,1,10,166,3,2,7};
static oid mplsTunnelCHopTable_oid[] = {1,3,6,1,2,1,10,166,3,2,8};
static oid mplsTunnelPerfTable_oid[] = {1,3,6,1,2,1,10,166,3,2,9};
static oid gmplsTunnelTable_oid[] = {1,3,6,1,2,1,10,166,13,2,1};
static oid gmplsTunnelHopTable_oid[] = {1,3,6,1,2,1,10,166,13,2,2};
static oid gmplsTunnelARHopTable_oid[] = {1,3,6,1,2,1,10,166,13,2,3};
static oid gmplsTunnelCHopTable_oid[] = {1,3,6,1,2,1,10,166,13,2,4};
static oid gmplsTunnelReversePerfTable_oid[] = {1,3,6,1,2,1,10,166,13,2,5};
static oid gmplsTunnelErrorTable_oid[] = {1,3,6,1,2,1,10,166,13,2,6};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid mplsTunnelUp_oid[] = {1,3,6,1,2,1,10,166,3,0,1};
static oid mplsTunnelDown_oid[] = {1,3,6,1,2,1,10,166,3,0,2};
static oid mplsTunnelRerouted_oid[] = {1,3,6,1,2,1,10,166,3,0,3};
static oid mplsTunnelReoptimized_oid[] = {1,3,6,1,2,1,10,166,3,0,4};
static oid gmplsTunnelDown_oid[] = {1,3,6,1,2,1,10,166,13,0,1};



/**
 *	initialize mplsTeStdMIB group mapper
 */
void
mplsTeStdMIB_init (void)
{
	extern oid mplsTeStdMIB_oid[];
	extern oid gmplsTeStdMIB_oid[];
	extern oid mplsTeScalars_oid[];
	extern oid mplsTeObjects_oid[];
	extern oid gmplsTeScalars_oid[];
	
	DEBUGMSGTL (("mplsTeStdMIB", "Initializing\n"));
	
	/* register mplsTeScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mplsTeScalars_mapper", &mplsTeScalars_mapper,
			mplsTeScalars_oid, OID_LENGTH (mplsTeScalars_oid),
			HANDLER_CAN_RWRITE
		),
		MPLSTUNNELCONFIGURED,
		MPLSTUNNELNOTIFICATIONMAXRATE
	);
	
	/* register mplsTeObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mplsTeObjects_mapper", &mplsTeObjects_mapper,
			mplsTeObjects_oid, OID_LENGTH (mplsTeObjects_oid),
			HANDLER_CAN_RWRITE
		),
		MPLSTUNNELINDEXNEXT,
		MPLSTUNNELNOTIFICATIONENABLE
	);
	
	/* register gmplsTeScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"gmplsTeScalars_mapper", &gmplsTeScalars_mapper,
			gmplsTeScalars_oid, OID_LENGTH (gmplsTeScalars_oid),
			HANDLER_CAN_RONLY
		),
		GMPLSTUNNELSCONFIGURED,
		GMPLSTUNNELSACTIVE
	);
	
	
	/* register mplsTeStdMIB group table mappers */
	mplsTunnelTable_init ();
	mplsTunnelHopTable_init ();
	mplsTunnelResourceTable_init ();
	mplsTunnelARHopTable_init ();
	mplsTunnelCHopTable_init ();
	mplsTunnelPerfTable_init ();
	gmplsTunnelTable_init ();
	gmplsTunnelHopTable_init ();
	gmplsTunnelARHopTable_init ();
	gmplsTunnelCHopTable_init ();
	gmplsTunnelReversePerfTable_init ();
	gmplsTunnelErrorTable_init ();
	
	/* register mplsTeStdMIB modules */
	sysORTable_createRegister ("mplsTeStdMIB", mplsTeStdMIB_oid, OID_LENGTH (mplsTeStdMIB_oid));
	sysORTable_createRegister ("gmplsTeStdMIB", gmplsTeStdMIB_oid, OID_LENGTH (gmplsTeStdMIB_oid));
}


/**
 *	scalar mapper(s)
 */
mplsTeScalars_t oMplsTeScalars;

/** mplsTeScalars scalar mapper **/
int
mplsTeScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid mplsTeScalars_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mplsTeScalars_oid)])
			{
			case MPLSTUNNELCONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeScalars.u32Configured);
				break;
			case MPLSTUNNELACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeScalars.u32Active);
				break;
			case MPLSTUNNELTEDISTPROTO:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsTeScalars.au8TEDistProto, oMplsTeScalars.u16TEDistProto_len);
				break;
			case MPLSTUNNELMAXHOPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeScalars.u32MaxHops);
				break;
			case MPLSTUNNELNOTIFICATIONMAXRATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeScalars.u32NotificationMaxRate);
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeScalars_oid)])
			{
			case MPLSTUNNELNOTIFICATIONMAXRATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeScalars_oid)])
			{
			case MPLSTUNNELNOTIFICATIONMAXRATE:
				/* XXX: perform the value change here */
				oMplsTeScalars.u32NotificationMaxRate = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeScalars_oid)])
			{
			case MPLSTUNNELNOTIFICATIONMAXRATE:
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

mplsTeObjects_t oMplsTeObjects;

/** mplsTeObjects scalar mapper **/
int
mplsTeObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid mplsTeObjects_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mplsTeObjects_oid)])
			{
			case MPLSTUNNELINDEXNEXT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeObjects.u32IndexNext);
				break;
			case MPLSTUNNELHOPLISTINDEXNEXT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeObjects.u32HopListIndexNext);
				break;
			case MPLSTUNNELRESOURCEINDEXNEXT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeObjects.u32ResourceIndexNext);
				break;
			case MPLSTUNNELNOTIFICATIONENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oMplsTeObjects.u8NotificationEnable);
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeObjects_oid)])
			{
			case MPLSTUNNELNOTIFICATIONENABLE:
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeObjects_oid)])
			{
			case MPLSTUNNELNOTIFICATIONENABLE:
				/* XXX: perform the value change here */
				oMplsTeObjects.u8NotificationEnable = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (mplsTeObjects_oid)])
			{
			case MPLSTUNNELNOTIFICATIONENABLE:
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

gmplsTeScalars_t oGmplsTeScalars;

/** gmplsTeScalars scalar mapper **/
int
gmplsTeScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid gmplsTeScalars_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (gmplsTeScalars_oid)])
			{
			case GMPLSTUNNELSCONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, oGmplsTeScalars.u32Configured);
				break;
			case GMPLSTUNNELSACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, oGmplsTeScalars.u32Active);
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
/** initialize mplsTunnelTable table mapper **/
void
mplsTunnelTable_init (void)
{
	extern oid mplsTunnelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelTable", &mplsTunnelTable_mapper,
		mplsTunnelTable_oid, OID_LENGTH (mplsTunnelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = MPLSTUNNELNAME;
	table_info->max_column = MPLSTUNNELSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelTable_getNext;
	iinfo->get_data_point = &mplsTunnelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTunnelTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelEntry_t, oBTreeNode);
	register mplsTunnelEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance < pEntry2->u32Instance) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId < pEntry2->u32IngressLSRId) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId == pEntry2->u32IngressLSRId && pEntry1->u32EgressLSRId < pEntry2->u32EgressLSRId) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Instance == pEntry2->u32Instance && pEntry1->u32IngressLSRId == pEntry2->u32IngressLSRId && pEntry1->u32EgressLSRId == pEntry2->u32EgressLSRId) ? 0: 1;
}

static int8_t
mplsTunnelTable_XC_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelEntry_t, oXC_BTreeNode);
	register mplsTunnelEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelEntry_t, oXC_BTreeNode);
	
	return
		(xBinCmp (pEntry1->oK.au8XCIndex, pEntry2->oK.au8XCIndex, pEntry1->oK.u16XCIndex_len, pEntry2->oK.u16XCIndex_len) == -1) ? -1:
		(xBinCmp (pEntry1->oK.au8XCIndex, pEntry2->oK.au8XCIndex, pEntry1->oK.u16XCIndex_len, pEntry2->oK.u16XCIndex_len) == 0) ? 0: 1;
}

xBTree_t oMplsTunnelTable_BTree = xBTree_initInline (&mplsTunnelTable_BTreeNodeCmp);
xBTree_t oMplsTunnelTable_XC_BTree = xBTree_initInline (&mplsTunnelTable_XC_BTreeNodeCmp);

/* create a new row in the table */
mplsTunnelEntry_t *
mplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->u32Instance = u32Instance;
	poEntry->u32IngressLSRId = u32IngressLSRId;
	poEntry->u32EgressLSRId = u32EgressLSRId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Name = ""*/;
	/*poEntry->au8Descr = ""*/;
	poEntry->u8IsIf = mplsTunnelIsIf_false_c;
	poEntry->u32IfIndex = 0;
	poEntry->i32Role = mplsTunnelRole_head_c;
	poEntry->i32SignallingProto = mplsTunnelSignallingProto_none_c;
	poEntry->i32SetupPrio = 0;
	poEntry->i32HoldingPrio = 0;
	poEntry->u8LocalProtectInUse = mplsTunnelLocalProtectInUse_false_c;
	poEntry->u32PrimaryInstance = 0;
	poEntry->u32InstancePriority = 0;
	poEntry->u32HopTableIndex = 0;
	poEntry->u32PathInUse = 0;
	poEntry->u32ARHopTableIndex = 0;
	poEntry->u32CHopTableIndex = 0;
	poEntry->u32ExcludeAnyAffinity = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsTunnelStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return poEntry;
}

mplsTunnelEntry_t *
mplsTunnelTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Instance = u32Instance;
	poTmpEntry->u32IngressLSRId = u32IngressLSRId;
	poTmpEntry->u32EgressLSRId = u32EgressLSRId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTunnelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelEntry_t, oBTreeNode);
}

mplsTunnelEntry_t *
mplsTunnelTable_XC_getByIndex (
	uint8_t *pau8XCIndex, size_t u16XCIndex_len)
{
	register mplsTunnelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->oK.au8XCIndex, pau8XCIndex, u16XCIndex_len);
	poTmpEntry->oK.u16XCIndex_len = u16XCIndex_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oXC_BTreeNode, &oMplsTunnelTable_XC_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelEntry_t, oXC_BTreeNode);
}

mplsTunnelEntry_t *
mplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Instance = u32Instance;
	poTmpEntry->u32IngressLSRId = u32IngressLSRId;
	poTmpEntry->u32EgressLSRId = u32EgressLSRId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTunnelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTunnelTable_removeEntry (mplsTunnelEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	xBTree_nodeRemove (&poEntry->oXC_BTreeNode, &oMplsTunnelTable_XC_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

mplsTunnelEntry_t *
mplsTunnelTable_createExt (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	mplsTunnelEntry_t *poEntry = NULL;
	
	if (u32Index == 0 || u32IngressLSRId == 0 || u32EgressLSRId == 0)
	{
		goto mplsTunnelTable_createExt_cleanup;
	}
	
	poEntry = mplsTunnelTable_createEntry (
		u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId);
	if (poEntry == NULL)
	{
		goto mplsTunnelTable_createExt_cleanup;
	}
	
	if (!mplsTunnelTable_createHier (poEntry))
	{
		mplsTunnelTable_removeEntry (poEntry);
		poEntry = NULL;
		goto mplsTunnelTable_createExt_cleanup;
	}
	
mplsTunnelTable_createExt_cleanup:
	
	return poEntry;
}

bool
mplsTunnelTable_removeExt (mplsTunnelEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!mplsTunnelTable_removeHier (poEntry))
	{
		goto mplsTunnelTable_removeExt_cleanup;
	}
	mplsTunnelTable_removeEntry (poEntry);
	bRetCode = true;
	
mplsTunnelTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
mplsTunnelTable_createHier (
	mplsTunnelEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	{
		register mplsTeNodeEntry_t *poNodeHead, *poNodeTail;
		
		if ((poNodeHead = mplsTeNodeTable_getByIndex (poEntry->u32IngressLSRId)) == NULL ||
			(poNodeTail = mplsTeNodeTable_getByIndex (poEntry->u32EgressLSRId)) == NULL)
		{
			goto mplsTunnelTable_createHier_cleanup;
		}
	}
	
	if (mplsTunnelPerfTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	if (mplsTunnelExtTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	if (gmplsTunnelTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	if (gmplsTunnelReversePerfTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	if (gmplsTunnelErrorTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	if (neMplsTunnelTable_createEntry (poEntry->u32Index, poEntry->u32Instance, poEntry->u32IngressLSRId, poEntry->u32EgressLSRId) == NULL)
	{
		goto mplsTunnelTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
mplsTunnelTable_createHier_cleanup:
	
	!bRetCode ? mplsTunnelTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
mplsTunnelTable_removeHier (
	mplsTunnelEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	neMplsTunnelTable_removeEntry (&poEntry->oNe);
	gmplsTunnelErrorTable_removeEntry (&poEntry->oError);
	gmplsTunnelReversePerfTable_removeEntry (&poEntry->oReversePerf);
	gmplsTunnelTable_removeEntry (&poEntry->oG);
	mplsTunnelExtTable_removeEntry (&poEntry->oX);
	mplsTunnelPerfTable_removeEntry (&poEntry->oPerf);
	
	bRetCode = true;
	
// mplsTunnelTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
mplsTunnelRowStatus_handler (
	mplsTunnelEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto mplsTunnelRowStatus_handler_success;
	}
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		/*if (!mplsTunnelRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsTunnelRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		/*if (!mplsTunnelRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsTunnelRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto mplsTunnelRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
	case xRowStatus_destroy_c:
		/*if (!mplsTunnelRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsTunnelRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
mplsTunnelRowStatus_handler_success:
	
	bRetCode = true;
	
mplsTunnelRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return mplsTunnelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelTable_getNext (
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
	*my_data_context = (void*) &poEntry->oReversePerf;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return put_index_data;
}

bool
mplsTunnelTable_get (
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
	
	*my_data_context = (void*) &poEntry->oReversePerf;
	return true;
}

/* mplsTunnelTable table mapper */
int
mplsTunnelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelEntry_t *table_entry;
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case MPLSTUNNELDESCR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Descr, table_entry->u16Descr_len);
				break;
			case MPLSTUNNELISIF:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8IsIf);
				break;
			case MPLSTUNNELIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case MPLSTUNNELOWNER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Owner);
				break;
			case MPLSTUNNELROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case MPLSTUNNELSIGNALLINGPROTO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SignallingProto);
				break;
			case MPLSTUNNELSETUPPRIO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SetupPrio);
				break;
			case MPLSTUNNELHOLDINGPRIO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32HoldingPrio);
				break;
			case MPLSTUNNELSESSIONATTRIBUTES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SessionAttributes, table_entry->u16SessionAttributes_len);
				break;
			case MPLSTUNNELLOCALPROTECTINUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8LocalProtectInUse);
				break;
			case MPLSTUNNELPRIMARYINSTANCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PrimaryInstance);
				break;
			case MPLSTUNNELINSTANCEPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32InstancePriority);
				break;
			case MPLSTUNNELHOPTABLEINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32HopTableIndex);
				break;
			case MPLSTUNNELPATHINUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PathInUse);
				break;
			case MPLSTUNNELARHOPTABLEINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ARHopTableIndex);
				break;
			case MPLSTUNNELCHOPTABLEINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CHopTableIndex);
				break;
			case MPLSTUNNELINCLUDEANYAFFINITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IncludeAnyAffinity);
				break;
			case MPLSTUNNELINCLUDEALLAFFINITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IncludeAllAffinity);
				break;
			case MPLSTUNNELEXCLUDEANYAFFINITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ExcludeAnyAffinity);
				break;
			case MPLSTUNNELTOTALUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32TotalUpTime);
				break;
			case MPLSTUNNELINSTANCEUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32InstanceUpTime);
				break;
			case MPLSTUNNELPRIMARYUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32PrimaryUpTime);
				break;
			case MPLSTUNNELPATHCHANGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PathChanges);
				break;
			case MPLSTUNNELLASTPATHCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastPathChange);
				break;
			case MPLSTUNNELCREATIONTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32CreationTime);
				break;
			case MPLSTUNNELSTATETRANSITIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32StateTransitions);
				break;
			case MPLSTUNNELADMINSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminStatus);
				break;
			case MPLSTUNNELOPERSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperStatus);
				break;
			case MPLSTUNNELROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSTUNNELSTORAGETYPE:
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELDESCR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Descr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELISIF:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELROLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELSIGNALLINGPROTO:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELSETUPPRIO:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOLDINGPRIO:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELSESSIONATTRIBUTES:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SessionAttributes));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELLOCALPROTECTINUSE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELINSTANCEPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPTABLEINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELPATHINUSE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELINCLUDEANYAFFINITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELINCLUDEALLAFFINITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXCLUDEANYAFFINITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELADMINSTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELSTORAGETYPE:
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsTunnelTable_createEntry (
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelTable_removeEntry (table_entry);
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELNAME:
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
			case MPLSTUNNELDESCR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Descr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Descr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Descr, sizeof (table_entry->au8Descr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Descr, 0, sizeof (table_entry->au8Descr));
				memcpy (table_entry->au8Descr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Descr_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELISIF:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8IsIf))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8IsIf, sizeof (table_entry->u8IsIf));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8IsIf = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Role))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Role, sizeof (table_entry->i32Role));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Role = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELSIGNALLINGPROTO:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SignallingProto))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SignallingProto, sizeof (table_entry->i32SignallingProto));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SignallingProto = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELSETUPPRIO:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SetupPrio))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SetupPrio, sizeof (table_entry->i32SetupPrio));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SetupPrio = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOLDINGPRIO:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32HoldingPrio))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32HoldingPrio, sizeof (table_entry->i32HoldingPrio));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32HoldingPrio = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELSESSIONATTRIBUTES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SessionAttributes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SessionAttributes_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SessionAttributes, sizeof (table_entry->au8SessionAttributes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SessionAttributes, 0, sizeof (table_entry->au8SessionAttributes));
				memcpy (table_entry->au8SessionAttributes, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SessionAttributes_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELLOCALPROTECTINUSE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8LocalProtectInUse))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8LocalProtectInUse, sizeof (table_entry->u8LocalProtectInUse));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8LocalProtectInUse = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELINSTANCEPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32InstancePriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32InstancePriority, sizeof (table_entry->u32InstancePriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32InstancePriority = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOPTABLEINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32HopTableIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32HopTableIndex, sizeof (table_entry->u32HopTableIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32HopTableIndex = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELPATHINUSE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PathInUse))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PathInUse, sizeof (table_entry->u32PathInUse));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PathInUse = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELINCLUDEANYAFFINITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IncludeAnyAffinity))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IncludeAnyAffinity, sizeof (table_entry->u32IncludeAnyAffinity));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IncludeAnyAffinity = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELINCLUDEALLAFFINITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IncludeAllAffinity))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IncludeAllAffinity, sizeof (table_entry->u32IncludeAllAffinity));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IncludeAllAffinity = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXCLUDEANYAFFINITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ExcludeAnyAffinity))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ExcludeAnyAffinity, sizeof (table_entry->u32ExcludeAnyAffinity));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ExcludeAnyAffinity = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELADMINSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminStatus, sizeof (table_entry->i32AdminStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminStatus = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELSTORAGETYPE:
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsTunnelTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELDESCR:
				memcpy (table_entry->au8Descr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Descr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELISIF:
				memcpy (&table_entry->u8IsIf, pvOldDdata, sizeof (table_entry->u8IsIf));
				break;
			case MPLSTUNNELROLE:
				memcpy (&table_entry->i32Role, pvOldDdata, sizeof (table_entry->i32Role));
				break;
			case MPLSTUNNELSIGNALLINGPROTO:
				memcpy (&table_entry->i32SignallingProto, pvOldDdata, sizeof (table_entry->i32SignallingProto));
				break;
			case MPLSTUNNELSETUPPRIO:
				memcpy (&table_entry->i32SetupPrio, pvOldDdata, sizeof (table_entry->i32SetupPrio));
				break;
			case MPLSTUNNELHOLDINGPRIO:
				memcpy (&table_entry->i32HoldingPrio, pvOldDdata, sizeof (table_entry->i32HoldingPrio));
				break;
			case MPLSTUNNELSESSIONATTRIBUTES:
				memcpy (table_entry->au8SessionAttributes, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SessionAttributes_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELLOCALPROTECTINUSE:
				memcpy (&table_entry->u8LocalProtectInUse, pvOldDdata, sizeof (table_entry->u8LocalProtectInUse));
				break;
			case MPLSTUNNELINSTANCEPRIORITY:
				memcpy (&table_entry->u32InstancePriority, pvOldDdata, sizeof (table_entry->u32InstancePriority));
				break;
			case MPLSTUNNELHOPTABLEINDEX:
				memcpy (&table_entry->u32HopTableIndex, pvOldDdata, sizeof (table_entry->u32HopTableIndex));
				break;
			case MPLSTUNNELPATHINUSE:
				memcpy (&table_entry->u32PathInUse, pvOldDdata, sizeof (table_entry->u32PathInUse));
				break;
			case MPLSTUNNELINCLUDEANYAFFINITY:
				memcpy (&table_entry->u32IncludeAnyAffinity, pvOldDdata, sizeof (table_entry->u32IncludeAnyAffinity));
				break;
			case MPLSTUNNELINCLUDEALLAFFINITY:
				memcpy (&table_entry->u32IncludeAllAffinity, pvOldDdata, sizeof (table_entry->u32IncludeAllAffinity));
				break;
			case MPLSTUNNELEXCLUDEANYAFFINITY:
				memcpy (&table_entry->u32ExcludeAnyAffinity, pvOldDdata, sizeof (table_entry->u32ExcludeAnyAffinity));
				break;
			case MPLSTUNNELADMINSTATUS:
				memcpy (&table_entry->i32AdminStatus, pvOldDdata, sizeof (table_entry->i32AdminStatus));
				break;
			case MPLSTUNNELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSTUNNELSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELROWSTATUS:
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
					mplsTunnelTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsTunnelHopTable table mapper **/
void
mplsTunnelHopTable_init (void)
{
	extern oid mplsTunnelHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelHopTable", &mplsTunnelHopTable_mapper,
		mplsTunnelHopTable_oid, OID_LENGTH (mplsTunnelHopTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopPathOptionIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopIndex */,
		0);
	table_info->min_column = MPLSTUNNELHOPADDRTYPE;
	table_info->max_column = MPLSTUNNELHOPSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelHopTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelHopTable_getNext;
	iinfo->get_data_point = &mplsTunnelHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTunnelHopTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelHopEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelHopEntry_t, oBTreeNode);
	register mplsTunnelHopEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelHopEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ListIndex < pEntry2->u32ListIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32PathOptionIndex < pEntry2->u32PathOptionIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32PathOptionIndex == pEntry2->u32PathOptionIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32PathOptionIndex == pEntry2->u32PathOptionIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsTunnelHopTable_BTree = xBTree_initInline (&mplsTunnelHopTable_BTreeNodeCmp);

/* create a new row in the table */
mplsTunnelHopEntry_t *
mplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ListIndex = u32ListIndex;
	poEntry->u32PathOptionIndex = u32PathOptionIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AddrType = mplsTunnelHopAddrType_ipv4_c;
	/*poEntry->au8IpAddr = 0*/;
	poEntry->u32IpPrefixLen = 32;
	poEntry->u8Include = mplsTunnelHopInclude_true_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsTunnelHopStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree);
	return poEntry;
}

mplsTunnelHopEntry_t *
mplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32PathOptionIndex = u32PathOptionIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTunnelHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelHopEntry_t, oBTreeNode);
}

mplsTunnelHopEntry_t *
mplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32PathOptionIndex = u32PathOptionIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTunnelHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelHopEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTunnelHopTable_removeEntry (mplsTunnelHopEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelHopTable_BTree);
	return mplsTunnelHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelHopTable_getNext (
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
mplsTunnelHopTable_get (
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

/* mplsTunnelHopTable table mapper */
int
mplsTunnelHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelHopEntry_t *table_entry;
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddrType);
				break;
			case MPLSTUNNELHOPIPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IpAddr, table_entry->u16IpAddr_len);
				break;
			case MPLSTUNNELHOPIPPREFIXLEN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IpPrefixLen);
				break;
			case MPLSTUNNELHOPASNUMBER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AsNumber, table_entry->u16AsNumber_len);
				break;
			case MPLSTUNNELHOPADDRUNNUM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AddrUnnum, table_entry->u16AddrUnnum_len);
				break;
			case MPLSTUNNELHOPLSPID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LspId, table_entry->u16LspId_len);
				break;
			case MPLSTUNNELHOPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case MPLSTUNNELHOPINCLUDE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Include);
				break;
			case MPLSTUNNELHOPPATHOPTIONNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PathOptionName, table_entry->u16PathOptionName_len);
				break;
			case MPLSTUNNELHOPENTRYPATHCOMP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryPathComp);
				break;
			case MPLSTUNNELHOPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSTUNNELHOPSTORAGETYPE:
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPADDRTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPIPADDR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8IpAddr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPIPPREFIXLEN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPASNUMBER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AsNumber));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPADDRUNNUM:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AddrUnnum));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPLSPID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LspId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPINCLUDE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPPATHOPTIONNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PathOptionName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPENTRYPATHCOMP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELHOPSTORAGETYPE:
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsTunnelHopTable_createEntry (
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelHopTable_removeEntry (table_entry);
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPADDRTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AddrType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AddrType, sizeof (table_entry->i32AddrType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AddrType = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOPIPADDR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8IpAddr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16IpAddr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8IpAddr, sizeof (table_entry->au8IpAddr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8IpAddr, 0, sizeof (table_entry->au8IpAddr));
				memcpy (table_entry->au8IpAddr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16IpAddr_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELHOPIPPREFIXLEN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IpPrefixLen))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IpPrefixLen, sizeof (table_entry->u32IpPrefixLen));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IpPrefixLen = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOPASNUMBER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AsNumber))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AsNumber_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AsNumber, sizeof (table_entry->au8AsNumber));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AsNumber, 0, sizeof (table_entry->au8AsNumber));
				memcpy (table_entry->au8AsNumber, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AsNumber_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELHOPADDRUNNUM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AddrUnnum))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AddrUnnum_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AddrUnnum, sizeof (table_entry->au8AddrUnnum));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AddrUnnum, 0, sizeof (table_entry->au8AddrUnnum));
				memcpy (table_entry->au8AddrUnnum, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AddrUnnum_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELHOPLSPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LspId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LspId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LspId, sizeof (table_entry->au8LspId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LspId, 0, sizeof (table_entry->au8LspId));
				memcpy (table_entry->au8LspId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LspId_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELHOPTYPE:
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
			case MPLSTUNNELHOPINCLUDE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8Include))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8Include, sizeof (table_entry->u8Include));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8Include = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOPPATHOPTIONNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PathOptionName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PathOptionName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PathOptionName, sizeof (table_entry->au8PathOptionName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PathOptionName, 0, sizeof (table_entry->au8PathOptionName));
				memcpy (table_entry->au8PathOptionName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PathOptionName_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELHOPENTRYPATHCOMP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EntryPathComp))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EntryPathComp, sizeof (table_entry->i32EntryPathComp));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EntryPathComp = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELHOPSTORAGETYPE:
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsTunnelHopTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPADDRTYPE:
				memcpy (&table_entry->i32AddrType, pvOldDdata, sizeof (table_entry->i32AddrType));
				break;
			case MPLSTUNNELHOPIPADDR:
				memcpy (table_entry->au8IpAddr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16IpAddr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELHOPIPPREFIXLEN:
				memcpy (&table_entry->u32IpPrefixLen, pvOldDdata, sizeof (table_entry->u32IpPrefixLen));
				break;
			case MPLSTUNNELHOPASNUMBER:
				memcpy (table_entry->au8AsNumber, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AsNumber_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELHOPADDRUNNUM:
				memcpy (table_entry->au8AddrUnnum, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AddrUnnum_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELHOPLSPID:
				memcpy (table_entry->au8LspId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LspId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELHOPTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case MPLSTUNNELHOPINCLUDE:
				memcpy (&table_entry->u8Include, pvOldDdata, sizeof (table_entry->u8Include));
				break;
			case MPLSTUNNELHOPPATHOPTIONNAME:
				memcpy (table_entry->au8PathOptionName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PathOptionName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTUNNELHOPENTRYPATHCOMP:
				memcpy (&table_entry->i32EntryPathComp, pvOldDdata, sizeof (table_entry->i32EntryPathComp));
				break;
			case MPLSTUNNELHOPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelHopTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSTUNNELHOPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELHOPROWSTATUS:
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
					mplsTunnelHopTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsTunnelResourceTable table mapper **/
void
mplsTunnelResourceTable_init (void)
{
	extern oid mplsTunnelResourceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelResourceTable", &mplsTunnelResourceTable_mapper,
		mplsTunnelResourceTable_oid, OID_LENGTH (mplsTunnelResourceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelResourceIndex */,
		0);
	table_info->min_column = MPLSTUNNELRESOURCEMAXRATE;
	table_info->max_column = MPLSTUNNELRESOURCESTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelResourceTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelResourceTable_getNext;
	iinfo->get_data_point = &mplsTunnelResourceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTunnelResourceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelResourceEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelResourceEntry_t, oBTreeNode);
	register mplsTunnelResourceEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelResourceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsTunnelResourceTable_BTree = xBTree_initInline (&mplsTunnelResourceTable_BTreeNodeCmp);

/* create a new row in the table */
mplsTunnelResourceEntry_t *
mplsTunnelResourceTable_createEntry (
	uint32_t u32Index)
{
	register mplsTunnelResourceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsTunnelResourceStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree);
	return poEntry;
}

mplsTunnelResourceEntry_t *
mplsTunnelResourceTable_getByIndex (
	uint32_t u32Index)
{
	register mplsTunnelResourceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelResourceEntry_t, oBTreeNode);
}

mplsTunnelResourceEntry_t *
mplsTunnelResourceTable_getNextIndex (
	uint32_t u32Index)
{
	register mplsTunnelResourceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelResourceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTunnelResourceTable_removeEntry (mplsTunnelResourceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelResourceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelResourceTable_BTree);
	return mplsTunnelResourceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelResourceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelResourceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelResourceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelResourceTable_BTree);
	return put_index_data;
}

bool
mplsTunnelResourceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelResourceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsTunnelResourceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsTunnelResourceTable table mapper */
int
mplsTunnelResourceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelResourceEntry_t *table_entry;
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEMAXRATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxRate);
				break;
			case MPLSTUNNELRESOURCEMEANRATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MeanRate);
				break;
			case MPLSTUNNELRESOURCEMAXBURSTSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxBurstSize);
				break;
			case MPLSTUNNELRESOURCEMEANBURSTSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MeanBurstSize);
				break;
			case MPLSTUNNELRESOURCEEXBURSTSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ExBurstSize);
				break;
			case MPLSTUNNELRESOURCEFREQUENCY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Frequency);
				break;
			case MPLSTUNNELRESOURCEWEIGHT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Weight);
				break;
			case MPLSTUNNELRESOURCEROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSTUNNELRESOURCESTORAGETYPE:
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEMAXRATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEMEANRATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEMAXBURSTSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEMEANBURSTSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEEXBURSTSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEFREQUENCY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEWEIGHT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCEROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELRESOURCESTORAGETYPE:
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsTunnelResourceTable_createEntry (
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelResourceTable_removeEntry (table_entry);
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEMAXRATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MaxRate))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MaxRate, sizeof (table_entry->u32MaxRate));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MaxRate = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEMEANRATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MeanRate))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MeanRate, sizeof (table_entry->u32MeanRate));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MeanRate = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEMAXBURSTSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MaxBurstSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MaxBurstSize, sizeof (table_entry->u32MaxBurstSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MaxBurstSize = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEMEANBURSTSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MeanBurstSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MeanBurstSize, sizeof (table_entry->u32MeanBurstSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MeanBurstSize = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEEXBURSTSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ExBurstSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ExBurstSize, sizeof (table_entry->u32ExBurstSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ExBurstSize = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEFREQUENCY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Frequency))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Frequency, sizeof (table_entry->i32Frequency));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Frequency = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCEWEIGHT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Weight))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Weight, sizeof (table_entry->u32Weight));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Weight = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELRESOURCESTORAGETYPE:
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsTunnelResourceTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEMAXRATE:
				memcpy (&table_entry->u32MaxRate, pvOldDdata, sizeof (table_entry->u32MaxRate));
				break;
			case MPLSTUNNELRESOURCEMEANRATE:
				memcpy (&table_entry->u32MeanRate, pvOldDdata, sizeof (table_entry->u32MeanRate));
				break;
			case MPLSTUNNELRESOURCEMAXBURSTSIZE:
				memcpy (&table_entry->u32MaxBurstSize, pvOldDdata, sizeof (table_entry->u32MaxBurstSize));
				break;
			case MPLSTUNNELRESOURCEMEANBURSTSIZE:
				memcpy (&table_entry->u32MeanBurstSize, pvOldDdata, sizeof (table_entry->u32MeanBurstSize));
				break;
			case MPLSTUNNELRESOURCEEXBURSTSIZE:
				memcpy (&table_entry->u32ExBurstSize, pvOldDdata, sizeof (table_entry->u32ExBurstSize));
				break;
			case MPLSTUNNELRESOURCEFREQUENCY:
				memcpy (&table_entry->i32Frequency, pvOldDdata, sizeof (table_entry->i32Frequency));
				break;
			case MPLSTUNNELRESOURCEWEIGHT:
				memcpy (&table_entry->u32Weight, pvOldDdata, sizeof (table_entry->u32Weight));
				break;
			case MPLSTUNNELRESOURCEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTunnelResourceTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSTUNNELRESOURCESTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelResourceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELRESOURCEROWSTATUS:
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
					mplsTunnelResourceTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsTunnelARHopTable table mapper **/
void
mplsTunnelARHopTable_init (void)
{
	extern oid mplsTunnelARHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelARHopTable", &mplsTunnelARHopTable_mapper,
		mplsTunnelARHopTable_oid, OID_LENGTH (mplsTunnelARHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelARHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelARHopIndex */,
		0);
	table_info->min_column = MPLSTUNNELARHOPADDRTYPE;
	table_info->max_column = MPLSTUNNELARHOPLSPID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelARHopTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelARHopTable_getNext;
	iinfo->get_data_point = &mplsTunnelARHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTunnelARHopTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelARHopEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelARHopEntry_t, oBTreeNode);
	register mplsTunnelARHopEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelARHopEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ListIndex < pEntry2->u32ListIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsTunnelARHopTable_BTree = xBTree_initInline (&mplsTunnelARHopTable_BTreeNodeCmp);

/* create a new row in the table */
mplsTunnelARHopEntry_t *
mplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelARHopEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ListIndex = u32ListIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AddrType = mplsTunnelARHopAddrType_ipv4_c;
	/*poEntry->au8IpAddr = 0*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree);
	return poEntry;
}

mplsTunnelARHopEntry_t *
mplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelARHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelARHopEntry_t, oBTreeNode);
}

mplsTunnelARHopEntry_t *
mplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelARHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelARHopEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTunnelARHopTable_removeEntry (mplsTunnelARHopEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelARHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelARHopTable_BTree);
	return mplsTunnelARHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelARHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelARHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelARHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree);
	return put_index_data;
}

bool
mplsTunnelARHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelARHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mplsTunnelARHopTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsTunnelARHopTable table mapper */
int
mplsTunnelARHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelARHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelARHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELARHOPADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddrType);
				break;
			case MPLSTUNNELARHOPIPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IpAddr, table_entry->u16IpAddr_len);
				break;
			case MPLSTUNNELARHOPADDRUNNUM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AddrUnnum, table_entry->u16AddrUnnum_len);
				break;
			case MPLSTUNNELARHOPLSPID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LspId, table_entry->u16LspId_len);
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

/** initialize mplsTunnelCHopTable table mapper **/
void
mplsTunnelCHopTable_init (void)
{
	extern oid mplsTunnelCHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelCHopTable", &mplsTunnelCHopTable_mapper,
		mplsTunnelCHopTable_oid, OID_LENGTH (mplsTunnelCHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelCHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelCHopIndex */,
		0);
	table_info->min_column = MPLSTUNNELCHOPADDRTYPE;
	table_info->max_column = MPLSTUNNELCHOPTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelCHopTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelCHopTable_getNext;
	iinfo->get_data_point = &mplsTunnelCHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTunnelCHopTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTunnelCHopEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTunnelCHopEntry_t, oBTreeNode);
	register mplsTunnelCHopEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTunnelCHopEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ListIndex < pEntry2->u32ListIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsTunnelCHopTable_BTree = xBTree_initInline (&mplsTunnelCHopTable_BTreeNodeCmp);

/* create a new row in the table */
mplsTunnelCHopEntry_t *
mplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelCHopEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ListIndex = u32ListIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AddrType = mplsTunnelCHopAddrType_ipv4_c;
	/*poEntry->au8IpAddr = 0*/;
	poEntry->u32IpPrefixLen = 32;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree);
	return poEntry;
}

mplsTunnelCHopEntry_t *
mplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelCHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelCHopEntry_t, oBTreeNode);
}

mplsTunnelCHopEntry_t *
mplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelCHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTunnelCHopEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTunnelCHopTable_removeEntry (mplsTunnelCHopEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelCHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelCHopTable_BTree);
	return mplsTunnelCHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelCHopTable_getNext (
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
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelCHopTable_BTree);
	return put_index_data;
}

bool
mplsTunnelCHopTable_get (
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
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsTunnelCHopTable table mapper */
int
mplsTunnelCHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelCHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelCHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELCHOPADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddrType);
				break;
			case MPLSTUNNELCHOPIPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IpAddr, table_entry->u16IpAddr_len);
				break;
			case MPLSTUNNELCHOPIPPREFIXLEN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IpPrefixLen);
				break;
			case MPLSTUNNELCHOPASNUMBER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AsNumber, table_entry->u16AsNumber_len);
				break;
			case MPLSTUNNELCHOPADDRUNNUM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AddrUnnum, table_entry->u16AddrUnnum_len);
				break;
			case MPLSTUNNELCHOPLSPID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LspId, table_entry->u16LspId_len);
				break;
			case MPLSTUNNELCHOPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
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

/** initialize mplsTunnelPerfTable table mapper **/
void
mplsTunnelPerfTable_init (void)
{
	extern oid mplsTunnelPerfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelPerfTable", &mplsTunnelPerfTable_mapper,
		mplsTunnelPerfTable_oid, OID_LENGTH (mplsTunnelPerfTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = MPLSTUNNELPERFPACKETS;
	table_info->max_column = MPLSTUNNELPERFHCBYTES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelPerfTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelPerfTable_getNext;
	iinfo->get_data_point = &mplsTunnelPerfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
mplsTunnelPerfEntry_t *
mplsTunnelPerfTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelPerfEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oPerf;
	
	return poEntry;
}

mplsTunnelPerfEntry_t *
mplsTunnelPerfTable_getByIndex (
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
	
	return &poTunnel->oPerf;
}

mplsTunnelPerfEntry_t *
mplsTunnelPerfTable_getNextIndex (
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
	
	return &poTunnel->oPerf;
}

/* remove a row from the table */
void
mplsTunnelPerfTable_removeEntry (mplsTunnelPerfEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelPerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return mplsTunnelPerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelPerfTable_getNext (
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
	*my_data_context = (void*) &poEntry->oPerf;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return put_index_data;
}

bool
mplsTunnelPerfTable_get (
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
	
	*my_data_context = (void*) &poEntry->oPerf;
	return true;
}

/* mplsTunnelPerfTable table mapper */
int
mplsTunnelPerfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelPerfEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsTunnelPerfEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELPERFPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Packets);
				break;
			case MPLSTUNNELPERFHCPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCPackets);
				break;
			case MPLSTUNNELPERFERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Errors);
				break;
			case MPLSTUNNELPERFBYTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Bytes);
				break;
			case MPLSTUNNELPERFHCBYTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCBytes);
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

/** initialize gmplsTunnelTable table mapper **/
void
gmplsTunnelTable_init (void)
{
	extern oid gmplsTunnelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelTable", &gmplsTunnelTable_mapper,
		gmplsTunnelTable_oid, OID_LENGTH (gmplsTunnelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = GMPLSTUNNELUNNUMIF;
	table_info->max_column = GMPLSTUNNELADMINSTATUSFLAGS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelTable_getNext;
	iinfo->get_data_point = &gmplsTunnelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsTunnelEntry_t *
gmplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register gmplsTunnelEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oG;
	
	poEntry->u8UnnumIf = gmplsTunnelUnnumIf_false_c;
	poEntry->i32LSPEncoding = gmplsTunnelLSPEncoding_notGmpls_c;
	poEntry->i32SwitchingType = gmplsTunnelSwitchingType_unknown_c;
	poEntry->i32GPid = gmplsTunnelGPid_unknown_c;
	poEntry->u8Secondary = gmplsTunnelSecondary_false_c;
	poEntry->i32Direction = gmplsTunnelDirection_forward_c;
	poEntry->i32PathComp = gmplsTunnelPathComp_dynamicFull_c;
	poEntry->i32UpstreamNotifyRecipientType = gmplsTunnelUpstreamNotifyRecipientType_unknown_c;
	/*poEntry->au8UpstreamNotifyRecipient = 0*/;
	poEntry->i32SendResvNotifyRecipientType = gmplsTunnelSendResvNotifyRecipientType_unknown_c;
	/*poEntry->au8SendResvNotifyRecipient = 0*/;
	poEntry->i32DownstreamNotifyRecipientType = gmplsTunnelDownstreamNotifyRecipientType_unknown_c;
	/*poEntry->au8DownstreamNotifyRecipient = 0*/;
	poEntry->i32SendPathNotifyRecipientType = gmplsTunnelSendPathNotifyRecipientType_unknown_c;
	/*poEntry->au8SendPathNotifyRecipient = 0*/;
	
	return poEntry;
}

gmplsTunnelEntry_t *
gmplsTunnelTable_getByIndex (
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
	
	return &poTunnel->oG;
}

gmplsTunnelEntry_t *
gmplsTunnelTable_getNextIndex (
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
	
	return &poTunnel->oG;
}

/* remove a row from the table */
void
gmplsTunnelTable_removeEntry (gmplsTunnelEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return gmplsTunnelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelTable_getNext (
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
gmplsTunnelTable_get (
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

/* gmplsTunnelTable table mapper */
int
gmplsTunnelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelEntry_t *table_entry;
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
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELUNNUMIF:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8UnnumIf);
				break;
			case GMPLSTUNNELATTRIBUTES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Attributes, table_entry->u16Attributes_len);
				break;
			case GMPLSTUNNELLSPENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LSPEncoding);
				break;
			case GMPLSTUNNELSWITCHINGTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SwitchingType);
				break;
			case GMPLSTUNNELLINKPROTECTION:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LinkProtection, table_entry->u16LinkProtection_len);
				break;
			case GMPLSTUNNELGPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32GPid);
				break;
			case GMPLSTUNNELSECONDARY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Secondary);
				break;
			case GMPLSTUNNELDIRECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Direction);
				break;
			case GMPLSTUNNELPATHCOMP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PathComp);
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UpstreamNotifyRecipientType);
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8UpstreamNotifyRecipient, table_entry->u16UpstreamNotifyRecipient_len);
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SendResvNotifyRecipientType);
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SendResvNotifyRecipient, table_entry->u16SendResvNotifyRecipient_len);
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32DownstreamNotifyRecipientType);
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DownstreamNotifyRecipient, table_entry->u16DownstreamNotifyRecipient_len);
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SendPathNotifyRecipientType);
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SendPathNotifyRecipient, table_entry->u16SendPathNotifyRecipient_len);
				break;
			case GMPLSTUNNELADMINSTATUSFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminStatusFlags, table_entry->u16AdminStatusFlags_len);
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
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELUNNUMIF:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELATTRIBUTES:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Attributes));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELLSPENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSWITCHINGTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELLINKPROTECTION:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LinkProtection));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELGPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSECONDARY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELDIRECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELPATHCOMP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8UpstreamNotifyRecipient));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENT:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SendResvNotifyRecipient));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8DownstreamNotifyRecipient));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENT:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SendPathNotifyRecipient));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSTUNNELADMINSTATUSFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminStatusFlags));
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
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELUNNUMIF:
			case GMPLSTUNNELATTRIBUTES:
			case GMPLSTUNNELLSPENCODING:
			case GMPLSTUNNELSWITCHINGTYPE:
			case GMPLSTUNNELLINKPROTECTION:
			case GMPLSTUNNELGPID:
			case GMPLSTUNNELSECONDARY:
			case GMPLSTUNNELDIRECTION:
			case GMPLSTUNNELPATHCOMP:
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE:
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT:
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE:
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENT:
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE:
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT:
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE:
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENT:
			case GMPLSTUNNELADMINSTATUSFLAGS:
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
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELUNNUMIF:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8UnnumIf))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8UnnumIf, sizeof (table_entry->u8UnnumIf));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8UnnumIf = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELATTRIBUTES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Attributes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Attributes_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Attributes, sizeof (table_entry->au8Attributes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Attributes, 0, sizeof (table_entry->au8Attributes));
				memcpy (table_entry->au8Attributes, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Attributes_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELLSPENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LSPEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LSPEncoding, sizeof (table_entry->i32LSPEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LSPEncoding = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELSWITCHINGTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SwitchingType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SwitchingType, sizeof (table_entry->i32SwitchingType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SwitchingType = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELLINKPROTECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LinkProtection))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LinkProtection_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LinkProtection, sizeof (table_entry->au8LinkProtection));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LinkProtection, 0, sizeof (table_entry->au8LinkProtection));
				memcpy (table_entry->au8LinkProtection, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LinkProtection_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELGPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32GPid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32GPid, sizeof (table_entry->i32GPid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32GPid = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELSECONDARY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8Secondary))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8Secondary, sizeof (table_entry->u8Secondary));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8Secondary = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELDIRECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Direction))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Direction, sizeof (table_entry->i32Direction));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Direction = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELPATHCOMP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PathComp))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PathComp, sizeof (table_entry->i32PathComp));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PathComp = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UpstreamNotifyRecipientType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UpstreamNotifyRecipientType, sizeof (table_entry->i32UpstreamNotifyRecipientType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UpstreamNotifyRecipientType = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8UpstreamNotifyRecipient))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16UpstreamNotifyRecipient_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8UpstreamNotifyRecipient, sizeof (table_entry->au8UpstreamNotifyRecipient));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8UpstreamNotifyRecipient, 0, sizeof (table_entry->au8UpstreamNotifyRecipient));
				memcpy (table_entry->au8UpstreamNotifyRecipient, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16UpstreamNotifyRecipient_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SendResvNotifyRecipientType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SendResvNotifyRecipientType, sizeof (table_entry->i32SendResvNotifyRecipientType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SendResvNotifyRecipientType = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SendResvNotifyRecipient))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SendResvNotifyRecipient_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SendResvNotifyRecipient, sizeof (table_entry->au8SendResvNotifyRecipient));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SendResvNotifyRecipient, 0, sizeof (table_entry->au8SendResvNotifyRecipient));
				memcpy (table_entry->au8SendResvNotifyRecipient, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SendResvNotifyRecipient_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32DownstreamNotifyRecipientType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32DownstreamNotifyRecipientType, sizeof (table_entry->i32DownstreamNotifyRecipientType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32DownstreamNotifyRecipientType = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8DownstreamNotifyRecipient))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16DownstreamNotifyRecipient_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8DownstreamNotifyRecipient, sizeof (table_entry->au8DownstreamNotifyRecipient));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8DownstreamNotifyRecipient, 0, sizeof (table_entry->au8DownstreamNotifyRecipient));
				memcpy (table_entry->au8DownstreamNotifyRecipient, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16DownstreamNotifyRecipient_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SendPathNotifyRecipientType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SendPathNotifyRecipientType, sizeof (table_entry->i32SendPathNotifyRecipientType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SendPathNotifyRecipientType = *request->requestvb->val.integer;
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SendPathNotifyRecipient))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SendPathNotifyRecipient_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SendPathNotifyRecipient, sizeof (table_entry->au8SendPathNotifyRecipient));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SendPathNotifyRecipient, 0, sizeof (table_entry->au8SendPathNotifyRecipient));
				memcpy (table_entry->au8SendPathNotifyRecipient, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SendPathNotifyRecipient_len = request->requestvb->val_len;
				break;
			case GMPLSTUNNELADMINSTATUSFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AdminStatusFlags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AdminStatusFlags_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AdminStatusFlags, sizeof (table_entry->au8AdminStatusFlags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdminStatusFlags, 0, sizeof (table_entry->au8AdminStatusFlags));
				memcpy (table_entry->au8AdminStatusFlags, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AdminStatusFlags_len = request->requestvb->val_len;
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
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELUNNUMIF:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8UnnumIf, pvOldDdata, sizeof (table_entry->u8UnnumIf));
				}
				break;
			case GMPLSTUNNELATTRIBUTES:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8Attributes, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16Attributes_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELLSPENCODING:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32LSPEncoding, pvOldDdata, sizeof (table_entry->i32LSPEncoding));
				}
				break;
			case GMPLSTUNNELSWITCHINGTYPE:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32SwitchingType, pvOldDdata, sizeof (table_entry->i32SwitchingType));
				}
				break;
			case GMPLSTUNNELLINKPROTECTION:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8LinkProtection, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16LinkProtection_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELGPID:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32GPid, pvOldDdata, sizeof (table_entry->i32GPid));
				}
				break;
			case GMPLSTUNNELSECONDARY:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8Secondary, pvOldDdata, sizeof (table_entry->u8Secondary));
				}
				break;
			case GMPLSTUNNELDIRECTION:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32Direction, pvOldDdata, sizeof (table_entry->i32Direction));
				}
				break;
			case GMPLSTUNNELPATHCOMP:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32PathComp, pvOldDdata, sizeof (table_entry->i32PathComp));
				}
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32UpstreamNotifyRecipientType, pvOldDdata, sizeof (table_entry->i32UpstreamNotifyRecipientType));
				}
				break;
			case GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8UpstreamNotifyRecipient, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16UpstreamNotifyRecipient_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32SendResvNotifyRecipientType, pvOldDdata, sizeof (table_entry->i32SendResvNotifyRecipientType));
				}
				break;
			case GMPLSTUNNELSENDRESVNOTIFYRECIPIENT:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8SendResvNotifyRecipient, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16SendResvNotifyRecipient_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32DownstreamNotifyRecipientType, pvOldDdata, sizeof (table_entry->i32DownstreamNotifyRecipientType));
				}
				break;
			case GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8DownstreamNotifyRecipient, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16DownstreamNotifyRecipient_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32SendPathNotifyRecipientType, pvOldDdata, sizeof (table_entry->i32SendPathNotifyRecipientType));
				}
				break;
			case GMPLSTUNNELSENDPATHNOTIFYRECIPIENT:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8SendPathNotifyRecipient, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16SendPathNotifyRecipient_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSTUNNELADMINSTATUSFLAGS:
				if (pvOldDdata == table_entry)
				{
					gmplsTunnelTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8AdminStatusFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16AdminStatusFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize gmplsTunnelHopTable table mapper **/
void
gmplsTunnelHopTable_init (void)
{
	extern oid gmplsTunnelHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelHopTable", &gmplsTunnelHopTable_mapper,
		gmplsTunnelHopTable_oid, OID_LENGTH (gmplsTunnelHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopPathOptionIndex */,
		ASN_UNSIGNED /* index: mplsTunnelHopIndex */,
		0);
	table_info->min_column = GMPLSTUNNELHOPLABELSTATUSES;
	table_info->max_column = GMPLSTUNNELHOPLABELSTATUSES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelHopTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelHopTable_getNext;
	iinfo->get_data_point = &gmplsTunnelHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsTunnelHopEntry_t *
gmplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register gmplsTunnelHopEntry_t *poEntry = NULL;
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getByIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnelHop->oG;
	
	/*poEntry->aoExplicitForwardLabelPtr = zeroDotZero*/;
	/*poEntry->aoExplicitReverseLabelPtr = zeroDotZero*/;
	
	return poEntry;
}

gmplsTunnelHopEntry_t *
gmplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getByIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelHop->oG;
}

gmplsTunnelHopEntry_t *
gmplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index)
{
	register mplsTunnelHopEntry_t *poTunnelHop = NULL;
	
	if ((poTunnelHop = mplsTunnelHopTable_getNextIndex (u32ListIndex, u32PathOptionIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelHop->oG;
}

/* remove a row from the table */
void
gmplsTunnelHopTable_removeEntry (gmplsTunnelHopEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelHopTable_BTree);
	return gmplsTunnelHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelHopTable_getNext (
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
	*my_data_context = (void*) &poEntry->oG;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelHopTable_BTree);
	return put_index_data;
}

bool
gmplsTunnelHopTable_get (
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
	
	*my_data_context = (void*) &poEntry->oG;
	return true;
}

/* gmplsTunnelHopTable table mapper */
int
gmplsTunnelHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (gmplsTunnelHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELHOPLABELSTATUSES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LabelStatuses, table_entry->u16LabelStatuses_len);
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

/** initialize gmplsTunnelARHopTable table mapper **/
void
gmplsTunnelARHopTable_init (void)
{
	extern oid gmplsTunnelARHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelARHopTable", &gmplsTunnelARHopTable_mapper,
		gmplsTunnelARHopTable_oid, OID_LENGTH (gmplsTunnelARHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelARHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelARHopIndex */,
		0);
	table_info->min_column = GMPLSTUNNELARHOPLABELSTATUSES;
	table_info->max_column = GMPLSTUNNELARHOPPROTECTION;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelARHopTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelARHopTable_getNext;
	iinfo->get_data_point = &gmplsTunnelARHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsTunnelARHopEntry_t *
gmplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register gmplsTunnelARHopEntry_t *poEntry = NULL;
	register mplsTunnelARHopEntry_t *poTunnelARHop = NULL;
	
	if ((poTunnelARHop = mplsTunnelARHopTable_getByIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnelARHop->oG;
	
	return poEntry;
}

gmplsTunnelARHopEntry_t *
gmplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelARHopEntry_t *poTunnelARHop = NULL;
	
	if ((poTunnelARHop = mplsTunnelARHopTable_getByIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelARHop->oG;
}

gmplsTunnelARHopEntry_t *
gmplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register mplsTunnelARHopEntry_t *poTunnelARHop = NULL;
	
	if ((poTunnelARHop = mplsTunnelARHopTable_getByIndex (u32ListIndex, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnelARHop->oG;
}

/* remove a row from the table */
void
gmplsTunnelARHopTable_removeEntry (gmplsTunnelARHopEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelARHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelARHopTable_BTree);
	return gmplsTunnelARHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelARHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelARHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelARHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) &poEntry->oG;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelARHopTable_BTree);
	return put_index_data;
}

bool
gmplsTunnelARHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelARHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mplsTunnelARHopTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) &poEntry->oG;
	return true;
}

/* gmplsTunnelARHopTable table mapper */
int
gmplsTunnelARHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelARHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (gmplsTunnelARHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELARHOPLABELSTATUSES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LabelStatuses, table_entry->u16LabelStatuses_len);
				break;
			case GMPLSTUNNELARHOPPROTECTION:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Protection, table_entry->u16Protection_len);
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

/** initialize gmplsTunnelCHopTable table mapper **/
void
gmplsTunnelCHopTable_init (void)
{
	extern oid gmplsTunnelCHopTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelCHopTable", &gmplsTunnelCHopTable_mapper,
		gmplsTunnelCHopTable_oid, OID_LENGTH (gmplsTunnelCHopTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelCHopListIndex */,
		ASN_UNSIGNED /* index: mplsTunnelCHopIndex */,
		0);
	table_info->min_column = GMPLSTUNNELCHOPLABELSTATUSES;
	table_info->max_column = GMPLSTUNNELCHOPLABELSTATUSES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelCHopTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelCHopTable_getNext;
	iinfo->get_data_point = &gmplsTunnelCHopTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
gmplsTunnelCHopTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register gmplsTunnelCHopEntry_t *pEntry1 = xBTree_entry (pNode1, gmplsTunnelCHopEntry_t, oBTreeNode);
	register gmplsTunnelCHopEntry_t *pEntry2 = xBTree_entry (pNode2, gmplsTunnelCHopEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ListIndex < pEntry2->u32ListIndex) ||
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ListIndex == pEntry2->u32ListIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oGmplsTunnelCHopTable_BTree = xBTree_initInline (&gmplsTunnelCHopTable_BTreeNodeCmp);

/* create a new row in the table */
gmplsTunnelCHopEntry_t *
gmplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register gmplsTunnelCHopEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ListIndex = u32ListIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree);
	return poEntry;
}

gmplsTunnelCHopEntry_t *
gmplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register gmplsTunnelCHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsTunnelCHopEntry_t, oBTreeNode);
}

gmplsTunnelCHopEntry_t *
gmplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index)
{
	register gmplsTunnelCHopEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ListIndex = u32ListIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsTunnelCHopEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
gmplsTunnelCHopTable_removeEntry (gmplsTunnelCHopEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelCHopTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oGmplsTunnelCHopTable_BTree);
	return gmplsTunnelCHopTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelCHopTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsTunnelCHopEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, gmplsTunnelCHopEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ListIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oGmplsTunnelCHopTable_BTree);
	return put_index_data;
}

bool
gmplsTunnelCHopTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsTunnelCHopEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = gmplsTunnelCHopTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* gmplsTunnelCHopTable table mapper */
int
gmplsTunnelCHopTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelCHopEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (gmplsTunnelCHopEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELCHOPLABELSTATUSES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LabelStatuses, table_entry->u16LabelStatuses_len);
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

/** initialize gmplsTunnelReversePerfTable table mapper **/
void
gmplsTunnelReversePerfTable_init (void)
{
	extern oid gmplsTunnelReversePerfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelReversePerfTable", &gmplsTunnelReversePerfTable_mapper,
		gmplsTunnelReversePerfTable_oid, OID_LENGTH (gmplsTunnelReversePerfTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = GMPLSTUNNELREVERSEPERFPACKETS;
	table_info->max_column = GMPLSTUNNELREVERSEPERFHCBYTES;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelReversePerfTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelReversePerfTable_getNext;
	iinfo->get_data_point = &gmplsTunnelReversePerfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsTunnelReversePerfEntry_t *
gmplsTunnelReversePerfTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register gmplsTunnelReversePerfEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oReversePerf;
	
	return poEntry;
}

gmplsTunnelReversePerfEntry_t *
gmplsTunnelReversePerfTable_getByIndex (
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
	
	return &poTunnel->oReversePerf;
}

gmplsTunnelReversePerfEntry_t *
gmplsTunnelReversePerfTable_getNextIndex (
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
	
	return &poTunnel->oReversePerf;
}

/* remove a row from the table */
void
gmplsTunnelReversePerfTable_removeEntry (gmplsTunnelReversePerfEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelReversePerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return gmplsTunnelReversePerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelReversePerfTable_getNext (
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
gmplsTunnelReversePerfTable_get (
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

/* gmplsTunnelReversePerfTable table mapper */
int
gmplsTunnelReversePerfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelReversePerfEntry_t *table_entry;
	register mplsTunnelEntry_t *poEntry = NULL;
	
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
			table_entry = &poEntry->oReversePerf;
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELREVERSEPERFPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Packets);
				break;
			case GMPLSTUNNELREVERSEPERFHCPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCPackets);
				break;
			case GMPLSTUNNELREVERSEPERFERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Errors);
				break;
			case GMPLSTUNNELREVERSEPERFBYTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Bytes);
				break;
			case GMPLSTUNNELREVERSEPERFHCBYTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCBytes);
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

/** initialize gmplsTunnelErrorTable table mapper **/
void
gmplsTunnelErrorTable_init (void)
{
	extern oid gmplsTunnelErrorTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsTunnelErrorTable", &gmplsTunnelErrorTable_mapper,
		gmplsTunnelErrorTable_oid, OID_LENGTH (gmplsTunnelErrorTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = GMPLSTUNNELERRORLASTERRORTYPE;
	table_info->max_column = GMPLSTUNNELERRORHELPSTRING;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsTunnelErrorTable_getFirst;
	iinfo->get_next_data_point = &gmplsTunnelErrorTable_getNext;
	iinfo->get_data_point = &gmplsTunnelErrorTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsTunnelErrorEntry_t *
gmplsTunnelErrorTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register gmplsTunnelErrorEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oError;
	
	return poEntry;
}

gmplsTunnelErrorEntry_t *
gmplsTunnelErrorTable_getByIndex (
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
	
	return &poTunnel->oError;
}

gmplsTunnelErrorEntry_t *
gmplsTunnelErrorTable_getNextIndex (
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
	
	return &poTunnel->oError;
}

/* remove a row from the table */
void
gmplsTunnelErrorTable_removeEntry (gmplsTunnelErrorEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsTunnelErrorTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return gmplsTunnelErrorTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsTunnelErrorTable_getNext (
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
	*my_data_context = (void*) &poEntry->oError;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return put_index_data;
}

bool
gmplsTunnelErrorTable_get (
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
	
	*my_data_context = (void*) &poEntry->oError;
	return true;
}

/* gmplsTunnelErrorTable table mapper */
int
gmplsTunnelErrorTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsTunnelErrorEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (gmplsTunnelErrorEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSTUNNELERRORLASTERRORTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LastErrorType);
				break;
			case GMPLSTUNNELERRORLASTTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastTime);
				break;
			case GMPLSTUNNELERRORREPORTERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ReporterType);
				break;
			case GMPLSTUNNELERRORREPORTER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Reporter, table_entry->u16Reporter_len);
				break;
			case GMPLSTUNNELERRORCODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Code);
				break;
			case GMPLSTUNNELERRORSUBCODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Subcode);
				break;
			case GMPLSTUNNELERRORTLVS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TLVs, table_entry->u16TLVs_len);
				break;
			case GMPLSTUNNELERRORHELPSTRING:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8HelpString, table_entry->u16HelpString_len);
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
mplsTunnelUp_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsTunnelUp_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsTunnelAdminStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,34, /* insert index here */};
	oid mplsTunnelOperStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,35, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsTunnelUp_oid, sizeof (mplsTunnelUp_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsTunnelAdminStatus_oid, OID_LENGTH (mplsTunnelAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsTunnelOperStatus_oid, OID_LENGTH (mplsTunnelOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelOperStatus */
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
mplsTunnelDown_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsTunnelDown_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsTunnelAdminStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,34, /* insert index here */};
	oid mplsTunnelOperStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,35, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsTunnelDown_oid, sizeof (mplsTunnelDown_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsTunnelAdminStatus_oid, OID_LENGTH (mplsTunnelAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsTunnelOperStatus_oid, OID_LENGTH (mplsTunnelOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelOperStatus */
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
mplsTunnelRerouted_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsTunnelRerouted_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsTunnelAdminStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,34, /* insert index here */};
	oid mplsTunnelOperStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,35, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsTunnelRerouted_oid, sizeof (mplsTunnelRerouted_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsTunnelAdminStatus_oid, OID_LENGTH (mplsTunnelAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsTunnelOperStatus_oid, OID_LENGTH (mplsTunnelOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelOperStatus */
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
mplsTunnelReoptimized_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsTunnelReoptimized_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsTunnelAdminStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,34, /* insert index here */};
	oid mplsTunnelOperStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,35, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsTunnelReoptimized_oid, sizeof (mplsTunnelReoptimized_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsTunnelAdminStatus_oid, OID_LENGTH (mplsTunnelAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsTunnelOperStatus_oid, OID_LENGTH (mplsTunnelOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelOperStatus */
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
gmplsTunnelDown_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid gmplsTunnelDown_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsTunnelAdminStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,34, /* insert index here */};
	oid mplsTunnelOperStatus_oid[] = {1,3,6,1,2,1,10,166,3,2,2,1,35, /* insert index here */};
	oid gmplsTunnelErrorLastErrorType_oid[] = {1,3,6,1,2,1,10,166,13,2,6,1,1, /* insert index here */};
	oid gmplsTunnelErrorReporterType_oid[] = {1,3,6,1,2,1,10,166,13,2,6,1,3, /* insert index here */};
	oid gmplsTunnelErrorReporter_oid[] = {1,3,6,1,2,1,10,166,13,2,6,1,4, /* insert index here */};
	oid gmplsTunnelErrorCode_oid[] = {1,3,6,1,2,1,10,166,13,2,6,1,5, /* insert index here */};
	oid gmplsTunnelErrorSubcode_oid[] = {1,3,6,1,2,1,10,166,13,2,6,1,6, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) gmplsTunnelDown_oid, sizeof (gmplsTunnelDown_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsTunnelAdminStatus_oid, OID_LENGTH (mplsTunnelAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsTunnelOperStatus_oid, OID_LENGTH (mplsTunnelOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsTunnelOperStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		gmplsTunnelErrorLastErrorType_oid, OID_LENGTH (gmplsTunnelErrorLastErrorType_oid),
		ASN_INTEGER,
		/* Set an appropriate value for gmplsTunnelErrorLastErrorType */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		gmplsTunnelErrorReporterType_oid, OID_LENGTH (gmplsTunnelErrorReporterType_oid),
		ASN_INTEGER,
		/* Set an appropriate value for gmplsTunnelErrorReporterType */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		gmplsTunnelErrorReporter_oid, OID_LENGTH (gmplsTunnelErrorReporter_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for gmplsTunnelErrorReporter */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		gmplsTunnelErrorCode_oid, OID_LENGTH (gmplsTunnelErrorCode_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for gmplsTunnelErrorCode */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		gmplsTunnelErrorSubcode_oid, OID_LENGTH (gmplsTunnelErrorSubcode_oid),
		ASN_UNSIGNED,
		/* Set an appropriate value for gmplsTunnelErrorSubcode */
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
