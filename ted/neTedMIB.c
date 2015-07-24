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
#include "neTedMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mplsIdStdMIB_oid[] = {1,3,6,1,2,1,10,166,18};
static oid mplsTeNodeConfigLocalIdNext_oid[] = {1,3,6,1,2,1,10,166,20,0,1};
static oid mplsTeNodeConfigTable_oid[] = {1,3,6,1,2,1,10,166,20,0,2};
static oid mplsTeNodeIpMapTable_oid[] = {1,3,6,1,2,1,10,166,20,0,3};
static oid mplsTeNodeIccMapTable_oid[] = {1,3,6,1,2,1,10,166,20,0,4};
static oid neTedMIB_oid[] = {1,3,6,1,4,1,36969,68};

static oid mplsIdObjects_oid[] = {1,3,6,1,2,1,10,166,18,1};
static oid mplsTeExtObjects_oid[] = {1,3,6,1,2,1,10,166,20,0};
static oid neTedScalars_oid[] = {1,3,6,1,4,1,36969,68,1,1};

static oid neTedNodeTable_oid[] = {1,3,6,1,4,1,36969,68,1,2};
static oid neTedLinkTable_oid[] = {1,3,6,1,4,1,36969,68,1,3};
static oid neTedAddressTable_oid[] = {1,3,6,1,4,1,36969,68,1,4};
static oid neTedNeighborTable_oid[] = {1,3,6,1,4,1,36969,68,1,5};
static oid neTeLinkAdjCapTable_oid[] = {1,3,6,1,4,1,36969,68,1,6};
static oid neTeCompLinkAdjCapTable_oid[] = {1,3,6,1,4,1,36969,68,1,7};



/**
 *	initialize neTedMIB group mapper
 */
void
neTedMIB_init (void)
{
	extern oid mplsIdStdMIB_oid[];
	extern oid mplsTeNodeConfigLocalIdNext_oid[];
	extern oid mplsTeNodeConfigTable_oid[];
	extern oid mplsTeNodeIpMapTable_oid[];
	extern oid mplsTeNodeIccMapTable_oid[];
	extern oid neTedMIB_oid[];
	extern oid mplsIdObjects_oid[];
	extern oid mplsTeExtObjects_oid[];
	extern oid neTedScalars_oid[];
	
	DEBUGMSGTL (("neTedMIB", "Initializing\n"));
	
	/* register mplsIdObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mplsIdObjects_mapper", &mplsIdObjects_mapper,
			mplsIdObjects_oid, OID_LENGTH (mplsIdObjects_oid),
			HANDLER_CAN_RWRITE
		),
		MPLSIDGLOBALID,
		MPLSIDICC
	);
	
	/* register mplsTeExtObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mplsTeExtObjects_mapper", &mplsTeExtObjects_mapper,
			mplsTeExtObjects_oid, OID_LENGTH (mplsTeExtObjects_oid),
			HANDLER_CAN_RONLY
		),
		MPLSTENODECONFIGLOCALIDNEXT,
		MPLSTENODECONFIGLOCALIDNEXT
	);
	
	/* register neTedScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"neTedScalars_mapper", &neTedScalars_mapper,
			neTedScalars_oid, OID_LENGTH (neTedScalars_oid),
			HANDLER_CAN_RONLY
		),
		NETEDNODECONFIGURED,
		NETEDNEIGHBORACTIVE
	);
	
	
	/* register neTedMIB group table mappers */
	mplsTeNodeConfigTable_init ();
	neTedNodeTable_init ();
	neTedLinkTable_init ();
	neTedAddressTable_init ();
	neTedNeighborTable_init ();
	neTeLinkAdjCapTable_init ();
	neTeCompLinkAdjCapTable_init ();
	
	/* register neTedMIB modules */
	sysORTable_createRegister ("mplsIdStdMIB", mplsIdStdMIB_oid, OID_LENGTH (mplsIdStdMIB_oid));
	sysORTable_createRegister ("mplsTeNodeConfigLocalIdNext", mplsTeNodeConfigLocalIdNext_oid, OID_LENGTH (mplsTeNodeConfigLocalIdNext_oid));
	sysORTable_createRegister ("mplsTeNodeConfigTable", mplsTeNodeConfigTable_oid, OID_LENGTH (mplsTeNodeConfigTable_oid));
	sysORTable_createRegister ("mplsTeNodeIpMapTable", mplsTeNodeIpMapTable_oid, OID_LENGTH (mplsTeNodeIpMapTable_oid));
	sysORTable_createRegister ("mplsTeNodeIccMapTable", mplsTeNodeIccMapTable_oid, OID_LENGTH (mplsTeNodeIccMapTable_oid));
	sysORTable_createRegister ("neTedMIB", neTedMIB_oid, OID_LENGTH (neTedMIB_oid));
}


/**
 *	scalar mapper(s)
 */
mplsIdObjects_t oMplsIdObjects;

/** mplsIdObjects scalar mapper **/
int
mplsIdObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid mplsIdObjects_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mplsIdObjects_oid)])
			{
			case MPLSIDGLOBALID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsIdObjects.au8GlobalId, oMplsIdObjects.u16GlobalId_len);
				break;
			case MPLSIDNODEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsIdObjects.u32NodeId);
				break;
			case MPLSIDCC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsIdObjects.au8Cc, oMplsIdObjects.u16Cc_len);
				break;
			case MPLSIDICC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsIdObjects.au8Icc, oMplsIdObjects.u16Icc_len);
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
			switch (request->requestvb->name[OID_LENGTH (mplsIdObjects_oid)])
			{
			case MPLSIDGLOBALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case MPLSIDNODEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case MPLSIDCC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case MPLSIDICC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
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
			switch (request->requestvb->name[OID_LENGTH (mplsIdObjects_oid)])
			{
			case MPLSIDGLOBALID:
				/* XXX: perform the value change here */
				memset (oMplsIdObjects.au8GlobalId, 0, sizeof (oMplsIdObjects.au8GlobalId));
				memcpy (oMplsIdObjects.au8GlobalId, request->requestvb->val.string, request->requestvb->val_len);
				oMplsIdObjects.u16GlobalId_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case MPLSIDNODEID:
				/* XXX: perform the value change here */
				oMplsIdObjects.u32NodeId = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case MPLSIDCC:
				/* XXX: perform the value change here */
				memset (oMplsIdObjects.au8Cc, 0, sizeof (oMplsIdObjects.au8Cc));
				memcpy (oMplsIdObjects.au8Cc, request->requestvb->val.string, request->requestvb->val_len);
				oMplsIdObjects.u16Cc_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case MPLSIDICC:
				/* XXX: perform the value change here */
				memset (oMplsIdObjects.au8Icc, 0, sizeof (oMplsIdObjects.au8Icc));
				memcpy (oMplsIdObjects.au8Icc, request->requestvb->val.string, request->requestvb->val_len);
				oMplsIdObjects.u16Icc_len = request->requestvb->val_len;
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
			switch (request->requestvb->name[OID_LENGTH (mplsIdObjects_oid)])
			{
			case MPLSIDGLOBALID:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case MPLSIDNODEID:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case MPLSIDCC:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case MPLSIDICC:
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

mplsTeExtObjects_t oMplsTeExtObjects;

/** mplsTeExtObjects scalar mapper **/
int
mplsTeExtObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid mplsTeExtObjects_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mplsTeExtObjects_oid)])
			{
			case MPLSTENODECONFIGLOCALIDNEXT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsTeExtObjects.u32NodeConfigLocalIdNext);
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

neTedScalars_t oNeTedScalars;

/** neTedScalars scalar mapper **/
int
neTedScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid neTedScalars_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (neTedScalars_oid)])
			{
			case NETEDNODECONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32NodeConfigured);
				break;
			case NETEDNODEACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32NodeActive);
				break;
			case NETEDLINKCONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32LinkConfigured);
				break;
			case NETEDLINKACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32LinkActive);
				break;
			case NETEDADDRESSCONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32AddressConfigured);
				break;
			case NETEDADDRESSACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32AddressActive);
				break;
			case NETEDNEIGHBORCONFIGURED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32NeighborConfigured);
				break;
			case NETEDNEIGHBORACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeTedScalars.u32NeighborActive);
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
/** initialize mplsTeNodeConfigTable table mapper **/
void
mplsTeNodeConfigTable_init (void)
{
	extern oid mplsTeNodeConfigTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTeNodeConfigTable", &mplsTeNodeConfigTable_mapper,
		mplsTeNodeConfigTable_oid, OID_LENGTH (mplsTeNodeConfigTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTeNodeConfigLocalId */,
		0);
	table_info->min_column = MPLSTENODECONFIGGLOBALID;
	table_info->max_column = MPLSTENODECONFIGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTeNodeConfigTable_getFirst;
	iinfo->get_next_data_point = &mplsTeNodeConfigTable_getNext;
	iinfo->get_data_point = &mplsTeNodeConfigTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsTeNodeConfigTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsTeNodeConfigEntry_t *pEntry1 = xBTree_entry (pNode1, mplsTeNodeConfigEntry_t, oBTreeNode);
	register mplsTeNodeConfigEntry_t *pEntry2 = xBTree_entry (pNode2, mplsTeNodeConfigEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32LocalId < pEntry2->u32LocalId) ? -1:
		(pEntry1->u32LocalId == pEntry2->u32LocalId) ? 0: 1;
}

xBTree_t oMplsTeNodeConfigTable_BTree = xBTree_initInline (&mplsTeNodeConfigTable_BTreeNodeCmp);

/* create a new row in the table */
mplsTeNodeConfigEntry_t *
mplsTeNodeConfigTable_createEntry (
	uint32_t u32LocalId)
{
	register mplsTeNodeConfigEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32LocalId = u32LocalId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8IccValid = mplsTeNodeConfigIccValid_false_c;
	poEntry->u8StorageType = mplsTeNodeConfigStorageType_volatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree);
	return poEntry;
}

mplsTeNodeConfigEntry_t *
mplsTeNodeConfigTable_getByIndex (
	uint32_t u32LocalId)
{
	register mplsTeNodeConfigEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LocalId = u32LocalId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTeNodeConfigEntry_t, oBTreeNode);
}

mplsTeNodeConfigEntry_t *
mplsTeNodeConfigTable_getNextIndex (
	uint32_t u32LocalId)
{
	register mplsTeNodeConfigEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LocalId = u32LocalId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsTeNodeConfigEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsTeNodeConfigTable_removeEntry (mplsTeNodeConfigEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTeNodeConfigTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTeNodeConfigTable_BTree);
	return mplsTeNodeConfigTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTeNodeConfigTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTeNodeConfigEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTeNodeConfigEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LocalId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTeNodeConfigTable_BTree);
	return put_index_data;
}

bool
mplsTeNodeConfigTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTeNodeConfigEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsTeNodeConfigTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsTeNodeConfigTable table mapper */
int
mplsTeNodeConfigTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTeNodeConfigEntry_t *table_entry;
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGGLOBALID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8GlobalId, table_entry->u16GlobalId_len);
				break;
			case MPLSTENODECONFIGCCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8CcId, table_entry->u16CcId_len);
				break;
			case MPLSTENODECONFIGICCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IccId, table_entry->u16IccId_len);
				break;
			case MPLSTENODECONFIGNODEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NodeId);
				break;
			case MPLSTENODECONFIGICCVALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8IccValid);
				break;
			case MPLSTENODECONFIGSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case MPLSTENODECONFIGROWSTATUS:
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGGLOBALID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8GlobalId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGCCID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8CcId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGICCID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8IccId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGNODEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGICCVALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTENODECONFIGROWSTATUS:
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsTeNodeConfigTable_createEntry (
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTeNodeConfigTable_removeEntry (table_entry);
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGGLOBALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8GlobalId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16GlobalId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8GlobalId, sizeof (table_entry->au8GlobalId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8GlobalId, 0, sizeof (table_entry->au8GlobalId));
				memcpy (table_entry->au8GlobalId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16GlobalId_len = request->requestvb->val_len;
				break;
			case MPLSTENODECONFIGCCID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8CcId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16CcId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8CcId, sizeof (table_entry->au8CcId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8CcId, 0, sizeof (table_entry->au8CcId));
				memcpy (table_entry->au8CcId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16CcId_len = request->requestvb->val_len;
				break;
			case MPLSTENODECONFIGICCID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8IccId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16IccId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8IccId, sizeof (table_entry->au8IccId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8IccId, 0, sizeof (table_entry->au8IccId));
				memcpy (table_entry->au8IccId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16IccId_len = request->requestvb->val_len;
				break;
			case MPLSTENODECONFIGNODEID:
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
			case MPLSTENODECONFIGICCVALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8IccValid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8IccValid, sizeof (table_entry->u8IccValid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8IccValid = *request->requestvb->val.integer;
				break;
			case MPLSTENODECONFIGSTORAGETYPE:
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsTeNodeConfigTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGGLOBALID:
				memcpy (table_entry->au8GlobalId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16GlobalId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTENODECONFIGCCID:
				memcpy (table_entry->au8CcId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16CcId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTENODECONFIGICCID:
				memcpy (table_entry->au8IccId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16IccId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSTENODECONFIGNODEID:
				memcpy (&table_entry->u32NodeId, pvOldDdata, sizeof (table_entry->u32NodeId));
				break;
			case MPLSTENODECONFIGICCVALID:
				memcpy (&table_entry->u8IccValid, pvOldDdata, sizeof (table_entry->u8IccValid));
				break;
			case MPLSTENODECONFIGSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case MPLSTENODECONFIGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsTeNodeConfigTable_removeEntry (table_entry);
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
			table_entry = (mplsTeNodeConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSTENODECONFIGROWSTATUS:
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
					mplsTeNodeConfigTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neTedNodeTable table mapper **/
void
neTedNodeTable_init (void)
{
	extern oid neTedNodeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTedNodeTable", &neTedNodeTable_mapper,
		neTedNodeTable_oid, OID_LENGTH (neTedNodeTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neTedNodeIndex */,
		0);
	table_info->min_column = NETEDNODEADDRTYPE;
	table_info->max_column = NETEDNODEDATAPATHID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTedNodeTable_getFirst;
	iinfo->get_next_data_point = &neTedNodeTable_getNext;
	iinfo->get_data_point = &neTedNodeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTedNodeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTedNodeEntry_t *pEntry1 = xBTree_entry (pNode1, neTedNodeEntry_t, oBTreeNode);
	register neTedNodeEntry_t *pEntry2 = xBTree_entry (pNode2, neTedNodeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeTedNodeTable_BTree = xBTree_initInline (&neTedNodeTable_BTreeNodeCmp);

/* create a new row in the table */
neTedNodeEntry_t *
neTedNodeTable_createEntry (
	uint32_t u32Index)
{
	register neTedNodeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedNodeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTedNodeTable_BTree);
	return poEntry;
}

neTedNodeEntry_t *
neTedNodeTable_getByIndex (
	uint32_t u32Index)
{
	register neTedNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTedNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedNodeEntry_t, oBTreeNode);
}

neTedNodeEntry_t *
neTedNodeTable_getNextIndex (
	uint32_t u32Index)
{
	register neTedNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTedNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedNodeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTedNodeTable_removeEntry (neTedNodeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedNodeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTedNodeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTedNodeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTedNodeTable_BTree);
	return neTedNodeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTedNodeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedNodeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTedNodeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTedNodeTable_BTree);
	return put_index_data;
}

bool
neTedNodeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedNodeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neTedNodeTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neTedNodeTable table mapper */
int
neTedNodeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTedNodeEntry_t *table_entry;
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
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddrType);
				break;
			case NETEDNODEADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Address, table_entry->u16Address_len);
				break;
			case NETEDNODEDATAPATHID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DataPathId, table_entry->u16DataPathId_len);
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
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDNODEADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Address));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDNODEDATAPATHID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8DataPathId));
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
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
			case NETEDNODEADDRESS:
			case NETEDNODEDATAPATHID:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTedNodeTable_createEntry (
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
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
			case NETEDNODEADDRESS:
			case NETEDNODEDATAPATHID:
				neTedNodeTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
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
			case NETEDNODEADDRESS:
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
			case NETEDNODEDATAPATHID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8DataPathId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16DataPathId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8DataPathId, sizeof (table_entry->au8DataPathId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8DataPathId, 0, sizeof (table_entry->au8DataPathId));
				memcpy (table_entry->au8DataPathId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16DataPathId_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neTedNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNODEADDRTYPE:
				if (pvOldDdata == table_entry)
				{
					neTedNodeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32AddrType, pvOldDdata, sizeof (table_entry->i32AddrType));
				}
				break;
			case NETEDNODEADDRESS:
				if (pvOldDdata == table_entry)
				{
					neTedNodeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8Address, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16Address_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NETEDNODEDATAPATHID:
				if (pvOldDdata == table_entry)
				{
					neTedNodeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8DataPathId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16DataPathId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize neTedLinkTable table mapper **/
void
neTedLinkTable_init (void)
{
	extern oid neTedLinkTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTedLinkTable", &neTedLinkTable_mapper,
		neTedLinkTable_oid, OID_LENGTH (neTedLinkTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neTedNodeIndex */,
		ASN_UNSIGNED /* index: neTedLinkIndex */,
		0);
	table_info->min_column = NETEDLINKDISTRIBUTEENABLE;
	table_info->max_column = NETEDLINKSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTedLinkTable_getFirst;
	iinfo->get_next_data_point = &neTedLinkTable_getNext;
	iinfo->get_data_point = &neTedLinkTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTedLinkTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTedLinkEntry_t *pEntry1 = xBTree_entry (pNode1, neTedLinkEntry_t, oBTreeNode);
	register neTedLinkEntry_t *pEntry2 = xBTree_entry (pNode2, neTedLinkEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32NodeIndex < pEntry2->u32NodeIndex) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeTedLinkTable_BTree = xBTree_initInline (&neTedLinkTable_BTreeNodeCmp);

/* create a new row in the table */
neTedLinkEntry_t *
neTedLinkTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32Index)
{
	register neTedLinkEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32NodeIndex = u32NodeIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedLinkTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8DistributeEnable = neTedLinkDistributeEnable_true_c;
	poEntry->u8AdjacencyEnable = neTedLinkAdjacencyEnable_false_c;
	xBitmap_setBitsRev (poEntry->au8DistributionScope, 1, 1, neTedLinkDistributionScope_as_c);
	poEntry->u32LocalAsn = 0;
	poEntry->u32IgpInstance = 0;
	poEntry->u32RemoteAsn = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neTedLinkStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTedLinkTable_BTree);
	return poEntry;
}

neTedLinkEntry_t *
neTedLinkTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32Index)
{
	register neTedLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTedLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedLinkEntry_t, oBTreeNode);
}

neTedLinkEntry_t *
neTedLinkTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32Index)
{
	register neTedLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTedLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedLinkEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTedLinkTable_removeEntry (neTedLinkEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedLinkTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTedLinkTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTedLinkTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTedLinkTable_BTree);
	return neTedLinkTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTedLinkTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedLinkEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTedLinkEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32NodeIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTedLinkTable_BTree);
	return put_index_data;
}

bool
neTedLinkTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedLinkEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neTedLinkTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neTedLinkTable table mapper */
int
neTedLinkTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTedLinkEntry_t *table_entry;
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDLINKDISTRIBUTEENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8DistributeEnable);
				break;
			case NETEDLINKADJACENCYENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8AdjacencyEnable);
				break;
			case NETEDLINKDISTRIBUTIONSCOPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DistributionScope, table_entry->u16DistributionScope_len);
				break;
			case NETEDLINKLOCALASN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LocalAsn);
				break;
			case NETEDLINKIGPINSTANCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IgpInstance);
				break;
			case NETEDLINKAREA:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Area);
				break;
			case NETEDLINKREMOTEASN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RemoteAsn);
				break;
			case NETEDLINKSWCAPTYPES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SwCapTypes, table_entry->u16SwCapTypes_len);
				break;
			case NETEDLINKSWCAPENCODINGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SwCapEncodings, table_entry->u16SwCapEncodings_len);
				break;
			case NETEDLINKADJCAPTYPES:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdjCapTypes, table_entry->u16AdjCapTypes_len);
				break;
			case NETEDLINKADJCAPENCODINGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdjCapEncodings, table_entry->u16AdjCapEncodings_len);
				break;
			case NETEDLINKROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NETEDLINKSTORAGETYPE:
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDLINKDISTRIBUTEENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKADJACENCYENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKDISTRIBUTIONSCOPE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8DistributionScope));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKLOCALASN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKIGPINSTANCE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKAREA:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKREMOTEASN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKSWCAPTYPES:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SwCapTypes));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKSWCAPENCODINGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SwCapEncodings));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKADJCAPTYPES:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdjCapTypes));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKADJCAPENCODINGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdjCapEncodings));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDLINKSTORAGETYPE:
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NETEDLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTedLinkTable_createEntry (
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedLinkTable_removeEntry (table_entry);
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDLINKDISTRIBUTEENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8DistributeEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8DistributeEnable, sizeof (table_entry->u8DistributeEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8DistributeEnable = *request->requestvb->val.integer;
				break;
			case NETEDLINKADJACENCYENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8AdjacencyEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8AdjacencyEnable, sizeof (table_entry->u8AdjacencyEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8AdjacencyEnable = *request->requestvb->val.integer;
				break;
			case NETEDLINKDISTRIBUTIONSCOPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8DistributionScope))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16DistributionScope_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8DistributionScope, sizeof (table_entry->au8DistributionScope));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8DistributionScope, 0, sizeof (table_entry->au8DistributionScope));
				memcpy (table_entry->au8DistributionScope, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16DistributionScope_len = request->requestvb->val_len;
				break;
			case NETEDLINKLOCALASN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LocalAsn))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LocalAsn, sizeof (table_entry->u32LocalAsn));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LocalAsn = *request->requestvb->val.integer;
				break;
			case NETEDLINKIGPINSTANCE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IgpInstance))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IgpInstance, sizeof (table_entry->u32IgpInstance));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IgpInstance = *request->requestvb->val.integer;
				break;
			case NETEDLINKAREA:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Area))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Area, sizeof (table_entry->u32Area));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Area = *request->requestvb->val.integer;
				break;
			case NETEDLINKREMOTEASN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RemoteAsn))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RemoteAsn, sizeof (table_entry->u32RemoteAsn));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RemoteAsn = *request->requestvb->val.integer;
				break;
			case NETEDLINKSWCAPTYPES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SwCapTypes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SwCapTypes_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SwCapTypes, sizeof (table_entry->au8SwCapTypes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SwCapTypes, 0, sizeof (table_entry->au8SwCapTypes));
				memcpy (table_entry->au8SwCapTypes, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SwCapTypes_len = request->requestvb->val_len;
				break;
			case NETEDLINKSWCAPENCODINGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SwCapEncodings))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SwCapEncodings_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SwCapEncodings, sizeof (table_entry->au8SwCapEncodings));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SwCapEncodings, 0, sizeof (table_entry->au8SwCapEncodings));
				memcpy (table_entry->au8SwCapEncodings, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SwCapEncodings_len = request->requestvb->val_len;
				break;
			case NETEDLINKADJCAPTYPES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AdjCapTypes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AdjCapTypes_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AdjCapTypes, sizeof (table_entry->au8AdjCapTypes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdjCapTypes, 0, sizeof (table_entry->au8AdjCapTypes));
				memcpy (table_entry->au8AdjCapTypes, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AdjCapTypes_len = request->requestvb->val_len;
				break;
			case NETEDLINKADJCAPENCODINGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AdjCapEncodings))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AdjCapEncodings_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AdjCapEncodings, sizeof (table_entry->au8AdjCapEncodings));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdjCapEncodings, 0, sizeof (table_entry->au8AdjCapEncodings));
				memcpy (table_entry->au8AdjCapEncodings, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AdjCapEncodings_len = request->requestvb->val_len;
				break;
			case NETEDLINKSTORAGETYPE:
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neTedLinkTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDLINKDISTRIBUTEENABLE:
				memcpy (&table_entry->u8DistributeEnable, pvOldDdata, sizeof (table_entry->u8DistributeEnable));
				break;
			case NETEDLINKADJACENCYENABLE:
				memcpy (&table_entry->u8AdjacencyEnable, pvOldDdata, sizeof (table_entry->u8AdjacencyEnable));
				break;
			case NETEDLINKDISTRIBUTIONSCOPE:
				memcpy (table_entry->au8DistributionScope, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16DistributionScope_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETEDLINKLOCALASN:
				memcpy (&table_entry->u32LocalAsn, pvOldDdata, sizeof (table_entry->u32LocalAsn));
				break;
			case NETEDLINKIGPINSTANCE:
				memcpy (&table_entry->u32IgpInstance, pvOldDdata, sizeof (table_entry->u32IgpInstance));
				break;
			case NETEDLINKAREA:
				memcpy (&table_entry->u32Area, pvOldDdata, sizeof (table_entry->u32Area));
				break;
			case NETEDLINKREMOTEASN:
				memcpy (&table_entry->u32RemoteAsn, pvOldDdata, sizeof (table_entry->u32RemoteAsn));
				break;
			case NETEDLINKSWCAPTYPES:
				memcpy (table_entry->au8SwCapTypes, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SwCapTypes_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETEDLINKSWCAPENCODINGS:
				memcpy (table_entry->au8SwCapEncodings, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SwCapEncodings_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETEDLINKADJCAPTYPES:
				memcpy (table_entry->au8AdjCapTypes, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AdjCapTypes_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETEDLINKADJCAPENCODINGS:
				memcpy (table_entry->au8AdjCapEncodings, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AdjCapEncodings_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETEDLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedLinkTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NETEDLINKSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neTedLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDLINKROWSTATUS:
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
					neTedLinkTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neTedAddressTable table mapper **/
void
neTedAddressTable_init (void)
{
	extern oid neTedAddressTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTedAddressTable", &neTedAddressTable_mapper,
		neTedAddressTable_oid, OID_LENGTH (neTedAddressTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neTedNodeIndex */,
		ASN_UNSIGNED /* index: neTedLinkIndex */,
		ASN_INTEGER /* index: neTedAddressType */,
		ASN_OCTET_STR /* index: neTedAddress */,
		ASN_UNSIGNED /* index: neTedAddressLength */,
		0);
	table_info->min_column = NETEDADDRESSROWSTATUS;
	table_info->max_column = NETEDADDRESSSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTedAddressTable_getFirst;
	iinfo->get_next_data_point = &neTedAddressTable_getNext;
	iinfo->get_data_point = &neTedAddressTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTedAddressTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTedAddressEntry_t *pEntry1 = xBTree_entry (pNode1, neTedAddressEntry_t, oBTreeNode);
	register neTedAddressEntry_t *pEntry2 = xBTree_entry (pNode2, neTedAddressEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32NodeIndex < pEntry2->u32NodeIndex) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex < pEntry2->u32LinkIndex) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32Length < pEntry2->u32Length) ? -1:
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32Length == pEntry2->u32Length) ? 0: 1;
}

xBTree_t oNeTedAddressTable_BTree = xBTree_initInline (&neTedAddressTable_BTreeNodeCmp);

/* create a new row in the table */
neTedAddressEntry_t *
neTedAddressTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length)
{
	register neTedAddressEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32NodeIndex = u32NodeIndex;
	poEntry->u32LinkIndex = u32LinkIndex;
	poEntry->i32Type = i32Type;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32Length = u32Length;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedAddressTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neTedAddressStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTedAddressTable_BTree);
	return poEntry;
}

neTedAddressEntry_t *
neTedAddressTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length)
{
	register neTedAddressEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32LinkIndex = u32LinkIndex;
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32Length = u32Length;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTedAddressTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedAddressEntry_t, oBTreeNode);
}

neTedAddressEntry_t *
neTedAddressTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length)
{
	register neTedAddressEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32LinkIndex = u32LinkIndex;
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32Length = u32Length;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTedAddressTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedAddressEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTedAddressTable_removeEntry (neTedAddressEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedAddressTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTedAddressTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTedAddressTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTedAddressTable_BTree);
	return neTedAddressTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTedAddressTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedAddressEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTedAddressEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32NodeIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LinkIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Type);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Length);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTedAddressTable_BTree);
	return put_index_data;
}

bool
neTedAddressTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedAddressEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = neTedAddressTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		(void*) idx4->val.string, idx4->val_len,
		*idx5->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neTedAddressTable table mapper */
int
neTedAddressTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTedAddressEntry_t *table_entry;
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NETEDADDRESSSTORAGETYPE:
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDADDRESSSTORAGETYPE:
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			register netsnmp_variable_list *idx5 = idx4->next_variable;
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTedAddressTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						*idx3->val.integer,
						(void*) idx4->val.string, idx4->val_len,
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedAddressTable_removeEntry (table_entry);
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSSTORAGETYPE:
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neTedAddressTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedAddressTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NETEDADDRESSSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neTedAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDADDRESSROWSTATUS:
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
					neTedAddressTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neTedNeighborTable table mapper **/
void
neTedNeighborTable_init (void)
{
	extern oid neTedNeighborTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTedNeighborTable", &neTedNeighborTable_mapper,
		neTedNeighborTable_oid, OID_LENGTH (neTedNeighborTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neTedNodeIndex */,
		ASN_UNSIGNED /* index: neTedLinkIndex */,
		ASN_UNSIGNED /* index: neTedNeighborIndex */,
		0);
	table_info->min_column = NETEDNEIGHBORLINK;
	table_info->max_column = NETEDNEIGHBORSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTedNeighborTable_getFirst;
	iinfo->get_next_data_point = &neTedNeighborTable_getNext;
	iinfo->get_data_point = &neTedNeighborTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTedNeighborTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTedNeighborEntry_t *pEntry1 = xBTree_entry (pNode1, neTedNeighborEntry_t, oBTreeNode);
	register neTedNeighborEntry_t *pEntry2 = xBTree_entry (pNode2, neTedNeighborEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32NodeIndex < pEntry2->u32NodeIndex) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex < pEntry2->u32LinkIndex) ||
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32NodeIndex == pEntry2->u32NodeIndex && pEntry1->u32LinkIndex == pEntry2->u32LinkIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeTedNeighborTable_BTree = xBTree_initInline (&neTedNeighborTable_BTreeNodeCmp);

/* create a new row in the table */
neTedNeighborEntry_t *
neTedNeighborTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index)
{
	register neTedNeighborEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32NodeIndex = u32NodeIndex;
	poEntry->u32LinkIndex = u32LinkIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedNeighborTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neTedNeighborStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTedNeighborTable_BTree);
	return poEntry;
}

neTedNeighborEntry_t *
neTedNeighborTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index)
{
	register neTedNeighborEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32LinkIndex = u32LinkIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTedNeighborTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedNeighborEntry_t, oBTreeNode);
}

neTedNeighborEntry_t *
neTedNeighborTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index)
{
	register neTedNeighborEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32NodeIndex = u32NodeIndex;
	poTmpEntry->u32LinkIndex = u32LinkIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTedNeighborTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTedNeighborEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTedNeighborTable_removeEntry (neTedNeighborEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTedNeighborTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTedNeighborTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTedNeighborTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTedNeighborTable_BTree);
	return neTedNeighborTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTedNeighborTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedNeighborEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTedNeighborEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32NodeIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LinkIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTedNeighborTable_BTree);
	return put_index_data;
}

bool
neTedNeighborTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTedNeighborEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = neTedNeighborTable_getByIndex (
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

/* neTedNeighborTable table mapper */
int
neTedNeighborTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTedNeighborEntry_t *table_entry;
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORLINK:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Link);
				break;
			case NETEDNEIGHBORROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NETEDNEIGHBORSTORAGETYPE:
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORLINK:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDNEIGHBORROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETEDNEIGHBORSTORAGETYPE:
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTedNeighborTable_createEntry (
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedNeighborTable_removeEntry (table_entry);
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORLINK:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Link))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Link, sizeof (table_entry->u32Link));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Link = *request->requestvb->val.integer;
				break;
			case NETEDNEIGHBORSTORAGETYPE:
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neTedNeighborTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORLINK:
				memcpy (&table_entry->u32Link, pvOldDdata, sizeof (table_entry->u32Link));
				break;
			case NETEDNEIGHBORROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTedNeighborTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NETEDNEIGHBORSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neTedNeighborEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETEDNEIGHBORROWSTATUS:
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
					neTedNeighborTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neTeLinkAdjCapTable table mapper **/
void
neTeLinkAdjCapTable_init (void)
{
	extern oid neTeLinkAdjCapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTeLinkAdjCapTable", &neTeLinkAdjCapTable_mapper,
		neTeLinkAdjCapTable_oid, OID_LENGTH (neTeLinkAdjCapTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: neTeLinkAdjCapId */,
		0);
	table_info->min_column = NETELINKADJCAPLOWERTYPE;
	table_info->max_column = NETELINKADJCAPSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTeLinkAdjCapTable_getFirst;
	iinfo->get_next_data_point = &neTeLinkAdjCapTable_getNext;
	iinfo->get_data_point = &neTeLinkAdjCapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTeLinkAdjCapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTeLinkAdjCapEntry_t *pEntry1 = xBTree_entry (pNode1, neTeLinkAdjCapEntry_t, oBTreeNode);
	register neTeLinkAdjCapEntry_t *pEntry2 = xBTree_entry (pNode2, neTeLinkAdjCapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oNeTeLinkAdjCapTable_BTree = xBTree_initInline (&neTeLinkAdjCapTable_BTreeNodeCmp);

/* create a new row in the table */
neTeLinkAdjCapEntry_t *
neTeLinkAdjCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeLinkAdjCapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neTeLinkAdjCapStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree);
	return poEntry;
}

neTeLinkAdjCapEntry_t *
neTeLinkAdjCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeLinkAdjCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTeLinkAdjCapEntry_t, oBTreeNode);
}

neTeLinkAdjCapEntry_t *
neTeLinkAdjCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeLinkAdjCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTeLinkAdjCapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTeLinkAdjCapTable_removeEntry (neTeLinkAdjCapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTeLinkAdjCapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTeLinkAdjCapTable_BTree);
	return neTeLinkAdjCapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTeLinkAdjCapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTeLinkAdjCapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTeLinkAdjCapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTeLinkAdjCapTable_BTree);
	return put_index_data;
}

bool
neTeLinkAdjCapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTeLinkAdjCapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neTeLinkAdjCapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neTeLinkAdjCapTable table mapper */
int
neTeLinkAdjCapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTeLinkAdjCapEntry_t *table_entry;
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPLOWERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LowerType);
				break;
			case NETELINKADJCAPLOWERENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LowerEncoding);
				break;
			case NETELINKADJCAPUPPERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UpperType);
				break;
			case NETELINKADJCAPUPPERENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UpperEncoding);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO0:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio0, table_entry->u16MaxLspBandwidthPrio0_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio1, table_entry->u16MaxLspBandwidthPrio1_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio2, table_entry->u16MaxLspBandwidthPrio2_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio3, table_entry->u16MaxLspBandwidthPrio3_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO4:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio4, table_entry->u16MaxLspBandwidthPrio4_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO5:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio5, table_entry->u16MaxLspBandwidthPrio5_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO6:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio6, table_entry->u16MaxLspBandwidthPrio6_len);
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO7:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio7, table_entry->u16MaxLspBandwidthPrio7_len);
				break;
			case NETELINKADJCAPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NETELINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPLOWERTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPLOWERENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPUPPERTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPUPPERENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO0:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio0));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO1:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio1));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO2:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio2));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO3:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio3));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO4:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio4));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO5:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio5));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO6:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio6));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO7:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio7));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETELINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTeLinkAdjCapTable_createEntry (
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTeLinkAdjCapTable_removeEntry (table_entry);
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPLOWERTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LowerType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LowerType, sizeof (table_entry->i32LowerType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LowerType = *request->requestvb->val.integer;
				break;
			case NETELINKADJCAPLOWERENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LowerEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LowerEncoding, sizeof (table_entry->i32LowerEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LowerEncoding = *request->requestvb->val.integer;
				break;
			case NETELINKADJCAPUPPERTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UpperType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UpperType, sizeof (table_entry->i32UpperType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UpperType = *request->requestvb->val.integer;
				break;
			case NETELINKADJCAPUPPERENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UpperEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UpperEncoding, sizeof (table_entry->i32UpperEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UpperEncoding = *request->requestvb->val.integer;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO0:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio0))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio0_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio0, sizeof (table_entry->au8MaxLspBandwidthPrio0));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio0, 0, sizeof (table_entry->au8MaxLspBandwidthPrio0));
				memcpy (table_entry->au8MaxLspBandwidthPrio0, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio0_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio1))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio1_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio1, sizeof (table_entry->au8MaxLspBandwidthPrio1));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio1, 0, sizeof (table_entry->au8MaxLspBandwidthPrio1));
				memcpy (table_entry->au8MaxLspBandwidthPrio1, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio1_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio2))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio2_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio2, sizeof (table_entry->au8MaxLspBandwidthPrio2));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio2, 0, sizeof (table_entry->au8MaxLspBandwidthPrio2));
				memcpy (table_entry->au8MaxLspBandwidthPrio2, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio2_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio3))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio3_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio3, sizeof (table_entry->au8MaxLspBandwidthPrio3));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio3, 0, sizeof (table_entry->au8MaxLspBandwidthPrio3));
				memcpy (table_entry->au8MaxLspBandwidthPrio3, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio3_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio4))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio4_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio4, sizeof (table_entry->au8MaxLspBandwidthPrio4));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio4, 0, sizeof (table_entry->au8MaxLspBandwidthPrio4));
				memcpy (table_entry->au8MaxLspBandwidthPrio4, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio4_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio5))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio5_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio5, sizeof (table_entry->au8MaxLspBandwidthPrio5));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio5, 0, sizeof (table_entry->au8MaxLspBandwidthPrio5));
				memcpy (table_entry->au8MaxLspBandwidthPrio5, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio5_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO6:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio6))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio6_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio6, sizeof (table_entry->au8MaxLspBandwidthPrio6));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio6, 0, sizeof (table_entry->au8MaxLspBandwidthPrio6));
				memcpy (table_entry->au8MaxLspBandwidthPrio6, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio6_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO7:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio7))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio7_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio7, sizeof (table_entry->au8MaxLspBandwidthPrio7));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio7, 0, sizeof (table_entry->au8MaxLspBandwidthPrio7));
				memcpy (table_entry->au8MaxLspBandwidthPrio7, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio7_len = request->requestvb->val_len;
				break;
			case NETELINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neTeLinkAdjCapTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPLOWERTYPE:
				memcpy (&table_entry->i32LowerType, pvOldDdata, sizeof (table_entry->i32LowerType));
				break;
			case NETELINKADJCAPLOWERENCODING:
				memcpy (&table_entry->i32LowerEncoding, pvOldDdata, sizeof (table_entry->i32LowerEncoding));
				break;
			case NETELINKADJCAPUPPERTYPE:
				memcpy (&table_entry->i32UpperType, pvOldDdata, sizeof (table_entry->i32UpperType));
				break;
			case NETELINKADJCAPUPPERENCODING:
				memcpy (&table_entry->i32UpperEncoding, pvOldDdata, sizeof (table_entry->i32UpperEncoding));
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO0:
				memcpy (table_entry->au8MaxLspBandwidthPrio0, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio0_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO1:
				memcpy (table_entry->au8MaxLspBandwidthPrio1, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio1_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO2:
				memcpy (table_entry->au8MaxLspBandwidthPrio2, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio2_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO3:
				memcpy (table_entry->au8MaxLspBandwidthPrio3, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio3_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO4:
				memcpy (table_entry->au8MaxLspBandwidthPrio4, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio4_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO5:
				memcpy (table_entry->au8MaxLspBandwidthPrio5, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio5_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO6:
				memcpy (table_entry->au8MaxLspBandwidthPrio6, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio6_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPMAXLSPBANDWIDTHPRIO7:
				memcpy (table_entry->au8MaxLspBandwidthPrio7, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio7_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETELINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTeLinkAdjCapTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NETELINKADJCAPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neTeLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETELINKADJCAPROWSTATUS:
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
					neTeLinkAdjCapTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neTeCompLinkAdjCapTable table mapper **/
void
neTeCompLinkAdjCapTable_init (void)
{
	extern oid neTeCompLinkAdjCapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neTeCompLinkAdjCapTable", &neTeCompLinkAdjCapTable_mapper,
		neTeCompLinkAdjCapTable_oid, OID_LENGTH (neTeCompLinkAdjCapTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: neTeCompLinkAdjCapId */,
		0);
	table_info->min_column = NETECOMPLINKADJCAPLOWERTYPE;
	table_info->max_column = NETECOMPLINKADJCAPSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neTeCompLinkAdjCapTable_getFirst;
	iinfo->get_next_data_point = &neTeCompLinkAdjCapTable_getNext;
	iinfo->get_data_point = &neTeCompLinkAdjCapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neTeCompLinkAdjCapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neTeCompLinkAdjCapEntry_t *pEntry1 = xBTree_entry (pNode1, neTeCompLinkAdjCapEntry_t, oBTreeNode);
	register neTeCompLinkAdjCapEntry_t *pEntry2 = xBTree_entry (pNode2, neTeCompLinkAdjCapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oNeTeCompLinkAdjCapTable_BTree = xBTree_initInline (&neTeCompLinkAdjCapTable_BTreeNodeCmp);

/* create a new row in the table */
neTeCompLinkAdjCapEntry_t *
neTeCompLinkAdjCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeCompLinkAdjCapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neTeCompLinkAdjCapStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree);
	return poEntry;
}

neTeCompLinkAdjCapEntry_t *
neTeCompLinkAdjCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeCompLinkAdjCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTeCompLinkAdjCapEntry_t, oBTreeNode);
}

neTeCompLinkAdjCapEntry_t *
neTeCompLinkAdjCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register neTeCompLinkAdjCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neTeCompLinkAdjCapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neTeCompLinkAdjCapTable_removeEntry (neTeCompLinkAdjCapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neTeCompLinkAdjCapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeTeCompLinkAdjCapTable_BTree);
	return neTeCompLinkAdjCapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neTeCompLinkAdjCapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTeCompLinkAdjCapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neTeCompLinkAdjCapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeTeCompLinkAdjCapTable_BTree);
	return put_index_data;
}

bool
neTeCompLinkAdjCapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neTeCompLinkAdjCapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neTeCompLinkAdjCapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neTeCompLinkAdjCapTable table mapper */
int
neTeCompLinkAdjCapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neTeCompLinkAdjCapEntry_t *table_entry;
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPLOWERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LowerType);
				break;
			case NETECOMPLINKADJCAPLOWERENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LowerEncoding);
				break;
			case NETECOMPLINKADJCAPUPPERTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UpperType);
				break;
			case NETECOMPLINKADJCAPUPPERENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UpperEncoding);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO0:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio0, table_entry->u16MaxLspBandwidthPrio0_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio1, table_entry->u16MaxLspBandwidthPrio1_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio2, table_entry->u16MaxLspBandwidthPrio2_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio3, table_entry->u16MaxLspBandwidthPrio3_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO4:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio4, table_entry->u16MaxLspBandwidthPrio4_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO5:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio5, table_entry->u16MaxLspBandwidthPrio5_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO6:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio6, table_entry->u16MaxLspBandwidthPrio6_len);
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO7:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio7, table_entry->u16MaxLspBandwidthPrio7_len);
				break;
			case NETECOMPLINKADJCAPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NETECOMPLINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPLOWERTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPLOWERENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPUPPERTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPUPPERENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO0:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio0));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO1:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio1));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO2:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio2));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO3:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio3));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO4:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio4));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO5:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio5));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO6:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio6));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO7:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio7));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NETECOMPLINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neTeCompLinkAdjCapTable_createEntry (
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTeCompLinkAdjCapTable_removeEntry (table_entry);
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPLOWERTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LowerType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LowerType, sizeof (table_entry->i32LowerType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LowerType = *request->requestvb->val.integer;
				break;
			case NETECOMPLINKADJCAPLOWERENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LowerEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LowerEncoding, sizeof (table_entry->i32LowerEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LowerEncoding = *request->requestvb->val.integer;
				break;
			case NETECOMPLINKADJCAPUPPERTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UpperType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UpperType, sizeof (table_entry->i32UpperType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UpperType = *request->requestvb->val.integer;
				break;
			case NETECOMPLINKADJCAPUPPERENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UpperEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UpperEncoding, sizeof (table_entry->i32UpperEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UpperEncoding = *request->requestvb->val.integer;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO0:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio0))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio0_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio0, sizeof (table_entry->au8MaxLspBandwidthPrio0));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio0, 0, sizeof (table_entry->au8MaxLspBandwidthPrio0));
				memcpy (table_entry->au8MaxLspBandwidthPrio0, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio0_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio1))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio1_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio1, sizeof (table_entry->au8MaxLspBandwidthPrio1));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio1, 0, sizeof (table_entry->au8MaxLspBandwidthPrio1));
				memcpy (table_entry->au8MaxLspBandwidthPrio1, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio1_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio2))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio2_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio2, sizeof (table_entry->au8MaxLspBandwidthPrio2));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio2, 0, sizeof (table_entry->au8MaxLspBandwidthPrio2));
				memcpy (table_entry->au8MaxLspBandwidthPrio2, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio2_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio3))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio3_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio3, sizeof (table_entry->au8MaxLspBandwidthPrio3));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio3, 0, sizeof (table_entry->au8MaxLspBandwidthPrio3));
				memcpy (table_entry->au8MaxLspBandwidthPrio3, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio3_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio4))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio4_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio4, sizeof (table_entry->au8MaxLspBandwidthPrio4));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio4, 0, sizeof (table_entry->au8MaxLspBandwidthPrio4));
				memcpy (table_entry->au8MaxLspBandwidthPrio4, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio4_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio5))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio5_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio5, sizeof (table_entry->au8MaxLspBandwidthPrio5));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio5, 0, sizeof (table_entry->au8MaxLspBandwidthPrio5));
				memcpy (table_entry->au8MaxLspBandwidthPrio5, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio5_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO6:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio6))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio6_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio6, sizeof (table_entry->au8MaxLspBandwidthPrio6));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio6, 0, sizeof (table_entry->au8MaxLspBandwidthPrio6));
				memcpy (table_entry->au8MaxLspBandwidthPrio6, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio6_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO7:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio7))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MaxLspBandwidthPrio7_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio7, sizeof (table_entry->au8MaxLspBandwidthPrio7));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio7, 0, sizeof (table_entry->au8MaxLspBandwidthPrio7));
				memcpy (table_entry->au8MaxLspBandwidthPrio7, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MaxLspBandwidthPrio7_len = request->requestvb->val_len;
				break;
			case NETECOMPLINKADJCAPSTORAGETYPE:
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neTeCompLinkAdjCapTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPLOWERTYPE:
				memcpy (&table_entry->i32LowerType, pvOldDdata, sizeof (table_entry->i32LowerType));
				break;
			case NETECOMPLINKADJCAPLOWERENCODING:
				memcpy (&table_entry->i32LowerEncoding, pvOldDdata, sizeof (table_entry->i32LowerEncoding));
				break;
			case NETECOMPLINKADJCAPUPPERTYPE:
				memcpy (&table_entry->i32UpperType, pvOldDdata, sizeof (table_entry->i32UpperType));
				break;
			case NETECOMPLINKADJCAPUPPERENCODING:
				memcpy (&table_entry->i32UpperEncoding, pvOldDdata, sizeof (table_entry->i32UpperEncoding));
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO0:
				memcpy (table_entry->au8MaxLspBandwidthPrio0, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio0_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO1:
				memcpy (table_entry->au8MaxLspBandwidthPrio1, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio1_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO2:
				memcpy (table_entry->au8MaxLspBandwidthPrio2, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio2_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO3:
				memcpy (table_entry->au8MaxLspBandwidthPrio3, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio3_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO4:
				memcpy (table_entry->au8MaxLspBandwidthPrio4, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio4_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO5:
				memcpy (table_entry->au8MaxLspBandwidthPrio5, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio5_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO6:
				memcpy (table_entry->au8MaxLspBandwidthPrio6, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio6_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO7:
				memcpy (table_entry->au8MaxLspBandwidthPrio7, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MaxLspBandwidthPrio7_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NETECOMPLINKADJCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neTeCompLinkAdjCapTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NETECOMPLINKADJCAPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neTeCompLinkAdjCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NETECOMPLINKADJCAPROWSTATUS:
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
					neTeCompLinkAdjCapTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
