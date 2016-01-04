/*
 *  Copyright (c) 2008-2016
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
#include "ieee8021SpbMib.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021SpbMib_oid[] = {1,3,111,2,802,1,1,26};

static oid ieee8021SpbSys_oid[] = {1,3,111,2,802,1,1,26,1,1};

static oid ieee8021SpbMtidStaticTable_oid[] = {1,3,111,2,802,1,1,26,1,2};
static oid ieee8021SpbTopIxDynamicTable_oid[] = {1,3,111,2,802,1,1,26,1,3};
static oid ieee8021SpbEctStaticTable_oid[] = {1,3,111,2,802,1,1,26,1,4};
static oid ieee8021SpbEctDynamicTable_oid[] = {1,3,111,2,802,1,1,26,1,5};
static oid ieee8021SpbAdjStaticTable_oid[] = {1,3,111,2,802,1,1,26,1,6};
static oid ieee8021SpbAdjDynamicTable_oid[] = {1,3,111,2,802,1,1,26,1,7};
static oid ieee8021SpbTopNodeTable_oid[] = {1,3,111,2,802,1,1,26,1,8};
static oid ieee8021SpbTopEctTable_oid[] = {1,3,111,2,802,1,1,26,1,9};
static oid ieee8021SpbTopEdgeTable_oid[] = {1,3,111,2,802,1,1,26,1,10};
static oid ieee8021SpbmTopSrvTable_oid[] = {1,3,111,2,802,1,1,26,1,11};
static oid ieee8021SpbvTopSrvTable_oid[] = {1,3,111,2,802,1,1,26,1,12};



/**
 *	initialize ieee8021SpbMib group mapper
 */
void
ieee8021SpbMib_init (void)
{
	extern oid ieee8021SpbMib_oid[];
	extern oid ieee8021SpbSys_oid[];
	
	DEBUGMSGTL (("ieee8021SpbMib", "Initializing\n"));
	
	/* register ieee8021SpbSys scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ieee8021SpbSys_mapper", &ieee8021SpbSys_mapper,
			ieee8021SpbSys_oid, OID_LENGTH (ieee8021SpbSys_oid),
			HANDLER_CAN_RWRITE
		),
		IEEE8021SPBSYSAREAADDRESS,
		IEEE8021SPBSYSDIGESTCONVENTION
	);
	
	
	/* register ieee8021SpbMib group table mappers */
	ieee8021SpbMtidStaticTable_init ();
	ieee8021SpbTopIxDynamicTable_init ();
	ieee8021SpbEctStaticTable_init ();
	ieee8021SpbEctDynamicTable_init ();
	ieee8021SpbAdjStaticTable_init ();
	ieee8021SpbAdjDynamicTable_init ();
	ieee8021SpbTopNodeTable_init ();
	ieee8021SpbTopEctTable_init ();
	ieee8021SpbTopEdgeTable_init ();
	ieee8021SpbmTopSrvTable_init ();
	ieee8021SpbvTopSrvTable_init ();
	
	/* register ieee8021SpbMib modules */
	sysORTable_createRegister ("ieee8021SpbMib", ieee8021SpbMib_oid, OID_LENGTH (ieee8021SpbMib_oid));
}


/**
 *	scalar mapper(s)
 */
ieee8021SpbSys_t oIeee8021SpbSys;

/** ieee8021SpbSys scalar mapper **/
int
ieee8021SpbSys_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ieee8021SpbSys_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021SpbSys_oid) - 1])
			{
			case IEEE8021SPBSYSAREAADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8AreaAddress, oIeee8021SpbSys.u16AreaAddress_len);
				break;
			case IEEE8021SPBSYSID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8Id, oIeee8021SpbSys.u16Id_len);
				break;
			case IEEE8021SPBSYSCONTROLADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8ControlAddr, oIeee8021SpbSys.u16ControlAddr_len);
				break;
			case IEEE8021SPBSYSNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8Name, oIeee8021SpbSys.u16Name_len);
				break;
			case IEEE8021SPBSYSBRIDGEPRIORITY:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8BridgePriority, oIeee8021SpbSys.u16BridgePriority_len);
				break;
			case IEEE8021SPBMSYSSPSOURCEID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021SpbSys.au8SpbmSysSPSourceId, oIeee8021SpbSys.u16SpbmSysSPSourceId_len);
				break;
			case IEEE8021SPBVSYSMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIeee8021SpbSys.i32SpbvSysMode);
				break;
			case IEEE8021SPBMSYSMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIeee8021SpbSys.i32SpbmSysMode);
				break;
			case IEEE8021SPBSYSDIGESTCONVENTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIeee8021SpbSys.i32DigestConvention);
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
			switch (request->requestvb->name[OID_LENGTH (ieee8021SpbSys_oid) - 1])
			{
			case IEEE8021SPBSYSAREAADDRESS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBSYSID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBSYSCONTROLADDR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBMSYSSPSOURCEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBVSYSMODE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBMSYSMODE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IEEE8021SPBSYSDIGESTCONVENTION:
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
			switch (request->requestvb->name[OID_LENGTH (ieee8021SpbSys_oid) - 1])
			{
			case IEEE8021SPBSYSAREAADDRESS:
				/* XXX: perform the value change here */
				memset (oIeee8021SpbSys.au8AreaAddress, 0, sizeof (oIeee8021SpbSys.au8AreaAddress));
				memcpy (oIeee8021SpbSys.au8AreaAddress, request->requestvb->val.string, request->requestvb->val_len);
				oIeee8021SpbSys.u16AreaAddress_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBSYSID:
				/* XXX: perform the value change here */
				memset (oIeee8021SpbSys.au8Id, 0, sizeof (oIeee8021SpbSys.au8Id));
				memcpy (oIeee8021SpbSys.au8Id, request->requestvb->val.string, request->requestvb->val_len);
				oIeee8021SpbSys.u16Id_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBSYSCONTROLADDR:
				/* XXX: perform the value change here */
				memset (oIeee8021SpbSys.au8ControlAddr, 0, sizeof (oIeee8021SpbSys.au8ControlAddr));
				memcpy (oIeee8021SpbSys.au8ControlAddr, request->requestvb->val.string, request->requestvb->val_len);
				oIeee8021SpbSys.u16ControlAddr_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBMSYSSPSOURCEID:
				/* XXX: perform the value change here */
				memset (oIeee8021SpbSys.au8SpbmSysSPSourceId, 0, sizeof (oIeee8021SpbSys.au8SpbmSysSPSourceId));
				memcpy (oIeee8021SpbSys.au8SpbmSysSPSourceId, request->requestvb->val.string, request->requestvb->val_len);
				oIeee8021SpbSys.u16SpbmSysSPSourceId_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBVSYSMODE:
				/* XXX: perform the value change here */
				oIeee8021SpbSys.i32SpbvSysMode = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBMSYSMODE:
				/* XXX: perform the value change here */
				oIeee8021SpbSys.i32SpbmSysMode = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IEEE8021SPBSYSDIGESTCONVENTION:
				/* XXX: perform the value change here */
				oIeee8021SpbSys.i32DigestConvention = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (ieee8021SpbSys_oid) - 1])
			{
			case IEEE8021SPBSYSAREAADDRESS:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBSYSID:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBSYSCONTROLADDR:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBMSYSSPSOURCEID:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBVSYSMODE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBMSYSMODE:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IEEE8021SPBSYSDIGESTCONVENTION:
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
/** initialize ieee8021SpbMtidStaticTable table mapper **/
void
ieee8021SpbMtidStaticTable_init (void)
{
	extern oid ieee8021SpbMtidStaticTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbMtidStaticTable", &ieee8021SpbMtidStaticTable_mapper,
		ieee8021SpbMtidStaticTable_oid, OID_LENGTH (ieee8021SpbMtidStaticTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbMtidStaticEntryMtid */,
		ASN_UNSIGNED /* index: ieee8021SpbTopIx */,
		0);
	table_info->min_column = IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD;
	table_info->max_column = IEEE8021SPBMTIDSTATICENTRYROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbMtidStaticTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbMtidStaticTable_getNext;
	iinfo->get_data_point = &ieee8021SpbMtidStaticTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbMtidStaticTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbMtidStaticEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbMtidStaticEntry_t, oBTreeNode);
	register ieee8021SpbMtidStaticEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbMtidStaticEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryMtid < pEntry2->u32EntryMtid) ||
		(pEntry1->u32EntryMtid == pEntry2->u32EntryMtid && pEntry1->u32TopIx < pEntry2->u32TopIx) ? -1:
		(pEntry1->u32EntryMtid == pEntry2->u32EntryMtid && pEntry1->u32TopIx == pEntry2->u32TopIx) ? 0: 1;
}

xBTree_t oIeee8021SpbMtidStaticTable_BTree = xBTree_initInline (&ieee8021SpbMtidStaticTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbMtidStaticEntry_t *
ieee8021SpbMtidStaticTable_createEntry (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx)
{
	register ieee8021SpbMtidStaticEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryMtid = u32EntryMtid;
	poEntry->u32TopIx = u32TopIx;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32MTidStaticEntryMtidOverload = ieee8021SpbMTidStaticEntryMtidOverload_false_c;
	poEntry->u8EntryRowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree);
	return poEntry;
}

ieee8021SpbMtidStaticEntry_t *
ieee8021SpbMtidStaticTable_getByIndex (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx)
{
	register ieee8021SpbMtidStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryMtid = u32EntryMtid;
	poTmpEntry->u32TopIx = u32TopIx;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbMtidStaticEntry_t, oBTreeNode);
}

ieee8021SpbMtidStaticEntry_t *
ieee8021SpbMtidStaticTable_getNextIndex (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx)
{
	register ieee8021SpbMtidStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryMtid = u32EntryMtid;
	poTmpEntry->u32TopIx = u32TopIx;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbMtidStaticEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbMtidStaticTable_removeEntry (ieee8021SpbMtidStaticEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbMtidStaticTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbMtidStaticTable_BTree);
	return ieee8021SpbMtidStaticTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbMtidStaticTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbMtidStaticEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbMtidStaticEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryMtid);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32TopIx);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbMtidStaticTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbMtidStaticTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbMtidStaticEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021SpbMtidStaticTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbMtidStaticTable table mapper */
int
ieee8021SpbMtidStaticTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbMtidStaticEntry_t *table_entry;
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MTidStaticEntryMtidOverload);
				break;
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8EntryRowStatus);
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021SpbMtidStaticTable_createEntry (
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbMtidStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MTidStaticEntryMtidOverload))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MTidStaticEntryMtidOverload, sizeof (table_entry->i32MTidStaticEntryMtidOverload));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MTidStaticEntryMtidOverload = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021SpbMtidStaticTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD:
				memcpy (&table_entry->i32MTidStaticEntryMtidOverload, pvOldDdata, sizeof (table_entry->i32MTidStaticEntryMtidOverload));
				break;
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbMtidStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbMtidStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTIDSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8EntryRowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8EntryRowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021SpbMtidStaticTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021SpbTopIxDynamicTable table mapper **/
void
ieee8021SpbTopIxDynamicTable_init (void)
{
	extern oid ieee8021SpbTopIxDynamicTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbTopIxDynamicTable", &ieee8021SpbTopIxDynamicTable_mapper,
		ieee8021SpbTopIxDynamicTable_oid, OID_LENGTH (ieee8021SpbTopIxDynamicTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbTopIxDynamicEntryTopIx */,
		0);
	table_info->min_column = IEEE8021SPBTOPIXDYNAMICENTRYAGREEDIGEST;
	table_info->max_column = IEEE8021SPBTOPIXDYNAMICENTRYAUXMCID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbTopIxDynamicTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbTopIxDynamicTable_getNext;
	iinfo->get_data_point = &ieee8021SpbTopIxDynamicTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbTopIxDynamicTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbTopIxDynamicEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbTopIxDynamicEntry_t, oBTreeNode);
	register ieee8021SpbTopIxDynamicEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbTopIxDynamicEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx) ? 0: 1;
}

xBTree_t oIeee8021SpbTopIxDynamicTable_BTree = xBTree_initInline (&ieee8021SpbTopIxDynamicTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbTopIxDynamicEntry_t *
ieee8021SpbTopIxDynamicTable_createEntry (
	uint32_t u32EntryTopIx)
{
	register ieee8021SpbTopIxDynamicEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree);
	return poEntry;
}

ieee8021SpbTopIxDynamicEntry_t *
ieee8021SpbTopIxDynamicTable_getByIndex (
	uint32_t u32EntryTopIx)
{
	register ieee8021SpbTopIxDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopIxDynamicEntry_t, oBTreeNode);
}

ieee8021SpbTopIxDynamicEntry_t *
ieee8021SpbTopIxDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx)
{
	register ieee8021SpbTopIxDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopIxDynamicEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbTopIxDynamicTable_removeEntry (ieee8021SpbTopIxDynamicEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbTopIxDynamicTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbTopIxDynamicTable_BTree);
	return ieee8021SpbTopIxDynamicTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbTopIxDynamicTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopIxDynamicEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbTopIxDynamicEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbTopIxDynamicTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbTopIxDynamicTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopIxDynamicEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021SpbTopIxDynamicTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbTopIxDynamicTable table mapper */
int
ieee8021SpbTopIxDynamicTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbTopIxDynamicEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbTopIxDynamicEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBTOPIXDYNAMICENTRYAGREEDIGEST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryAgreeDigest, table_entry->u16EntryAgreeDigest_len);
				break;
			case IEEE8021SPBTOPIXDYNAMICENTRYMCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryMCID, table_entry->u16EntryMCID_len);
				break;
			case IEEE8021SPBTOPIXDYNAMICENTRYAUXMCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryAuxMCID, table_entry->u16EntryAuxMCID_len);
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

/** initialize ieee8021SpbEctStaticTable table mapper **/
void
ieee8021SpbEctStaticTable_init (void)
{
	extern oid ieee8021SpbEctStaticTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbEctStaticTable", &ieee8021SpbEctStaticTable_mapper,
		ieee8021SpbEctStaticTable_oid, OID_LENGTH (ieee8021SpbEctStaticTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbEctStaticEntryTopIx */,
		ASN_INTEGER /* index: ieee8021SpbEctStaticEntryBaseVid */,
		0);
	table_info->min_column = IEEE8021SPBECTSTATICENTRYECTALGORITHM;
	table_info->max_column = IEEE8021SPBECTSTATICENTRYROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbEctStaticTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbEctStaticTable_getNext;
	iinfo->get_data_point = &ieee8021SpbEctStaticTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbEctStaticTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbEctStaticEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbEctStaticEntry_t, oBTreeNode);
	register ieee8021SpbEctStaticEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbEctStaticEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->i32EntryBaseVid < pEntry2->i32EntryBaseVid) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->i32EntryBaseVid == pEntry2->i32EntryBaseVid) ? 0: 1;
}

xBTree_t oIeee8021SpbEctStaticTable_BTree = xBTree_initInline (&ieee8021SpbEctStaticTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbEctStaticEntry_t *
ieee8021SpbEctStaticTable_createEntry (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctStaticEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	poEntry->i32EntryBaseVid = i32EntryBaseVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8EntryEctAlgorithm = "00-80-c2-01"*/;
	poEntry->u8EntryRowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree);
	return poEntry;
}

ieee8021SpbEctStaticEntry_t *
ieee8021SpbEctStaticTable_getByIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbEctStaticEntry_t, oBTreeNode);
}

ieee8021SpbEctStaticEntry_t *
ieee8021SpbEctStaticTable_getNextIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbEctStaticEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbEctStaticTable_removeEntry (ieee8021SpbEctStaticEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbEctStaticTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbEctStaticTable_BTree);
	return ieee8021SpbEctStaticTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbEctStaticTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbEctStaticEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbEctStaticEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32EntryBaseVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbEctStaticTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbEctStaticTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbEctStaticEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021SpbEctStaticTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbEctStaticTable table mapper */
int
ieee8021SpbEctStaticTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbEctStaticEntry_t *table_entry;
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYECTALGORITHM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryEctAlgorithm, table_entry->u16EntryEctAlgorithm_len);
				break;
			case IEEE8021SPBVECTSTATICENTRYSPVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SpbvEctStaticEntrySpvid);
				break;
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8EntryRowStatus);
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYECTALGORITHM:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8EntryEctAlgorithm));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021SPBVECTSTATICENTRYSPVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021SpbEctStaticTable_createEntry (
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbEctStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYECTALGORITHM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8EntryEctAlgorithm))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16EntryEctAlgorithm_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8EntryEctAlgorithm, sizeof (table_entry->au8EntryEctAlgorithm));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8EntryEctAlgorithm, 0, sizeof (table_entry->au8EntryEctAlgorithm));
				memcpy (table_entry->au8EntryEctAlgorithm, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16EntryEctAlgorithm_len = request->requestvb->val_len;
				break;
			case IEEE8021SPBVECTSTATICENTRYSPVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SpbvEctStaticEntrySpvid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SpbvEctStaticEntrySpvid, sizeof (table_entry->i32SpbvEctStaticEntrySpvid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SpbvEctStaticEntrySpvid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021SpbEctStaticTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYECTALGORITHM:
				memcpy (table_entry->au8EntryEctAlgorithm, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16EntryEctAlgorithm_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021SPBVECTSTATICENTRYSPVID:
				memcpy (&table_entry->i32SpbvEctStaticEntrySpvid, pvOldDdata, sizeof (table_entry->i32SpbvEctStaticEntrySpvid));
				break;
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbEctStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbEctStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8EntryRowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8EntryRowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021SpbEctStaticTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021SpbEctDynamicTable table mapper **/
void
ieee8021SpbEctDynamicTable_init (void)
{
	extern oid ieee8021SpbEctDynamicTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbEctDynamicTable", &ieee8021SpbEctDynamicTable_mapper,
		ieee8021SpbEctDynamicTable_oid, OID_LENGTH (ieee8021SpbEctDynamicTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbEctDynamicEntryTopIx */,
		ASN_INTEGER /* index: ieee8021SpbEctDynamicEntryBaseVid */,
		0);
	table_info->min_column = IEEE8021SPBECTDYNAMICENTRYMODE;
	table_info->max_column = IEEE8021SPBECTDYNAMICENTRYINGRESSCHECKDISCARDS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbEctDynamicTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbEctDynamicTable_getNext;
	iinfo->get_data_point = &ieee8021SpbEctDynamicTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbEctDynamicTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbEctDynamicEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbEctDynamicEntry_t, oBTreeNode);
	register ieee8021SpbEctDynamicEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbEctDynamicEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->i32EntryBaseVid < pEntry2->i32EntryBaseVid) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->i32EntryBaseVid == pEntry2->i32EntryBaseVid) ? 0: 1;
}

xBTree_t oIeee8021SpbEctDynamicTable_BTree = xBTree_initInline (&ieee8021SpbEctDynamicTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbEctDynamicEntry_t *
ieee8021SpbEctDynamicTable_createEntry (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctDynamicEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	poEntry->i32EntryBaseVid = i32EntryBaseVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree);
	return poEntry;
}

ieee8021SpbEctDynamicEntry_t *
ieee8021SpbEctDynamicTable_getByIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbEctDynamicEntry_t, oBTreeNode);
}

ieee8021SpbEctDynamicEntry_t *
ieee8021SpbEctDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbEctDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbEctDynamicEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbEctDynamicTable_removeEntry (ieee8021SpbEctDynamicEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbEctDynamicTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbEctDynamicTable_BTree);
	return ieee8021SpbEctDynamicTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbEctDynamicTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbEctDynamicEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbEctDynamicEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32EntryBaseVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbEctDynamicTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbEctDynamicTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbEctDynamicEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021SpbEctDynamicTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbEctDynamicTable table mapper */
int
ieee8021SpbEctDynamicTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbEctDynamicEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbEctDynamicEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBECTDYNAMICENTRYMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryMode);
				break;
			case IEEE8021SPBECTDYNAMICENTRYLOCALUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryLocalUse);
				break;
			case IEEE8021SPBECTDYNAMICENTRYREMOTEUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryRemoteUse);
				break;
			case IEEE8021SPBECTDYNAMICENTRYINGRESSCHECKDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryIngressCheckDiscards);
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

/** initialize ieee8021SpbAdjStaticTable table mapper **/
void
ieee8021SpbAdjStaticTable_init (void)
{
	extern oid ieee8021SpbAdjStaticTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbAdjStaticTable", &ieee8021SpbAdjStaticTable_mapper,
		ieee8021SpbAdjStaticTable_oid, OID_LENGTH (ieee8021SpbAdjStaticTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbAdjStaticEntryTopIx */,
		ASN_INTEGER /* index: ieee8021SpbAdjStaticEntryIfIndex */,
		0);
	table_info->min_column = IEEE8021SPBADJSTATICENTRYMETRIC;
	table_info->max_column = IEEE8021SPBADJSTATICENTRYROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbAdjStaticTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbAdjStaticTable_getNext;
	iinfo->get_data_point = &ieee8021SpbAdjStaticTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbAdjStaticTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbAdjStaticEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbAdjStaticEntry_t, oBTreeNode);
	register ieee8021SpbAdjStaticEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbAdjStaticEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->u32EntryIfIndex < pEntry2->u32EntryIfIndex) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->u32EntryIfIndex == pEntry2->u32EntryIfIndex) ? 0: 1;
}

xBTree_t oIeee8021SpbAdjStaticTable_BTree = xBTree_initInline (&ieee8021SpbAdjStaticTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbAdjStaticEntry_t *
ieee8021SpbAdjStaticTable_createEntry (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex)
{
	register ieee8021SpbAdjStaticEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	poEntry->u32EntryIfIndex = u32EntryIfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8EntryRowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree);
	return poEntry;
}

ieee8021SpbAdjStaticEntry_t *
ieee8021SpbAdjStaticTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex)
{
	register ieee8021SpbAdjStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->u32EntryIfIndex = u32EntryIfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbAdjStaticEntry_t, oBTreeNode);
}

ieee8021SpbAdjStaticEntry_t *
ieee8021SpbAdjStaticTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex)
{
	register ieee8021SpbAdjStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->u32EntryIfIndex = u32EntryIfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbAdjStaticEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbAdjStaticTable_removeEntry (ieee8021SpbAdjStaticEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbAdjStaticTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbAdjStaticTable_BTree);
	return ieee8021SpbAdjStaticTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbAdjStaticTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbAdjStaticEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbAdjStaticEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32EntryIfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbAdjStaticTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbAdjStaticTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbAdjStaticEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021SpbAdjStaticTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbAdjStaticTable table mapper */
int
ieee8021SpbAdjStaticTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbAdjStaticEntry_t *table_entry;
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryMetric);
				break;
			case IEEE8021SPBADJSTATICENTRYIFADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryIfAdminState);
				break;
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8EntryRowStatus);
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021SPBADJSTATICENTRYIFADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021SpbAdjStaticTable_createEntry (
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbAdjStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EntryMetric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EntryMetric, sizeof (table_entry->i32EntryMetric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EntryMetric = *request->requestvb->val.integer;
				break;
			case IEEE8021SPBADJSTATICENTRYIFADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EntryIfAdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EntryIfAdminState, sizeof (table_entry->i32EntryIfAdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EntryIfAdminState = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021SpbAdjStaticTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYMETRIC:
				memcpy (&table_entry->i32EntryMetric, pvOldDdata, sizeof (table_entry->i32EntryMetric));
				break;
			case IEEE8021SPBADJSTATICENTRYIFADMINSTATE:
				memcpy (&table_entry->i32EntryIfAdminState, pvOldDdata, sizeof (table_entry->i32EntryIfAdminState));
				break;
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021SpbAdjStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021SpbAdjStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJSTATICENTRYROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8EntryRowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8EntryRowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021SpbAdjStaticTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021SpbAdjDynamicTable table mapper **/
void
ieee8021SpbAdjDynamicTable_init (void)
{
	extern oid ieee8021SpbAdjDynamicTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbAdjDynamicTable", &ieee8021SpbAdjDynamicTable_mapper,
		ieee8021SpbAdjDynamicTable_oid, OID_LENGTH (ieee8021SpbAdjDynamicTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbAdjDynamicEntryTopIx */,
		ASN_INTEGER /* index: ieee8021SpbAdjDynamicEntryIfIndex */,
		ASN_OCTET_STR /* index: ieee8021SpbAdjDynamicEntryPeerSysId */,
		0);
	table_info->min_column = IEEE8021SPBADJDYNAMICENTRYPORT;
	table_info->max_column = IEEE8021SPBADJDYNAMICENTRYISISCIRCINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbAdjDynamicTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbAdjDynamicTable_getNext;
	iinfo->get_data_point = &ieee8021SpbAdjDynamicTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbAdjDynamicTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbAdjDynamicEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbAdjDynamicEntry_t, oBTreeNode);
	register ieee8021SpbAdjDynamicEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbAdjDynamicEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->u32EntryIfIndex < pEntry2->u32EntryIfIndex) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->u32EntryIfIndex == pEntry2->u32EntryIfIndex && xBinCmp (pEntry1->au8EntryPeerSysId, pEntry2->au8EntryPeerSysId, pEntry1->u16EntryPeerSysId_len, pEntry2->u16EntryPeerSysId_len) == -1) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && pEntry1->u32EntryIfIndex == pEntry2->u32EntryIfIndex && xBinCmp (pEntry1->au8EntryPeerSysId, pEntry2->au8EntryPeerSysId, pEntry1->u16EntryPeerSysId_len, pEntry2->u16EntryPeerSysId_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021SpbAdjDynamicTable_BTree = xBTree_initInline (&ieee8021SpbAdjDynamicTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbAdjDynamicEntry_t *
ieee8021SpbAdjDynamicTable_createEntry (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len)
{
	register ieee8021SpbAdjDynamicEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	poEntry->u32EntryIfIndex = u32EntryIfIndex;
	memcpy (poEntry->au8EntryPeerSysId, pau8EntryPeerSysId, u16EntryPeerSysId_len);
	poEntry->u16EntryPeerSysId_len = u16EntryPeerSysId_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree);
	return poEntry;
}

ieee8021SpbAdjDynamicEntry_t *
ieee8021SpbAdjDynamicTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len)
{
	register ieee8021SpbAdjDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->u32EntryIfIndex = u32EntryIfIndex;
	memcpy (poTmpEntry->au8EntryPeerSysId, pau8EntryPeerSysId, u16EntryPeerSysId_len);
	poTmpEntry->u16EntryPeerSysId_len = u16EntryPeerSysId_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbAdjDynamicEntry_t, oBTreeNode);
}

ieee8021SpbAdjDynamicEntry_t *
ieee8021SpbAdjDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len)
{
	register ieee8021SpbAdjDynamicEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	poTmpEntry->u32EntryIfIndex = u32EntryIfIndex;
	memcpy (poTmpEntry->au8EntryPeerSysId, pau8EntryPeerSysId, u16EntryPeerSysId_len);
	poTmpEntry->u16EntryPeerSysId_len = u16EntryPeerSysId_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbAdjDynamicEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbAdjDynamicTable_removeEntry (ieee8021SpbAdjDynamicEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbAdjDynamicTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbAdjDynamicTable_BTree);
	return ieee8021SpbAdjDynamicTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbAdjDynamicTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbAdjDynamicEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbAdjDynamicEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32EntryIfIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntryPeerSysId, poEntry->u16EntryPeerSysId_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbAdjDynamicTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbAdjDynamicTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbAdjDynamicEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021SpbAdjDynamicTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbAdjDynamicTable table mapper */
int
ieee8021SpbAdjDynamicTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbAdjDynamicEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbAdjDynamicEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBADJDYNAMICENTRYPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryPort);
				break;
			case IEEE8021SPBADJDYNAMICENTRYIFOPERSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryIfOperState);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERSYSNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryPeerSysName, table_entry->u16EntryPeerSysName_len);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERAGREEDIGEST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryPeerAgreeDigest, table_entry->u16EntryPeerAgreeDigest_len);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERMCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryPeerMCID, table_entry->u16EntryPeerMCID_len);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERAUXMCID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryPeerAuxMCID, table_entry->u16EntryPeerAuxMCID_len);
				break;
			case IEEE8021SPBADJDYNAMICENTRYLOCALCIRCUITID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryLocalCircuitID);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERLOCALCIRCUITID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryPeerLocalCircuitID);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPORTIDENTIFIER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryPortIdentifier);
				break;
			case IEEE8021SPBADJDYNAMICENTRYPEERPORTIDENTIFIER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryPeerPortIdentifier);
				break;
			case IEEE8021SPBADJDYNAMICENTRYISISCIRCINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EntryIsisCircIndex);
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

/** initialize ieee8021SpbTopNodeTable table mapper **/
void
ieee8021SpbTopNodeTable_init (void)
{
	extern oid ieee8021SpbTopNodeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbTopNodeTable", &ieee8021SpbTopNodeTable_mapper,
		ieee8021SpbTopNodeTable_oid, OID_LENGTH (ieee8021SpbTopNodeTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbTopNodeEntryTopIx */,
		ASN_OCTET_STR /* index: ieee8021SpbTopNodeEntrySysId */,
		0);
	table_info->min_column = IEEE8021SPBTOPNODEENTRYBRIDGEPRIORITY;
	table_info->max_column = IEEE8021SPBTOPNODEENTRYSYSNAME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbTopNodeTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbTopNodeTable_getNext;
	iinfo->get_data_point = &ieee8021SpbTopNodeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbTopNodeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbTopNodeEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbTopNodeEntry_t, oBTreeNode);
	register ieee8021SpbTopNodeEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbTopNodeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == -1) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021SpbTopNodeTable_BTree = xBTree_initInline (&ieee8021SpbTopNodeTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbTopNodeEntry_t *
ieee8021SpbTopNodeTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len)
{
	register ieee8021SpbTopNodeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poEntry->u16EntrySysId_len = u16EntrySysId_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree);
	return poEntry;
}

ieee8021SpbTopNodeEntry_t *
ieee8021SpbTopNodeTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len)
{
	register ieee8021SpbTopNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopNodeEntry_t, oBTreeNode);
}

ieee8021SpbTopNodeEntry_t *
ieee8021SpbTopNodeTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len)
{
	register ieee8021SpbTopNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopNodeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbTopNodeTable_removeEntry (ieee8021SpbTopNodeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbTopNodeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbTopNodeTable_BTree);
	return ieee8021SpbTopNodeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbTopNodeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopNodeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbTopNodeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysId, poEntry->u16EntrySysId_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbTopNodeTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbTopNodeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopNodeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021SpbTopNodeTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbTopNodeTable table mapper */
int
ieee8021SpbTopNodeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbTopNodeEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbTopNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBTOPNODEENTRYBRIDGEPRIORITY:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryBridgePriority, table_entry->u16EntryBridgePriority_len);
				break;
			case IEEE8021SPBMTOPNODEENTRYSPSOURCEID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SpbmTopNodeEntrySPsourceID, table_entry->u16SpbmTopNodeEntrySPsourceID_len);
				break;
			case IEEE8021SPBTOPNODEENTRYSYSNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntrySysName, table_entry->u16EntrySysName_len);
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

/** initialize ieee8021SpbTopEctTable table mapper **/
void
ieee8021SpbTopEctTable_init (void)
{
	extern oid ieee8021SpbTopEctTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbTopEctTable", &ieee8021SpbTopEctTable_mapper,
		ieee8021SpbTopEctTable_oid, OID_LENGTH (ieee8021SpbTopEctTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbTopEctEntryTopIx */,
		ASN_OCTET_STR /* index: ieee8021SpbTopEctEntrySysId */,
		ASN_INTEGER /* index: ieee8021SpbTopEctEntryBaseVid */,
		0);
	table_info->min_column = IEEE8021SPBTOPECTENTRYECTALGORITHM;
	table_info->max_column = IEEE8021SPBTOPECTENTRYLOCALUSE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbTopEctTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbTopEctTable_getNext;
	iinfo->get_data_point = &ieee8021SpbTopEctTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbTopEctTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbTopEctEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbTopEctEntry_t, oBTreeNode);
	register ieee8021SpbTopEctEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbTopEctEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == -1) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->i32EntryBaseVid < pEntry2->i32EntryBaseVid) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->i32EntryBaseVid == pEntry2->i32EntryBaseVid) ? 0: 1;
}

xBTree_t oIeee8021SpbTopEctTable_BTree = xBTree_initInline (&ieee8021SpbTopEctTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbTopEctEntry_t *
ieee8021SpbTopEctTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbTopEctEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poEntry->u16EntrySysId_len = u16EntrySysId_len;
	poEntry->i32EntryBaseVid = i32EntryBaseVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree);
	return poEntry;
}

ieee8021SpbTopEctEntry_t *
ieee8021SpbTopEctTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbTopEctEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopEctEntry_t, oBTreeNode);
}

ieee8021SpbTopEctEntry_t *
ieee8021SpbTopEctTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid)
{
	register ieee8021SpbTopEctEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopEctEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbTopEctTable_removeEntry (ieee8021SpbTopEctEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbTopEctTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbTopEctTable_BTree);
	return ieee8021SpbTopEctTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbTopEctTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopEctEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbTopEctEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysId, poEntry->u16EntrySysId_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32EntryBaseVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbTopEctTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbTopEctTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopEctEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021SpbTopEctTable_getByIndex (
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

/* ieee8021SpbTopEctTable table mapper */
int
ieee8021SpbTopEctTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbTopEctEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbTopEctEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBTOPECTENTRYECTALGORITHM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryEctAlgorithm, table_entry->u16EntryEctAlgorithm_len);
				break;
			case IEEE8021SPBTOPECTENTRYMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryMode);
				break;
			case IEEE8021SPBVTOPECTSYSMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SpbvTopEctSysMode);
				break;
			case IEEE8021SPBVTOPECTENTRYSPVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SpbvTopEctEntrySpvid);
				break;
			case IEEE8021SPBTOPECTENTRYLOCALUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryLocalUse);
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

/** initialize ieee8021SpbTopEdgeTable table mapper **/
void
ieee8021SpbTopEdgeTable_init (void)
{
	extern oid ieee8021SpbTopEdgeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbTopEdgeTable", &ieee8021SpbTopEdgeTable_mapper,
		ieee8021SpbTopEdgeTable_oid, OID_LENGTH (ieee8021SpbTopEdgeTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbTopEdgeEntryTopIx */,
		ASN_OCTET_STR /* index: ieee8021SpbTopEdgeEntrySysIdNear */,
		ASN_OCTET_STR /* index: ieee8021SpbTopEdgeEntrySysIdFar */,
		0);
	table_info->min_column = IEEE8021SPBTOPEDGEENTRYMETRICNEAR2FAR;
	table_info->max_column = IEEE8021SPBTOPEDGEENTRYMETRICFAR2NEAR;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbTopEdgeTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbTopEdgeTable_getNext;
	iinfo->get_data_point = &ieee8021SpbTopEdgeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbTopEdgeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbTopEdgeEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbTopEdgeEntry_t, oBTreeNode);
	register ieee8021SpbTopEdgeEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbTopEdgeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysIdNear, pEntry2->au8EntrySysIdNear, pEntry1->u16EntrySysIdNear_len, pEntry2->u16EntrySysIdNear_len) == -1) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysIdNear, pEntry2->au8EntrySysIdNear, pEntry1->u16EntrySysIdNear_len, pEntry2->u16EntrySysIdNear_len) == 0 && xBinCmp (pEntry1->au8EntrySysIdFar, pEntry2->au8EntrySysIdFar, pEntry1->u16EntrySysIdFar_len, pEntry2->u16EntrySysIdFar_len) == -1) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysIdNear, pEntry2->au8EntrySysIdNear, pEntry1->u16EntrySysIdNear_len, pEntry2->u16EntrySysIdNear_len) == 0 && xBinCmp (pEntry1->au8EntrySysIdFar, pEntry2->au8EntrySysIdFar, pEntry1->u16EntrySysIdFar_len, pEntry2->u16EntrySysIdFar_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021SpbTopEdgeTable_BTree = xBTree_initInline (&ieee8021SpbTopEdgeTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbTopEdgeEntry_t *
ieee8021SpbTopEdgeTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len)
{
	register ieee8021SpbTopEdgeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poEntry->au8EntrySysIdNear, pau8EntrySysIdNear, u16EntrySysIdNear_len);
	poEntry->u16EntrySysIdNear_len = u16EntrySysIdNear_len;
	memcpy (poEntry->au8EntrySysIdFar, pau8EntrySysIdFar, u16EntrySysIdFar_len);
	poEntry->u16EntrySysIdFar_len = u16EntrySysIdFar_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree);
	return poEntry;
}

ieee8021SpbTopEdgeEntry_t *
ieee8021SpbTopEdgeTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len)
{
	register ieee8021SpbTopEdgeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysIdNear, pau8EntrySysIdNear, u16EntrySysIdNear_len);
	poTmpEntry->u16EntrySysIdNear_len = u16EntrySysIdNear_len;
	memcpy (poTmpEntry->au8EntrySysIdFar, pau8EntrySysIdFar, u16EntrySysIdFar_len);
	poTmpEntry->u16EntrySysIdFar_len = u16EntrySysIdFar_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopEdgeEntry_t, oBTreeNode);
}

ieee8021SpbTopEdgeEntry_t *
ieee8021SpbTopEdgeTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len)
{
	register ieee8021SpbTopEdgeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysIdNear, pau8EntrySysIdNear, u16EntrySysIdNear_len);
	poTmpEntry->u16EntrySysIdNear_len = u16EntrySysIdNear_len;
	memcpy (poTmpEntry->au8EntrySysIdFar, pau8EntrySysIdFar, u16EntrySysIdFar_len);
	poTmpEntry->u16EntrySysIdFar_len = u16EntrySysIdFar_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbTopEdgeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbTopEdgeTable_removeEntry (ieee8021SpbTopEdgeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbTopEdgeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbTopEdgeTable_BTree);
	return ieee8021SpbTopEdgeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbTopEdgeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopEdgeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbTopEdgeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysIdNear, poEntry->u16EntrySysIdNear_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysIdFar, poEntry->u16EntrySysIdFar_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbTopEdgeTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbTopEdgeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbTopEdgeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021SpbTopEdgeTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbTopEdgeTable table mapper */
int
ieee8021SpbTopEdgeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbTopEdgeEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbTopEdgeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBTOPEDGEENTRYMETRICNEAR2FAR:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryMetricNear2Far);
				break;
			case IEEE8021SPBTOPEDGEENTRYMETRICFAR2NEAR:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryMetricFar2Near);
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

/** initialize ieee8021SpbmTopSrvTable table mapper **/
void
ieee8021SpbmTopSrvTable_init (void)
{
	extern oid ieee8021SpbmTopSrvTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbmTopSrvTable", &ieee8021SpbmTopSrvTable_mapper,
		ieee8021SpbmTopSrvTable_oid, OID_LENGTH (ieee8021SpbmTopSrvTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbmTopSrvEntryTopIx */,
		ASN_OCTET_STR /* index: ieee8021SpbmTopSrvEntrySysId */,
		ASN_UNSIGNED /* index: ieee8021SpbmTopSrvEntryIsid */,
		ASN_INTEGER /* index: ieee8021SpbmTopSrvEntryBaseVid */,
		ASN_OCTET_STR /* index: ieee8021SpbmTopSrvEntryMac */,
		0);
	table_info->min_column = IEEE8021SPBMTOPSRVENTRYISIDFLAGS;
	table_info->max_column = IEEE8021SPBMTOPSRVENTRYISIDFLAGS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbmTopSrvTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbmTopSrvTable_getNext;
	iinfo->get_data_point = &ieee8021SpbmTopSrvTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbmTopSrvTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbmTopSrvEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbmTopSrvEntry_t, oBTreeNode);
	register ieee8021SpbmTopSrvEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbmTopSrvEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == -1) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->u32EntryIsid < pEntry2->u32EntryIsid) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->u32EntryIsid == pEntry2->u32EntryIsid && pEntry1->i32EntryBaseVid < pEntry2->i32EntryBaseVid) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->u32EntryIsid == pEntry2->u32EntryIsid && pEntry1->i32EntryBaseVid == pEntry2->i32EntryBaseVid && xBinCmp (pEntry1->au8EntryMac, pEntry2->au8EntryMac, pEntry1->u16EntryMac_len, pEntry2->u16EntryMac_len) == -1) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && pEntry1->u32EntryIsid == pEntry2->u32EntryIsid && pEntry1->i32EntryBaseVid == pEntry2->i32EntryBaseVid && xBinCmp (pEntry1->au8EntryMac, pEntry2->au8EntryMac, pEntry1->u16EntryMac_len, pEntry2->u16EntryMac_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021SpbmTopSrvTable_BTree = xBTree_initInline (&ieee8021SpbmTopSrvTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbmTopSrvEntry_t *
ieee8021SpbmTopSrvTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len)
{
	register ieee8021SpbmTopSrvEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poEntry->u16EntrySysId_len = u16EntrySysId_len;
	poEntry->u32EntryIsid = u32EntryIsid;
	poEntry->i32EntryBaseVid = i32EntryBaseVid;
	memcpy (poEntry->au8EntryMac, pau8EntryMac, u16EntryMac_len);
	poEntry->u16EntryMac_len = u16EntryMac_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree);
	return poEntry;
}

ieee8021SpbmTopSrvEntry_t *
ieee8021SpbmTopSrvTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len)
{
	register ieee8021SpbmTopSrvEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	poTmpEntry->u32EntryIsid = u32EntryIsid;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	memcpy (poTmpEntry->au8EntryMac, pau8EntryMac, u16EntryMac_len);
	poTmpEntry->u16EntryMac_len = u16EntryMac_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbmTopSrvEntry_t, oBTreeNode);
}

ieee8021SpbmTopSrvEntry_t *
ieee8021SpbmTopSrvTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len)
{
	register ieee8021SpbmTopSrvEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	poTmpEntry->u32EntryIsid = u32EntryIsid;
	poTmpEntry->i32EntryBaseVid = i32EntryBaseVid;
	memcpy (poTmpEntry->au8EntryMac, pau8EntryMac, u16EntryMac_len);
	poTmpEntry->u16EntryMac_len = u16EntryMac_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbmTopSrvEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbmTopSrvTable_removeEntry (ieee8021SpbmTopSrvEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbmTopSrvTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbmTopSrvTable_BTree);
	return ieee8021SpbmTopSrvTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbmTopSrvTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbmTopSrvEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbmTopSrvEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysId, poEntry->u16EntrySysId_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryIsid);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32EntryBaseVid);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntryMac, poEntry->u16EntryMac_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbmTopSrvTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbmTopSrvTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbmTopSrvEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = ieee8021SpbmTopSrvTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer,
		*idx4->val.integer,
		(void*) idx5->val.string, idx5->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbmTopSrvTable table mapper */
int
ieee8021SpbmTopSrvTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbmTopSrvEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbmTopSrvEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBMTOPSRVENTRYISIDFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryIsidFlags, table_entry->u16EntryIsidFlags_len);
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

/** initialize ieee8021SpbvTopSrvTable table mapper **/
void
ieee8021SpbvTopSrvTable_init (void)
{
	extern oid ieee8021SpbvTopSrvTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021SpbvTopSrvTable", &ieee8021SpbvTopSrvTable_mapper,
		ieee8021SpbvTopSrvTable_oid, OID_LENGTH (ieee8021SpbvTopSrvTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021SpbvTopSrvEntryTopIx */,
		ASN_OCTET_STR /* index: ieee8021SpbvTopSrvEntrySysId */,
		ASN_OCTET_STR /* index: ieee8021SpbvTopSrvEntryMMac */,
		0);
	table_info->min_column = IEEE8021SPBVTOPSRVENTRYBASEVID;
	table_info->max_column = IEEE8021SPBVTOPSRVENTRYMMACFLAGS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021SpbvTopSrvTable_getFirst;
	iinfo->get_next_data_point = &ieee8021SpbvTopSrvTable_getNext;
	iinfo->get_data_point = &ieee8021SpbvTopSrvTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021SpbvTopSrvTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021SpbvTopSrvEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021SpbvTopSrvEntry_t, oBTreeNode);
	register ieee8021SpbvTopSrvEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021SpbvTopSrvEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32EntryTopIx < pEntry2->u32EntryTopIx) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == -1) ||
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && xBinCmp (pEntry1->au8EntryMMac, pEntry2->au8EntryMMac, pEntry1->u16EntryMMac_len, pEntry2->u16EntryMMac_len) == -1) ? -1:
		(pEntry1->u32EntryTopIx == pEntry2->u32EntryTopIx && xBinCmp (pEntry1->au8EntrySysId, pEntry2->au8EntrySysId, pEntry1->u16EntrySysId_len, pEntry2->u16EntrySysId_len) == 0 && xBinCmp (pEntry1->au8EntryMMac, pEntry2->au8EntryMMac, pEntry1->u16EntryMMac_len, pEntry2->u16EntryMMac_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021SpbvTopSrvTable_BTree = xBTree_initInline (&ieee8021SpbvTopSrvTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021SpbvTopSrvEntry_t *
ieee8021SpbvTopSrvTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len)
{
	register ieee8021SpbvTopSrvEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poEntry->u16EntrySysId_len = u16EntrySysId_len;
	memcpy (poEntry->au8EntryMMac, pau8EntryMMac, u16EntryMMac_len);
	poEntry->u16EntryMMac_len = u16EntryMMac_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree);
	return poEntry;
}

ieee8021SpbvTopSrvEntry_t *
ieee8021SpbvTopSrvTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len)
{
	register ieee8021SpbvTopSrvEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	memcpy (poTmpEntry->au8EntryMMac, pau8EntryMMac, u16EntryMMac_len);
	poTmpEntry->u16EntryMMac_len = u16EntryMMac_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbvTopSrvEntry_t, oBTreeNode);
}

ieee8021SpbvTopSrvEntry_t *
ieee8021SpbvTopSrvTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len)
{
	register ieee8021SpbvTopSrvEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32EntryTopIx = u32EntryTopIx;
	memcpy (poTmpEntry->au8EntrySysId, pau8EntrySysId, u16EntrySysId_len);
	poTmpEntry->u16EntrySysId_len = u16EntrySysId_len;
	memcpy (poTmpEntry->au8EntryMMac, pau8EntryMMac, u16EntryMMac_len);
	poTmpEntry->u16EntryMMac_len = u16EntryMMac_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021SpbvTopSrvEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021SpbvTopSrvTable_removeEntry (ieee8021SpbvTopSrvEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021SpbvTopSrvTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021SpbvTopSrvTable_BTree);
	return ieee8021SpbvTopSrvTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021SpbvTopSrvTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbvTopSrvEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021SpbvTopSrvEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EntryTopIx);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntrySysId, poEntry->u16EntrySysId_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8EntryMMac, poEntry->u16EntryMMac_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021SpbvTopSrvTable_BTree);
	return put_index_data;
}

bool
ieee8021SpbvTopSrvTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021SpbvTopSrvEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021SpbvTopSrvTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021SpbvTopSrvTable table mapper */
int
ieee8021SpbvTopSrvTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021SpbvTopSrvEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021SpbvTopSrvEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021SPBVTOPSRVENTRYBASEVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EntryBaseVid);
				break;
			case IEEE8021SPBVTOPSRVENTRYMMACFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EntryMMacFlags, table_entry->u16EntryMMacFlags_len);
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
