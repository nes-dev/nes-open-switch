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
#include "ieee8021MstpMib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021MstpCistTable_oid[] = {1,3,111,2,802,1,1,6,1,1};
static oid ieee8021MstpTable_oid[] = {1,3,111,2,802,1,1,6,1,2};
static oid ieee8021MstpCistPortTable_oid[] = {1,3,111,2,802,1,1,6,1,3};
static oid ieee8021MstpPortTable_oid[] = {1,3,111,2,802,1,1,6,1,4};
static oid ieee8021MstpConfigIdTable_oid[] = {1,3,111,2,802,1,1,6,1,7};
static oid ieee8021MstpCistPortExtensionTable_oid[] = {1,3,111,2,802,1,1,6,1,8};
static oid ieee8021MstpFidToMstiV2Table_oid[] = {1,3,111,2,802,1,1,6,1,9};
static oid ieee8021MstpVlanV2Table_oid[] = {1,3,111,2,802,1,1,6,1,10};



/**
 *	initialize ieee8021MstpMib group mapper
 */
void
ieee8021MstpMib_init (void)
{
	DEBUGMSGTL (("ieee8021MstpMib", "Initializing\n"));
	
	
	/* register ieee8021MstpMib group table mappers */
	ieee8021MstpCistTable_init ();
	ieee8021MstpTable_init ();
	ieee8021MstpCistPortTable_init ();
	ieee8021MstpPortTable_init ();
	ieee8021MstpConfigIdTable_init ();
	ieee8021MstpCistPortExtensionTable_init ();
	ieee8021MstpFidToMstiV2Table_init ();
	ieee8021MstpVlanV2Table_init ();
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize ieee8021MstpCistTable table mapper **/
void
ieee8021MstpCistTable_init (void)
{
	extern oid ieee8021MstpCistTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpCistTable", &ieee8021MstpCistTable_mapper,
		ieee8021MstpCistTable_oid, OID_LENGTH (ieee8021MstpCistTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpCistComponentId */,
		0);
	table_info->min_column = IEEE8021MSTPCISTBRIDGEIDENTIFIER;
	table_info->max_column = IEEE8021MSTPCISTMAXHOPS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpCistTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpCistTable_getNext;
	iinfo->get_data_point = &ieee8021MstpCistTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpCistTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpCistEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpCistEntry_t, oBTreeNode);
	register ieee8021MstpCistEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpCistEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId) ? 0: 1;
}

xBTree_t oIeee8021MstpCistTable_BTree = xBTree_initInline (&ieee8021MstpCistTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpCistEntry_t *
ieee8021MstpCistTable_createEntry (
	uint32_t u32ComponentId)
{
	ieee8021MstpCistEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree);
	return poEntry;
}

ieee8021MstpCistEntry_t *
ieee8021MstpCistTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021MstpCistEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistEntry_t, oBTreeNode);
}

ieee8021MstpCistEntry_t *
ieee8021MstpCistTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021MstpCistEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpCistTable_removeEntry (ieee8021MstpCistEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpCistTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpCistTable_BTree);
	return ieee8021MstpCistTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpCistTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpCistEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpCistTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpCistTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021MstpCistTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpCistTable table mapper */
int
ieee8021MstpCistTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpCistEntry_t *table_entry;
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
			table_entry = (ieee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTBRIDGEIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8BridgeIdentifier, table_entry->u16BridgeIdentifier_len);
				break;
			case IEEE8021MSTPCISTTOPOLOGYCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TopologyChange);
				break;
			case IEEE8021MSTPCISTREGIONALROOTIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RegionalRootIdentifier, table_entry->u16RegionalRootIdentifier_len);
				break;
			case IEEE8021MSTPCISTPATHCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PathCost);
				break;
			case IEEE8021MSTPCISTMAXHOPS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MaxHops);
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
			table_entry = (ieee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTMAXHOPS:
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
			table_entry = (ieee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTMAXHOPS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MaxHops))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MaxHops, sizeof (table_entry->i32MaxHops));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MaxHops = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTMAXHOPS:
				memcpy (&table_entry->i32MaxHops, pvOldDdata, sizeof (table_entry->i32MaxHops));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpTable table mapper **/
void
ieee8021MstpTable_init (void)
{
	extern oid ieee8021MstpTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpTable", &ieee8021MstpTable_mapper,
		ieee8021MstpTable_oid, OID_LENGTH (ieee8021MstpTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpId */,
		0);
	table_info->min_column = IEEE8021MSTPBRIDGEID;
	table_info->max_column = IEEE8021MSTPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpTable_getNext;
	iinfo->get_data_point = &ieee8021MstpTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpEntry_t, oBTreeNode);
	register ieee8021MstpEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oIeee8021MstpTable_BTree = xBTree_initInline (&ieee8021MstpTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpEntry_t *
ieee8021MstpTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	ieee8021MstpEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpTable_BTree);
	return poEntry;
}

ieee8021MstpEntry_t *
ieee8021MstpTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021MstpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpEntry_t, oBTreeNode);
}

ieee8021MstpEntry_t *
ieee8021MstpTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021MstpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpTable_removeEntry (ieee8021MstpEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpTable_BTree);
	return ieee8021MstpTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021MstpTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpTable table mapper */
int
ieee8021MstpTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpEntry_t *table_entry;
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPBRIDGEID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8BridgeId, table_entry->u16BridgeId_len);
				break;
			case IEEE8021MSTPTIMESINCETOPOLOGYCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32TimeSinceTopologyChange);
				break;
			case IEEE8021MSTPTOPOLOGYCHANGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64TopologyChanges);
				break;
			case IEEE8021MSTPTOPOLOGYCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TopologyChange);
				break;
			case IEEE8021MSTPDESIGNATEDROOT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DesignatedRoot, table_entry->u16DesignatedRoot_len);
				break;
			case IEEE8021MSTPROOTPATHCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RootPathCost);
				break;
			case IEEE8021MSTPROOTPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RootPort);
				break;
			case IEEE8021MSTPBRIDGEPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32BridgePriority);
				break;
			case IEEE8021MSTPVIDS0:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Vids0, table_entry->u16Vids0_len);
				break;
			case IEEE8021MSTPVIDS1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Vids1, table_entry->u16Vids1_len);
				break;
			case IEEE8021MSTPVIDS2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Vids2, table_entry->u16Vids2_len);
				break;
			case IEEE8021MSTPVIDS3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Vids3, table_entry->u16Vids3_len);
				break;
			case IEEE8021MSTPROWSTATUS:
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPBRIDGEPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPROWSTATUS:
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021MstpTable_createEntry (
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021MstpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPBRIDGEPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32BridgePriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32BridgePriority, sizeof (table_entry->i32BridgePriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32BridgePriority = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021MstpTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPBRIDGEPRIORITY:
				memcpy (&table_entry->i32BridgePriority, pvOldDdata, sizeof (table_entry->i32BridgePriority));
				break;
			case IEEE8021MSTPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021MstpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPROWSTATUS:
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
					ieee8021MstpTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpCistPortTable table mapper **/
void
ieee8021MstpCistPortTable_init (void)
{
	extern oid ieee8021MstpCistPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpCistPortTable", &ieee8021MstpCistPortTable_mapper,
		ieee8021MstpCistPortTable_oid, OID_LENGTH (ieee8021MstpCistPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortNum */,
		0);
	table_info->min_column = IEEE8021MSTPCISTPORTUPTIME;
	table_info->max_column = IEEE8021MSTPCISTPORTISL2GP;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpCistPortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpCistPortTable_getNext;
	iinfo->get_data_point = &ieee8021MstpCistPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpCistPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpCistPortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpCistPortEntry_t, oBTreeNode);
	register ieee8021MstpCistPortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpCistPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num < pEntry2->u32Num) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num == pEntry2->u32Num) ? 0: 1;
}

xBTree_t oIeee8021MstpCistPortTable_BTree = xBTree_initInline (&ieee8021MstpCistPortTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpCistPortEntry_t *
ieee8021MstpCistPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	ieee8021MstpCistPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Num = u32Num;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AdminEdgePort = ieee8021MstpCistPortAdminEdgePort_true_c;
	poEntry->i32EnableBPDURx = ieee8021MstpCistPortEnableBPDURx_true_c;
	poEntry->i32EnableBPDUTx = ieee8021MstpCistPortEnableBPDUTx_true_c;
	poEntry->i32IsL2Gp = ieee8021MstpCistPortIsL2Gp_false_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree);
	return poEntry;
}

ieee8021MstpCistPortEntry_t *
ieee8021MstpCistPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register ieee8021MstpCistPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistPortEntry_t, oBTreeNode);
}

ieee8021MstpCistPortEntry_t *
ieee8021MstpCistPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register ieee8021MstpCistPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpCistPortTable_removeEntry (ieee8021MstpCistPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpCistPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpCistPortTable_BTree);
	return ieee8021MstpCistPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpCistPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpCistPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Num);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpCistPortTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpCistPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021MstpCistPortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpCistPortTable table mapper */
int
ieee8021MstpCistPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpCistPortEntry_t *table_entry;
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
			table_entry = (ieee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32Uptime);
				break;
			case IEEE8021MSTPCISTPORTADMINPATHCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminPathCost);
				break;
			case IEEE8021MSTPCISTPORTDESIGNATEDROOT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DesignatedRoot, table_entry->u16DesignatedRoot_len);
				break;
			case IEEE8021MSTPCISTPORTTOPOLOGYCHANGEACK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TopologyChangeAck);
				break;
			case IEEE8021MSTPCISTPORTHELLOTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32HelloTime);
				break;
			case IEEE8021MSTPCISTPORTADMINEDGEPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminEdgePort);
				break;
			case IEEE8021MSTPCISTPORTOPEREDGEPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperEdgePort);
				break;
			case IEEE8021MSTPCISTPORTMACENABLED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MacEnabled);
				break;
			case IEEE8021MSTPCISTPORTMACOPERATIONAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MacOperational);
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RestrictedRole);
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDTCN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RestrictedTcn);
				break;
			case IEEE8021MSTPCISTPORTROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case IEEE8021MSTPCISTPORTDISPUTED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Disputed);
				break;
			case IEEE8021MSTPCISTPORTCISTREGIONALROOTID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8CistRegionalRootId, table_entry->u16CistRegionalRootId_len);
				break;
			case IEEE8021MSTPCISTPORTCISTPATHCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CistPathCost);
				break;
			case IEEE8021MSTPCISTPORTPROTOCOLMIGRATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ProtocolMigration);
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDURX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableBPDURx);
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDUTX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableBPDUTx);
				break;
			case IEEE8021MSTPCISTPORTPSEUDOROOTID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PseudoRootId, table_entry->u16PseudoRootId_len);
				break;
			case IEEE8021MSTPCISTPORTISL2GP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IsL2Gp);
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
			table_entry = (ieee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTADMINPATHCOST:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTADMINEDGEPORT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTMACENABLED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDROLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDTCN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTPROTOCOLMIGRATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDURX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDUTX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTPSEUDOROOTID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PseudoRootId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCISTPORTISL2GP:
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
			table_entry = (ieee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTADMINPATHCOST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminPathCost))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminPathCost, sizeof (table_entry->i32AdminPathCost));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminPathCost = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTADMINEDGEPORT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminEdgePort))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminEdgePort, sizeof (table_entry->i32AdminEdgePort));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminEdgePort = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTMACENABLED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MacEnabled))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MacEnabled, sizeof (table_entry->i32MacEnabled));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MacEnabled = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RestrictedRole))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RestrictedRole, sizeof (table_entry->i32RestrictedRole));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RestrictedRole = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDTCN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RestrictedTcn))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RestrictedTcn, sizeof (table_entry->i32RestrictedTcn));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RestrictedTcn = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTPROTOCOLMIGRATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ProtocolMigration))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ProtocolMigration, sizeof (table_entry->i32ProtocolMigration));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ProtocolMigration = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDURX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableBPDURx))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableBPDURx, sizeof (table_entry->i32EnableBPDURx));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableBPDURx = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDUTX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableBPDUTx))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableBPDUTx, sizeof (table_entry->i32EnableBPDUTx));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableBPDUTx = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCISTPORTPSEUDOROOTID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PseudoRootId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PseudoRootId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PseudoRootId, sizeof (table_entry->au8PseudoRootId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PseudoRootId, 0, sizeof (table_entry->au8PseudoRootId));
				memcpy (table_entry->au8PseudoRootId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PseudoRootId_len = request->requestvb->val_len;
				break;
			case IEEE8021MSTPCISTPORTISL2GP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IsL2Gp))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IsL2Gp, sizeof (table_entry->i32IsL2Gp));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IsL2Gp = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTADMINPATHCOST:
				memcpy (&table_entry->i32AdminPathCost, pvOldDdata, sizeof (table_entry->i32AdminPathCost));
				break;
			case IEEE8021MSTPCISTPORTADMINEDGEPORT:
				memcpy (&table_entry->i32AdminEdgePort, pvOldDdata, sizeof (table_entry->i32AdminEdgePort));
				break;
			case IEEE8021MSTPCISTPORTMACENABLED:
				memcpy (&table_entry->i32MacEnabled, pvOldDdata, sizeof (table_entry->i32MacEnabled));
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDROLE:
				memcpy (&table_entry->i32RestrictedRole, pvOldDdata, sizeof (table_entry->i32RestrictedRole));
				break;
			case IEEE8021MSTPCISTPORTRESTRICTEDTCN:
				memcpy (&table_entry->i32RestrictedTcn, pvOldDdata, sizeof (table_entry->i32RestrictedTcn));
				break;
			case IEEE8021MSTPCISTPORTPROTOCOLMIGRATION:
				memcpy (&table_entry->i32ProtocolMigration, pvOldDdata, sizeof (table_entry->i32ProtocolMigration));
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDURX:
				memcpy (&table_entry->i32EnableBPDURx, pvOldDdata, sizeof (table_entry->i32EnableBPDURx));
				break;
			case IEEE8021MSTPCISTPORTENABLEBPDUTX:
				memcpy (&table_entry->i32EnableBPDUTx, pvOldDdata, sizeof (table_entry->i32EnableBPDUTx));
				break;
			case IEEE8021MSTPCISTPORTPSEUDOROOTID:
				memcpy (table_entry->au8PseudoRootId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PseudoRootId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021MSTPCISTPORTISL2GP:
				memcpy (&table_entry->i32IsL2Gp, pvOldDdata, sizeof (table_entry->i32IsL2Gp));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpPortTable table mapper **/
void
ieee8021MstpPortTable_init (void)
{
	extern oid ieee8021MstpPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpPortTable", &ieee8021MstpPortTable_mapper,
		ieee8021MstpPortTable_oid, OID_LENGTH (ieee8021MstpPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpPortMstId */,
		ASN_UNSIGNED /* index: ieee8021MstpPortNum */,
		0);
	table_info->min_column = IEEE8021MSTPPORTUPTIME;
	table_info->max_column = IEEE8021MSTPPORTDISPUTED;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpPortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpPortTable_getNext;
	iinfo->get_data_point = &ieee8021MstpPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpPortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpPortEntry_t, oBTreeNode);
	register ieee8021MstpPortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32MstId < pEntry2->u32MstId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32MstId == pEntry2->u32MstId && pEntry1->u32Num < pEntry2->u32Num) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32MstId == pEntry2->u32MstId && pEntry1->u32Num == pEntry2->u32Num) ? 0: 1;
}

xBTree_t oIeee8021MstpPortTable_BTree = xBTree_initInline (&ieee8021MstpPortTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpPortEntry_t *
ieee8021MstpPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num)
{
	ieee8021MstpPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32MstId = u32MstId;
	poEntry->u32Num = u32Num;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree);
	return poEntry;
}

ieee8021MstpPortEntry_t *
ieee8021MstpPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num)
{
	register ieee8021MstpPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32MstId = u32MstId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpPortEntry_t, oBTreeNode);
}

ieee8021MstpPortEntry_t *
ieee8021MstpPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num)
{
	register ieee8021MstpPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32MstId = u32MstId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpPortTable_removeEntry (ieee8021MstpPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpPortTable_BTree);
	return ieee8021MstpPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MstId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Num);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpPortTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021MstpPortTable_getByIndex (
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

/* ieee8021MstpPortTable table mapper */
int
ieee8021MstpPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpPortEntry_t *table_entry;
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
			table_entry = (ieee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPPORTUPTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32Uptime);
				break;
			case IEEE8021MSTPPORTSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case IEEE8021MSTPPORTPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Priority);
				break;
			case IEEE8021MSTPPORTPATHCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PathCost);
				break;
			case IEEE8021MSTPPORTDESIGNATEDROOT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DesignatedRoot, table_entry->u16DesignatedRoot_len);
				break;
			case IEEE8021MSTPPORTDESIGNATEDCOST:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32DesignatedCost);
				break;
			case IEEE8021MSTPPORTDESIGNATEDBRIDGE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DesignatedBridge, table_entry->u16DesignatedBridge_len);
				break;
			case IEEE8021MSTPPORTDESIGNATEDPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DesignatedPort);
				break;
			case IEEE8021MSTPPORTROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case IEEE8021MSTPPORTDISPUTED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Disputed);
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
			table_entry = (ieee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPPORTPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPPORTPATHCOST:
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
			table_entry = (ieee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPPORTPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Priority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Priority, sizeof (table_entry->i32Priority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Priority = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPPORTPATHCOST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PathCost))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PathCost, sizeof (table_entry->i32PathCost));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PathCost = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPPORTPRIORITY:
				memcpy (&table_entry->i32Priority, pvOldDdata, sizeof (table_entry->i32Priority));
				break;
			case IEEE8021MSTPPORTPATHCOST:
				memcpy (&table_entry->i32PathCost, pvOldDdata, sizeof (table_entry->i32PathCost));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpConfigIdTable table mapper **/
void
ieee8021MstpConfigIdTable_init (void)
{
	extern oid ieee8021MstpConfigIdTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpConfigIdTable", &ieee8021MstpConfigIdTable_mapper,
		ieee8021MstpConfigIdTable_oid, OID_LENGTH (ieee8021MstpConfigIdTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpConfigIdComponentId */,
		0);
	table_info->min_column = IEEE8021MSTPCONFIGIDFORMATSELECTOR;
	table_info->max_column = IEEE8021MSTPCONFIGURATIONDIGEST;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpConfigIdTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpConfigIdTable_getNext;
	iinfo->get_data_point = &ieee8021MstpConfigIdTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpConfigIdTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpConfigIdEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpConfigIdEntry_t, oBTreeNode);
	register ieee8021MstpConfigIdEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpConfigIdEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId) ? 0: 1;
}

xBTree_t oIeee8021MstpConfigIdTable_BTree = xBTree_initInline (&ieee8021MstpConfigIdTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpConfigIdEntry_t *
ieee8021MstpConfigIdTable_createEntry (
	uint32_t u32ComponentId)
{
	ieee8021MstpConfigIdEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpConfigIdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree);
	return poEntry;
}

ieee8021MstpConfigIdEntry_t *
ieee8021MstpConfigIdTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021MstpConfigIdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpConfigIdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpConfigIdEntry_t, oBTreeNode);
}

ieee8021MstpConfigIdEntry_t *
ieee8021MstpConfigIdTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021MstpConfigIdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpConfigIdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpConfigIdEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpConfigIdTable_removeEntry (ieee8021MstpConfigIdEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpConfigIdTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpConfigIdTable_BTree);
	return ieee8021MstpConfigIdTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpConfigIdTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpConfigIdEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpConfigIdEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpConfigIdTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpConfigIdTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpConfigIdEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021MstpConfigIdTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpConfigIdTable table mapper */
int
ieee8021MstpConfigIdTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpConfigIdEntry_t *table_entry;
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
			table_entry = (ieee8021MstpConfigIdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCONFIGIDFORMATSELECTOR:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32FormatSelector);
				break;
			case IEEE8021MSTPCONFIGURATIONNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ConfigurationName, table_entry->u16ConfigurationName_len);
				break;
			case IEEE8021MSTPREVISIONLEVEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RevisionLevel);
				break;
			case IEEE8021MSTPCONFIGURATIONDIGEST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ConfigurationDigest, table_entry->u16ConfigurationDigest_len);
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
			table_entry = (ieee8021MstpConfigIdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCONFIGIDFORMATSELECTOR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPCONFIGURATIONNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ConfigurationName));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021MSTPREVISIONLEVEL:
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
			table_entry = (ieee8021MstpConfigIdEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpConfigIdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCONFIGIDFORMATSELECTOR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32FormatSelector))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32FormatSelector, sizeof (table_entry->i32FormatSelector));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32FormatSelector = *request->requestvb->val.integer;
				break;
			case IEEE8021MSTPCONFIGURATIONNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ConfigurationName))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ConfigurationName_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ConfigurationName, sizeof (table_entry->au8ConfigurationName));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ConfigurationName, 0, sizeof (table_entry->au8ConfigurationName));
				memcpy (table_entry->au8ConfigurationName, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ConfigurationName_len = request->requestvb->val_len;
				break;
			case IEEE8021MSTPREVISIONLEVEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RevisionLevel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RevisionLevel, sizeof (table_entry->u32RevisionLevel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RevisionLevel = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpConfigIdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCONFIGIDFORMATSELECTOR:
				memcpy (&table_entry->i32FormatSelector, pvOldDdata, sizeof (table_entry->i32FormatSelector));
				break;
			case IEEE8021MSTPCONFIGURATIONNAME:
				memcpy (table_entry->au8ConfigurationName, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ConfigurationName_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021MSTPREVISIONLEVEL:
				memcpy (&table_entry->u32RevisionLevel, pvOldDdata, sizeof (table_entry->u32RevisionLevel));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpCistPortExtensionTable table mapper **/
void
ieee8021MstpCistPortExtensionTable_init (void)
{
	extern oid ieee8021MstpCistPortExtensionTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpCistPortExtensionTable", &ieee8021MstpCistPortExtensionTable_mapper,
		ieee8021MstpCistPortExtensionTable_oid, OID_LENGTH (ieee8021MstpCistPortExtensionTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortNum */,
		0);
	table_info->min_column = IEEE8021MSTPCISTPORTAUTOEDGEPORT;
	table_info->max_column = IEEE8021MSTPCISTPORTAUTOISOLATEPORT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpCistPortExtensionTable_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpCistPortExtensionTable_getNext;
	iinfo->get_data_point = &ieee8021MstpCistPortExtensionTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpCistPortExtensionTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpCistPortExtensionEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpCistPortExtensionEntry_t, oBTreeNode);
	register ieee8021MstpCistPortExtensionEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpCistPortExtensionEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num < pEntry2->u32Num) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num == pEntry2->u32Num) ? 0: 1;
}

xBTree_t oIeee8021MstpCistPortExtensionTable_BTree = xBTree_initInline (&ieee8021MstpCistPortExtensionTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpCistPortExtensionEntry_t *
ieee8021MstpCistPortExtensionTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	ieee8021MstpCistPortExtensionEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortExtensionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Num = u32Num;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree);
	return poEntry;
}

ieee8021MstpCistPortExtensionEntry_t *
ieee8021MstpCistPortExtensionTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register ieee8021MstpCistPortExtensionEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortExtensionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistPortExtensionEntry_t, oBTreeNode);
}

ieee8021MstpCistPortExtensionEntry_t *
ieee8021MstpCistPortExtensionTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register ieee8021MstpCistPortExtensionEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpCistPortExtensionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpCistPortExtensionEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpCistPortExtensionTable_removeEntry (ieee8021MstpCistPortExtensionEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpCistPortExtensionTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpCistPortExtensionTable_BTree);
	return ieee8021MstpCistPortExtensionTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpCistPortExtensionTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistPortExtensionEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpCistPortExtensionEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Num);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpCistPortExtensionTable_BTree);
	return put_index_data;
}

bool
ieee8021MstpCistPortExtensionTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpCistPortExtensionEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021MstpCistPortExtensionTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpCistPortExtensionTable table mapper */
int
ieee8021MstpCistPortExtensionTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpCistPortExtensionEntry_t *table_entry;
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
			table_entry = (ieee8021MstpCistPortExtensionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTAUTOEDGEPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AutoEdgePort);
				break;
			case IEEE8021MSTPCISTPORTAUTOISOLATEPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AutoIsolatePort);
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
			table_entry = (ieee8021MstpCistPortExtensionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTAUTOEDGEPORT:
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
			table_entry = (ieee8021MstpCistPortExtensionEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpCistPortExtensionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTAUTOEDGEPORT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AutoEdgePort))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AutoEdgePort, sizeof (table_entry->i32AutoEdgePort));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AutoEdgePort = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpCistPortExtensionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPCISTPORTAUTOEDGEPORT:
				memcpy (&table_entry->i32AutoEdgePort, pvOldDdata, sizeof (table_entry->i32AutoEdgePort));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpFidToMstiV2Table table mapper **/
void
ieee8021MstpFidToMstiV2Table_init (void)
{
	extern oid ieee8021MstpFidToMstiV2Table_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpFidToMstiV2Table", &ieee8021MstpFidToMstiV2Table_mapper,
		ieee8021MstpFidToMstiV2Table_oid, OID_LENGTH (ieee8021MstpFidToMstiV2Table_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpFidToMstiV2ComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpFidToMstiV2Fid */,
		0);
	table_info->min_column = IEEE8021MSTPFIDTOMSTIV2MSTID;
	table_info->max_column = IEEE8021MSTPFIDTOMSTIV2MSTID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpFidToMstiV2Table_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpFidToMstiV2Table_getNext;
	iinfo->get_data_point = &ieee8021MstpFidToMstiV2Table_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpFidToMstiV2Table_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpFidToMstiV2Entry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	register ieee8021MstpFidToMstiV2Entry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Fid < pEntry2->u32Fid) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Fid == pEntry2->u32Fid) ? 0: 1;
}

xBTree_t oIeee8021MstpFidToMstiV2Table_BTree = xBTree_initInline (&ieee8021MstpFidToMstiV2Table_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpFidToMstiV2Entry_t *
ieee8021MstpFidToMstiV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	ieee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpFidToMstiV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Fid = u32Fid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree);
	return poEntry;
}

ieee8021MstpFidToMstiV2Entry_t *
ieee8021MstpFidToMstiV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	register ieee8021MstpFidToMstiV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpFidToMstiV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Fid = u32Fid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpFidToMstiV2Entry_t, oBTreeNode);
}

ieee8021MstpFidToMstiV2Entry_t *
ieee8021MstpFidToMstiV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	register ieee8021MstpFidToMstiV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpFidToMstiV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Fid = u32Fid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpFidToMstiV2Entry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpFidToMstiV2Table_removeEntry (ieee8021MstpFidToMstiV2Entry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpFidToMstiV2Table_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpFidToMstiV2Table_BTree);
	return ieee8021MstpFidToMstiV2Table_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpFidToMstiV2Table_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Fid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpFidToMstiV2Table_BTree);
	return put_index_data;
}

bool
ieee8021MstpFidToMstiV2Table_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021MstpFidToMstiV2Table_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpFidToMstiV2Table table mapper */
int
ieee8021MstpFidToMstiV2Table_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpFidToMstiV2Entry_t *table_entry;
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
			table_entry = (ieee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPFIDTOMSTIV2MSTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MstId);
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
			table_entry = (ieee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPFIDTOMSTIV2MSTID:
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
			table_entry = (ieee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPFIDTOMSTIV2MSTID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MstId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MstId, sizeof (table_entry->u32MstId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MstId = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPFIDTOMSTIV2MSTID:
				memcpy (&table_entry->u32MstId, pvOldDdata, sizeof (table_entry->u32MstId));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021MstpVlanV2Table table mapper **/
void
ieee8021MstpVlanV2Table_init (void)
{
	extern oid ieee8021MstpVlanV2Table_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021MstpVlanV2Table", &ieee8021MstpVlanV2Table_mapper,
		ieee8021MstpVlanV2Table_oid, OID_LENGTH (ieee8021MstpVlanV2Table_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpVlanV2ComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpVlanV2Id */,
		0);
	table_info->min_column = IEEE8021MSTPVLANV2MSTID;
	table_info->max_column = IEEE8021MSTPVLANV2MSTID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021MstpVlanV2Table_getFirst;
	iinfo->get_next_data_point = &ieee8021MstpVlanV2Table_getNext;
	iinfo->get_data_point = &ieee8021MstpVlanV2Table_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021MstpVlanV2Table_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021MstpVlanV2Entry_t *pEntry1 = xBTree_entry (pNode1, ieee8021MstpVlanV2Entry_t, oBTreeNode);
	register ieee8021MstpVlanV2Entry_t *pEntry2 = xBTree_entry (pNode2, ieee8021MstpVlanV2Entry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oIeee8021MstpVlanV2Table_BTree = xBTree_initInline (&ieee8021MstpVlanV2Table_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021MstpVlanV2Entry_t *
ieee8021MstpVlanV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	ieee8021MstpVlanV2Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021MstpVlanV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree);
	return poEntry;
}

ieee8021MstpVlanV2Entry_t *
ieee8021MstpVlanV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021MstpVlanV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpVlanV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpVlanV2Entry_t, oBTreeNode);
}

ieee8021MstpVlanV2Entry_t *
ieee8021MstpVlanV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021MstpVlanV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021MstpVlanV2Entry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021MstpVlanV2Entry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021MstpVlanV2Table_removeEntry (ieee8021MstpVlanV2Entry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021MstpVlanV2Table_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021MstpVlanV2Table_BTree);
	return ieee8021MstpVlanV2Table_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021MstpVlanV2Table_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpVlanV2Entry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021MstpVlanV2Entry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021MstpVlanV2Table_BTree);
	return put_index_data;
}

bool
ieee8021MstpVlanV2Table_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021MstpVlanV2Entry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021MstpVlanV2Table_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021MstpVlanV2Table table mapper */
int
ieee8021MstpVlanV2Table_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021MstpVlanV2Entry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021MstpVlanV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021MSTPVLANV2MSTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MstId);
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