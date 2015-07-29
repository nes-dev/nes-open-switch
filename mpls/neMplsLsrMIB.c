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
#include "mplsLsrStdMIB.h"
#include "neMplsLsrMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid neMplsLsrMIB_oid[] = {1,3,6,1,4,1,36969,63};

static oid neMplsLabelScopeTable_oid[] = {1,3,6,1,4,1,36969,63,1,3};
static oid neMplsLabelRangeTable_oid[] = {1,3,6,1,4,1,36969,63,1,4};
static oid neMplsInSegmentTable_oid[] = {1,3,6,1,4,1,36969,63,1,5};
static oid neMplsOutSegmentTable_oid[] = {1,3,6,1,4,1,36969,63,1,6};
static oid neMplsXCTable_oid[] = {1,3,6,1,4,1,36969,63,1,7};
static oid neMplsLabelStackTable_oid[] = {1,3,6,1,4,1,36969,63,1,8};
static oid neMplsSegmentMapTable_oid[] = {1,3,6,1,4,1,36969,63,1,9};



/**
 *	initialize neMplsLsrMIB group mapper
 */
void
neMplsLsrMIB_init (void)
{
	extern oid neMplsLsrMIB_oid[];
	
	DEBUGMSGTL (("neMplsLsrMIB", "Initializing\n"));
	
	
	/* register neMplsLsrMIB group table mappers */
	neMplsLabelScopeTable_init ();
	neMplsLabelRangeTable_init ();
	neMplsInSegmentTable_init ();
	neMplsOutSegmentTable_init ();
	neMplsXCTable_init ();
	neMplsLabelStackTable_init ();
	neMplsSegmentMapTable_init ();
	
	/* register neMplsLsrMIB modules */
	sysORTable_createRegister ("neMplsLsrMIB", neMplsLsrMIB_oid, OID_LENGTH (neMplsLsrMIB_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize neMplsLabelScopeTable table mapper **/
void
neMplsLabelScopeTable_init (void)
{
	extern oid neMplsLabelScopeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsLabelScopeTable", &neMplsLabelScopeTable_mapper,
		neMplsLabelScopeTable_oid, OID_LENGTH (neMplsLabelScopeTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neMplsLabelScopeIndex */,
		0);
	table_info->min_column = NEMPLSLABELSCOPETYPE;
	table_info->max_column = NEMPLSLABELSCOPESTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsLabelScopeTable_getFirst;
	iinfo->get_next_data_point = &neMplsLabelScopeTable_getNext;
	iinfo->get_data_point = &neMplsLabelScopeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsLabelScopeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsLabelScopeEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsLabelScopeEntry_t, oBTreeNode);
	register neMplsLabelScopeEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsLabelScopeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeMplsLabelScopeTable_BTree = xBTree_initInline (&neMplsLabelScopeTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsLabelScopeEntry_t *
neMplsLabelScopeTable_createEntry (
	uint32_t u32Index)
{
	register neMplsLabelScopeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree);
	return poEntry;
}

neMplsLabelScopeEntry_t *
neMplsLabelScopeTable_getByIndex (
	uint32_t u32Index)
{
	register neMplsLabelScopeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsLabelScopeEntry_t, oBTreeNode);
}

neMplsLabelScopeEntry_t *
neMplsLabelScopeTable_getNextIndex (
	uint32_t u32Index)
{
	register neMplsLabelScopeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsLabelScopeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsLabelScopeTable_removeEntry (neMplsLabelScopeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsLabelScopeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsLabelScopeTable_BTree);
	return neMplsLabelScopeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsLabelScopeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsLabelScopeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsLabelScopeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsLabelScopeTable_BTree);
	return put_index_data;
}

bool
neMplsLabelScopeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsLabelScopeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neMplsLabelScopeTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsLabelScopeTable table mapper */
int
neMplsLabelScopeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsLabelScopeEntry_t *table_entry;
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case NEMPLSLABELSCOPELABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSLABELSCOPEIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NeighbourAddrType);
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NeighbourAddress, table_entry->u16NeighbourAddress_len);
				break;
			case NEMPLSLABELSCOPEROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEMPLSLABELSCOPESTORAGETYPE:
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPELABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPEIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NeighbourAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPEROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSCOPESTORAGETYPE:
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsLabelScopeTable_createEntry (
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsLabelScopeTable_removeEntry (table_entry);
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPETYPE:
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
			case NEMPLSLABELSCOPELABELTYPE:
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
			case NEMPLSLABELSCOPEIFINDEX:
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
			case NEMPLSLABELSCOPENEIGHBOURADDRTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32NeighbourAddrType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32NeighbourAddrType, sizeof (table_entry->i32NeighbourAddrType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32NeighbourAddrType = *request->requestvb->val.integer;
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NeighbourAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NeighbourAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NeighbourAddress, sizeof (table_entry->au8NeighbourAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NeighbourAddress, 0, sizeof (table_entry->au8NeighbourAddress));
				memcpy (table_entry->au8NeighbourAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NeighbourAddress_len = request->requestvb->val_len;
				break;
			case NEMPLSLABELSCOPESTORAGETYPE:
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neMplsLabelScopeTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPETYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case NEMPLSLABELSCOPELABELTYPE:
				memcpy (&table_entry->i32LabelType, pvOldDdata, sizeof (table_entry->i32LabelType));
				break;
			case NEMPLSLABELSCOPEIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRTYPE:
				memcpy (&table_entry->i32NeighbourAddrType, pvOldDdata, sizeof (table_entry->i32NeighbourAddrType));
				break;
			case NEMPLSLABELSCOPENEIGHBOURADDRESS:
				memcpy (table_entry->au8NeighbourAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NeighbourAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEMPLSLABELSCOPEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsLabelScopeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEMPLSLABELSCOPESTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsLabelScopeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSCOPEROWSTATUS:
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
					neMplsLabelScopeTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neMplsLabelRangeTable table mapper **/
void
neMplsLabelRangeTable_init (void)
{
	extern oid neMplsLabelRangeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsLabelRangeTable", &neMplsLabelRangeTable_mapper,
		neMplsLabelRangeTable_oid, OID_LENGTH (neMplsLabelRangeTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neMplsLabelScopeIndex */,
		ASN_OCTET_STR /* index: neMplsLabelRangeMin */,
		ASN_OCTET_STR /* index: neMplsLabelRangeMax */,
		ASN_INTEGER /* index: neMplsLabelRangeIfIndex */,
		0);
	table_info->min_column = NEMPLSLABELRANGEROWSTATUS;
	table_info->max_column = NEMPLSLABELRANGESTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsLabelRangeTable_getFirst;
	iinfo->get_next_data_point = &neMplsLabelRangeTable_getNext;
	iinfo->get_data_point = &neMplsLabelRangeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsLabelRangeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsLabelRangeEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsLabelRangeEntry_t, oBTreeNode);
	register neMplsLabelRangeEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsLabelRangeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ScopeIndex < pEntry2->u32ScopeIndex) ||
		(pEntry1->u32ScopeIndex == pEntry2->u32ScopeIndex && xBinCmp (pEntry1->au8Min, pEntry2->au8Min, pEntry1->u16Min_len, pEntry2->u16Min_len) == -1) ||
		(pEntry1->u32ScopeIndex == pEntry2->u32ScopeIndex && xBinCmp (pEntry1->au8Min, pEntry2->au8Min, pEntry1->u16Min_len, pEntry2->u16Min_len) == 0 && xBinCmp (pEntry1->au8Max, pEntry2->au8Max, pEntry1->u16Max_len, pEntry2->u16Max_len) == -1) ||
		(pEntry1->u32ScopeIndex == pEntry2->u32ScopeIndex && xBinCmp (pEntry1->au8Min, pEntry2->au8Min, pEntry1->u16Min_len, pEntry2->u16Min_len) == 0 && xBinCmp (pEntry1->au8Max, pEntry2->au8Max, pEntry1->u16Max_len, pEntry2->u16Max_len) == 0 && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32ScopeIndex == pEntry2->u32ScopeIndex && xBinCmp (pEntry1->au8Min, pEntry2->au8Min, pEntry1->u16Min_len, pEntry2->u16Min_len) == 0 && xBinCmp (pEntry1->au8Max, pEntry2->au8Max, pEntry1->u16Max_len, pEntry2->u16Max_len) == 0 && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oNeMplsLabelRangeTable_BTree = xBTree_initInline (&neMplsLabelRangeTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsLabelRangeEntry_t *
neMplsLabelRangeTable_createEntry (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex)
{
	register neMplsLabelRangeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ScopeIndex = u32ScopeIndex;
	memcpy (poEntry->au8Min, pau8Min, u16Min_len);
	poEntry->u16Min_len = u16Min_len;
	memcpy (poEntry->au8Max, pau8Max, u16Max_len);
	poEntry->u16Max_len = u16Max_len;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree);
	return poEntry;
}

neMplsLabelRangeEntry_t *
neMplsLabelRangeTable_getByIndex (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex)
{
	register neMplsLabelRangeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ScopeIndex = u32ScopeIndex;
	memcpy (poTmpEntry->au8Min, pau8Min, u16Min_len);
	poTmpEntry->u16Min_len = u16Min_len;
	memcpy (poTmpEntry->au8Max, pau8Max, u16Max_len);
	poTmpEntry->u16Max_len = u16Max_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsLabelRangeEntry_t, oBTreeNode);
}

neMplsLabelRangeEntry_t *
neMplsLabelRangeTable_getNextIndex (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex)
{
	register neMplsLabelRangeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ScopeIndex = u32ScopeIndex;
	memcpy (poTmpEntry->au8Min, pau8Min, u16Min_len);
	poTmpEntry->u16Min_len = u16Min_len;
	memcpy (poTmpEntry->au8Max, pau8Max, u16Max_len);
	poTmpEntry->u16Max_len = u16Max_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsLabelRangeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsLabelRangeTable_removeEntry (neMplsLabelRangeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsLabelRangeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsLabelRangeTable_BTree);
	return neMplsLabelRangeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsLabelRangeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsLabelRangeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsLabelRangeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ScopeIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Min, poEntry->u16Min_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Max, poEntry->u16Max_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsLabelRangeTable_BTree);
	return put_index_data;
}

bool
neMplsLabelRangeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsLabelRangeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = neMplsLabelRangeTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		(void*) idx3->val.string, idx3->val_len,
		*idx4->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsLabelRangeTable table mapper */
int
neMplsLabelRangeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsLabelRangeEntry_t *table_entry;
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEMPLSLABELRANGESTORAGETYPE:
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELRANGESTORAGETYPE:
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsLabelRangeTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len,
						(void*) idx3->val.string, idx3->val_len,
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsLabelRangeTable_removeEntry (table_entry);
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGESTORAGETYPE:
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neMplsLabelRangeTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neMplsLabelRangeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEMPLSLABELRANGESTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsLabelRangeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELRANGEROWSTATUS:
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
					neMplsLabelRangeTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neMplsInSegmentTable table mapper **/
void
neMplsInSegmentTable_init (void)
{
	extern oid neMplsInSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsInSegmentTable", &neMplsInSegmentTable_mapper,
		neMplsInSegmentTable_oid, OID_LENGTH (neMplsInSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsInSegmentIndex */,
		0);
	table_info->min_column = NEMPLSINSEGMENTLABELTYPE;
	table_info->max_column = NEMPLSINSEGMENTLABEL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsInSegmentTable_getFirst;
	iinfo->get_next_data_point = &neMplsInSegmentTable_getNext;
	iinfo->get_data_point = &neMplsInSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsInSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsInSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsInSegmentEntry_t, oBTreeNode);
	register neMplsInSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsInSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oNeMplsInSegmentTable_BTree = xBTree_initInline (&neMplsInSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsInSegmentEntry_t *
neMplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsInSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree);
	return poEntry;
}

neMplsInSegmentEntry_t *
neMplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsInSegmentEntry_t, oBTreeNode);
}

neMplsInSegmentEntry_t *
neMplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsInSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsInSegmentTable_removeEntry (neMplsInSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsInSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsInSegmentTable_BTree);
	return neMplsInSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsInSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsInSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsInSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsInSegmentTable_BTree);
	return put_index_data;
}

bool
neMplsInSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsInSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neMplsInSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsInSegmentTable table mapper */
int
neMplsInSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsInSegmentEntry_t *table_entry;
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
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSINSEGMENTLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Label, table_entry->u16Label_len);
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
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSINSEGMENTLABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Label));
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
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
			case NEMPLSINSEGMENTLABEL:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsInSegmentTable_createEntry (
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
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
			case NEMPLSINSEGMENTLABEL:
				neMplsInSegmentTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
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
			case NEMPLSINSEGMENTLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Label))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Label_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Label, sizeof (table_entry->au8Label));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Label, 0, sizeof (table_entry->au8Label));
				memcpy (table_entry->au8Label, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Label_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSINSEGMENTLABELTYPE:
				if (pvOldDdata == table_entry)
				{
					neMplsInSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32LabelType, pvOldDdata, sizeof (table_entry->i32LabelType));
				}
				break;
			case NEMPLSINSEGMENTLABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsInSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8Label, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16Label_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize neMplsOutSegmentTable table mapper **/
void
neMplsOutSegmentTable_init (void)
{
	extern oid neMplsOutSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsOutSegmentTable", &neMplsOutSegmentTable_mapper,
		neMplsOutSegmentTable_oid, OID_LENGTH (neMplsOutSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsOutSegmentIndex */,
		0);
	table_info->min_column = NEMPLSOUTSEGMENTLABELTYPE;
	table_info->max_column = NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsOutSegmentTable_getFirst;
	iinfo->get_next_data_point = &neMplsOutSegmentTable_getNext;
	iinfo->get_data_point = &neMplsOutSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsOutSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsOutSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsOutSegmentEntry_t, oBTreeNode);
	register neMplsOutSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsOutSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oNeMplsOutSegmentTable_BTree = xBTree_initInline (&neMplsOutSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsOutSegmentEntry_t *
neMplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsOutSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree);
	return poEntry;
}

neMplsOutSegmentEntry_t *
neMplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsOutSegmentEntry_t, oBTreeNode);
}

neMplsOutSegmentEntry_t *
neMplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register neMplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsOutSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsOutSegmentTable_removeEntry (neMplsOutSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsOutSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsOutSegmentTable_BTree);
	return neMplsOutSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsOutSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsOutSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsOutSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsOutSegmentTable_BTree);
	return put_index_data;
}

bool
neMplsOutSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsOutSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neMplsOutSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsOutSegmentTable table mapper */
int
neMplsOutSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsOutSegmentEntry_t *table_entry;
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
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSOUTSEGMENTTOPLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TopLabel, table_entry->u16TopLabel_len);
				break;
			case NEMPLSOUTSEGMENTSWAPLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SwapLabel, table_entry->u16SwapLabel_len);
				break;
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NextHopPhysAddress, table_entry->u16NextHopPhysAddress_len);
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
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSOUTSEGMENTTOPLABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TopLabel));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSOUTSEGMENTSWAPLABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SwapLabel));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NextHopPhysAddress));
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
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
			case NEMPLSOUTSEGMENTTOPLABEL:
			case NEMPLSOUTSEGMENTSWAPLABEL:
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsOutSegmentTable_createEntry (
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
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
			case NEMPLSOUTSEGMENTTOPLABEL:
			case NEMPLSOUTSEGMENTSWAPLABEL:
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				neMplsOutSegmentTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
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
			case NEMPLSOUTSEGMENTTOPLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TopLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TopLabel_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TopLabel, sizeof (table_entry->au8TopLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TopLabel, 0, sizeof (table_entry->au8TopLabel));
				memcpy (table_entry->au8TopLabel, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TopLabel_len = request->requestvb->val_len;
				break;
			case NEMPLSOUTSEGMENTSWAPLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SwapLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SwapLabel_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SwapLabel, sizeof (table_entry->au8SwapLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SwapLabel, 0, sizeof (table_entry->au8SwapLabel));
				memcpy (table_entry->au8SwapLabel, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SwapLabel_len = request->requestvb->val_len;
				break;
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NextHopPhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NextHopPhysAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NextHopPhysAddress, sizeof (table_entry->au8NextHopPhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NextHopPhysAddress, 0, sizeof (table_entry->au8NextHopPhysAddress));
				memcpy (table_entry->au8NextHopPhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NextHopPhysAddress_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSOUTSEGMENTLABELTYPE:
				if (pvOldDdata == table_entry)
				{
					neMplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32LabelType, pvOldDdata, sizeof (table_entry->i32LabelType));
				}
				break;
			case NEMPLSOUTSEGMENTTOPLABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8TopLabel, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16TopLabel_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEMPLSOUTSEGMENTSWAPLABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8SwapLabel, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16SwapLabel_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS:
				if (pvOldDdata == table_entry)
				{
					neMplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8NextHopPhysAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16NextHopPhysAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize neMplsXCTable table mapper **/
void
neMplsXCTable_init (void)
{
	extern oid neMplsXCTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsXCTable", &neMplsXCTable_mapper,
		neMplsXCTable_oid, OID_LENGTH (neMplsXCTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsXCIndex */,
		ASN_OCTET_STR /* index: mplsXCInSegmentIndex */,
		ASN_OCTET_STR /* index: mplsXCOutSegmentIndex */,
		0);
	table_info->min_column = NEMPLSXCTYPE;
	table_info->max_column = NEMPLSXCTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsXCTable_getFirst;
	iinfo->get_next_data_point = &neMplsXCTable_getNext;
	iinfo->get_data_point = &neMplsXCTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsXCTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsXCEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsXCEntry_t, oBTreeNode);
	register neMplsXCEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsXCEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == 0) ? 0: 1;
}

xBTree_t oNeMplsXCTable_BTree = xBTree_initInline (&neMplsXCTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsXCEntry_t *
neMplsXCTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register neMplsXCEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	memcpy (poEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsXCTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsXCTable_BTree);
	return poEntry;
}

neMplsXCEntry_t *
neMplsXCTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register neMplsXCEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	memcpy (poTmpEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poTmpEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poTmpEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poTmpEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsXCTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsXCEntry_t, oBTreeNode);
}

neMplsXCEntry_t *
neMplsXCTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register neMplsXCEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	memcpy (poTmpEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poTmpEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poTmpEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poTmpEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsXCTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsXCEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsXCTable_removeEntry (neMplsXCEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsXCTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsXCTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsXCTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsXCTable_BTree);
	return neMplsXCTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsXCTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsXCEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsXCEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8InSegmentIndex, poEntry->u16InSegmentIndex_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8OutSegmentIndex, poEntry->u16OutSegmentIndex_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsXCTable_BTree);
	return put_index_data;
}

bool
neMplsXCTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsXCEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = neMplsXCTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsXCTable table mapper */
int
neMplsXCTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsXCEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSXCTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
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

/** initialize neMplsLabelStackTable table mapper **/
void
neMplsLabelStackTable_init (void)
{
	extern oid neMplsLabelStackTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsLabelStackTable", &neMplsLabelStackTable_mapper,
		neMplsLabelStackTable_oid, OID_LENGTH (neMplsLabelStackTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsLabelStackIndex */,
		ASN_UNSIGNED /* index: mplsLabelStackLabelIndex */,
		0);
	table_info->min_column = NEMPLSLABELSTACKLABELTYPE;
	table_info->max_column = NEMPLSLABELSTACKLABEL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsLabelStackTable_getFirst;
	iinfo->get_next_data_point = &neMplsLabelStackTable_getNext;
	iinfo->get_data_point = &neMplsLabelStackTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neMplsLabelStackEntry_t *
neMplsLabelStackTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register neMplsLabelStackEntry_t *poEntry = NULL;
	register mplsLabelStackEntry_t *poLabelStack = NULL;
	
	if ((poLabelStack = mplsLabelStackTable_getByIndex (pau8Index, u16Index_len, u32LabelIndex)) == NULL)
	{
		return NULL;
	}
	poEntry = &poLabelStack->oNe;
	
	return poEntry;
}

neMplsLabelStackEntry_t *
neMplsLabelStackTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register mplsLabelStackEntry_t *poLabelStack = NULL;
	
	if ((poLabelStack = mplsLabelStackTable_getByIndex (pau8Index, u16Index_len, u32LabelIndex)) == NULL)
	{
		return NULL;
	}
	
	return &poLabelStack->oNe;
}

neMplsLabelStackEntry_t *
neMplsLabelStackTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register mplsLabelStackEntry_t *poLabelStack = NULL;
	
	if ((poLabelStack = mplsLabelStackTable_getNextIndex (pau8Index, u16Index_len, u32LabelIndex)) == NULL)
	{
		return NULL;
	}
	
	return &poLabelStack->oNe;
}

/* remove a row from the table */
void
neMplsLabelStackTable_removeEntry (neMplsLabelStackEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsLabelStackTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsLabelStackTable_BTree);
	return neMplsLabelStackTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsLabelStackTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsLabelStackEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsLabelStackEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LabelIndex);
	*my_data_context = (void*) &poEntry->oNe;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree);
	return put_index_data;
}

bool
neMplsLabelStackTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsLabelStackEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mplsLabelStackTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) &poEntry->oNe;
	return true;
}

/* neMplsLabelStackTable table mapper */
int
neMplsLabelStackTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsLabelStackEntry_t *table_entry;
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
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LabelType);
				break;
			case NEMPLSLABELSTACKLABEL:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Label, table_entry->u16Label_len);
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
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEMPLSLABELSTACKLABEL:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Label));
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
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
			case NEMPLSLABELSTACKLABEL:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neMplsLabelStackTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
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
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
			case NEMPLSLABELSTACKLABEL:
				neMplsLabelStackTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
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
			case NEMPLSLABELSTACKLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Label))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Label_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Label, sizeof (table_entry->au8Label));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Label, 0, sizeof (table_entry->au8Label));
				memcpy (table_entry->au8Label, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Label_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neMplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSLABELSTACKLABELTYPE:
				if (pvOldDdata == table_entry)
				{
					neMplsLabelStackTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32LabelType, pvOldDdata, sizeof (table_entry->i32LabelType));
				}
				break;
			case NEMPLSLABELSTACKLABEL:
				if (pvOldDdata == table_entry)
				{
					neMplsLabelStackTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8Label, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16Label_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/** initialize neMplsSegmentMapTable table mapper **/
void
neMplsSegmentMapTable_init (void)
{
	extern oid neMplsSegmentMapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neMplsSegmentMapTable", &neMplsSegmentMapTable_mapper,
		neMplsSegmentMapTable_oid, OID_LENGTH (neMplsSegmentMapTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: mplsInterfaceIndex */,
		ASN_INTEGER /* index: neMplsSegmentMapType */,
		ASN_INTEGER /* index: neMplsSegmentMapLabelType */,
		ASN_OCTET_STR /* index: neMplsSegmentMapLabel */,
		0);
	table_info->min_column = NEMPLSSEGMENTMAPSEGMENT;
	table_info->max_column = NEMPLSSEGMENTMAPSEGMENT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neMplsSegmentMapTable_getFirst;
	iinfo->get_next_data_point = &neMplsSegmentMapTable_getNext;
	iinfo->get_data_point = &neMplsSegmentMapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neMplsSegmentMapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neMplsSegmentMapEntry_t *pEntry1 = xBTree_entry (pNode1, neMplsSegmentMapEntry_t, oBTreeNode);
	register neMplsSegmentMapEntry_t *pEntry2 = xBTree_entry (pNode2, neMplsSegmentMapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32InterfaceIndex < pEntry2->u32InterfaceIndex) ||
		(pEntry1->u32InterfaceIndex == pEntry2->u32InterfaceIndex && pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->u32InterfaceIndex == pEntry2->u32InterfaceIndex && pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32LabelType < pEntry2->i32LabelType) ||
		(pEntry1->u32InterfaceIndex == pEntry2->u32InterfaceIndex && pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32LabelType == pEntry2->i32LabelType && xBinCmp (pEntry1->au8Label, pEntry2->au8Label, pEntry1->u16Label_len, pEntry2->u16Label_len) == -1) ? -1:
		(pEntry1->u32InterfaceIndex == pEntry2->u32InterfaceIndex && pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32LabelType == pEntry2->i32LabelType && xBinCmp (pEntry1->au8Label, pEntry2->au8Label, pEntry1->u16Label_len, pEntry2->u16Label_len) == 0) ? 0: 1;
}

xBTree_t oNeMplsSegmentMapTable_BTree = xBTree_initInline (&neMplsSegmentMapTable_BTreeNodeCmp);

/* create a new row in the table */
neMplsSegmentMapEntry_t *
neMplsSegmentMapTable_createEntry (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len)
{
	register neMplsSegmentMapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32InterfaceIndex = u32InterfaceIndex;
	poEntry->i32Type = i32Type;
	poEntry->i32LabelType = i32LabelType;
	memcpy (poEntry->au8Label, pau8Label, u16Label_len);
	poEntry->u16Label_len = u16Label_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree);
	return poEntry;
}

neMplsSegmentMapEntry_t *
neMplsSegmentMapTable_getByIndex (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len)
{
	register neMplsSegmentMapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32InterfaceIndex = u32InterfaceIndex;
	poTmpEntry->i32Type = i32Type;
	poTmpEntry->i32LabelType = i32LabelType;
	memcpy (poTmpEntry->au8Label, pau8Label, u16Label_len);
	poTmpEntry->u16Label_len = u16Label_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsSegmentMapEntry_t, oBTreeNode);
}

neMplsSegmentMapEntry_t *
neMplsSegmentMapTable_getNextIndex (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len)
{
	register neMplsSegmentMapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32InterfaceIndex = u32InterfaceIndex;
	poTmpEntry->i32Type = i32Type;
	poTmpEntry->i32LabelType = i32LabelType;
	memcpy (poTmpEntry->au8Label, pau8Label, u16Label_len);
	poTmpEntry->u16Label_len = u16Label_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neMplsSegmentMapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neMplsSegmentMapTable_removeEntry (neMplsSegmentMapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neMplsSegmentMapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeMplsSegmentMapTable_BTree);
	return neMplsSegmentMapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neMplsSegmentMapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsSegmentMapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neMplsSegmentMapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32InterfaceIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Type);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LabelType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Label, poEntry->u16Label_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeMplsSegmentMapTable_BTree);
	return put_index_data;
}

bool
neMplsSegmentMapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neMplsSegmentMapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = neMplsSegmentMapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		(void*) idx4->val.string, idx4->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neMplsSegmentMapTable table mapper */
int
neMplsSegmentMapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neMplsSegmentMapEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neMplsSegmentMapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEMPLSSEGMENTMAPSEGMENT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Segment, table_entry->u16Segment_len);
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
