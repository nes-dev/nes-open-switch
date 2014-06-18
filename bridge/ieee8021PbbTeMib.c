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
#include "ieee8021PbbTeMib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021PbbTeProtectionGroupListTable_oid[] = {1,3,111,2,802,1,1,10,1,1};
static oid ieee8021PbbTeMASharedGroupTable_oid[] = {1,3,111,2,802,1,1,10,1,2};
static oid ieee8021PbbTeTesiTable_oid[] = {1,3,111,2,802,1,1,10,1,3};
static oid ieee8021PbbTeTeSiEspTable_oid[] = {1,3,111,2,802,1,1,10,1,4};
static oid ieee8021PbbTeProtectionGroupConfigTable_oid[] = {1,3,111,2,802,1,1,10,1,5};
static oid ieee8021PbbTeProtectionGroupISidTable_oid[] = {1,3,111,2,802,1,1,10,1,6};
static oid ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_oid[] = {1,3,111,2,802,1,1,10,1,7};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid ieee8021PbbTeProtectionGroupAdminFailure_oid[] = {1,3,111,2,802,1,1,10,0,1};



/**
 *	initialize ieee8021PbbTeMib group mapper
 */
void
ieee8021PbbTeMib_init (void)
{
	DEBUGMSGTL (("ieee8021PbbTeMib", "Initializing\n"));
	
	
	/* register ieee8021PbbTeMib group table mappers */
	ieee8021PbbTeProtectionGroupListTable_init ();
	ieee8021PbbTeMASharedGroupTable_init ();
	ieee8021PbbTeTesiTable_init ();
	ieee8021PbbTeTeSiEspTable_init ();
	ieee8021PbbTeProtectionGroupConfigTable_init ();
	ieee8021PbbTeProtectionGroupISidTable_init ();
	ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_init ();
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize ieee8021PbbTeProtectionGroupListTable table mapper **/
void
ieee8021PbbTeProtectionGroupListTable_init (void)
{
	extern oid ieee8021PbbTeProtectionGroupListTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeProtectionGroupListTable", &ieee8021PbbTeProtectionGroupListTable_mapper,
		ieee8021PbbTeProtectionGroupListTable_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupListTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBaseComponentId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeProtectionGroupListGroupId */,
		0);
	table_info->min_column = IEEE8021PBBTEPROTECTIONGROUPLISTMD;
	table_info->max_column = IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeProtectionGroupListTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeProtectionGroupListTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeProtectionGroupListTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeProtectionGroupListTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeProtectionGroupListEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeProtectionGroupListEntry_t, oBTreeNode);
	register ieee8021PbbTeProtectionGroupListEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeProtectionGroupListEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBaseComponentId < pEntry2->u32BridgeBaseComponentId) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32GroupId < pEntry2->u32GroupId) ? -1:
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32GroupId == pEntry2->u32GroupId) ? 0: 1;
}

xBTree_t oIeee8021PbbTeProtectionGroupListTable_BTree = xBTree_initInline (&ieee8021PbbTeProtectionGroupListTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeProtectionGroupListEntry_t *
ieee8021PbbTeProtectionGroupListTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId)
{
	ieee8021PbbTeProtectionGroupListEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poEntry->u32GroupId = u32GroupId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = ieee8021PbbTeProtectionGroupListStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree);
	return poEntry;
}

ieee8021PbbTeProtectionGroupListEntry_t *
ieee8021PbbTeProtectionGroupListTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId)
{
	register ieee8021PbbTeProtectionGroupListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32GroupId = u32GroupId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupListEntry_t, oBTreeNode);
}

ieee8021PbbTeProtectionGroupListEntry_t *
ieee8021PbbTeProtectionGroupListTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId)
{
	register ieee8021PbbTeProtectionGroupListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32GroupId = u32GroupId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupListEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeProtectionGroupListTable_removeEntry (ieee8021PbbTeProtectionGroupListEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeProtectionGroupListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeProtectionGroupListTable_BTree);
	return ieee8021PbbTeProtectionGroupListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeProtectionGroupListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupListEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeProtectionGroupListEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBaseComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32GroupId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupListTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeProtectionGroupListTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupListEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbTeProtectionGroupListTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeProtectionGroupListTable table mapper */
int
ieee8021PbbTeProtectionGroupListTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeProtectionGroupListEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTMD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MD);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTWORKINGMA:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WorkingMA);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTPROTECTIONMA:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ProtectionMA);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTMD:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTWORKINGMA:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTPROTECTIONMA:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeProtectionGroupListTable_createEntry (
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeProtectionGroupListTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTMD:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MD))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MD, sizeof (table_entry->u32MD));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MD = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTWORKINGMA:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WorkingMA))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WorkingMA, sizeof (table_entry->u32WorkingMA));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WorkingMA = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTPROTECTIONMA:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ProtectionMA))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ProtectionMA, sizeof (table_entry->u32ProtectionMA));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ProtectionMA = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbTeProtectionGroupListTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTMD:
				memcpy (&table_entry->u32MD, pvOldDdata, sizeof (table_entry->u32MD));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTWORKINGMA:
				memcpy (&table_entry->u32WorkingMA, pvOldDdata, sizeof (table_entry->u32WorkingMA));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTPROTECTIONMA:
				memcpy (&table_entry->u32ProtectionMA, pvOldDdata, sizeof (table_entry->u32ProtectionMA));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeProtectionGroupListTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeProtectionGroupListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS:
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
					ieee8021PbbTeProtectionGroupListTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbTeMASharedGroupTable table mapper **/
void
ieee8021PbbTeMASharedGroupTable_init (void)
{
	extern oid ieee8021PbbTeMASharedGroupTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeMASharedGroupTable", &ieee8021PbbTeMASharedGroupTable_mapper,
		ieee8021PbbTeMASharedGroupTable_oid, OID_LENGTH (ieee8021PbbTeMASharedGroupTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBaseComponentId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeProtectionGroupListGroupId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeMASharedGroupSubIndex */,
		0);
	table_info->min_column = IEEE8021PBBTEMASHAREDGROUPID;
	table_info->max_column = IEEE8021PBBTEMASHAREDGROUPID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeMASharedGroupTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeMASharedGroupTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeMASharedGroupTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeMASharedGroupTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeMASharedGroupEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeMASharedGroupEntry_t, oBTreeNode);
	register ieee8021PbbTeMASharedGroupEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeMASharedGroupEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBaseComponentId < pEntry2->u32BridgeBaseComponentId) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32PbbTeProtectionGroupListGroupId < pEntry2->u32PbbTeProtectionGroupListGroupId) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32PbbTeProtectionGroupListGroupId == pEntry2->u32PbbTeProtectionGroupListGroupId && pEntry1->u32SubIndex < pEntry2->u32SubIndex) ? -1:
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32PbbTeProtectionGroupListGroupId == pEntry2->u32PbbTeProtectionGroupListGroupId && pEntry1->u32SubIndex == pEntry2->u32SubIndex) ? 0: 1;
}

xBTree_t oIeee8021PbbTeMASharedGroupTable_BTree = xBTree_initInline (&ieee8021PbbTeMASharedGroupTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeMASharedGroupEntry_t *
ieee8021PbbTeMASharedGroupTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex)
{
	ieee8021PbbTeMASharedGroupEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeMASharedGroupEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	poEntry->u32SubIndex = u32SubIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree);
	return poEntry;
}

ieee8021PbbTeMASharedGroupEntry_t *
ieee8021PbbTeMASharedGroupTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex)
{
	register ieee8021PbbTeMASharedGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeMASharedGroupEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	poTmpEntry->u32SubIndex = u32SubIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeMASharedGroupEntry_t, oBTreeNode);
}

ieee8021PbbTeMASharedGroupEntry_t *
ieee8021PbbTeMASharedGroupTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex)
{
	register ieee8021PbbTeMASharedGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeMASharedGroupEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	poTmpEntry->u32SubIndex = u32SubIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeMASharedGroupEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeMASharedGroupTable_removeEntry (ieee8021PbbTeMASharedGroupEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeMASharedGroupTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeMASharedGroupTable_BTree);
	return ieee8021PbbTeMASharedGroupTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeMASharedGroupTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeMASharedGroupEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeMASharedGroupEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBaseComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PbbTeProtectionGroupListGroupId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32SubIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeMASharedGroupTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeMASharedGroupTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeMASharedGroupEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbbTeMASharedGroupTable_getByIndex (
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

/* ieee8021PbbTeMASharedGroupTable table mapper */
int
ieee8021PbbTeMASharedGroupTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeMASharedGroupEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbTeMASharedGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEMASHAREDGROUPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Id);
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

/** initialize ieee8021PbbTeTesiTable table mapper **/
void
ieee8021PbbTeTesiTable_init (void)
{
	extern oid ieee8021PbbTeTesiTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeTesiTable", &ieee8021PbbTeTesiTable_mapper,
		ieee8021PbbTeTesiTable_oid, OID_LENGTH (ieee8021PbbTeTesiTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021PbbTeTesiId */,
		0);
	table_info->min_column = IEEE8021PBBTETESICOMPONENT;
	table_info->max_column = IEEE8021PBBTETESIROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeTesiTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeTesiTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeTesiTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeTesiTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeTesiEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeTesiEntry_t, oBTreeNode);
	register ieee8021PbbTeTesiEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeTesiEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oIeee8021PbbTeTesiTable_BTree = xBTree_initInline (&ieee8021PbbTeTesiTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeTesiEntry_t *
ieee8021PbbTeTesiTable_createEntry (
	uint32_t u32Id)
{
	ieee8021PbbTeTesiEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTesiEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = ieee8021PbbTeTesiStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree);
	return poEntry;
}

ieee8021PbbTeTesiEntry_t *
ieee8021PbbTeTesiTable_getByIndex (
	uint32_t u32Id)
{
	register ieee8021PbbTeTesiEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTesiEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeTesiEntry_t, oBTreeNode);
}

ieee8021PbbTeTesiEntry_t *
ieee8021PbbTeTesiTable_getNextIndex (
	uint32_t u32Id)
{
	register ieee8021PbbTeTesiEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTesiEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeTesiEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeTesiTable_removeEntry (ieee8021PbbTeTesiEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeTesiTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeTesiTable_BTree);
	return ieee8021PbbTeTesiTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeTesiTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeTesiEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeTesiEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeTesiTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeTesiTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeTesiEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021PbbTeTesiTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeTesiTable table mapper */
int
ieee8021PbbTeTesiTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeTesiEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESICOMPONENT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Component);
				break;
			case IEEE8021PBBTETESIBRIDGEPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32BridgePort);
				break;
			case IEEE8021PBBTETESISTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBTETESIROWSTATUS:
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESICOMPONENT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTETESIBRIDGEPORT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTETESISTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTETESIROWSTATUS:
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeTesiTable_createEntry (
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeTesiTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESICOMPONENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Component))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Component, sizeof (table_entry->u32Component));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Component = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTETESIBRIDGEPORT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32BridgePort))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32BridgePort, sizeof (table_entry->u32BridgePort));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32BridgePort = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTETESISTORAGETYPE:
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbTeTesiTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESICOMPONENT:
				memcpy (&table_entry->u32Component, pvOldDdata, sizeof (table_entry->u32Component));
				break;
			case IEEE8021PBBTETESIBRIDGEPORT:
				memcpy (&table_entry->u32BridgePort, pvOldDdata, sizeof (table_entry->u32BridgePort));
				break;
			case IEEE8021PBBTETESISTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBTETESIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeTesiTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeTesiEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIROWSTATUS:
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
					ieee8021PbbTeTesiTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbTeTeSiEspTable table mapper **/
void
ieee8021PbbTeTeSiEspTable_init (void)
{
	extern oid ieee8021PbbTeTeSiEspTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeTeSiEspTable", &ieee8021PbbTeTeSiEspTable_mapper,
		ieee8021PbbTeTeSiEspTable_oid, OID_LENGTH (ieee8021PbbTeTeSiEspTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021PbbTeTesiId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeTeSiEspEspIndex */,
		0);
	table_info->min_column = IEEE8021PBBTETESIESPESP;
	table_info->max_column = IEEE8021PBBTETESIESPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeTeSiEspTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeTeSiEspTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeTeSiEspTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeTeSiEspTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeTeSiEspEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeTeSiEspEntry_t, oBTreeNode);
	register ieee8021PbbTeTeSiEspEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeTeSiEspEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32TesiId < pEntry2->u32TesiId) ||
		(pEntry1->u32TesiId == pEntry2->u32TesiId && pEntry1->u32EspIndex < pEntry2->u32EspIndex) ? -1:
		(pEntry1->u32TesiId == pEntry2->u32TesiId && pEntry1->u32EspIndex == pEntry2->u32EspIndex) ? 0: 1;
}

xBTree_t oIeee8021PbbTeTeSiEspTable_BTree = xBTree_initInline (&ieee8021PbbTeTeSiEspTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeTeSiEspEntry_t *
ieee8021PbbTeTeSiEspTable_createEntry (
	uint32_t u32TesiId,
	uint32_t u32EspIndex)
{
	ieee8021PbbTeTeSiEspEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTeSiEspEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32TesiId = u32TesiId;
	poEntry->u32EspIndex = u32EspIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = ieee8021PbbTeTeSiEspStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree);
	return poEntry;
}

ieee8021PbbTeTeSiEspEntry_t *
ieee8021PbbTeTeSiEspTable_getByIndex (
	uint32_t u32TesiId,
	uint32_t u32EspIndex)
{
	register ieee8021PbbTeTeSiEspEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTeSiEspEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32TesiId = u32TesiId;
	poTmpEntry->u32EspIndex = u32EspIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeTeSiEspEntry_t, oBTreeNode);
}

ieee8021PbbTeTeSiEspEntry_t *
ieee8021PbbTeTeSiEspTable_getNextIndex (
	uint32_t u32TesiId,
	uint32_t u32EspIndex)
{
	register ieee8021PbbTeTeSiEspEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeTeSiEspEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32TesiId = u32TesiId;
	poTmpEntry->u32EspIndex = u32EspIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeTeSiEspEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeTeSiEspTable_removeEntry (ieee8021PbbTeTeSiEspEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeTeSiEspTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeTeSiEspTable_BTree);
	return ieee8021PbbTeTeSiEspTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeTeSiEspTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeTeSiEspEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeTeSiEspEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32TesiId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EspIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeTeSiEspTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeTeSiEspTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeTeSiEspEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbTeTeSiEspTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeTeSiEspTable table mapper */
int
ieee8021PbbTeTeSiEspTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeTeSiEspEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPESP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Esp, table_entry->u16Esp_len);
				break;
			case IEEE8021PBBTETESIESPSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBTETESIESPROWSTATUS:
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPESP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Esp));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTETESIESPSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTETESIESPROWSTATUS:
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeTeSiEspTable_createEntry (
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeTeSiEspTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPESP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Esp))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Esp_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Esp, sizeof (table_entry->au8Esp));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Esp, 0, sizeof (table_entry->au8Esp));
				memcpy (table_entry->au8Esp, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Esp_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBTETESIESPSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbTeTeSiEspTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPESP:
				memcpy (table_entry->au8Esp, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Esp_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBTETESIESPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBTETESIESPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeTeSiEspTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeTeSiEspEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTETESIESPROWSTATUS:
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
					ieee8021PbbTeTeSiEspTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbTeProtectionGroupConfigTable table mapper **/
void
ieee8021PbbTeProtectionGroupConfigTable_init (void)
{
	extern oid ieee8021PbbTeProtectionGroupConfigTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeProtectionGroupConfigTable", &ieee8021PbbTeProtectionGroupConfigTable_mapper,
		ieee8021PbbTeProtectionGroupConfigTable_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupConfigTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBaseComponentId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeProtectionGroupListGroupId */,
		0);
	table_info->min_column = IEEE8021PBBTEPROTECTIONGROUPCONFIGSTATE;
	table_info->max_column = IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeProtectionGroupConfigTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeProtectionGroupConfigTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeProtectionGroupConfigTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeProtectionGroupConfigTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeProtectionGroupConfigEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeProtectionGroupConfigEntry_t, oBTreeNode);
	register ieee8021PbbTeProtectionGroupConfigEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeProtectionGroupConfigEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBaseComponentId < pEntry2->u32BridgeBaseComponentId) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32PbbTeProtectionGroupListGroupId < pEntry2->u32PbbTeProtectionGroupListGroupId) ? -1:
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32PbbTeProtectionGroupListGroupId == pEntry2->u32PbbTeProtectionGroupListGroupId) ? 0: 1;
}

xBTree_t oIeee8021PbbTeProtectionGroupConfigTable_BTree = xBTree_initInline (&ieee8021PbbTeProtectionGroupConfigTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeProtectionGroupConfigEntry_t *
ieee8021PbbTeProtectionGroupConfigTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId)
{
	ieee8021PbbTeProtectionGroupConfigEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupConfigEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32CommandAdmin = ieee8021PbbTeProtectionGroupConfigCommandAdmin_clear_c;
	poEntry->u32WTR = 5;
	poEntry->u32HoldOff = 0;
	poEntry->i32NotifyEnable = ieee8021PbbTeProtectionGroupConfigNotifyEnable_false_c;
	poEntry->u8StorageType = ieee8021PbbTeProtectionGroupConfigStorageType_nonVolatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree);
	return poEntry;
}

ieee8021PbbTeProtectionGroupConfigEntry_t *
ieee8021PbbTeProtectionGroupConfigTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId)
{
	register ieee8021PbbTeProtectionGroupConfigEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupConfigEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupConfigEntry_t, oBTreeNode);
}

ieee8021PbbTeProtectionGroupConfigEntry_t *
ieee8021PbbTeProtectionGroupConfigTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId)
{
	register ieee8021PbbTeProtectionGroupConfigEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupConfigEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32PbbTeProtectionGroupListGroupId = u32PbbTeProtectionGroupListGroupId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupConfigEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeProtectionGroupConfigTable_removeEntry (ieee8021PbbTeProtectionGroupConfigEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeProtectionGroupConfigTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeProtectionGroupConfigTable_BTree);
	return ieee8021PbbTeProtectionGroupConfigTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeProtectionGroupConfigTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupConfigEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeProtectionGroupConfigEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBaseComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PbbTeProtectionGroupListGroupId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupConfigTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeProtectionGroupConfigTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupConfigEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbTeProtectionGroupConfigTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeProtectionGroupConfigTable table mapper */
int
ieee8021PbbTeProtectionGroupConfigTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeProtectionGroupConfigEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CommandStatus);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDLAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CommandLast);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CommandAdmin);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGACTIVEREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActiveRequests);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WTR);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32HoldOff);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NotifyEnable);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeProtectionGroupConfigTable_createEntry (
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
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
				ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CommandAdmin))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CommandAdmin, sizeof (table_entry->i32CommandAdmin));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CommandAdmin = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WTR))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WTR, sizeof (table_entry->u32WTR));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WTR = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32HoldOff))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32HoldOff, sizeof (table_entry->u32HoldOff));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32HoldOff = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32NotifyEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32NotifyEnable, sizeof (table_entry->i32NotifyEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32NotifyEnable = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
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
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbbTeProtectionGroupConfigEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN:
				if (pvOldDdata == table_entry)
				{
					ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32CommandAdmin, pvOldDdata, sizeof (table_entry->i32CommandAdmin));
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR:
				if (pvOldDdata == table_entry)
				{
					ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32WTR, pvOldDdata, sizeof (table_entry->u32WTR));
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF:
				if (pvOldDdata == table_entry)
				{
					ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32HoldOff, pvOldDdata, sizeof (table_entry->u32HoldOff));
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE:
				if (pvOldDdata == table_entry)
				{
					ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32NotifyEnable, pvOldDdata, sizeof (table_entry->i32NotifyEnable));
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE:
				if (pvOldDdata == table_entry)
				{
					ieee8021PbbTeProtectionGroupConfigTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
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

/** initialize ieee8021PbbTeProtectionGroupISidTable table mapper **/
void
ieee8021PbbTeProtectionGroupISidTable_init (void)
{
	extern oid ieee8021PbbTeProtectionGroupISidTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeProtectionGroupISidTable", &ieee8021PbbTeProtectionGroupISidTable_mapper,
		ieee8021PbbTeProtectionGroupISidTable_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupISidTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021PbbTeProtectionGroupISidIndex */,
		0);
	table_info->min_column = IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID;
	table_info->max_column = IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeProtectionGroupISidTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeProtectionGroupISidTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeProtectionGroupISidTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeProtectionGroupISidTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeProtectionGroupISidEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeProtectionGroupISidEntry_t, oBTreeNode);
	register ieee8021PbbTeProtectionGroupISidEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeProtectionGroupISidEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIeee8021PbbTeProtectionGroupISidTable_BTree = xBTree_initInline (&ieee8021PbbTeProtectionGroupISidTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeProtectionGroupISidEntry_t *
ieee8021PbbTeProtectionGroupISidTable_createEntry (
	uint32_t u32Index)
{
	ieee8021PbbTeProtectionGroupISidEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupISidEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = ieee8021PbbTeProtectionGroupISidStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree);
	return poEntry;
}

ieee8021PbbTeProtectionGroupISidEntry_t *
ieee8021PbbTeProtectionGroupISidTable_getByIndex (
	uint32_t u32Index)
{
	register ieee8021PbbTeProtectionGroupISidEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupISidEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupISidEntry_t, oBTreeNode);
}

ieee8021PbbTeProtectionGroupISidEntry_t *
ieee8021PbbTeProtectionGroupISidTable_getNextIndex (
	uint32_t u32Index)
{
	register ieee8021PbbTeProtectionGroupISidEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeProtectionGroupISidEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeProtectionGroupISidEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeProtectionGroupISidTable_removeEntry (ieee8021PbbTeProtectionGroupISidEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeProtectionGroupISidTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeProtectionGroupISidTable_BTree);
	return ieee8021PbbTeProtectionGroupISidTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeProtectionGroupISidTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupISidEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeProtectionGroupISidEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeProtectionGroupISidTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeProtectionGroupISidTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeProtectionGroupISidEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021PbbTeProtectionGroupISidTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeProtectionGroupISidTable table mapper */
int
ieee8021PbbTeProtectionGroupISidTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeProtectionGroupISidEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ComponentId);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDGROUPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32GroupId);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDGROUPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeProtectionGroupISidTable_createEntry (
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeProtectionGroupISidTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ComponentId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ComponentId, sizeof (table_entry->u32ComponentId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ComponentId = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDGROUPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32GroupId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32GroupId, sizeof (table_entry->u32GroupId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32GroupId = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbTeProtectionGroupISidTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID:
				memcpy (&table_entry->u32ComponentId, pvOldDdata, sizeof (table_entry->u32ComponentId));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDGROUPID:
				memcpy (&table_entry->u32GroupId, pvOldDdata, sizeof (table_entry->u32GroupId));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeProtectionGroupISidTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeProtectionGroupISidEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS:
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
					ieee8021PbbTeProtectionGroupISidTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbTeBridgeStaticForwardAnyUnicastTable table mapper **/
void
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_init (void)
{
	extern oid ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbTeBridgeStaticForwardAnyUnicastTable", &ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_mapper,
		ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_oid, OID_LENGTH (ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021PbbTeBridgeStaticForwardAnyUnicastVlanIndex */,
		0);
	table_info->min_column = IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS;
	table_info->max_column = IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNext;
	iinfo->get_data_point = &ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t, oBTreeNode);
	register ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32QBridgeVlanCurrentComponentId < pEntry2->u32QBridgeVlanCurrentComponentId) ||
		(pEntry1->u32QBridgeVlanCurrentComponentId == pEntry2->u32QBridgeVlanCurrentComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ? -1:
		(pEntry1->u32QBridgeVlanCurrentComponentId == pEntry2->u32QBridgeVlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex) ? 0: 1;
}

xBTree_t oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree = xBTree_initInline (&ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_createEntry (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32QBridgeVlanCurrentComponentId = u32QBridgeVlanCurrentComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8StorageType = ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree);
	return poEntry;
}

ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getByIndex (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32QBridgeVlanCurrentComponentId = u32QBridgeVlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t, oBTreeNode);
}

ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNextIndex (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32QBridgeVlanCurrentComponentId = u32QBridgeVlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_removeEntry (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree);
	return ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32QBridgeVlanCurrentComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbTeBridgeStaticForwardAnyUnicastTable table mapper */
int
ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *table_entry;
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EgressPorts, table_entry->u16EgressPorts_len);
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTFORBIDDENPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForbiddenPorts, table_entry->u16ForbiddenPorts_len);
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8EgressPorts));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTFORBIDDENPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ForbiddenPorts));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_createEntry (
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8EgressPorts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16EgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8EgressPorts, sizeof (table_entry->au8EgressPorts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8EgressPorts, 0, sizeof (table_entry->au8EgressPorts));
				memcpy (table_entry->au8EgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16EgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTFORBIDDENPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ForbiddenPorts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ForbiddenPorts, sizeof (table_entry->au8ForbiddenPorts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ForbiddenPorts, 0, sizeof (table_entry->au8ForbiddenPorts));
				memcpy (table_entry->au8ForbiddenPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTSTORAGETYPE:
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS:
				memcpy (table_entry->au8EgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16EgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTFORBIDDENPORTS:
				memcpy (table_entry->au8ForbiddenPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS:
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
					ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_removeEntry (table_entry);
					break;
				}
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
ieee8021PbbTeProtectionGroupAdminFailure_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid ieee8021PbbTeProtectionGroupAdminFailure_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid ieee8021PbbTeProtectionGroupConfigState_oid[] = {1,3,111,2,802,1,1,10,1,5,1,1, /* insert index here */};
	oid ieee8021PbbTeProtectionGroupConfigCommandStatus_oid[] = {1,3,111,2,802,1,1,10,1,5,1,2, /* insert index here */};
	oid ieee8021PbbTeProtectionGroupConfigCommandLast_oid[] = {1,3,111,2,802,1,1,10,1,5,1,3, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) ieee8021PbbTeProtectionGroupAdminFailure_oid, sizeof (ieee8021PbbTeProtectionGroupAdminFailure_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		ieee8021PbbTeProtectionGroupConfigState_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupConfigState_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ieee8021PbbTeProtectionGroupConfigState */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ieee8021PbbTeProtectionGroupConfigCommandStatus_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupConfigCommandStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ieee8021PbbTeProtectionGroupConfigCommandStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ieee8021PbbTeProtectionGroupConfigCommandLast_oid, OID_LENGTH (ieee8021PbbTeProtectionGroupConfigCommandLast_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ieee8021PbbTeProtectionGroupConfigCommandLast */
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
