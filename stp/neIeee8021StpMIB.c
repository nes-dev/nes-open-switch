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
#include "neIeee8021StpMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid neIeee8021StpMIB_oid[] = {1,3,6,1,4,1,36969,72};

static oid neIeee8021MstpCistTable_oid[] = {1,3,6,1,4,1,36969,72,1,1};
static oid neIeee8021MstpTable_oid[] = {1,3,6,1,4,1,36969,72,1,2};
static oid neIeee8021MstpCistPortTable_oid[] = {1,3,6,1,4,1,36969,72,1,3};
static oid neIeee8021MstpPortTable_oid[] = {1,3,6,1,4,1,36969,72,1,4};
static oid neIeee8021MstpFidToMstiV2Table_oid[] = {1,3,6,1,4,1,36969,72,1,5};
static oid neIeee8021MstpVlanV2Table_oid[] = {1,3,6,1,4,1,36969,72,1,6};



/**
 *	initialize neIeee8021StpMIB group mapper
 */
void
neIeee8021StpMIB_init (void)
{
	extern oid neIeee8021StpMIB_oid[];
	
	DEBUGMSGTL (("neIeee8021StpMIB", "Initializing\n"));
	
	
	/* register neIeee8021StpMIB group table mappers */
	neIeee8021MstpCistTable_init ();
	neIeee8021MstpTable_init ();
	neIeee8021MstpCistPortTable_init ();
	neIeee8021MstpPortTable_init ();
	neIeee8021MstpFidToMstiV2Table_init ();
	neIeee8021MstpVlanV2Table_init ();
	
	/* register neIeee8021StpMIB modules */
	sysORTable_createRegister ("neIeee8021StpMIB", neIeee8021StpMIB_oid, OID_LENGTH (neIeee8021StpMIB_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize neIeee8021MstpCistTable table mapper **/
void
neIeee8021MstpCistTable_init (void)
{
	extern oid neIeee8021MstpCistTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpCistTable", &neIeee8021MstpCistTable_mapper,
		neIeee8021MstpCistTable_oid, OID_LENGTH (neIeee8021MstpCistTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpCistComponentId */,
		0);
	table_info->min_column = NEIEEE8021MSTPCISTADMINFLAGS;
	table_info->max_column = NEIEEE8021MSTPCISTTEMPLATEID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpCistTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpCistTable_getNext;
	iinfo->get_data_point = &neIeee8021MstpCistTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpCistTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpCistEntry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpCistEntry_t, oBTreeNode);
	register neIeee8021MstpCistEntry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpCistEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId) ? 0: 1;
}

xBTree_t oNeIeee8021MstpCistTable_BTree = xBTree_initInline (&neIeee8021MstpCistTable_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpCistEntry_t *
neIeee8021MstpCistTable_createEntry (
	uint32_t u32ComponentId)
{
	register neIeee8021MstpCistEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree);
	return poEntry;
}

neIeee8021MstpCistEntry_t *
neIeee8021MstpCistTable_getByIndex (
	uint32_t u32ComponentId)
{
	register neIeee8021MstpCistEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpCistEntry_t, oBTreeNode);
}

neIeee8021MstpCistEntry_t *
neIeee8021MstpCistTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register neIeee8021MstpCistEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpCistEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpCistTable_removeEntry (neIeee8021MstpCistEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpCistTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpCistTable_BTree);
	return neIeee8021MstpCistTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpCistTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpCistEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpCistEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpCistTable_BTree);
	return put_index_data;
}

bool
neIeee8021MstpCistTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpCistEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neIeee8021MstpCistTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021MstpCistTable table mapper */
int
neIeee8021MstpCistTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpCistEntry_t *table_entry;
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
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, table_entry->u16AdminFlags_len);
				break;
			case NEIEEE8021MSTPCISTTEMPLATEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TemplateId);
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
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIEEE8021MSTPCISTTEMPLATEID:
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
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
			case NEIEEE8021MSTPCISTTEMPLATEID:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neIeee8021MstpCistTable_createEntry (
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
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
			case NEIEEE8021MSTPCISTTEMPLATEID:
				neIeee8021MstpCistTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AdminFlags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AdminFlags_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AdminFlags, sizeof (table_entry->au8AdminFlags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdminFlags, 0, sizeof (table_entry->au8AdminFlags));
				memcpy (table_entry->au8AdminFlags, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AdminFlags_len = request->requestvb->val_len;
				break;
			case NEIEEE8021MSTPCISTTEMPLATEID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TemplateId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TemplateId, sizeof (table_entry->u32TemplateId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TemplateId = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpCistEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTADMINFLAGS:
				if (pvOldDdata == table_entry)
				{
					neIeee8021MstpCistTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8AdminFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16AdminFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEIEEE8021MSTPCISTTEMPLATEID:
				if (pvOldDdata == table_entry)
				{
					neIeee8021MstpCistTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32TemplateId, pvOldDdata, sizeof (table_entry->u32TemplateId));
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

/** initialize neIeee8021MstpTable table mapper **/
void
neIeee8021MstpTable_init (void)
{
	extern oid neIeee8021MstpTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpTable", &neIeee8021MstpTable_mapper,
		neIeee8021MstpTable_oid, OID_LENGTH (neIeee8021MstpTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpId */,
		0);
	table_info->min_column = NEIEEE8021MSTPADMINFLAGS;
	table_info->max_column = NEIEEE8021MSTPMSTITYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpTable_getNext;
	iinfo->get_data_point = &neIeee8021MstpTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpEntry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpEntry_t, oBTreeNode);
	register neIeee8021MstpEntry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u16Id < pEntry2->u16Id) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u16Id == pEntry2->u16Id) ? 0: 1;
}

xBTree_t oNeIeee8021MstpTable_BTree = xBTree_initInline (&neIeee8021MstpTable_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpEntry_t *
neIeee8021MstpTable_createEntry (
	uint32_t u32ComponentId,
	uint16_t u16Id)
{
	register neIeee8021MstpEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u16Id = u16Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32MstiType = neIeee8021MstpMstiType_mstp_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree);
	return poEntry;
}

neIeee8021MstpEntry_t *
neIeee8021MstpTable_getByIndex (
	uint32_t u32ComponentId,
	uint16_t u16Id)
{
	register neIeee8021MstpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u16Id = u16Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpEntry_t, oBTreeNode);
}

neIeee8021MstpEntry_t *
neIeee8021MstpTable_getNextIndex (
	uint32_t u32ComponentId,
	uint16_t u16Id)
{
	register neIeee8021MstpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u16Id = u16Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpTable_removeEntry (neIeee8021MstpEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpTable_BTree);
	return neIeee8021MstpTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u16Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpTable_BTree);
	return put_index_data;
}

bool
neIeee8021MstpTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIeee8021MstpTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021MstpTable table mapper */
int
neIeee8021MstpTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpEntry_t *table_entry;
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
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, table_entry->u16AdminFlags_len);
				break;
			case NEIEEE8021MSTPMSTITYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MstiType);
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
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIEEE8021MSTPMSTITYPE:
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
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
			case NEIEEE8021MSTPMSTITYPE:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neIeee8021MstpTable_createEntry (
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
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
			case NEIEEE8021MSTPMSTITYPE:
				neIeee8021MstpTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AdminFlags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AdminFlags_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AdminFlags, sizeof (table_entry->au8AdminFlags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdminFlags, 0, sizeof (table_entry->au8AdminFlags));
				memcpy (table_entry->au8AdminFlags, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AdminFlags_len = request->requestvb->val_len;
				break;
			case NEIEEE8021MSTPMSTITYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MstiType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MstiType, sizeof (table_entry->i32MstiType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MstiType = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPADMINFLAGS:
				if (pvOldDdata == table_entry)
				{
					neIeee8021MstpTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8AdminFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16AdminFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case NEIEEE8021MSTPMSTITYPE:
				if (pvOldDdata == table_entry)
				{
					neIeee8021MstpTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32MstiType, pvOldDdata, sizeof (table_entry->i32MstiType));
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

/** initialize neIeee8021MstpCistPortTable table mapper **/
void
neIeee8021MstpCistPortTable_init (void)
{
	extern oid neIeee8021MstpCistPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpCistPortTable", &neIeee8021MstpCistPortTable_mapper,
		neIeee8021MstpCistPortTable_oid, OID_LENGTH (neIeee8021MstpCistPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpCistPortNum */,
		0);
	table_info->min_column = NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE;
	table_info->max_column = NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpCistPortTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpCistPortTable_getNext;
	iinfo->get_data_point = &neIeee8021MstpCistPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpCistPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpCistPortEntry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpCistPortEntry_t, oBTreeNode);
	register neIeee8021MstpCistPortEntry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpCistPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num < pEntry2->u32Num) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Num == pEntry2->u32Num) ? 0: 1;
}

xBTree_t oNeIeee8021MstpCistPortTable_BTree = xBTree_initInline (&neIeee8021MstpCistPortTable_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpCistPortEntry_t *
neIeee8021MstpCistPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register neIeee8021MstpCistPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Num = u32Num;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree);
	return poEntry;
}

neIeee8021MstpCistPortEntry_t *
neIeee8021MstpCistPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register neIeee8021MstpCistPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpCistPortEntry_t, oBTreeNode);
}

neIeee8021MstpCistPortEntry_t *
neIeee8021MstpCistPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num)
{
	register neIeee8021MstpCistPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpCistPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpCistPortTable_removeEntry (neIeee8021MstpCistPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpCistPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpCistPortTable_BTree);
	return neIeee8021MstpCistPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpCistPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpCistPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpCistPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Num);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpCistPortTable_BTree);
	return put_index_data;
}

bool
neIeee8021MstpCistPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpCistPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIeee8021MstpCistPortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021MstpCistPortTable table mapper */
int
neIeee8021MstpCistPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpCistPortEntry_t *table_entry;
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
			table_entry = (neIeee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RestrictedDomainRole);
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
			table_entry = (neIeee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE:
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
			table_entry = (neIeee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (neIeee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8RestrictedDomainRole))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8RestrictedDomainRole, sizeof (table_entry->u8RestrictedDomainRole));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8RestrictedDomainRole = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpCistPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE:
				memcpy (&table_entry->u8RestrictedDomainRole, pvOldDdata, sizeof (table_entry->u8RestrictedDomainRole));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIeee8021MstpPortTable table mapper **/
void
neIeee8021MstpPortTable_init (void)
{
	extern oid neIeee8021MstpPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpPortTable", &neIeee8021MstpPortTable_mapper,
		neIeee8021MstpPortTable_oid, OID_LENGTH (neIeee8021MstpPortTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpPortMstId */,
		ASN_UNSIGNED /* index: ieee8021MstpPortNum */,
		0);
	table_info->min_column = NEIEEE8021MSTPPORTFLAGS;
	table_info->max_column = NEIEEE8021MSTPPORTFLAGS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpPortTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpPortTable_getNext;
	iinfo->get_data_point = &neIeee8021MstpPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpPortEntry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpPortEntry_t, oBTreeNode);
	register neIeee8021MstpPortEntry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u16MstId < pEntry2->u16MstId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u16MstId == pEntry2->u16MstId && pEntry1->u32Num < pEntry2->u32Num) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u16MstId == pEntry2->u16MstId && pEntry1->u32Num == pEntry2->u32Num) ? 0: 1;
}

xBTree_t oNeIeee8021MstpPortTable_BTree = xBTree_initInline (&neIeee8021MstpPortTable_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpPortEntry_t *
neIeee8021MstpPortTable_createEntry (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num)
{
	register neIeee8021MstpPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u16MstId = u16MstId;
	poEntry->u32Num = u32Num;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree);
	return poEntry;
}

neIeee8021MstpPortEntry_t *
neIeee8021MstpPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num)
{
	register neIeee8021MstpPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u16MstId = u16MstId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpPortEntry_t, oBTreeNode);
}

neIeee8021MstpPortEntry_t *
neIeee8021MstpPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num)
{
	register neIeee8021MstpPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u16MstId = u16MstId;
	poTmpEntry->u32Num = u32Num;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpPortTable_removeEntry (neIeee8021MstpPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpPortTable_BTree);
	return neIeee8021MstpPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u16MstId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Num);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpPortTable_BTree);
	return put_index_data;
}

bool
neIeee8021MstpPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = neIeee8021MstpPortTable_getByIndex (
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

/* neIeee8021MstpPortTable table mapper */
int
neIeee8021MstpPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpPortEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neIeee8021MstpPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPPORTFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Flags, table_entry->u16Flags_len);
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

/** initialize neIeee8021MstpFidToMstiV2Table table mapper **/
void
neIeee8021MstpFidToMstiV2Table_init (void)
{
	extern oid neIeee8021MstpFidToMstiV2Table_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpFidToMstiV2Table", &neIeee8021MstpFidToMstiV2Table_mapper,
		neIeee8021MstpFidToMstiV2Table_oid, OID_LENGTH (neIeee8021MstpFidToMstiV2Table_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpFidToMstiV2ComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpFidToMstiV2Fid */,
		0);
	table_info->min_column = NEIEEE8021MSTPFIDTOMSTIV2SPTID;
	table_info->max_column = NEIEEE8021MSTPFIDTOMSTIV2SPTID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpFidToMstiV2Table_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpFidToMstiV2Table_getNext;
	iinfo->get_data_point = &neIeee8021MstpFidToMstiV2Table_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpFidToMstiV2Table_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpFidToMstiV2Entry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	register neIeee8021MstpFidToMstiV2Entry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Fid < pEntry2->u32Fid) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Fid == pEntry2->u32Fid) ? 0: 1;
}

xBTree_t oNeIeee8021MstpFidToMstiV2Table_BTree = xBTree_initInline (&neIeee8021MstpFidToMstiV2Table_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpFidToMstiV2Entry_t *
neIeee8021MstpFidToMstiV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	register neIeee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Fid = u32Fid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree);
	return poEntry;
}

neIeee8021MstpFidToMstiV2Entry_t *
neIeee8021MstpFidToMstiV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	register neIeee8021MstpFidToMstiV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Fid = u32Fid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpFidToMstiV2Entry_t, oBTreeNode);
}

neIeee8021MstpFidToMstiV2Entry_t *
neIeee8021MstpFidToMstiV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid)
{
	register neIeee8021MstpFidToMstiV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Fid = u32Fid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpFidToMstiV2Entry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpFidToMstiV2Table_removeEntry (neIeee8021MstpFidToMstiV2Entry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpFidToMstiV2Table_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpFidToMstiV2Table_BTree);
	return neIeee8021MstpFidToMstiV2Table_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpFidToMstiV2Table_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpFidToMstiV2Entry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Fid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpFidToMstiV2Table_BTree);
	return put_index_data;
}

bool
neIeee8021MstpFidToMstiV2Table_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpFidToMstiV2Entry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIeee8021MstpFidToMstiV2Table_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021MstpFidToMstiV2Table table mapper */
int
neIeee8021MstpFidToMstiV2Table_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpFidToMstiV2Entry_t *table_entry;
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
			table_entry = (neIeee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPFIDTOMSTIV2SPTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u16SptId);
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
			table_entry = (neIeee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPFIDTOMSTIV2SPTID:
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
			table_entry = (neIeee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (neIeee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPFIDTOMSTIV2SPTID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u16SptId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u16SptId, sizeof (table_entry->u16SptId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u16SptId = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIeee8021MstpFidToMstiV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPFIDTOMSTIV2SPTID:
				memcpy (&table_entry->u16SptId, pvOldDdata, sizeof (table_entry->u16SptId));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIeee8021MstpVlanV2Table table mapper **/
void
neIeee8021MstpVlanV2Table_init (void)
{
	extern oid neIeee8021MstpVlanV2Table_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021MstpVlanV2Table", &neIeee8021MstpVlanV2Table_mapper,
		neIeee8021MstpVlanV2Table_oid, OID_LENGTH (neIeee8021MstpVlanV2Table_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021MstpVlanV2ComponentId */,
		ASN_UNSIGNED /* index: ieee8021MstpVlanV2Id */,
		0);
	table_info->min_column = NEIEEE8021MSTPVLANV2SPTID;
	table_info->max_column = NEIEEE8021MSTPVLANV2SPTID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021MstpVlanV2Table_getFirst;
	iinfo->get_next_data_point = &neIeee8021MstpVlanV2Table_getNext;
	iinfo->get_data_point = &neIeee8021MstpVlanV2Table_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIeee8021MstpVlanV2Table_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIeee8021MstpVlanV2Entry_t *pEntry1 = xBTree_entry (pNode1, neIeee8021MstpVlanV2Entry_t, oBTreeNode);
	register neIeee8021MstpVlanV2Entry_t *pEntry2 = xBTree_entry (pNode2, neIeee8021MstpVlanV2Entry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oNeIeee8021MstpVlanV2Table_BTree = xBTree_initInline (&neIeee8021MstpVlanV2Table_BTreeNodeCmp);

/* create a new row in the table */
neIeee8021MstpVlanV2Entry_t *
neIeee8021MstpVlanV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register neIeee8021MstpVlanV2Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree);
	return poEntry;
}

neIeee8021MstpVlanV2Entry_t *
neIeee8021MstpVlanV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register neIeee8021MstpVlanV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpVlanV2Entry_t, oBTreeNode);
}

neIeee8021MstpVlanV2Entry_t *
neIeee8021MstpVlanV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register neIeee8021MstpVlanV2Entry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIeee8021MstpVlanV2Entry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIeee8021MstpVlanV2Table_removeEntry (neIeee8021MstpVlanV2Entry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021MstpVlanV2Table_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIeee8021MstpVlanV2Table_BTree);
	return neIeee8021MstpVlanV2Table_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021MstpVlanV2Table_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpVlanV2Entry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIeee8021MstpVlanV2Entry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIeee8021MstpVlanV2Table_BTree);
	return put_index_data;
}

bool
neIeee8021MstpVlanV2Table_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIeee8021MstpVlanV2Entry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIeee8021MstpVlanV2Table_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021MstpVlanV2Table table mapper */
int
neIeee8021MstpVlanV2Table_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021MstpVlanV2Entry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neIeee8021MstpVlanV2Entry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021MSTPVLANV2SPTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u16SptId);
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
