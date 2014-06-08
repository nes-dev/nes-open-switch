/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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
#include "ieee8021CfmV2Mib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



/* array length = OID_LENGTH + 1 */
static oid ieee8021CfmStackTable_oid[] = {1,3,111,2,802,1,1,8,1,1,2};
static oid ieee8021CfmDefaultMdTable_oid[] = {1,3,111,2,802,1,1,8,1,2,5};
static oid ieee8021CfmVlanTable_oid[] = {1,3,111,2,802,1,1,8,1,3,2};
static oid ieee8021CfmConfigErrorListTable_oid[] = {1,3,111,2,802,1,1,8,1,4,2};
static oid ieee8021CfmMaCompTable_oid[] = {1,3,111,2,802,1,1,8,1,6,4};



/**
 *	initialize ieee8021CfmV2Mib group mapper
 */
void
ieee8021CfmV2Mib_init (void)
{
	DEBUGMSGTL (("ieee8021CfmV2Mib", "Initializing\n"));
	
	
	/* register ieee8021CfmV2Mib group table mappers */
	ieee8021CfmStackTable_init ();
	ieee8021CfmDefaultMdTable_init ();
	ieee8021CfmVlanTable_init ();
	ieee8021CfmConfigErrorListTable_init ();
	ieee8021CfmMaCompTable_init ();
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize ieee8021CfmStackTable table mapper **/
void
ieee8021CfmStackTable_init (void)
{
	extern oid ieee8021CfmStackTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021CfmStackTable", &ieee8021CfmStackTable_mapper,
		ieee8021CfmStackTable_oid, OID_LENGTH (ieee8021CfmStackTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021CfmStackifIndex */,
		ASN_INTEGER /* index: ieee8021CfmStackServiceSelectorType */,
		ASN_UNSIGNED /* index: ieee8021CfmStackServiceSelectorOrNone */,
		ASN_INTEGER /* index: ieee8021CfmStackMdLevel */,
		ASN_INTEGER /* index: ieee8021CfmStackDirection */,
		0);
	table_info->min_column = IEEE8021CFMSTACKMDINDEX;
	table_info->max_column = IEEE8021CFMSTACKMACADDRESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021CfmStackTable_getFirst;
	iinfo->get_next_data_point = &ieee8021CfmStackTable_getNext;
	iinfo->get_data_point = &ieee8021CfmStackTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021CfmStackTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021CfmStackEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021CfmStackEntry_t, oBTreeNode);
	register ieee8021CfmStackEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021CfmStackEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32StackifIndex < pEntry2->u32StackifIndex) ||
		(pEntry1->u32StackifIndex == pEntry2->u32StackifIndex && pEntry1->i32ServiceSelectorType < pEntry2->i32ServiceSelectorType) ||
		(pEntry1->u32StackifIndex == pEntry2->u32StackifIndex && pEntry1->i32ServiceSelectorType == pEntry2->i32ServiceSelectorType && pEntry1->u32ServiceSelectorOrNone < pEntry2->u32ServiceSelectorOrNone) ||
		(pEntry1->u32StackifIndex == pEntry2->u32StackifIndex && pEntry1->i32ServiceSelectorType == pEntry2->i32ServiceSelectorType && pEntry1->u32ServiceSelectorOrNone == pEntry2->u32ServiceSelectorOrNone && pEntry1->i32MdLevel < pEntry2->i32MdLevel) ||
		(pEntry1->u32StackifIndex == pEntry2->u32StackifIndex && pEntry1->i32ServiceSelectorType == pEntry2->i32ServiceSelectorType && pEntry1->u32ServiceSelectorOrNone == pEntry2->u32ServiceSelectorOrNone && pEntry1->i32MdLevel == pEntry2->i32MdLevel && pEntry1->i32Direction < pEntry2->i32Direction) ? -1:
		(pEntry1->u32StackifIndex == pEntry2->u32StackifIndex && pEntry1->i32ServiceSelectorType == pEntry2->i32ServiceSelectorType && pEntry1->u32ServiceSelectorOrNone == pEntry2->u32ServiceSelectorOrNone && pEntry1->i32MdLevel == pEntry2->i32MdLevel && pEntry1->i32Direction == pEntry2->i32Direction) ? 0: 1;
}

xBTree_t oIeee8021CfmStackTable_BTree = xBTree_initInline (&ieee8021CfmStackTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021CfmStackEntry_t *
ieee8021CfmStackTable_createEntry (
	uint32_t u32StackifIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction)
{
	ieee8021CfmStackEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021CfmStackEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32StackifIndex = u32StackifIndex;
	poEntry->i32ServiceSelectorType = i32ServiceSelectorType;
	poEntry->u32ServiceSelectorOrNone = u32ServiceSelectorOrNone;
	poEntry->i32MdLevel = i32MdLevel;
	poEntry->i32Direction = i32Direction;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree);
	return poEntry;
}

ieee8021CfmStackEntry_t *
ieee8021CfmStackTable_getByIndex (
	uint32_t u32StackifIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction)
{
	register ieee8021CfmStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmStackEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32StackifIndex = u32StackifIndex;
	poTmpEntry->i32ServiceSelectorType = i32ServiceSelectorType;
	poTmpEntry->u32ServiceSelectorOrNone = u32ServiceSelectorOrNone;
	poTmpEntry->i32MdLevel = i32MdLevel;
	poTmpEntry->i32Direction = i32Direction;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmStackEntry_t, oBTreeNode);
}

ieee8021CfmStackEntry_t *
ieee8021CfmStackTable_getNextIndex (
	uint32_t u32StackifIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction)
{
	register ieee8021CfmStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmStackEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32StackifIndex = u32StackifIndex;
	poTmpEntry->i32ServiceSelectorType = i32ServiceSelectorType;
	poTmpEntry->u32ServiceSelectorOrNone = u32ServiceSelectorOrNone;
	poTmpEntry->i32MdLevel = i32MdLevel;
	poTmpEntry->i32Direction = i32Direction;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmStackEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021CfmStackTable_removeEntry (ieee8021CfmStackEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021CfmStackTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021CfmStackTable_BTree);
	return ieee8021CfmStackTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021CfmStackTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmStackEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021CfmStackEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32StackifIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32ServiceSelectorType);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ServiceSelectorOrNone);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32MdLevel);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Direction);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021CfmStackTable_BTree);
	return put_index_data;
}

bool
ieee8021CfmStackTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmStackEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = ieee8021CfmStackTable_getByIndex (
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

/* ieee8021CfmStackTable table mapper */
int
ieee8021CfmStackTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021CfmStackEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021CfmStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMSTACKMDINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MdIndex);
				break;
			case IEEE8021CFMSTACKMAINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaIndex);
				break;
			case IEEE8021CFMSTACKMEPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MepId);
				break;
			case IEEE8021CFMSTACKMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MacAddress, table_entry->u16MacAddress_len);
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

/** initialize ieee8021CfmDefaultMdTable table mapper **/
void
ieee8021CfmDefaultMdTable_init (void)
{
	extern oid ieee8021CfmDefaultMdTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021CfmDefaultMdTable", &ieee8021CfmDefaultMdTable_mapper,
		ieee8021CfmDefaultMdTable_oid, OID_LENGTH (ieee8021CfmDefaultMdTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021CfmDefaultMdComponentId */,
		ASN_INTEGER /* index: ieee8021CfmDefaultMdPrimarySelectorType */,
		ASN_UNSIGNED /* index: ieee8021CfmDefaultMdPrimarySelector */,
		0);
	table_info->min_column = IEEE8021CFMDEFAULTMDSTATUS;
	table_info->max_column = IEEE8021CFMDEFAULTMDIDPERMISSION;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021CfmDefaultMdTable_getFirst;
	iinfo->get_next_data_point = &ieee8021CfmDefaultMdTable_getNext;
	iinfo->get_data_point = &ieee8021CfmDefaultMdTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021CfmDefaultMdTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021CfmDefaultMdEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021CfmDefaultMdEntry_t, oBTreeNode);
	register ieee8021CfmDefaultMdEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021CfmDefaultMdEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32PrimarySelectorType < pEntry2->i32PrimarySelectorType) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32PrimarySelectorType == pEntry2->i32PrimarySelectorType && pEntry1->u32PrimarySelector < pEntry2->u32PrimarySelector) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32PrimarySelectorType == pEntry2->i32PrimarySelectorType && pEntry1->u32PrimarySelector == pEntry2->u32PrimarySelector) ? 0: 1;
}

xBTree_t oIeee8021CfmDefaultMdTable_BTree = xBTree_initInline (&ieee8021CfmDefaultMdTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021CfmDefaultMdEntry_t *
ieee8021CfmDefaultMdTable_createEntry (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector)
{
	ieee8021CfmDefaultMdEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021CfmDefaultMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->i32PrimarySelectorType = i32PrimarySelectorType;
	poEntry->u32PrimarySelector = u32PrimarySelector;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Level = -1;
	poEntry->i32MhfCreation = ieee8021CfmDefaultMdMhfCreation_defMHFdefer_c;
	poEntry->i32IdPermission = ieee8021CfmDefaultMdIdPermission_sendIdDefer_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree);
	return poEntry;
}

ieee8021CfmDefaultMdEntry_t *
ieee8021CfmDefaultMdTable_getByIndex (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector)
{
	register ieee8021CfmDefaultMdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmDefaultMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->i32PrimarySelectorType = i32PrimarySelectorType;
	poTmpEntry->u32PrimarySelector = u32PrimarySelector;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmDefaultMdEntry_t, oBTreeNode);
}

ieee8021CfmDefaultMdEntry_t *
ieee8021CfmDefaultMdTable_getNextIndex (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector)
{
	register ieee8021CfmDefaultMdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmDefaultMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->i32PrimarySelectorType = i32PrimarySelectorType;
	poTmpEntry->u32PrimarySelector = u32PrimarySelector;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmDefaultMdEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021CfmDefaultMdTable_removeEntry (ieee8021CfmDefaultMdEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021CfmDefaultMdTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021CfmDefaultMdTable_BTree);
	return ieee8021CfmDefaultMdTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021CfmDefaultMdTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmDefaultMdEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021CfmDefaultMdEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PrimarySelectorType);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PrimarySelector);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021CfmDefaultMdTable_BTree);
	return put_index_data;
}

bool
ieee8021CfmDefaultMdTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmDefaultMdEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021CfmDefaultMdTable_getByIndex (
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

/* ieee8021CfmDefaultMdTable table mapper */
int
ieee8021CfmDefaultMdTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021CfmDefaultMdEntry_t *table_entry;
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
			table_entry = (ieee8021CfmDefaultMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMDEFAULTMDSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Status);
				break;
			case IEEE8021CFMDEFAULTMDLEVEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Level);
				break;
			case IEEE8021CFMDEFAULTMDMHFCREATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MhfCreation);
				break;
			case IEEE8021CFMDEFAULTMDIDPERMISSION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IdPermission);
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
			table_entry = (ieee8021CfmDefaultMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMDEFAULTMDLEVEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMDEFAULTMDMHFCREATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMDEFAULTMDIDPERMISSION:
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
			table_entry = (ieee8021CfmDefaultMdEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021CfmDefaultMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMDEFAULTMDLEVEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Level))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Level, sizeof (table_entry->i32Level));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Level = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMDEFAULTMDMHFCREATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MhfCreation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MhfCreation, sizeof (table_entry->i32MhfCreation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MhfCreation = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMDEFAULTMDIDPERMISSION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IdPermission))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IdPermission, sizeof (table_entry->i32IdPermission));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IdPermission = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021CfmDefaultMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMDEFAULTMDLEVEL:
				memcpy (&table_entry->i32Level, pvOldDdata, sizeof (table_entry->i32Level));
				break;
			case IEEE8021CFMDEFAULTMDMHFCREATION:
				memcpy (&table_entry->i32MhfCreation, pvOldDdata, sizeof (table_entry->i32MhfCreation));
				break;
			case IEEE8021CFMDEFAULTMDIDPERMISSION:
				memcpy (&table_entry->i32IdPermission, pvOldDdata, sizeof (table_entry->i32IdPermission));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021CfmVlanTable table mapper **/
void
ieee8021CfmVlanTable_init (void)
{
	extern oid ieee8021CfmVlanTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021CfmVlanTable", &ieee8021CfmVlanTable_mapper,
		ieee8021CfmVlanTable_oid, OID_LENGTH (ieee8021CfmVlanTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021CfmVlanComponentId */,
		ASN_UNSIGNED /* index: ieee8021CfmVlanSelector */,
		0);
	table_info->min_column = IEEE8021CFMVLANPRIMARYSELECTOR;
	table_info->max_column = IEEE8021CFMVLANROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021CfmVlanTable_getFirst;
	iinfo->get_next_data_point = &ieee8021CfmVlanTable_getNext;
	iinfo->get_data_point = &ieee8021CfmVlanTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021CfmVlanTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021CfmVlanEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021CfmVlanEntry_t, oBTreeNode);
	register ieee8021CfmVlanEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021CfmVlanEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Selector < pEntry2->u32Selector) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Selector == pEntry2->u32Selector) ? 0: 1;
}

xBTree_t oIeee8021CfmVlanTable_BTree = xBTree_initInline (&ieee8021CfmVlanTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021CfmVlanEntry_t *
ieee8021CfmVlanTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Selector)
{
	ieee8021CfmVlanEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021CfmVlanEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Selector = u32Selector;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree);
	return poEntry;
}

ieee8021CfmVlanEntry_t *
ieee8021CfmVlanTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Selector)
{
	register ieee8021CfmVlanEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmVlanEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Selector = u32Selector;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmVlanEntry_t, oBTreeNode);
}

ieee8021CfmVlanEntry_t *
ieee8021CfmVlanTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Selector)
{
	register ieee8021CfmVlanEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmVlanEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Selector = u32Selector;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmVlanEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021CfmVlanTable_removeEntry (ieee8021CfmVlanEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021CfmVlanTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021CfmVlanTable_BTree);
	return ieee8021CfmVlanTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021CfmVlanTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmVlanEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021CfmVlanEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Selector);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021CfmVlanTable_BTree);
	return put_index_data;
}

bool
ieee8021CfmVlanTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmVlanEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021CfmVlanTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021CfmVlanTable table mapper */
int
ieee8021CfmVlanTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021CfmVlanEntry_t *table_entry;
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANPRIMARYSELECTOR:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PrimarySelector);
				break;
			case IEEE8021CFMVLANROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RowStatus);
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANPRIMARYSELECTOR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMVLANROWSTATUS:
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021CfmVlanTable_createEntry (
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021CfmVlanTable_removeEntry (table_entry);
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANPRIMARYSELECTOR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PrimarySelector))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PrimarySelector, sizeof (table_entry->u32PrimarySelector));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PrimarySelector = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021CfmVlanTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANPRIMARYSELECTOR:
				memcpy (&table_entry->u32PrimarySelector, pvOldDdata, sizeof (table_entry->u32PrimarySelector));
				break;
			case IEEE8021CFMVLANROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021CfmVlanTable_removeEntry (table_entry);
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
			table_entry = (ieee8021CfmVlanEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMVLANROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->i32RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->i32RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021CfmVlanTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021CfmConfigErrorListTable table mapper **/
void
ieee8021CfmConfigErrorListTable_init (void)
{
	extern oid ieee8021CfmConfigErrorListTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021CfmConfigErrorListTable", &ieee8021CfmConfigErrorListTable_mapper,
		ieee8021CfmConfigErrorListTable_oid, OID_LENGTH (ieee8021CfmConfigErrorListTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021CfmConfigErrorListSelectorType */,
		ASN_UNSIGNED /* index: ieee8021CfmConfigErrorListSelector */,
		ASN_INTEGER /* index: ieee8021CfmConfigErrorListIfIndex */,
		0);
	table_info->min_column = IEEE8021CFMCONFIGERRORLISTERRORTYPE;
	table_info->max_column = IEEE8021CFMCONFIGERRORLISTERRORTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021CfmConfigErrorListTable_getFirst;
	iinfo->get_next_data_point = &ieee8021CfmConfigErrorListTable_getNext;
	iinfo->get_data_point = &ieee8021CfmConfigErrorListTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021CfmConfigErrorListTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021CfmConfigErrorListEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021CfmConfigErrorListEntry_t, oBTreeNode);
	register ieee8021CfmConfigErrorListEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021CfmConfigErrorListEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32SelectorType < pEntry2->i32SelectorType) ||
		(pEntry1->i32SelectorType == pEntry2->i32SelectorType && pEntry1->u32Selector < pEntry2->u32Selector) ||
		(pEntry1->i32SelectorType == pEntry2->i32SelectorType && pEntry1->u32Selector == pEntry2->u32Selector && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->i32SelectorType == pEntry2->i32SelectorType && pEntry1->u32Selector == pEntry2->u32Selector && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIeee8021CfmConfigErrorListTable_BTree = xBTree_initInline (&ieee8021CfmConfigErrorListTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021CfmConfigErrorListEntry_t *
ieee8021CfmConfigErrorListTable_createEntry (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex)
{
	ieee8021CfmConfigErrorListEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021CfmConfigErrorListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32SelectorType = i32SelectorType;
	poEntry->u32Selector = u32Selector;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree);
	return poEntry;
}

ieee8021CfmConfigErrorListEntry_t *
ieee8021CfmConfigErrorListTable_getByIndex (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex)
{
	register ieee8021CfmConfigErrorListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmConfigErrorListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SelectorType = i32SelectorType;
	poTmpEntry->u32Selector = u32Selector;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmConfigErrorListEntry_t, oBTreeNode);
}

ieee8021CfmConfigErrorListEntry_t *
ieee8021CfmConfigErrorListTable_getNextIndex (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex)
{
	register ieee8021CfmConfigErrorListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmConfigErrorListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32SelectorType = i32SelectorType;
	poTmpEntry->u32Selector = u32Selector;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmConfigErrorListEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021CfmConfigErrorListTable_removeEntry (ieee8021CfmConfigErrorListEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021CfmConfigErrorListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021CfmConfigErrorListTable_BTree);
	return ieee8021CfmConfigErrorListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021CfmConfigErrorListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmConfigErrorListEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021CfmConfigErrorListEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32SelectorType);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Selector);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021CfmConfigErrorListTable_BTree);
	return put_index_data;
}

bool
ieee8021CfmConfigErrorListTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmConfigErrorListEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021CfmConfigErrorListTable_getByIndex (
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

/* ieee8021CfmConfigErrorListTable table mapper */
int
ieee8021CfmConfigErrorListTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021CfmConfigErrorListEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021CfmConfigErrorListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMCONFIGERRORLISTERRORTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ErrorType, table_entry->u16ErrorType_len);
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

/** initialize ieee8021CfmMaCompTable table mapper **/
void
ieee8021CfmMaCompTable_init (void)
{
	extern oid ieee8021CfmMaCompTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021CfmMaCompTable", &ieee8021CfmMaCompTable_mapper,
		ieee8021CfmMaCompTable_oid, OID_LENGTH (ieee8021CfmMaCompTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021CfmMaComponentId */,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		0);
	table_info->min_column = IEEE8021CFMMACOMPPRIMARYSELECTORTYPE;
	table_info->max_column = IEEE8021CFMMACOMPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021CfmMaCompTable_getFirst;
	iinfo->get_next_data_point = &ieee8021CfmMaCompTable_getNext;
	iinfo->get_data_point = &ieee8021CfmMaCompTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021CfmMaCompTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021CfmMaCompEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021CfmMaCompEntry_t, oBTreeNode);
	register ieee8021CfmMaCompEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021CfmMaCompEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Dot1agCfmMdIndex < pEntry2->u32Dot1agCfmMdIndex) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Dot1agCfmMdIndex == pEntry2->u32Dot1agCfmMdIndex && pEntry1->u32Dot1agCfmMaIndex < pEntry2->u32Dot1agCfmMaIndex) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Dot1agCfmMdIndex == pEntry2->u32Dot1agCfmMdIndex && pEntry1->u32Dot1agCfmMaIndex == pEntry2->u32Dot1agCfmMaIndex) ? 0: 1;
}

xBTree_t oIeee8021CfmMaCompTable_BTree = xBTree_initInline (&ieee8021CfmMaCompTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021CfmMaCompEntry_t *
ieee8021CfmMaCompTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex)
{
	ieee8021CfmMaCompEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021CfmMaCompEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Dot1agCfmMdIndex = u32Dot1agCfmMdIndex;
	poEntry->u32Dot1agCfmMaIndex = u32Dot1agCfmMaIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32MhfCreation = ieee8021CfmMaCompMhfCreation_defMHFdefer_c;
	poEntry->i32IdPermission = ieee8021CfmMaCompIdPermission_sendIdDefer_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree);
	return poEntry;
}

ieee8021CfmMaCompEntry_t *
ieee8021CfmMaCompTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex)
{
	register ieee8021CfmMaCompEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmMaCompEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Dot1agCfmMdIndex = u32Dot1agCfmMdIndex;
	poTmpEntry->u32Dot1agCfmMaIndex = u32Dot1agCfmMaIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmMaCompEntry_t, oBTreeNode);
}

ieee8021CfmMaCompEntry_t *
ieee8021CfmMaCompTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex)
{
	register ieee8021CfmMaCompEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021CfmMaCompEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Dot1agCfmMdIndex = u32Dot1agCfmMdIndex;
	poTmpEntry->u32Dot1agCfmMaIndex = u32Dot1agCfmMaIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021CfmMaCompEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021CfmMaCompTable_removeEntry (ieee8021CfmMaCompEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021CfmMaCompTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021CfmMaCompTable_BTree);
	return ieee8021CfmMaCompTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021CfmMaCompTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmMaCompEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021CfmMaCompEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Dot1agCfmMdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Dot1agCfmMaIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021CfmMaCompTable_BTree);
	return put_index_data;
}

bool
ieee8021CfmMaCompTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021CfmMaCompEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021CfmMaCompTable_getByIndex (
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

/* ieee8021CfmMaCompTable table mapper */
int
ieee8021CfmMaCompTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021CfmMaCompEntry_t *table_entry;
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPPRIMARYSELECTORTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PrimarySelectorType);
				break;
			case IEEE8021CFMMACOMPPRIMARYSELECTORORNONE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PrimarySelectorOrNone);
				break;
			case IEEE8021CFMMACOMPMHFCREATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MhfCreation);
				break;
			case IEEE8021CFMMACOMPIDPERMISSION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IdPermission);
				break;
			case IEEE8021CFMMACOMPNUMBEROFVIDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NumberOfVids);
				break;
			case IEEE8021CFMMACOMPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RowStatus);
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPPRIMARYSELECTORTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMMACOMPPRIMARYSELECTORORNONE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMMACOMPMHFCREATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMMACOMPIDPERMISSION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMMACOMPNUMBEROFVIDS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021CFMMACOMPROWSTATUS:
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021CfmMaCompTable_createEntry (
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021CfmMaCompTable_removeEntry (table_entry);
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPPRIMARYSELECTORTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PrimarySelectorType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PrimarySelectorType, sizeof (table_entry->i32PrimarySelectorType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PrimarySelectorType = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMMACOMPPRIMARYSELECTORORNONE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PrimarySelectorOrNone))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PrimarySelectorOrNone, sizeof (table_entry->u32PrimarySelectorOrNone));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PrimarySelectorOrNone = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMMACOMPMHFCREATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MhfCreation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MhfCreation, sizeof (table_entry->i32MhfCreation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MhfCreation = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMMACOMPIDPERMISSION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IdPermission))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IdPermission, sizeof (table_entry->i32IdPermission));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IdPermission = *request->requestvb->val.integer;
				break;
			case IEEE8021CFMMACOMPNUMBEROFVIDS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32NumberOfVids))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32NumberOfVids, sizeof (table_entry->u32NumberOfVids));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32NumberOfVids = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021CfmMaCompTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPPRIMARYSELECTORTYPE:
				memcpy (&table_entry->i32PrimarySelectorType, pvOldDdata, sizeof (table_entry->i32PrimarySelectorType));
				break;
			case IEEE8021CFMMACOMPPRIMARYSELECTORORNONE:
				memcpy (&table_entry->u32PrimarySelectorOrNone, pvOldDdata, sizeof (table_entry->u32PrimarySelectorOrNone));
				break;
			case IEEE8021CFMMACOMPMHFCREATION:
				memcpy (&table_entry->i32MhfCreation, pvOldDdata, sizeof (table_entry->i32MhfCreation));
				break;
			case IEEE8021CFMMACOMPIDPERMISSION:
				memcpy (&table_entry->i32IdPermission, pvOldDdata, sizeof (table_entry->i32IdPermission));
				break;
			case IEEE8021CFMMACOMPNUMBEROFVIDS:
				memcpy (&table_entry->u32NumberOfVids, pvOldDdata, sizeof (table_entry->u32NumberOfVids));
				break;
			case IEEE8021CFMMACOMPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021CfmMaCompTable_removeEntry (table_entry);
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
			table_entry = (ieee8021CfmMaCompEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021CFMMACOMPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->i32RowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->i32RowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021CfmMaCompTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
