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
#include "system/systemMIB.h"
#include "bridgeUtils.h"
#include "ethernet/ieee8021BridgeMib.h"
#include "ieee8021PbMib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021PbMib_oid[] = {1,3,111,2,802,1,1,5};

static oid ieee8021PbCVidRegistrationTable_oid[] = {1,3,111,2,802,1,1,5,1,2};
static oid ieee8021PbEdgePortTable_oid[] = {1,3,111,2,802,1,1,5,1,3};
static oid ieee8021PbServicePriorityRegenerationTable_oid[] = {1,3,111,2,802,1,1,5,1,4};
static oid ieee8021PbCnpTable_oid[] = {1,3,111,2,802,1,1,5,1,5};
static oid ieee8021PbPnpTable_oid[] = {1,3,111,2,802,1,1,5,1,6};
static oid ieee8021PbCepTable_oid[] = {1,3,111,2,802,1,1,5,1,7};
static oid ieee8021PbRcapTable_oid[] = {1,3,111,2,802,1,1,5,1,8};
static oid ieee8021PbInternalInterfaceTable_oid[] = {1,3,111,2,802,1,1,5,1,9};



/**
 *	initialize ieee8021PbMib group mapper
 */
void
ieee8021PbMib_init (void)
{
	extern oid ieee8021PbMib_oid[];
	
	DEBUGMSGTL (("ieee8021PbMib", "Initializing\n"));
	
	
	/* register ieee8021PbMib group table mappers */
	ieee8021PbCVidRegistrationTable_init ();
	ieee8021PbEdgePortTable_init ();
	ieee8021PbServicePriorityRegenerationTable_init ();
	ieee8021PbCnpTable_init ();
	ieee8021PbPnpTable_init ();
	ieee8021PbCepTable_init ();
	ieee8021PbRcapTable_init ();
	ieee8021PbInternalInterfaceTable_init ();
	
	/* register ieee8021PbMib modules */
	sysORTable_createRegister ("ieee8021PbMib", ieee8021PbMib_oid, OID_LENGTH (ieee8021PbMib_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize ieee8021PbCVidRegistrationTable table mapper **/
void
ieee8021PbCVidRegistrationTable_init (void)
{
	extern oid ieee8021PbCVidRegistrationTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbCVidRegistrationTable", &ieee8021PbCVidRegistrationTable_mapper,
		ieee8021PbCVidRegistrationTable_oid, OID_LENGTH (ieee8021PbCVidRegistrationTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021PbCVidRegistrationCVid */,
		0);
	table_info->min_column = IEEE8021PBCVIDREGISTRATIONSVID;
	table_info->max_column = IEEE8021PBCVIDREGISTRATIONROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbCVidRegistrationTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbCVidRegistrationTable_getNext;
	iinfo->get_data_point = &ieee8021PbCVidRegistrationTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbCVidRegistrationTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbCVidRegistrationEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbCVidRegistrationEntry_t, oBTreeNode);
	register ieee8021PbCVidRegistrationEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbCVidRegistrationEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32CVid < pEntry2->u32CVid) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32CVid == pEntry2->u32CVid) ? 0: 1;
}

xBTree_t oIeee8021PbCVidRegistrationTable_BTree = xBTree_initInline (&ieee8021PbCVidRegistrationTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbCVidRegistrationEntry_t *
ieee8021PbCVidRegistrationTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32CVid)
{
	register ieee8021PbCVidRegistrationEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32CVid = u32CVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32UntaggedPep = ieee8021PbCVidRegistrationUntaggedPep_true_c;
	poEntry->i32UntaggedCep = ieee8021PbCVidRegistrationUntaggedCep_true_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree);
	return poEntry;
}

ieee8021PbCVidRegistrationEntry_t *
ieee8021PbCVidRegistrationTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32CVid)
{
	register ieee8021PbCVidRegistrationEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32CVid = u32CVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCVidRegistrationEntry_t, oBTreeNode);
}

ieee8021PbCVidRegistrationEntry_t *
ieee8021PbCVidRegistrationTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32CVid)
{
	register ieee8021PbCVidRegistrationEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32CVid = u32CVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCVidRegistrationEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbCVidRegistrationTable_removeEntry (ieee8021PbCVidRegistrationEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbCVidRegistrationTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbCVidRegistrationTable_BTree);
	return ieee8021PbCVidRegistrationTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbCVidRegistrationTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCVidRegistrationEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbCVidRegistrationEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32CVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbCVidRegistrationTable_BTree);
	return put_index_data;
}

bool
ieee8021PbCVidRegistrationTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCVidRegistrationEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbCVidRegistrationTable_getByIndex (
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

/* ieee8021PbCVidRegistrationTable table mapper */
int
ieee8021PbCVidRegistrationTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbCVidRegistrationEntry_t *table_entry;
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONSVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32SVid);
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDPEP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UntaggedPep);
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDCEP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UntaggedCep);
				break;
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONSVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDPEP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDCEP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbCVidRegistrationTable_createEntry (
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCVidRegistrationTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONSVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32SVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32SVid, sizeof (table_entry->u32SVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32SVid = *request->requestvb->val.integer;
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDPEP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UntaggedPep))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UntaggedPep, sizeof (table_entry->i32UntaggedPep));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UntaggedPep = *request->requestvb->val.integer;
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDCEP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UntaggedCep))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UntaggedCep, sizeof (table_entry->i32UntaggedCep));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UntaggedCep = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbCVidRegistrationTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONSVID:
				memcpy (&table_entry->u32SVid, pvOldDdata, sizeof (table_entry->u32SVid));
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDPEP:
				memcpy (&table_entry->i32UntaggedPep, pvOldDdata, sizeof (table_entry->i32UntaggedPep));
				break;
			case IEEE8021PBCVIDREGISTRATIONUNTAGGEDCEP:
				memcpy (&table_entry->i32UntaggedCep, pvOldDdata, sizeof (table_entry->i32UntaggedCep));
				break;
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCVidRegistrationTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCVidRegistrationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCVIDREGISTRATIONROWSTATUS:
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
					ieee8021PbCVidRegistrationTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbEdgePortTable table mapper **/
void
ieee8021PbEdgePortTable_init (void)
{
	extern oid ieee8021PbEdgePortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbEdgePortTable", &ieee8021PbEdgePortTable_mapper,
		ieee8021PbEdgePortTable_oid, OID_LENGTH (ieee8021PbEdgePortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021PbEdgePortSVid */,
		0);
	table_info->min_column = IEEE8021PBEDGEPORTPVID;
	table_info->max_column = IEEE8021PBEDGEPORTENABLEINGRESSFILTERING;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbEdgePortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbEdgePortTable_getNext;
	iinfo->get_data_point = &ieee8021PbEdgePortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbEdgePortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbEdgePortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbEdgePortEntry_t, oBTreeNode);
	register ieee8021PbEdgePortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbEdgePortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32SVid < pEntry2->u32SVid) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32SVid == pEntry2->u32SVid) ? 0: 1;
}

xBTree_t oIeee8021PbEdgePortTable_BTree = xBTree_initInline (&ieee8021PbEdgePortTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbEdgePortEntry_t *
ieee8021PbEdgePortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid)
{
	register ieee8021PbEdgePortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32SVid = u32SVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AcceptableFrameTypes = ieee8021PbEdgePortAcceptableFrameTypes_admitAll_c;
	poEntry->i32EnableIngressFiltering = ieee8021PbEdgePortEnableIngressFiltering_true_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree);
	return poEntry;
}

ieee8021PbEdgePortEntry_t *
ieee8021PbEdgePortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid)
{
	register ieee8021PbEdgePortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32SVid = u32SVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbEdgePortEntry_t, oBTreeNode);
}

ieee8021PbEdgePortEntry_t *
ieee8021PbEdgePortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid)
{
	register ieee8021PbEdgePortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32SVid = u32SVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbEdgePortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbEdgePortTable_removeEntry (ieee8021PbEdgePortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021PbEdgePortEntry_t *
ieee8021PbEdgePortTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid)
{
	ieee8021PbEdgePortEntry_t *poEntry = NULL;
	
	poEntry = ieee8021PbEdgePortTable_createEntry (
		u32BridgeBasePortComponentId,
		u32BridgeBasePort,
		u32SVid);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021PbEdgePortTable_createHier (poEntry))
	{
		ieee8021PbEdgePortTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021PbEdgePortTable_removeExt (ieee8021PbEdgePortEntry_t *poEntry)
{
	if (!ieee8021PbEdgePortTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021PbEdgePortTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021PbEdgePortTable_createHier (
	ieee8021PbEdgePortEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
	
	if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBaseEntry_t *pCComponent = NULL;
	
	if ((pCComponent = ieee8021BridgeBaseTable_getByIndex (poIeee8021PbCepEntry->u32CComponentId)) == NULL)
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	
	register uint16_t u16PortIndex = 0;
	register ieee8021PbCnpEntry_t *poIeee8021PbCnpEntry = NULL;
	
	while (
		(poIeee8021PbCnpEntry = ieee8021PbCnpTable_getNextIndex (poEntry->u32BridgeBasePortComponentId, u16PortIndex)) != NULL &&
		poIeee8021PbCnpEntry->u32BridgeBasePortComponentId == poEntry->u32BridgeBasePortComponentId &&
		(poIeee8021PbCnpEntry->u32CComponentId != poIeee8021PbCepEntry->u32CComponentId ||
		 poIeee8021PbCnpEntry->u32SVid != poEntry->u32SVid))
	{
		u16PortIndex = poIeee8021PbCnpEntry->u32BridgeBasePort;
	}
	
	if ((poIeee8021PbCnpEntry == NULL ||
		 poIeee8021PbCnpEntry->u32BridgeBasePortComponentId != poEntry->u32BridgeBasePortComponentId ||
		 poIeee8021PbCnpEntry->u32CComponentId != poIeee8021PbCepEntry->u32CComponentId ||
		 poIeee8021PbCnpEntry->u32SVid != poEntry->u32SVid) &&
		(poIeee8021PbCnpEntry = ieee8021PbCnpTable_createExt (poEntry->u32BridgeBasePortComponentId, ieee8021BridgeBasePort_zero_c)) == NULL)
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poCnpPortEntry = NULL;
	
	if ((poCnpPortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poIeee8021PbCnpEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poPepPortEntry = NULL;
	
	if ((poPepPortEntry = ieee8021BridgeBasePortTable_createExt (pCComponent, poIeee8021PbCnpEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	poPepPortEntry->i32Type = ieee8021BridgeBasePortType_providerEdgePort_c;
	
	poIeee8021PbCnpEntry->u32CComponentId = poIeee8021PbCepEntry->u32CComponentId;
	poIeee8021PbCnpEntry->u32SVid = poEntry->u32SVid;
	
	if (!ieee8021PbILan_createEntry (poCnpPortEntry, poPepPortEntry))
	{
		goto ieee8021PbEdgePortTable_createHier_cleanup;
	}
	
	poEntry->u32CComponentId = poIeee8021PbCepEntry->u32CComponentId;
	poEntry->u32PepPort = poIeee8021PbCnpEntry->u32BridgeBasePort;
	
	bRetCode = true;
	
ieee8021PbEdgePortTable_createHier_cleanup:
	
	!bRetCode ? ieee8021PbEdgePortTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
ieee8021PbEdgePortTable_removeHier (
	ieee8021PbEdgePortEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021PbCepEntry_t *poIeee8021PbCepEntry = NULL;
	
	if ((poIeee8021PbCepEntry = ieee8021PbCepTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbEdgePortTable_removeHier_success;
	}
	
	register ieee8021BridgeBaseEntry_t *pCComponent = NULL;
	
	if ((pCComponent = ieee8021BridgeBaseTable_getByIndex (poIeee8021PbCepEntry->u32CComponentId)) == NULL)
	{
		goto ieee8021PbEdgePortTable_removeHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poPepPortEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poCnpPortEntry = NULL;
	
	if ((poPepPortEntry = ieee8021BridgeBasePortTable_getByIndex (poIeee8021PbCepEntry->u32CComponentId, poEntry->u32PepPort)) == NULL ||
		(poCnpPortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32PepPort)) == NULL)
	{
		goto ieee8021PbEdgePortTable_removeHier_cleanup;
	}
	
	if (!ieee8021PbILan_removeEntry (poCnpPortEntry, poPepPortEntry))
	{
		goto ieee8021PbEdgePortTable_removeHier_cleanup;
	}
	
	if (!ieee8021BridgeBasePortTable_removeExt (pCComponent, poPepPortEntry))
	{
		goto ieee8021PbEdgePortTable_removeHier_cleanup;
	}
	
	register ieee8021PbCnpEntry_t *poIeee8021PbCnpEntry = NULL;
	
	if ((poIeee8021PbCnpEntry = ieee8021PbCnpTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32PepPort)) != NULL &&
		!ieee8021PbCnpTable_removeExt (poIeee8021PbCnpEntry))
	{
		goto ieee8021PbEdgePortTable_removeHier_cleanup;
	}
	
ieee8021PbEdgePortTable_removeHier_success:
	
	bRetCode = true;
	
ieee8021PbEdgePortTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbEdgePortRowStatus_handler (
	ieee8021PbEdgePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	poEntry->u8RowStatus = u8RowStatus;
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbEdgePortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbEdgePortTable_BTree);
	return ieee8021PbEdgePortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbEdgePortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbEdgePortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbEdgePortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32SVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbEdgePortTable_BTree);
	return put_index_data;
}

bool
ieee8021PbEdgePortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbEdgePortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbEdgePortTable_getByIndex (
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

/* ieee8021PbEdgePortTable table mapper */
int
ieee8021PbEdgePortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbEdgePortEntry_t *table_entry;
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
			table_entry = (ieee8021PbEdgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBEDGEPORTPVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32PVid);
				break;
			case IEEE8021PBEDGEPORTDEFAULTUSERPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DefaultUserPriority);
				break;
			case IEEE8021PBEDGEPORTACCEPTABLEFRAMETYPES:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AcceptableFrameTypes);
				break;
			case IEEE8021PBEDGEPORTENABLEINGRESSFILTERING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableIngressFiltering);
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
			table_entry = (ieee8021PbEdgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBEDGEPORTPVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBEDGEPORTDEFAULTUSERPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBEDGEPORTACCEPTABLEFRAMETYPES:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBEDGEPORTENABLEINGRESSFILTERING:
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
			table_entry = (ieee8021PbEdgePortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021PbEdgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBEDGEPORTPVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PVid, sizeof (table_entry->u32PVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PVid = *request->requestvb->val.integer;
				break;
			case IEEE8021PBEDGEPORTDEFAULTUSERPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32DefaultUserPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32DefaultUserPriority, sizeof (table_entry->u32DefaultUserPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32DefaultUserPriority = *request->requestvb->val.integer;
				break;
			case IEEE8021PBEDGEPORTACCEPTABLEFRAMETYPES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AcceptableFrameTypes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AcceptableFrameTypes, sizeof (table_entry->i32AcceptableFrameTypes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AcceptableFrameTypes = *request->requestvb->val.integer;
				break;
			case IEEE8021PBEDGEPORTENABLEINGRESSFILTERING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableIngressFiltering))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableIngressFiltering, sizeof (table_entry->i32EnableIngressFiltering));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableIngressFiltering = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbEdgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBEDGEPORTPVID:
				memcpy (&table_entry->u32PVid, pvOldDdata, sizeof (table_entry->u32PVid));
				break;
			case IEEE8021PBEDGEPORTDEFAULTUSERPRIORITY:
				memcpy (&table_entry->u32DefaultUserPriority, pvOldDdata, sizeof (table_entry->u32DefaultUserPriority));
				break;
			case IEEE8021PBEDGEPORTACCEPTABLEFRAMETYPES:
				memcpy (&table_entry->i32AcceptableFrameTypes, pvOldDdata, sizeof (table_entry->i32AcceptableFrameTypes));
				break;
			case IEEE8021PBEDGEPORTENABLEINGRESSFILTERING:
				memcpy (&table_entry->i32EnableIngressFiltering, pvOldDdata, sizeof (table_entry->i32EnableIngressFiltering));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbServicePriorityRegenerationTable table mapper **/
void
ieee8021PbServicePriorityRegenerationTable_init (void)
{
	extern oid ieee8021PbServicePriorityRegenerationTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbServicePriorityRegenerationTable", &ieee8021PbServicePriorityRegenerationTable_mapper,
		ieee8021PbServicePriorityRegenerationTable_oid, OID_LENGTH (ieee8021PbServicePriorityRegenerationTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021PbServicePriorityRegenerationSVid */,
		ASN_UNSIGNED /* index: ieee8021PbServicePriorityRegenerationReceivedPriority */,
		0);
	table_info->min_column = IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY;
	table_info->max_column = IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbServicePriorityRegenerationTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbServicePriorityRegenerationTable_getNext;
	iinfo->get_data_point = &ieee8021PbServicePriorityRegenerationTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbServicePriorityRegenerationTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbServicePriorityRegenerationEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbServicePriorityRegenerationEntry_t, oBTreeNode);
	register ieee8021PbServicePriorityRegenerationEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbServicePriorityRegenerationEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32SVid < pEntry2->u32SVid) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32SVid == pEntry2->u32SVid && pEntry1->u32ReceivedPriority < pEntry2->u32ReceivedPriority) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32SVid == pEntry2->u32SVid && pEntry1->u32ReceivedPriority == pEntry2->u32ReceivedPriority) ? 0: 1;
}

xBTree_t oIeee8021PbServicePriorityRegenerationTable_BTree = xBTree_initInline (&ieee8021PbServicePriorityRegenerationTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbServicePriorityRegenerationEntry_t *
ieee8021PbServicePriorityRegenerationTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid,
	uint32_t u32ReceivedPriority)
{
	register ieee8021PbServicePriorityRegenerationEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32SVid = u32SVid;
	poEntry->u32ReceivedPriority = u32ReceivedPriority;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree);
	return poEntry;
}

ieee8021PbServicePriorityRegenerationEntry_t *
ieee8021PbServicePriorityRegenerationTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid,
	uint32_t u32ReceivedPriority)
{
	register ieee8021PbServicePriorityRegenerationEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32SVid = u32SVid;
	poTmpEntry->u32ReceivedPriority = u32ReceivedPriority;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbServicePriorityRegenerationEntry_t, oBTreeNode);
}

ieee8021PbServicePriorityRegenerationEntry_t *
ieee8021PbServicePriorityRegenerationTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32SVid,
	uint32_t u32ReceivedPriority)
{
	register ieee8021PbServicePriorityRegenerationEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32SVid = u32SVid;
	poTmpEntry->u32ReceivedPriority = u32ReceivedPriority;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbServicePriorityRegenerationEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbServicePriorityRegenerationTable_removeEntry (ieee8021PbServicePriorityRegenerationEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbServicePriorityRegenerationTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbServicePriorityRegenerationTable_BTree);
	return ieee8021PbServicePriorityRegenerationTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbServicePriorityRegenerationTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbServicePriorityRegenerationEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbServicePriorityRegenerationEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32SVid);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ReceivedPriority);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbServicePriorityRegenerationTable_BTree);
	return put_index_data;
}

bool
ieee8021PbServicePriorityRegenerationTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbServicePriorityRegenerationEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = ieee8021PbServicePriorityRegenerationTable_getByIndex (
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

/* ieee8021PbServicePriorityRegenerationTable table mapper */
int
ieee8021PbServicePriorityRegenerationTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbServicePriorityRegenerationEntry_t *table_entry;
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
			table_entry = (ieee8021PbServicePriorityRegenerationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RegeneratedPriority);
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
			table_entry = (ieee8021PbServicePriorityRegenerationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY:
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
			table_entry = (ieee8021PbServicePriorityRegenerationEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021PbServicePriorityRegenerationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RegeneratedPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RegeneratedPriority, sizeof (table_entry->u32RegeneratedPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RegeneratedPriority = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbServicePriorityRegenerationEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY:
				memcpy (&table_entry->u32RegeneratedPriority, pvOldDdata, sizeof (table_entry->u32RegeneratedPriority));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbCnpTable table mapper **/
void
ieee8021PbCnpTable_init (void)
{
	extern oid ieee8021PbCnpTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbCnpTable", &ieee8021PbCnpTable_mapper,
		ieee8021PbCnpTable_oid, OID_LENGTH (ieee8021PbCnpTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBCNPCCOMPONENTID;
	table_info->max_column = IEEE8021PBCNPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbCnpTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbCnpTable_getNext;
	iinfo->get_data_point = &ieee8021PbCnpTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbCnpTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbCnpEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbCnpEntry_t, oBTreeNode);
	register ieee8021PbCnpEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbCnpEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbCnpTable_BTree = xBTree_initInline (&ieee8021PbCnpTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbCnpEntry_t *
ieee8021PbCnpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCnpEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree);
	return poEntry;
}

ieee8021PbCnpEntry_t *
ieee8021PbCnpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCnpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCnpEntry_t, oBTreeNode);
}

ieee8021PbCnpEntry_t *
ieee8021PbCnpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCnpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCnpEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbCnpTable_removeEntry (ieee8021PbCnpEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021PbCnpEntry_t *
ieee8021PbCnpTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	return NULL;
}

bool
ieee8021PbCnpTable_removeExt (ieee8021PbCnpEntry_t *poEntry)
{
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbCnpTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbCnpTable_BTree);
	return ieee8021PbCnpTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbCnpTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCnpEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbCnpEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbCnpTable_BTree);
	return put_index_data;
}

bool
ieee8021PbCnpTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCnpEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbCnpTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbCnpTable table mapper */
int
ieee8021PbCnpTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbCnpEntry_t *table_entry;
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPCCOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CComponentId);
				break;
			case IEEE8021PBCNPSVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32SVid);
				break;
			case IEEE8021PBCNPROWSTATUS:
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPCCOMPONENTID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBCNPSVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBCNPROWSTATUS:
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbCnpTable_createEntry (
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCnpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPCCOMPONENTID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CComponentId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CComponentId, sizeof (table_entry->u32CComponentId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CComponentId = *request->requestvb->val.integer;
				break;
			case IEEE8021PBCNPSVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32SVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32SVid, sizeof (table_entry->u32SVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32SVid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbCnpTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPCCOMPONENTID:
				memcpy (&table_entry->u32CComponentId, pvOldDdata, sizeof (table_entry->u32CComponentId));
				break;
			case IEEE8021PBCNPSVID:
				memcpy (&table_entry->u32SVid, pvOldDdata, sizeof (table_entry->u32SVid));
				break;
			case IEEE8021PBCNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCnpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCNPROWSTATUS:
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
					ieee8021PbCnpTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbPnpTable table mapper **/
void
ieee8021PbPnpTable_init (void)
{
	extern oid ieee8021PbPnpTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbPnpTable", &ieee8021PbPnpTable_mapper,
		ieee8021PbPnpTable_oid, OID_LENGTH (ieee8021PbPnpTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBPNPROWSTATUS;
	table_info->max_column = IEEE8021PBPNPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbPnpTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbPnpTable_getNext;
	iinfo->get_data_point = &ieee8021PbPnpTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbPnpTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbPnpEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbPnpEntry_t, oBTreeNode);
	register ieee8021PbPnpEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbPnpEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbPnpTable_BTree = xBTree_initInline (&ieee8021PbPnpTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbPnpEntry_t *
ieee8021PbPnpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbPnpEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree);
	return poEntry;
}

ieee8021PbPnpEntry_t *
ieee8021PbPnpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbPnpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbPnpEntry_t, oBTreeNode);
}

ieee8021PbPnpEntry_t *
ieee8021PbPnpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbPnpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbPnpEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbPnpTable_removeEntry (ieee8021PbPnpEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021PbPnpEntry_t *
ieee8021PbPnpTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021PbPnpEntry_t *poEntry = NULL;
	
	poEntry = ieee8021PbPnpTable_createEntry (
		u32BridgeBasePortComponentId,
		u32BridgeBasePort);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021PbPnpTable_createHier (poEntry))
	{
		ieee8021PbPnpTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021PbPnpTable_removeExt (ieee8021PbPnpEntry_t *poEntry)
{
	if (!ieee8021PbPnpTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021PbPnpTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021PbPnpTable_createHier (
	ieee8021PbPnpEntry_t *poEntry)
{
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL ||
		(poIeee8021BridgeBaseEntry->u8RowStatus == xRowStatus_active_c && poIeee8021BridgeBaseEntry->i32ComponentType != ieee8021BridgeBaseComponentType_bComponent_c &&
		 poIeee8021BridgeBaseEntry->i32ComponentType != ieee8021BridgeBaseComponentType_sVlanComponent_c))
	{
		goto ieee8021PbPnpTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) == NULL &&
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_createExt (poIeee8021BridgeBaseEntry, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbPnpTable_createHier_cleanup;
	}
	
	poIeee8021BridgeBasePortEntry->i32Type = ieee8021BridgeBasePortType_providerNetworkPort_c;
	
	return true;
	
	
ieee8021PbPnpTable_createHier_cleanup:
	
	ieee8021PbPnpTable_removeHier (poEntry);
	return false;
}

bool
ieee8021PbPnpTable_removeHier (
	ieee8021PbPnpEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL)
	{
		goto ieee8021PbPnpTable_removeHier_success;
	}
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) != NULL &&
		!ieee8021BridgeBasePortTable_removeExt (poIeee8021BridgeBaseEntry, poIeee8021BridgeBasePortEntry))
	{
		goto ieee8021PbPnpTable_removeHier_cleanup;
	}
	
ieee8021PbPnpTable_removeHier_success:
	
	bRetCode = true;
	
ieee8021PbPnpTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbPnpRowStatus_handler (
	ieee8021PbPnpEntry_t *poEntry, uint8_t u8RowStatus)
{
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL ||
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32BridgeBasePortComponentId, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbPnpRowStatus_handler_cleanup;
	}
	
	if (poEntry->u8RowStatus == u8RowStatus)
	{
		goto ieee8021PbPnpRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		(((u8RowStatus & xRowStatus_mask_c) == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 ((u8RowStatus & xRowStatus_mask_c) == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021PbPnpRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poIeee8021BridgeBaseEntry->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbPnpRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbPnpRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021PbPnpRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbPnpRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021PbPnpRowStatus_handler_success:
	
	return true;
	
	
ieee8021PbPnpRowStatus_handler_cleanup:
	
	return u8RowStatus & xRowStatus_fromParent_c;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbPnpTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbPnpTable_BTree);
	return ieee8021PbPnpTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbPnpTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbPnpEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbPnpEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbPnpTable_BTree);
	return put_index_data;
}

bool
ieee8021PbPnpTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbPnpEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbPnpTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbPnpTable table mapper */
int
ieee8021PbPnpTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbPnpEntry_t *table_entry;
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbPnpTable_createEntry (
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbPnpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbPnpTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbPnpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbPnpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBPNPROWSTATUS:
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
					ieee8021PbPnpTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbCepTable table mapper **/
void
ieee8021PbCepTable_init (void)
{
	extern oid ieee8021PbCepTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbCepTable", &ieee8021PbCepTable_mapper,
		ieee8021PbCepTable_oid, OID_LENGTH (ieee8021PbCepTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBCEPCCOMPONENTID;
	table_info->max_column = IEEE8021PBCEPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbCepTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbCepTable_getNext;
	iinfo->get_data_point = &ieee8021PbCepTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbCepTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbCepEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbCepEntry_t, oBTreeNode);
	register ieee8021PbCepEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbCepEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbCepTable_BTree = xBTree_initInline (&ieee8021PbCepTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbCepEntry_t *
ieee8021PbCepTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCepEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCepTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbCepTable_BTree);
	return poEntry;
}

ieee8021PbCepEntry_t *
ieee8021PbCepTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCepEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbCepTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCepEntry_t, oBTreeNode);
}

ieee8021PbCepEntry_t *
ieee8021PbCepTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbCepEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbCepTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbCepEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbCepTable_removeEntry (ieee8021PbCepEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbCepTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbCepTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021PbCepEntry_t *
ieee8021PbCepTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021PbCepEntry_t *poEntry = NULL;
	
	poEntry = ieee8021PbCepTable_createEntry (
		u32BridgeBasePortComponentId,
		u32BridgeBasePort);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021PbCepTable_createHier (poEntry))
	{
		ieee8021PbCepTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021PbCepTable_removeExt (ieee8021PbCepEntry_t *poEntry)
{
	if (!ieee8021PbCepTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021PbCepTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021PbCepTable_createHier (
	ieee8021PbCepEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *pSComponent = NULL;
	
	if ((pSComponent = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL ||
		(pSComponent->u8RowStatus == xRowStatus_active_c && pSComponent->i32ComponentType != ieee8021BridgeBaseComponentType_sVlanComponent_c))
	{
		goto ieee8021PbCepTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBaseEntry_t *pCComponent = NULL;
	
	if ((pCComponent = ieee8021BridgeBaseTable_createExt (ieee8021BridgeBaseComponent_zero_c)) == NULL)
	{
		goto ieee8021PbCepTable_createHier_cleanup;
	}
	pCComponent->i32ComponentType = ieee8021BridgeBaseComponentType_cVlanComponent_c;
	
	poEntry->u32CComponentId = pCComponent->u32ComponentId;
	
	if (!ieee8021BridgeBasePortTable_allocateIndex (pSComponent, &poEntry->u32BridgeBasePort))
	{
		goto ieee8021PbCepTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32CComponentId, poEntry->u32BridgeBasePort)) == NULL &&
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_createExt (pCComponent, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbCepTable_createHier_cleanup;
	}
	
	poIeee8021BridgeBasePortEntry->i32Type = ieee8021BridgeBasePortType_customerEdgePort_c;
	
	bRetCode = true;
	
ieee8021PbCepTable_createHier_cleanup:
	
	if (!bRetCode)
	{
		ieee8021PbCepTable_removeHier (poEntry);
	}
	return bRetCode;
}

bool
ieee8021PbCepTable_removeHier (
	ieee8021PbCepEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *pSComponent = NULL;
	register ieee8021BridgeBaseEntry_t *pCComponent = NULL;
	
	if ((pSComponent = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL ||
		(pCComponent = ieee8021BridgeBaseTable_getByIndex (poEntry->u32CComponentId)) == NULL)
	{
		goto ieee8021PbCepTable_removeHier_success;
	}
	
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32CComponentId, poEntry->u32BridgeBasePort)) != NULL &&
		!ieee8021BridgeBasePortTable_removeExt (pCComponent, poIeee8021BridgeBasePortEntry))
	{
		goto ieee8021PbCepTable_removeHier_cleanup;
	}
	
	if (!ieee8021BridgeBasePortTable_removeIndex (pSComponent, poEntry->u32BridgeBasePort))
	{
		goto ieee8021PbCepTable_removeHier_cleanup;
	}
	
	if (!ieee8021BridgeBaseTable_removeExt (pCComponent))
	{
		goto ieee8021PbCepTable_removeHier_cleanup;
	}
	
ieee8021PbCepTable_removeHier_success:
	
	bRetCode = true;
	
ieee8021PbCepTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021PbCepRowStatus_handler (
	ieee8021PbCepEntry_t *poEntry, uint8_t u8RowStatus)
{
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL ||
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32CComponentId, poEntry->u32BridgeBasePort)) == NULL)
	{
		goto ieee8021PbCepRowStatus_handler_cleanup;
	}
	
	if (poEntry->u8RowStatus == u8RowStatus)
	{
		goto ieee8021PbCepRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		(((u8RowStatus & xRowStatus_mask_c) == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 ((u8RowStatus & xRowStatus_mask_c) == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021PbCepRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poIeee8021BridgeBaseEntry->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbCepRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbCepRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021PbCepRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021BridgeBasePortRowStatus_handler (poIeee8021BridgeBasePortEntry, u8RealStatus))
		{
			goto ieee8021PbCepRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021PbCepRowStatus_handler_success:
	
	return true;
	
	
ieee8021PbCepRowStatus_handler_cleanup:
	
	return u8RowStatus & xRowStatus_fromParent_c;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbCepTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbCepTable_BTree);
	return ieee8021PbCepTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbCepTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCepEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbCepEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbCepTable_BTree);
	return put_index_data;
}

bool
ieee8021PbCepTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbCepEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbCepTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbCepTable table mapper */
int
ieee8021PbCepTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbCepEntry_t *table_entry;
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPCCOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CComponentId);
				break;
			case IEEE8021PBCEPCEPPORTNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CepPortNumber);
				break;
			case IEEE8021PBCEPROWSTATUS:
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbCepTable_createEntry (
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCepTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbCepTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbCepTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbCepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBCEPROWSTATUS:
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
					ieee8021PbCepTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbRcapTable table mapper **/
void
ieee8021PbRcapTable_init (void)
{
	extern oid ieee8021PbRcapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbRcapTable", &ieee8021PbRcapTable_mapper,
		ieee8021PbRcapTable_oid, OID_LENGTH (ieee8021PbRcapTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBRCAPSCOMPONENTID;
	table_info->max_column = IEEE8021PBRCAPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbRcapTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbRcapTable_getNext;
	iinfo->get_data_point = &ieee8021PbRcapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbRcapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbRcapEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbRcapEntry_t, oBTreeNode);
	register ieee8021PbRcapEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbRcapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbRcapTable_BTree = xBTree_initInline (&ieee8021PbRcapTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbRcapEntry_t *
ieee8021PbRcapTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbRcapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree);
	return poEntry;
}

ieee8021PbRcapEntry_t *
ieee8021PbRcapTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbRcapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbRcapEntry_t, oBTreeNode);
}

ieee8021PbRcapEntry_t *
ieee8021PbRcapTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbRcapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbRcapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbRcapTable_removeEntry (ieee8021PbRcapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbRcapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbRcapTable_BTree);
	return ieee8021PbRcapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbRcapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbRcapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbRcapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbRcapTable_BTree);
	return put_index_data;
}

bool
ieee8021PbRcapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbRcapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbRcapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbRcapTable table mapper */
int
ieee8021PbRcapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbRcapEntry_t *table_entry;
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPSCOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SComponentId);
				break;
			case IEEE8021PBRCAPRCAPPORTNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RcapPortNumber);
				break;
			case IEEE8021PBRCAPROWSTATUS:
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbRcapTable_createEntry (
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbRcapTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbRcapTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbRcapTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbRcapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBRCAPROWSTATUS:
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
					ieee8021PbRcapTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbInternalInterfaceTable table mapper **/
void
ieee8021PbInternalInterfaceTable_init (void)
{
	extern oid ieee8021PbInternalInterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbInternalInterfaceTable", &ieee8021PbInternalInterfaceTable_mapper,
		ieee8021PbInternalInterfaceTable_oid, OID_LENGTH (ieee8021PbInternalInterfaceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021PbIiExternalSVid */,
		0);
	table_info->min_column = IEEE8021PBIIINTERNALPORTNUMBER;
	table_info->max_column = IEEE8021PBIIROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbInternalInterfaceTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbInternalInterfaceTable_getNext;
	iinfo->get_data_point = &ieee8021PbInternalInterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbInternalInterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbInternalInterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbInternalInterfaceEntry_t, oBTreeNode);
	register ieee8021PbInternalInterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbInternalInterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32PbIiExternalSVid < pEntry2->u32PbIiExternalSVid) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32PbIiExternalSVid == pEntry2->u32PbIiExternalSVid) ? 0: 1;
}

xBTree_t oIeee8021PbInternalInterfaceTable_BTree = xBTree_initInline (&ieee8021PbInternalInterfaceTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbInternalInterfaceEntry_t *
ieee8021PbInternalInterfaceTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32PbIiExternalSVid)
{
	register ieee8021PbInternalInterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32PbIiExternalSVid = u32PbIiExternalSVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8PbIiRowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree);
	return poEntry;
}

ieee8021PbInternalInterfaceEntry_t *
ieee8021PbInternalInterfaceTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32PbIiExternalSVid)
{
	register ieee8021PbInternalInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32PbIiExternalSVid = u32PbIiExternalSVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbInternalInterfaceEntry_t, oBTreeNode);
}

ieee8021PbInternalInterfaceEntry_t *
ieee8021PbInternalInterfaceTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32PbIiExternalSVid)
{
	register ieee8021PbInternalInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32PbIiExternalSVid = u32PbIiExternalSVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbInternalInterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbInternalInterfaceTable_removeEntry (ieee8021PbInternalInterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbInternalInterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbInternalInterfaceTable_BTree);
	return ieee8021PbInternalInterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbInternalInterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbInternalInterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbInternalInterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32PbIiExternalSVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbInternalInterfaceTable_BTree);
	return put_index_data;
}

bool
ieee8021PbInternalInterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbInternalInterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbInternalInterfaceTable_getByIndex (
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

/* ieee8021PbInternalInterfaceTable table mapper */
int
ieee8021PbInternalInterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbInternalInterfaceEntry_t *table_entry;
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIINTERNALPORTNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PbIiInternalPortNumber);
				break;
			case IEEE8021PBIIINTERNALPORTTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbIiInternalPortType);
				break;
			case IEEE8021PBIIINTERNALSVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32PbIiInternalSVid);
				break;
			case IEEE8021PBIIROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8PbIiRowStatus);
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIINTERNALPORTTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBIIINTERNALSVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBIIROWSTATUS:
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbInternalInterfaceTable_createEntry (
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbInternalInterfaceTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIINTERNALPORTTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PbIiInternalPortType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PbIiInternalPortType, sizeof (table_entry->i32PbIiInternalPortType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PbIiInternalPortType = *request->requestvb->val.integer;
				break;
			case IEEE8021PBIIINTERNALSVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PbIiInternalSVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PbIiInternalSVid, sizeof (table_entry->u32PbIiInternalSVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PbIiInternalSVid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbInternalInterfaceTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIINTERNALPORTTYPE:
				memcpy (&table_entry->i32PbIiInternalPortType, pvOldDdata, sizeof (table_entry->i32PbIiInternalPortType));
				break;
			case IEEE8021PBIIINTERNALSVID:
				memcpy (&table_entry->u32PbIiInternalSVid, pvOldDdata, sizeof (table_entry->u32PbIiInternalSVid));
				break;
			case IEEE8021PBIIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbInternalInterfaceTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbInternalInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBIIROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8PbIiRowStatus = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8PbIiRowStatus = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ieee8021PbInternalInterfaceTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
