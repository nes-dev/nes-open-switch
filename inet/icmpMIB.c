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
#include "icmpMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid icmp_oid[] = {1,3,6,1,2,1,5};

static oid icmpStatsTable_oid[] = {1,3,6,1,2,1,5,29};
static oid icmpMsgStatsTable_oid[] = {1,3,6,1,2,1,5,30};



/**
 *	initialize icmpMIB group mapper
 */
void
icmpMIB_init (void)
{
	extern oid icmp_oid[];
	
	DEBUGMSGTL (("icmpMIB", "Initializing\n"));
	
	
	/* register icmpMIB group table mappers */
	icmpStatsTable_init ();
	icmpMsgStatsTable_init ();
	
	/* register icmpMIB modules */
	sysORTable_createRegister ("icmp", icmp_oid, OID_LENGTH (icmp_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize icmpStatsTable table mapper **/
void
icmpStatsTable_init (void)
{
	extern oid icmpStatsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"icmpStatsTable", &icmpStatsTable_mapper,
		icmpStatsTable_oid, OID_LENGTH (icmpStatsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: icmpStatsIPVersion */,
		0);
	table_info->min_column = ICMPSTATSINMSGS;
	table_info->max_column = ICMPSTATSOUTERRORS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &icmpStatsTable_getFirst;
	iinfo->get_next_data_point = &icmpStatsTable_getNext;
	iinfo->get_data_point = &icmpStatsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
icmpStatsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register icmpStatsEntry_t *pEntry1 = xBTree_entry (pNode1, icmpStatsEntry_t, oBTreeNode);
	register icmpStatsEntry_t *pEntry2 = xBTree_entry (pNode2, icmpStatsEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IPVersion < pEntry2->i32IPVersion) ? -1:
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion) ? 0: 1;
}

xBTree_t oIcmpStatsTable_BTree = xBTree_initInline (&icmpStatsTable_BTreeNodeCmp);

/* create a new row in the table */
icmpStatsEntry_t *
icmpStatsTable_createEntry (
	int32_t i32IPVersion)
{
	icmpStatsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (icmpStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IPVersion = i32IPVersion;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIcmpStatsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIcmpStatsTable_BTree);
	return poEntry;
}

icmpStatsEntry_t *
icmpStatsTable_getByIndex (
	int32_t i32IPVersion)
{
	register icmpStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (icmpStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIcmpStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, icmpStatsEntry_t, oBTreeNode);
}

icmpStatsEntry_t *
icmpStatsTable_getNextIndex (
	int32_t i32IPVersion)
{
	register icmpStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (icmpStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIcmpStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, icmpStatsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
icmpStatsTable_removeEntry (icmpStatsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIcmpStatsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIcmpStatsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
icmpStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIcmpStatsTable_BTree);
	return icmpStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
icmpStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	icmpStatsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, icmpStatsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IPVersion);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIcmpStatsTable_BTree);
	return put_index_data;
}

bool
icmpStatsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	icmpStatsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = icmpStatsTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* icmpStatsTable table mapper */
int
icmpStatsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	icmpStatsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (icmpStatsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ICMPSTATSINMSGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMsgs);
				break;
			case ICMPSTATSINERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InErrors);
				break;
			case ICMPSTATSOUTMSGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMsgs);
				break;
			case ICMPSTATSOUTERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutErrors);
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

/** initialize icmpMsgStatsTable table mapper **/
void
icmpMsgStatsTable_init (void)
{
	extern oid icmpMsgStatsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"icmpMsgStatsTable", &icmpMsgStatsTable_mapper,
		icmpMsgStatsTable_oid, OID_LENGTH (icmpMsgStatsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: icmpMsgStatsIPVersion */,
		ASN_INTEGER /* index: icmpMsgStatsType */,
		0);
	table_info->min_column = ICMPMSGSTATSINPKTS;
	table_info->max_column = ICMPMSGSTATSOUTPKTS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &icmpMsgStatsTable_getFirst;
	iinfo->get_next_data_point = &icmpMsgStatsTable_getNext;
	iinfo->get_data_point = &icmpMsgStatsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
icmpMsgStatsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register icmpMsgStatsEntry_t *pEntry1 = xBTree_entry (pNode1, icmpMsgStatsEntry_t, oBTreeNode);
	register icmpMsgStatsEntry_t *pEntry2 = xBTree_entry (pNode2, icmpMsgStatsEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IPVersion < pEntry2->i32IPVersion) ||
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion && pEntry1->i32Type < pEntry2->i32Type) ? -1:
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion && pEntry1->i32Type == pEntry2->i32Type) ? 0: 1;
}

xBTree_t oIcmpMsgStatsTable_BTree = xBTree_initInline (&icmpMsgStatsTable_BTreeNodeCmp);

/* create a new row in the table */
icmpMsgStatsEntry_t *
icmpMsgStatsTable_createEntry (
	int32_t i32IPVersion,
	int32_t i32Type)
{
	icmpMsgStatsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (icmpMsgStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IPVersion = i32IPVersion;
	poEntry->i32Type = i32Type;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree);
	return poEntry;
}

icmpMsgStatsEntry_t *
icmpMsgStatsTable_getByIndex (
	int32_t i32IPVersion,
	int32_t i32Type)
{
	register icmpMsgStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (icmpMsgStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	poTmpEntry->i32Type = i32Type;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, icmpMsgStatsEntry_t, oBTreeNode);
}

icmpMsgStatsEntry_t *
icmpMsgStatsTable_getNextIndex (
	int32_t i32IPVersion,
	int32_t i32Type)
{
	register icmpMsgStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (icmpMsgStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	poTmpEntry->i32Type = i32Type;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, icmpMsgStatsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
icmpMsgStatsTable_removeEntry (icmpMsgStatsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
icmpMsgStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIcmpMsgStatsTable_BTree);
	return icmpMsgStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
icmpMsgStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	icmpMsgStatsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, icmpMsgStatsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IPVersion);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Type);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIcmpMsgStatsTable_BTree);
	return put_index_data;
}

bool
icmpMsgStatsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	icmpMsgStatsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = icmpMsgStatsTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* icmpMsgStatsTable table mapper */
int
icmpMsgStatsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	icmpMsgStatsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (icmpMsgStatsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ICMPMSGSTATSINPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InPkts);
				break;
			case ICMPMSGSTATSOUTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutPkts);
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
