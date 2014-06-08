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
#include "lagMIB.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



/* array length = OID_LENGTH + 1 */
static oid lagMIBObjects_oid[] = {1,2,840,10006,300,43,1,3};

static oid dot3adAggTable_oid[] = {1,2,840,10006,300,43,1,1,1};
static oid dot3adAggPortListTable_oid[] = {1,2,840,10006,300,43,1,1,2};
static oid dot3adAggPortTable_oid[] = {1,2,840,10006,300,43,1,2,1};
static oid dot3adAggPortStatsTable_oid[] = {1,2,840,10006,300,43,1,2,2};
static oid dot3adAggPortDebugTable_oid[] = {1,2,840,10006,300,43,1,2,3};
static oid dot3adAggPortXTable_oid[] = {1,2,840,10006,300,43,1,2,4};



/**
 *	initialize lagMIB group mapper
 */
void
lagMIB_init (void)
{
	extern oid lagMIBObjects_oid[];
	
	DEBUGMSGTL (("lagMIB", "Initializing\n"));
	
	/* register lagMIBObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"lagMIBObjects_mapper", &lagMIBObjects_mapper,
			lagMIBObjects_oid, OID_LENGTH (lagMIBObjects_oid) - 1,
			HANDLER_CAN_RONLY
		),
		DOT3ADTABLESLASTCHANGED,
		DOT3ADTABLESLASTCHANGED
	);
	
	
	/* register lagMIB group table mappers */
	dot3adAggTable_init ();
	dot3adAggPortListTable_init ();
	dot3adAggPortTable_init ();
	dot3adAggPortStatsTable_init ();
	dot3adAggPortDebugTable_init ();
	dot3adAggPortXTable_init ();
}


/**
 *	scalar mapper(s)
 */
lagMIBObjects_t oLagMIBObjects;

/** lagMIBObjects scalar mapper **/
int
lagMIBObjects_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid lagMIBObjects_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (lagMIBObjects_oid) - 1])
			{
			case DOT3ADTABLESLASTCHANGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, oLagMIBObjects.u32Dot3adTablesLastChanged);
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
/** initialize dot3adAggTable table mapper **/
void
dot3adAggTable_init (void)
{
	extern oid dot3adAggTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggTable", &dot3adAggTable_mapper,
		dot3adAggTable_oid, OID_LENGTH (dot3adAggTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggIndex */,
		0);
	table_info->min_column = DOT3ADAGGMACADDRESS;
	table_info->max_column = DOT3ADAGGCOLLECTORMAXDELAY;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggTable_getNext;
	iinfo->get_data_point = &dot3adAggTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggEntry_t, oBTreeNode);
	register dot3adAggEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggTable_BTree = xBTree_initInline (&dot3adAggTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggEntry_t *
dot3adAggTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggTable_BTree);
	return poEntry;
}

dot3adAggEntry_t *
dot3adAggTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggEntry_t, oBTreeNode);
}

dot3adAggEntry_t *
dot3adAggTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggTable_removeEntry (dot3adAggEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggTable_BTree);
	return dot3adAggTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggTable_BTree);
	return put_index_data;
}

bool
dot3adAggTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggTable table mapper */
int
dot3adAggTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggEntry_t *table_entry;
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
			table_entry = (dot3adAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MACAddress, table_entry->u16MACAddress_len);
				break;
			case DOT3ADAGGACTORSYSTEMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorSystemPriority);
				break;
			case DOT3ADAGGACTORSYSTEMID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ActorSystemID, table_entry->u16ActorSystemID_len);
				break;
			case DOT3ADAGGAGGREGATEORINDIVIDUAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AggregateOrIndividual);
				break;
			case DOT3ADAGGACTORADMINKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorAdminKey);
				break;
			case DOT3ADAGGACTOROPERKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorOperKey);
				break;
			case DOT3ADAGGPARTNERSYSTEMID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PartnerSystemID, table_entry->u16PartnerSystemID_len);
				break;
			case DOT3ADAGGPARTNERSYSTEMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerSystemPriority);
				break;
			case DOT3ADAGGPARTNEROPERKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerOperKey);
				break;
			case DOT3ADAGGCOLLECTORMAXDELAY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CollectorMaxDelay);
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
			table_entry = (dot3adAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGACTORSYSTEMPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGACTORADMINKEY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGCOLLECTORMAXDELAY:
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
			table_entry = (dot3adAggEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (dot3adAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGACTORSYSTEMPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorSystemPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorSystemPriority, sizeof (table_entry->i32ActorSystemPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorSystemPriority = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGACTORADMINKEY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorAdminKey))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorAdminKey, sizeof (table_entry->i32ActorAdminKey));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorAdminKey = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGCOLLECTORMAXDELAY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CollectorMaxDelay))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CollectorMaxDelay, sizeof (table_entry->i32CollectorMaxDelay));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CollectorMaxDelay = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (dot3adAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGACTORSYSTEMPRIORITY:
				memcpy (&table_entry->i32ActorSystemPriority, pvOldDdata, sizeof (table_entry->i32ActorSystemPriority));
				break;
			case DOT3ADAGGACTORADMINKEY:
				memcpy (&table_entry->i32ActorAdminKey, pvOldDdata, sizeof (table_entry->i32ActorAdminKey));
				break;
			case DOT3ADAGGCOLLECTORMAXDELAY:
				memcpy (&table_entry->i32CollectorMaxDelay, pvOldDdata, sizeof (table_entry->i32CollectorMaxDelay));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot3adAggPortListTable table mapper **/
void
dot3adAggPortListTable_init (void)
{
	extern oid dot3adAggPortListTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggPortListTable", &dot3adAggPortListTable_mapper,
		dot3adAggPortListTable_oid, OID_LENGTH (dot3adAggPortListTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggIndex */,
		0);
	table_info->min_column = DOT3ADAGGPORTLISTPORTS;
	table_info->max_column = DOT3ADAGGPORTLISTPORTS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggPortListTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggPortListTable_getNext;
	iinfo->get_data_point = &dot3adAggPortListTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggPortListTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortListEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortListEntry_t, oBTreeNode);
	register dot3adAggPortListEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortListEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggPortListTable_BTree = xBTree_initInline (&dot3adAggPortListTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortListEntry_t *
dot3adAggPortListTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggPortListEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggPortListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortListTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortListTable_BTree);
	return poEntry;
}

dot3adAggPortListEntry_t *
dot3adAggPortListTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortListEntry_t, oBTreeNode);
}

dot3adAggPortListEntry_t *
dot3adAggPortListTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortListEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortListTable_removeEntry (dot3adAggPortListEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortListTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortListTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortListTable_BTree);
	return dot3adAggPortListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortListEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortListEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortListTable_BTree);
	return put_index_data;
}

bool
dot3adAggPortListTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortListEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggPortListTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggPortListTable table mapper */
int
dot3adAggPortListTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggPortListEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot3adAggPortListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTLISTPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Ports, table_entry->u16Ports_len);
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

/** initialize dot3adAggPortTable table mapper **/
void
dot3adAggPortTable_init (void)
{
	extern oid dot3adAggPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggPortTable", &dot3adAggPortTable_mapper,
		dot3adAggPortTable_oid, OID_LENGTH (dot3adAggPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = DOT3ADAGGPORTACTORSYSTEMPRIORITY;
	table_info->max_column = DOT3ADAGGPORTAGGREGATEORINDIVIDUAL;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggPortTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggPortTable_getNext;
	iinfo->get_data_point = &dot3adAggPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortEntry_t, oBTreeNode);
	register dot3adAggPortEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggPortTable_BTree = xBTree_initInline (&dot3adAggPortTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortEntry_t *
dot3adAggPortTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortTable_BTree);
	return poEntry;
}

dot3adAggPortEntry_t *
dot3adAggPortTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortEntry_t, oBTreeNode);
}

dot3adAggPortEntry_t *
dot3adAggPortTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortTable_removeEntry (dot3adAggPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortTable_BTree);
	return dot3adAggPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortTable_BTree);
	return put_index_data;
}

bool
dot3adAggPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggPortTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggPortTable table mapper */
int
dot3adAggPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggPortEntry_t *table_entry;
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
			table_entry = (dot3adAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTACTORSYSTEMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorSystemPriority);
				break;
			case DOT3ADAGGPORTACTORSYSTEMID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ActorSystemID, table_entry->u16ActorSystemID_len);
				break;
			case DOT3ADAGGPORTACTORADMINKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorAdminKey);
				break;
			case DOT3ADAGGPORTACTOROPERKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorOperKey);
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerAdminSystemPriority);
				break;
			case DOT3ADAGGPORTPARTNEROPERSYSTEMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerOperSystemPriority);
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PartnerAdminSystemID, table_entry->u16PartnerAdminSystemID_len);
				break;
			case DOT3ADAGGPORTPARTNEROPERSYSTEMID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PartnerOperSystemID, table_entry->u16PartnerOperSystemID_len);
				break;
			case DOT3ADAGGPORTPARTNERADMINKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerAdminKey);
				break;
			case DOT3ADAGGPORTPARTNEROPERKEY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerOperKey);
				break;
			case DOT3ADAGGPORTSELECTEDAGGID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32SelectedAggID);
				break;
			case DOT3ADAGGPORTATTACHEDAGGID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32AttachedAggID);
				break;
			case DOT3ADAGGPORTACTORPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorPort);
				break;
			case DOT3ADAGGPORTACTORPORTPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorPortPriority);
				break;
			case DOT3ADAGGPORTPARTNERADMINPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerAdminPort);
				break;
			case DOT3ADAGGPORTPARTNEROPERPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerOperPort);
				break;
			case DOT3ADAGGPORTPARTNERADMINPORTPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerAdminPortPriority);
				break;
			case DOT3ADAGGPORTPARTNEROPERPORTPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerOperPortPriority);
				break;
			case DOT3ADAGGPORTACTORADMINSTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ActorAdminState, table_entry->u16ActorAdminState_len);
				break;
			case DOT3ADAGGPORTACTOROPERSTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ActorOperState, table_entry->u16ActorOperState_len);
				break;
			case DOT3ADAGGPORTPARTNERADMINSTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PartnerAdminState, table_entry->u16PartnerAdminState_len);
				break;
			case DOT3ADAGGPORTPARTNEROPERSTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PartnerOperState, table_entry->u16PartnerOperState_len);
				break;
			case DOT3ADAGGPORTAGGREGATEORINDIVIDUAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AggregateOrIndividual);
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
			table_entry = (dot3adAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTACTORSYSTEMPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTACTORADMINKEY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTACTOROPERKEY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PartnerAdminSystemID));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINKEY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTACTORPORTPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINPORT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINPORTPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTACTORADMINSTATE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ActorAdminState));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT3ADAGGPORTPARTNERADMINSTATE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PartnerAdminState));
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
			table_entry = (dot3adAggPortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (dot3adAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTACTORSYSTEMPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorSystemPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorSystemPriority, sizeof (table_entry->i32ActorSystemPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorSystemPriority = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTACTORADMINKEY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorAdminKey))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorAdminKey, sizeof (table_entry->i32ActorAdminKey));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorAdminKey = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTACTOROPERKEY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorOperKey))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorOperKey, sizeof (table_entry->i32ActorOperKey));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorOperKey = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PartnerAdminSystemPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PartnerAdminSystemPriority, sizeof (table_entry->i32PartnerAdminSystemPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PartnerAdminSystemPriority = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PartnerAdminSystemID))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PartnerAdminSystemID_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PartnerAdminSystemID, sizeof (table_entry->au8PartnerAdminSystemID));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PartnerAdminSystemID, 0, sizeof (table_entry->au8PartnerAdminSystemID));
				memcpy (table_entry->au8PartnerAdminSystemID, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PartnerAdminSystemID_len = request->requestvb->val_len;
				break;
			case DOT3ADAGGPORTPARTNERADMINKEY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PartnerAdminKey))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PartnerAdminKey, sizeof (table_entry->i32PartnerAdminKey));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PartnerAdminKey = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTACTORPORTPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ActorPortPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ActorPortPriority, sizeof (table_entry->i32ActorPortPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ActorPortPriority = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTPARTNERADMINPORT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PartnerAdminPort))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PartnerAdminPort, sizeof (table_entry->i32PartnerAdminPort));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PartnerAdminPort = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTPARTNERADMINPORTPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PartnerAdminPortPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PartnerAdminPortPriority, sizeof (table_entry->i32PartnerAdminPortPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PartnerAdminPortPriority = *request->requestvb->val.integer;
				break;
			case DOT3ADAGGPORTACTORADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ActorAdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ActorAdminState_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ActorAdminState, sizeof (table_entry->au8ActorAdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ActorAdminState, 0, sizeof (table_entry->au8ActorAdminState));
				memcpy (table_entry->au8ActorAdminState, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ActorAdminState_len = request->requestvb->val_len;
				break;
			case DOT3ADAGGPORTPARTNERADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PartnerAdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PartnerAdminState_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PartnerAdminState, sizeof (table_entry->au8PartnerAdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PartnerAdminState, 0, sizeof (table_entry->au8PartnerAdminState));
				memcpy (table_entry->au8PartnerAdminState, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PartnerAdminState_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (dot3adAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTACTORSYSTEMPRIORITY:
				memcpy (&table_entry->i32ActorSystemPriority, pvOldDdata, sizeof (table_entry->i32ActorSystemPriority));
				break;
			case DOT3ADAGGPORTACTORADMINKEY:
				memcpy (&table_entry->i32ActorAdminKey, pvOldDdata, sizeof (table_entry->i32ActorAdminKey));
				break;
			case DOT3ADAGGPORTACTOROPERKEY:
				memcpy (&table_entry->i32ActorOperKey, pvOldDdata, sizeof (table_entry->i32ActorOperKey));
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMPRIORITY:
				memcpy (&table_entry->i32PartnerAdminSystemPriority, pvOldDdata, sizeof (table_entry->i32PartnerAdminSystemPriority));
				break;
			case DOT3ADAGGPORTPARTNERADMINSYSTEMID:
				memcpy (table_entry->au8PartnerAdminSystemID, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PartnerAdminSystemID_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT3ADAGGPORTPARTNERADMINKEY:
				memcpy (&table_entry->i32PartnerAdminKey, pvOldDdata, sizeof (table_entry->i32PartnerAdminKey));
				break;
			case DOT3ADAGGPORTACTORPORTPRIORITY:
				memcpy (&table_entry->i32ActorPortPriority, pvOldDdata, sizeof (table_entry->i32ActorPortPriority));
				break;
			case DOT3ADAGGPORTPARTNERADMINPORT:
				memcpy (&table_entry->i32PartnerAdminPort, pvOldDdata, sizeof (table_entry->i32PartnerAdminPort));
				break;
			case DOT3ADAGGPORTPARTNERADMINPORTPRIORITY:
				memcpy (&table_entry->i32PartnerAdminPortPriority, pvOldDdata, sizeof (table_entry->i32PartnerAdminPortPriority));
				break;
			case DOT3ADAGGPORTACTORADMINSTATE:
				memcpy (table_entry->au8ActorAdminState, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ActorAdminState_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT3ADAGGPORTPARTNERADMINSTATE:
				memcpy (table_entry->au8PartnerAdminState, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PartnerAdminState_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot3adAggPortStatsTable table mapper **/
void
dot3adAggPortStatsTable_init (void)
{
	extern oid dot3adAggPortStatsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggPortStatsTable", &dot3adAggPortStatsTable_mapper,
		dot3adAggPortStatsTable_oid, OID_LENGTH (dot3adAggPortStatsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = DOT3ADAGGPORTSTATSLACPDUSRX;
	table_info->max_column = DOT3ADAGGPORTSTATSMARKERRESPONSEPDUSTX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggPortStatsTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggPortStatsTable_getNext;
	iinfo->get_data_point = &dot3adAggPortStatsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggPortStatsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortStatsEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortStatsEntry_t, oBTreeNode);
	register dot3adAggPortStatsEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortStatsEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggPortStatsTable_BTree = xBTree_initInline (&dot3adAggPortStatsTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggPortStatsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggPortStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree);
	return poEntry;
}

dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortStatsEntry_t, oBTreeNode);
}

dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortStatsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortStatsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortStatsTable_removeEntry (dot3adAggPortStatsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortStatsTable_BTree);
	return dot3adAggPortStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortStatsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortStatsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortStatsTable_BTree);
	return put_index_data;
}

bool
dot3adAggPortStatsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortStatsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggPortStatsTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggPortStatsTable table mapper */
int
dot3adAggPortStatsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggPortStatsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot3adAggPortStatsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTSTATSLACPDUSRX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LACPDUsRx);
				break;
			case DOT3ADAGGPORTSTATSMARKERPDUSRX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32MarkerPDUsRx);
				break;
			case DOT3ADAGGPORTSTATSMARKERRESPONSEPDUSRX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32MarkerResponsePDUsRx);
				break;
			case DOT3ADAGGPORTSTATSUNKNOWNRX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32UnknownRx);
				break;
			case DOT3ADAGGPORTSTATSILLEGALRX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IllegalRx);
				break;
			case DOT3ADAGGPORTSTATSLACPDUSTX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LACPDUsTx);
				break;
			case DOT3ADAGGPORTSTATSMARKERPDUSTX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32MarkerPDUsTx);
				break;
			case DOT3ADAGGPORTSTATSMARKERRESPONSEPDUSTX:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32MarkerResponsePDUsTx);
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

/** initialize dot3adAggPortDebugTable table mapper **/
void
dot3adAggPortDebugTable_init (void)
{
	extern oid dot3adAggPortDebugTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggPortDebugTable", &dot3adAggPortDebugTable_mapper,
		dot3adAggPortDebugTable_oid, OID_LENGTH (dot3adAggPortDebugTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = DOT3ADAGGPORTDEBUGRXSTATE;
	table_info->max_column = DOT3ADAGGPORTDEBUGPARTNERCHANGECOUNT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggPortDebugTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggPortDebugTable_getNext;
	iinfo->get_data_point = &dot3adAggPortDebugTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggPortDebugTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortDebugEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortDebugEntry_t, oBTreeNode);
	register dot3adAggPortDebugEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortDebugEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggPortDebugTable_BTree = xBTree_initInline (&dot3adAggPortDebugTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggPortDebugEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggPortDebugEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree);
	return poEntry;
}

dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortDebugEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortDebugEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortDebugEntry_t, oBTreeNode);
}

dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortDebugEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortDebugEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortDebugEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortDebugTable_removeEntry (dot3adAggPortDebugEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortDebugTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortDebugTable_BTree);
	return dot3adAggPortDebugTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortDebugTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortDebugEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortDebugEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortDebugTable_BTree);
	return put_index_data;
}

bool
dot3adAggPortDebugTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortDebugEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggPortDebugTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggPortDebugTable table mapper */
int
dot3adAggPortDebugTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggPortDebugEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot3adAggPortDebugEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTDEBUGRXSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RxState);
				break;
			case DOT3ADAGGPORTDEBUGLASTRXTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastRxTime);
				break;
			case DOT3ADAGGPORTDEBUGMUXSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MuxState);
				break;
			case DOT3ADAGGPORTDEBUGMUXREASON:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MuxReason, table_entry->u16MuxReason_len);
				break;
			case DOT3ADAGGPORTDEBUGACTORCHURNSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ActorChurnState);
				break;
			case DOT3ADAGGPORTDEBUGPARTNERCHURNSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PartnerChurnState);
				break;
			case DOT3ADAGGPORTDEBUGACTORCHURNCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ActorChurnCount);
				break;
			case DOT3ADAGGPORTDEBUGPARTNERCHURNCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PartnerChurnCount);
				break;
			case DOT3ADAGGPORTDEBUGACTORSYNCTRANSITIONCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ActorSyncTransitionCount);
				break;
			case DOT3ADAGGPORTDEBUGPARTNERSYNCTRANSITIONCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PartnerSyncTransitionCount);
				break;
			case DOT3ADAGGPORTDEBUGACTORCHANGECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ActorChangeCount);
				break;
			case DOT3ADAGGPORTDEBUGPARTNERCHANGECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32PartnerChangeCount);
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

/** initialize dot3adAggPortXTable table mapper **/
void
dot3adAggPortXTable_init (void)
{
	extern oid dot3adAggPortXTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot3adAggPortXTable", &dot3adAggPortXTable_mapper,
		dot3adAggPortXTable_oid, OID_LENGTH (dot3adAggPortXTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = DOT3ADAGGPORTPROTOCOLDA;
	table_info->max_column = DOT3ADAGGPORTPROTOCOLDA;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot3adAggPortXTable_getFirst;
	iinfo->get_next_data_point = &dot3adAggPortXTable_getNext;
	iinfo->get_data_point = &dot3adAggPortXTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot3adAggPortXTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortXEntry_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortXEntry_t, oBTreeNode);
	register dot3adAggPortXEntry_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortXEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot3adAggPortXTable_BTree = xBTree_initInline (&dot3adAggPortXTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortXEntry_t *
dot3adAggPortXTable_createEntry (
	uint32_t u32Index)
{
	dot3adAggPortXEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot3adAggPortXEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortXTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8ProtocolDA = 1652522221570*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortXTable_BTree);
	return poEntry;
}

dot3adAggPortXEntry_t *
dot3adAggPortXTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortXEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortXEntry_t, oBTreeNode);
}

dot3adAggPortXEntry_t *
dot3adAggPortXTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot3adAggPortXEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortXEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortXTable_removeEntry (dot3adAggPortXEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortXTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortXTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortXTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortXTable_BTree);
	return dot3adAggPortXTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortXTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortXEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortXEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortXTable_BTree);
	return put_index_data;
}

bool
dot3adAggPortXTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortXEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot3adAggPortXTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot3adAggPortXTable table mapper */
int
dot3adAggPortXTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot3adAggPortXEntry_t *table_entry;
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
			table_entry = (dot3adAggPortXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTPROTOCOLDA:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ProtocolDA, table_entry->u16ProtocolDA_len);
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
			table_entry = (dot3adAggPortXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTPROTOCOLDA:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ProtocolDA));
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
			table_entry = (dot3adAggPortXEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (dot3adAggPortXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTPROTOCOLDA:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ProtocolDA))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ProtocolDA_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ProtocolDA, sizeof (table_entry->au8ProtocolDA));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ProtocolDA, 0, sizeof (table_entry->au8ProtocolDA));
				memcpy (table_entry->au8ProtocolDA, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ProtocolDA_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (dot3adAggPortXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTPROTOCOLDA:
				memcpy (table_entry->au8ProtocolDA, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ProtocolDA_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
