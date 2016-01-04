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
#include "mefEnniOvcMib.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mefEnniOvcMib_oid[] = {1,3,6,1,4,1,15007,2,3};

static oid mefServiceOvcAttributes_oid[] = {1,3,6,1,4,1,15007,2,3,1,3};

static oid mefServiceEnniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,1,1};
static oid mefServiceVuniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,2,1};
static oid mefServiceOvcCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,3,2};
static oid mefServiceOvcStatusTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,3,4};
static oid mefServiceOvcEndPtPerEnniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,3,5};
static oid mefServiceOvcEndPtPerUniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,3,6};
static oid mefServiceOvcEndPtPerVuniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,3,1,3,7};



/**
 *	initialize mefEnniOvcMib group mapper
 */
void
mefEnniOvcMib_init (void)
{
	extern oid mefEnniOvcMib_oid[];
	extern oid mefServiceOvcAttributes_oid[];
	
	DEBUGMSGTL (("mefEnniOvcMib", "Initializing\n"));
	
	/* register mefServiceOvcAttributes scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceOvcAttributes_mapper", &mefServiceOvcAttributes_mapper,
			mefServiceOvcAttributes_oid, OID_LENGTH (mefServiceOvcAttributes_oid),
			HANDLER_CAN_RONLY
		),
		MEFSERVICEOVCNEXTINDEX,
		MEFSERVICEOVCNEXTINDEX
	);
	
	
	/* register mefEnniOvcMib group table mappers */
	mefServiceEnniCfgTable_init ();
	mefServiceVuniCfgTable_init ();
	mefServiceOvcCfgTable_init ();
	mefServiceOvcStatusTable_init ();
	mefServiceOvcEndPtPerEnniCfgTable_init ();
	mefServiceOvcEndPtPerUniCfgTable_init ();
	mefServiceOvcEndPtPerVuniCfgTable_init ();
	
	/* register mefEnniOvcMib modules */
	sysORTable_createRegister ("mefEnniOvcMib", mefEnniOvcMib_oid, OID_LENGTH (mefEnniOvcMib_oid));
}


/**
 *	scalar mapper(s)
 */
mefServiceOvcAttributes_t oMefServiceOvcAttributes;

/** mefServiceOvcAttributes scalar mapper **/
int
mefServiceOvcAttributes_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceOvcAttributes_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceOvcAttributes_oid) - 1])
			{
			case MEFSERVICEOVCNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMefServiceOvcAttributes.u32NextIndex);
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
/** initialize mefServiceEnniCfgTable table mapper **/
void
mefServiceEnniCfgTable_init (void)
{
	extern oid mefServiceEnniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceEnniCfgTable", &mefServiceEnniCfgTable_mapper,
		mefServiceEnniCfgTable_oid, OID_LENGTH (mefServiceEnniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEENNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEENNICFGVUNINEXTINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceEnniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceEnniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceEnniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceEnniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceEnniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceEnniCfgEntry_t, oBTreeNode);
	register mefServiceEnniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceEnniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceEnniCfgTable_BTree = xBTree_initInline (&mefServiceEnniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceEnniCfgEntry_t *
mefServiceEnniCfgTable_createEntry (
	uint32_t u32IfIndex)
{
	register mefServiceEnniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->u32NumberLinks = 1;
	poEntry->i32Protection = mefServiceEnniCfgProtection_none_c;
	poEntry->u32MaxNumberOvcEndPts = 1;
	poEntry->u32VuniNextIndex = 1;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree);
	return poEntry;
}

mefServiceEnniCfgEntry_t *
mefServiceEnniCfgTable_getByIndex (
	uint32_t u32IfIndex)
{
	register mefServiceEnniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEnniCfgEntry_t, oBTreeNode);
}

mefServiceEnniCfgEntry_t *
mefServiceEnniCfgTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register mefServiceEnniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEnniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceEnniCfgTable_removeEntry (mefServiceEnniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceEnniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceEnniCfgTable_BTree);
	return mefServiceEnniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceEnniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEnniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceEnniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceEnniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceEnniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEnniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceEnniCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceEnniCfgTable table mapper */
int
mefServiceEnniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceEnniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEENNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEENNICFGNUMBERLINKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NumberLinks);
				break;
			case MEFSERVICEENNICFGPROTECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Protection);
				break;
			case MEFSERVICEENNICFGMAXNUMBEROVCENDPTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxNumberOvcEndPts);
				break;
			case MEFSERVICEENNICFGVUNINEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32VuniNextIndex);
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
			table_entry = (mefServiceEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEENNICFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEENNICFGNUMBERLINKS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEENNICFGPROTECTION:
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
			table_entry = (mefServiceEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (mefServiceEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEENNICFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEENNICFGNUMBERLINKS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32NumberLinks))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32NumberLinks, sizeof (table_entry->u32NumberLinks));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32NumberLinks = *request->requestvb->val.integer;
				break;
			case MEFSERVICEENNICFGPROTECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Protection))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Protection, sizeof (table_entry->i32Protection));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Protection = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (mefServiceEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEENNICFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEENNICFGNUMBERLINKS:
				memcpy (&table_entry->u32NumberLinks, pvOldDdata, sizeof (table_entry->u32NumberLinks));
				break;
			case MEFSERVICEENNICFGPROTECTION:
				memcpy (&table_entry->i32Protection, pvOldDdata, sizeof (table_entry->i32Protection));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceVuniCfgTable table mapper **/
void
mefServiceVuniCfgTable_init (void)
{
	extern oid mefServiceVuniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceVuniCfgTable", &mefServiceVuniCfgTable_mapper,
		mefServiceVuniCfgTable_oid, OID_LENGTH (mefServiceVuniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: mefServiceVuniCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEVUNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEVUNICFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceVuniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceVuniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceVuniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceVuniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceVuniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceVuniCfgEntry_t, oBTreeNode);
	register mefServiceVuniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceVuniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceVuniCfgTable_BTree = xBTree_initInline (&mefServiceVuniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceVuniCfgEntry_t *
mefServiceVuniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Index)
{
	register mefServiceVuniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->u32CeVidUntagged = 1;
	poEntry->u32CePriorityUntagged = 0;
	/*poEntry->au8SVlanMap = "1"*/;
	poEntry->u32MaxNumberOvcEndPoints = 1;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	poEntry->u32L2cpGrpIndex = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree);
	return poEntry;
}

mefServiceVuniCfgEntry_t *
mefServiceVuniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Index)
{
	register mefServiceVuniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceVuniCfgEntry_t, oBTreeNode);
}

mefServiceVuniCfgEntry_t *
mefServiceVuniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Index)
{
	register mefServiceVuniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceVuniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceVuniCfgTable_removeEntry (mefServiceVuniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceVuniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceVuniCfgTable_BTree);
	return mefServiceVuniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceVuniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceVuniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceVuniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceVuniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceVuniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceVuniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceVuniCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceVuniCfgTable table mapper */
int
mefServiceVuniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceVuniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEVUNICFGCEVIDUNTAGGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CeVidUntagged);
				break;
			case MEFSERVICEVUNICFGCEPRIORITYUNTAGGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CePriorityUntagged);
				break;
			case MEFSERVICEVUNICFGSVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SVlanMap, table_entry->u16SVlanMap_len);
				break;
			case MEFSERVICEVUNICFGMAXNUMBEROVCENDPOINTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxNumberOvcEndPoints);
				break;
			case MEFSERVICEVUNICFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEVUNICFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
				break;
			case MEFSERVICEVUNICFGL2CPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32L2cpGrpIndex);
				break;
			case MEFSERVICEVUNICFGROWSTATUS:
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGCEVIDUNTAGGED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGCEPRIORITYUNTAGGED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGSVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGEGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGL2CPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEVUNICFGROWSTATUS:
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceVuniCfgTable_createEntry (
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceVuniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEVUNICFGCEVIDUNTAGGED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CeVidUntagged))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CeVidUntagged, sizeof (table_entry->u32CeVidUntagged));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CeVidUntagged = *request->requestvb->val.integer;
				break;
			case MEFSERVICEVUNICFGCEPRIORITYUNTAGGED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CePriorityUntagged))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CePriorityUntagged, sizeof (table_entry->u32CePriorityUntagged));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CePriorityUntagged = *request->requestvb->val.integer;
				break;
			case MEFSERVICEVUNICFGSVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SVlanMap, sizeof (table_entry->au8SVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SVlanMap, 0, sizeof (table_entry->au8SVlanMap));
				memcpy (table_entry->au8SVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEVUNICFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEVUNICFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEVUNICFGL2CPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32L2cpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32L2cpGrpIndex, sizeof (table_entry->u32L2cpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32L2cpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceVuniCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEVUNICFGCEVIDUNTAGGED:
				memcpy (&table_entry->u32CeVidUntagged, pvOldDdata, sizeof (table_entry->u32CeVidUntagged));
				break;
			case MEFSERVICEVUNICFGCEPRIORITYUNTAGGED:
				memcpy (&table_entry->u32CePriorityUntagged, pvOldDdata, sizeof (table_entry->u32CePriorityUntagged));
				break;
			case MEFSERVICEVUNICFGSVLANMAP:
				memcpy (table_entry->au8SVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEVUNICFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEVUNICFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			case MEFSERVICEVUNICFGL2CPGRPINDEX:
				memcpy (&table_entry->u32L2cpGrpIndex, pvOldDdata, sizeof (table_entry->u32L2cpGrpIndex));
				break;
			case MEFSERVICEVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceVuniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEVUNICFGROWSTATUS:
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
					mefServiceVuniCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceOvcCfgTable table mapper **/
void
mefServiceOvcCfgTable_init (void)
{
	extern oid mefServiceOvcCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceOvcCfgTable", &mefServiceOvcCfgTable_mapper,
		mefServiceOvcCfgTable_oid, OID_LENGTH (mefServiceOvcCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceOvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEOVCCFGIDENTIFIER;
	table_info->max_column = MEFSERVICEOVCCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceOvcCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceOvcCfgTable_getNext;
	iinfo->get_data_point = &mefServiceOvcCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceOvcCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceOvcCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceOvcCfgEntry_t, oBTreeNode);
	register mefServiceOvcCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceOvcCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceOvcCfgTable_BTree = xBTree_initInline (&mefServiceOvcCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceOvcCfgEntry_t *
mefServiceOvcCfgTable_createEntry (
	uint32_t u32Index)
{
	register mefServiceOvcCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->i32ServiceType = mefServiceOvcCfgServiceType_pointToPoint_c;
	poEntry->u32MtuSize = 1522;
	poEntry->i32CeVlanIdPreservation = mefServiceOvcCfgCeVlanIdPreservation_preserve_c;
	poEntry->i32CeVlanCosPreservation = mefServiceOvcCfgCeVlanCosPreservation_preserve_c;
	poEntry->i32SVlanIdPreservation = mefServiceOvcCfgSVlanIdPreservation_preserve_c;
	poEntry->i32SVlanCosPreservation = mefServiceOvcCfgSVlanCosPreservation_preserve_c;
	poEntry->i32ColorForwarding = mefServiceOvcCfgColorForwarding_colorFwdYes_c;
	poEntry->i32ColorIndicator = mefServiceOvcCfgColorIndicator_colorIndicatorPcp_c;
	poEntry->i32UnicastDelivery = mefServiceOvcCfgUnicastDelivery_unconditional_c;
	poEntry->i32MulticastDelivery = mefServiceOvcCfgMulticastDelivery_unconditional_c;
	poEntry->i32BroadcastDelivery = mefServiceOvcCfgBroadcastDelivery_unconditional_c;
	poEntry->u32L2cpGrpIndex = 0;
	poEntry->i32AdminState = mefServiceOvcCfgAdminState_unlocked_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree);
	return poEntry;
}

mefServiceOvcCfgEntry_t *
mefServiceOvcCfgTable_getByIndex (
	uint32_t u32Index)
{
	register mefServiceOvcCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcCfgEntry_t, oBTreeNode);
}

mefServiceOvcCfgEntry_t *
mefServiceOvcCfgTable_getNextIndex (
	uint32_t u32Index)
{
	register mefServiceOvcCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceOvcCfgTable_removeEntry (mefServiceOvcCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceOvcCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceOvcCfgTable_BTree);
	return mefServiceOvcCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceOvcCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceOvcCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceOvcCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceOvcCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceOvcCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceOvcCfgTable table mapper */
int
mefServiceOvcCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceOvcCfgEntry_t *table_entry;
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEOVCCFGSERVICETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ServiceType);
				break;
			case MEFSERVICEOVCCFGMTUSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MtuSize);
				break;
			case MEFSERVICEOVCCFGCEVLANIDPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CeVlanIdPreservation);
				break;
			case MEFSERVICEOVCCFGCEVLANCOSPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CeVlanCosPreservation);
				break;
			case MEFSERVICEOVCCFGSVLANIDPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SVlanIdPreservation);
				break;
			case MEFSERVICEOVCCFGSVLANCOSPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SVlanCosPreservation);
				break;
			case MEFSERVICEOVCCFGCOLORFORWARDING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ColorForwarding);
				break;
			case MEFSERVICEOVCCFGCOLORINDICATOR:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ColorIndicator);
				break;
			case MEFSERVICEOVCCFGUNICASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UnicastDelivery);
				break;
			case MEFSERVICEOVCCFGMULTICASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MulticastDelivery);
				break;
			case MEFSERVICEOVCCFGBROADCASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32BroadcastDelivery);
				break;
			case MEFSERVICEOVCCFGL2CPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32L2cpGrpIndex);
				break;
			case MEFSERVICEOVCCFGADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminState);
				break;
			case MEFSERVICEOVCCFGROWSTATUS:
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGSERVICETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGMTUSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGCEVLANIDPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGCEVLANCOSPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGSVLANIDPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGSVLANCOSPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGCOLORFORWARDING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGCOLORINDICATOR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGUNICASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGMULTICASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGBROADCASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGL2CPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCCFGROWSTATUS:
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceOvcCfgTable_createEntry (
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCCFGSERVICETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ServiceType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ServiceType, sizeof (table_entry->i32ServiceType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ServiceType = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGMTUSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MtuSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MtuSize, sizeof (table_entry->u32MtuSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MtuSize = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGCEVLANIDPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CeVlanIdPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CeVlanIdPreservation, sizeof (table_entry->i32CeVlanIdPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CeVlanIdPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGCEVLANCOSPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CeVlanCosPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CeVlanCosPreservation, sizeof (table_entry->i32CeVlanCosPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CeVlanCosPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGSVLANIDPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SVlanIdPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SVlanIdPreservation, sizeof (table_entry->i32SVlanIdPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SVlanIdPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGSVLANCOSPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SVlanCosPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SVlanCosPreservation, sizeof (table_entry->i32SVlanCosPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SVlanCosPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGCOLORFORWARDING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ColorForwarding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ColorForwarding, sizeof (table_entry->i32ColorForwarding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ColorForwarding = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGCOLORINDICATOR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ColorIndicator))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ColorIndicator, sizeof (table_entry->i32ColorIndicator));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ColorIndicator = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGUNICASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UnicastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UnicastDelivery, sizeof (table_entry->i32UnicastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UnicastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGMULTICASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MulticastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MulticastDelivery, sizeof (table_entry->i32MulticastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MulticastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGBROADCASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32BroadcastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32BroadcastDelivery, sizeof (table_entry->i32BroadcastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32BroadcastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGL2CPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32L2cpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32L2cpGrpIndex, sizeof (table_entry->u32L2cpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32L2cpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCCFGADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminState, sizeof (table_entry->i32AdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminState = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceOvcCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCCFGSERVICETYPE:
				memcpy (&table_entry->i32ServiceType, pvOldDdata, sizeof (table_entry->i32ServiceType));
				break;
			case MEFSERVICEOVCCFGMTUSIZE:
				memcpy (&table_entry->u32MtuSize, pvOldDdata, sizeof (table_entry->u32MtuSize));
				break;
			case MEFSERVICEOVCCFGCEVLANIDPRESERVATION:
				memcpy (&table_entry->i32CeVlanIdPreservation, pvOldDdata, sizeof (table_entry->i32CeVlanIdPreservation));
				break;
			case MEFSERVICEOVCCFGCEVLANCOSPRESERVATION:
				memcpy (&table_entry->i32CeVlanCosPreservation, pvOldDdata, sizeof (table_entry->i32CeVlanCosPreservation));
				break;
			case MEFSERVICEOVCCFGSVLANIDPRESERVATION:
				memcpy (&table_entry->i32SVlanIdPreservation, pvOldDdata, sizeof (table_entry->i32SVlanIdPreservation));
				break;
			case MEFSERVICEOVCCFGSVLANCOSPRESERVATION:
				memcpy (&table_entry->i32SVlanCosPreservation, pvOldDdata, sizeof (table_entry->i32SVlanCosPreservation));
				break;
			case MEFSERVICEOVCCFGCOLORFORWARDING:
				memcpy (&table_entry->i32ColorForwarding, pvOldDdata, sizeof (table_entry->i32ColorForwarding));
				break;
			case MEFSERVICEOVCCFGCOLORINDICATOR:
				memcpy (&table_entry->i32ColorIndicator, pvOldDdata, sizeof (table_entry->i32ColorIndicator));
				break;
			case MEFSERVICEOVCCFGUNICASTDELIVERY:
				memcpy (&table_entry->i32UnicastDelivery, pvOldDdata, sizeof (table_entry->i32UnicastDelivery));
				break;
			case MEFSERVICEOVCCFGMULTICASTDELIVERY:
				memcpy (&table_entry->i32MulticastDelivery, pvOldDdata, sizeof (table_entry->i32MulticastDelivery));
				break;
			case MEFSERVICEOVCCFGBROADCASTDELIVERY:
				memcpy (&table_entry->i32BroadcastDelivery, pvOldDdata, sizeof (table_entry->i32BroadcastDelivery));
				break;
			case MEFSERVICEOVCCFGL2CPGRPINDEX:
				memcpy (&table_entry->u32L2cpGrpIndex, pvOldDdata, sizeof (table_entry->u32L2cpGrpIndex));
				break;
			case MEFSERVICEOVCCFGADMINSTATE:
				memcpy (&table_entry->i32AdminState, pvOldDdata, sizeof (table_entry->i32AdminState));
				break;
			case MEFSERVICEOVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCCFGROWSTATUS:
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
					mefServiceOvcCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceOvcStatusTable table mapper **/
void
mefServiceOvcStatusTable_init (void)
{
	extern oid mefServiceOvcStatusTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceOvcStatusTable", &mefServiceOvcStatusTable_mapper,
		mefServiceOvcStatusTable_oid, OID_LENGTH (mefServiceOvcStatusTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceOvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEOVCSTATUSMAXMTUSIZE;
	table_info->max_column = MEFSERVICEOVCSTATUSOPERATIONALSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceOvcStatusTable_getFirst;
	iinfo->get_next_data_point = &mefServiceOvcStatusTable_getNext;
	iinfo->get_data_point = &mefServiceOvcStatusTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceOvcStatusTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceOvcStatusEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceOvcStatusEntry_t, oBTreeNode);
	register mefServiceOvcStatusEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceOvcStatusEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ? -1:
		(pEntry1->u32CfgIndex == pEntry2->u32CfgIndex) ? 0: 1;
}

xBTree_t oMefServiceOvcStatusTable_BTree = xBTree_initInline (&mefServiceOvcStatusTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceOvcStatusEntry_t *
mefServiceOvcStatusTable_createEntry (
	uint32_t u32CfgIndex)
{
	register mefServiceOvcStatusEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CfgIndex = u32CfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree);
	return poEntry;
}

mefServiceOvcStatusEntry_t *
mefServiceOvcStatusTable_getByIndex (
	uint32_t u32CfgIndex)
{
	register mefServiceOvcStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcStatusEntry_t, oBTreeNode);
}

mefServiceOvcStatusEntry_t *
mefServiceOvcStatusTable_getNextIndex (
	uint32_t u32CfgIndex)
{
	register mefServiceOvcStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcStatusEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceOvcStatusTable_removeEntry (mefServiceOvcStatusEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceOvcStatusTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceOvcStatusTable_BTree);
	return mefServiceOvcStatusTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceOvcStatusTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcStatusEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceOvcStatusEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceOvcStatusTable_BTree);
	return put_index_data;
}

bool
mefServiceOvcStatusTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcStatusEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceOvcStatusTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceOvcStatusTable table mapper */
int
mefServiceOvcStatusTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceOvcStatusEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceOvcStatusEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCSTATUSMAXMTUSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxMtuSize);
				break;
			case MEFSERVICEOVCSTATUSMAXNUMENNIOVCENDPT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxNumEnniOvcEndPt);
				break;
			case MEFSERVICEOVCSTATUSMAXNUMVUNIOVCENDPT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxNumVuniOvcEndPt);
				break;
			case MEFSERVICEOVCSTATUSOPERATIONALSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperationalState);
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

/** initialize mefServiceOvcEndPtPerEnniCfgTable table mapper **/
void
mefServiceOvcEndPtPerEnniCfgTable_init (void)
{
	extern oid mefServiceOvcEndPtPerEnniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceOvcEndPtPerEnniCfgTable", &mefServiceOvcEndPtPerEnniCfgTable_mapper,
		mefServiceOvcEndPtPerEnniCfgTable_oid, OID_LENGTH (mefServiceOvcEndPtPerEnniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: mefServiceOvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEOVCENDPTPERENNICFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceOvcEndPtPerEnniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceOvcEndPtPerEnniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceOvcEndPtPerEnniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceOvcEndPtPerEnniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceOvcEndPtPerEnniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceOvcEndPtPerEnniCfgEntry_t, oBTreeNode);
	register mefServiceOvcEndPtPerEnniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceOvcEndPtPerEnniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex == pEntry2->u32CfgIndex) ? 0: 1;
}

xBTree_t oMefServiceOvcEndPtPerEnniCfgTable_BTree = xBTree_initInline (&mefServiceOvcEndPtPerEnniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceOvcEndPtPerEnniCfgEntry_t *
mefServiceOvcEndPtPerEnniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerEnniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32CfgIndex = u32CfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Role = mefServiceOvcEndPtPerEnniCfgRole_root_c;
	/*poEntry->au8RootSVlanMap = ""*/;
	/*poEntry->au8LeafSVlanMap = ""*/;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree);
	return poEntry;
}

mefServiceOvcEndPtPerEnniCfgEntry_t *
mefServiceOvcEndPtPerEnniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerEnniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerEnniCfgEntry_t, oBTreeNode);
}

mefServiceOvcEndPtPerEnniCfgEntry_t *
mefServiceOvcEndPtPerEnniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerEnniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerEnniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceOvcEndPtPerEnniCfgTable_removeEntry (mefServiceOvcEndPtPerEnniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceOvcEndPtPerEnniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceOvcEndPtPerEnniCfgTable_BTree);
	return mefServiceOvcEndPtPerEnniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceOvcEndPtPerEnniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerEnniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceOvcEndPtPerEnniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerEnniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceOvcEndPtPerEnniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerEnniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceOvcEndPtPerEnniCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceOvcEndPtPerEnniCfgTable table mapper */
int
mefServiceOvcEndPtPerEnniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceOvcEndPtPerEnniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROOTSVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RootSVlanMap, table_entry->u16RootSVlanMap_len);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGLEAFSVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LeafSVlanMap, table_entry->u16LeafSVlanMap_len);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROOTSVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8RootSVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGLEAFSVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LeafSVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGEGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceOvcEndPtPerEnniCfgTable_createEntry (
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerEnniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Role))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Role, sizeof (table_entry->i32Role));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Role = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROOTSVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8RootSVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16RootSVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8RootSVlanMap, sizeof (table_entry->au8RootSVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8RootSVlanMap, 0, sizeof (table_entry->au8RootSVlanMap));
				memcpy (table_entry->au8RootSVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16RootSVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGLEAFSVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LeafSVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LeafSVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LeafSVlanMap, sizeof (table_entry->au8LeafSVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LeafSVlanMap, 0, sizeof (table_entry->au8LeafSVlanMap));
				memcpy (table_entry->au8LeafSVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LeafSVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceOvcEndPtPerEnniCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROLE:
				memcpy (&table_entry->i32Role, pvOldDdata, sizeof (table_entry->i32Role));
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROOTSVLANMAP:
				memcpy (table_entry->au8RootSVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16RootSVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGLEAFSVLANMAP:
				memcpy (table_entry->au8LeafSVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LeafSVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCENDPTPERENNICFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERENNICFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerEnniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerEnniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERENNICFGROWSTATUS:
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
					mefServiceOvcEndPtPerEnniCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceOvcEndPtPerUniCfgTable table mapper **/
void
mefServiceOvcEndPtPerUniCfgTable_init (void)
{
	extern oid mefServiceOvcEndPtPerUniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceOvcEndPtPerUniCfgTable", &mefServiceOvcEndPtPerUniCfgTable_mapper,
		mefServiceOvcEndPtPerUniCfgTable_oid, OID_LENGTH (mefServiceOvcEndPtPerUniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: mefServiceOvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEOVCENDPTPERUNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEOVCENDPTPERUNICFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceOvcEndPtPerUniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceOvcEndPtPerUniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceOvcEndPtPerUniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceOvcEndPtPerUniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceOvcEndPtPerUniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceOvcEndPtPerUniCfgEntry_t, oBTreeNode);
	register mefServiceOvcEndPtPerUniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceOvcEndPtPerUniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex == pEntry2->u32CfgIndex) ? 0: 1;
}

xBTree_t oMefServiceOvcEndPtPerUniCfgTable_BTree = xBTree_initInline (&mefServiceOvcEndPtPerUniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceOvcEndPtPerUniCfgEntry_t *
mefServiceOvcEndPtPerUniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerUniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32CfgIndex = u32CfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Role = mefServiceOvcEndPtPerUniCfgRole_root_c;
	/*poEntry->au8CeVlanMap = "1:4095"*/;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree);
	return poEntry;
}

mefServiceOvcEndPtPerUniCfgEntry_t *
mefServiceOvcEndPtPerUniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerUniCfgEntry_t, oBTreeNode);
}

mefServiceOvcEndPtPerUniCfgEntry_t *
mefServiceOvcEndPtPerUniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceOvcEndPtPerUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerUniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceOvcEndPtPerUniCfgTable_removeEntry (mefServiceOvcEndPtPerUniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceOvcEndPtPerUniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceOvcEndPtPerUniCfgTable_BTree);
	return mefServiceOvcEndPtPerUniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceOvcEndPtPerUniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerUniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceOvcEndPtPerUniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerUniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceOvcEndPtPerUniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerUniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceOvcEndPtPerUniCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceOvcEndPtPerUniCfgTable table mapper */
int
mefServiceOvcEndPtPerUniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceOvcEndPtPerUniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEOVCENDPTPERUNICFGROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case MEFSERVICEOVCENDPTPERUNICFGCEVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8CeVlanMap, table_entry->u16CeVlanMap_len);
				break;
			case MEFSERVICEOVCENDPTPERUNICFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERUNICFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERUNICFGCEVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8CeVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERUNICFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERUNICFGEGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceOvcEndPtPerUniCfgTable_createEntry (
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerUniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Role))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Role, sizeof (table_entry->i32Role));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Role = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERUNICFGCEVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8CeVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16CeVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8CeVlanMap, sizeof (table_entry->au8CeVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8CeVlanMap, 0, sizeof (table_entry->au8CeVlanMap));
				memcpy (table_entry->au8CeVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16CeVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCENDPTPERUNICFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERUNICFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceOvcEndPtPerUniCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROLE:
				memcpy (&table_entry->i32Role, pvOldDdata, sizeof (table_entry->i32Role));
				break;
			case MEFSERVICEOVCENDPTPERUNICFGCEVLANMAP:
				memcpy (table_entry->au8CeVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16CeVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCENDPTPERUNICFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERUNICFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerUniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERUNICFGROWSTATUS:
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
					mefServiceOvcEndPtPerUniCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceOvcEndPtPerVuniCfgTable table mapper **/
void
mefServiceOvcEndPtPerVuniCfgTable_init (void)
{
	extern oid mefServiceOvcEndPtPerVuniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceOvcEndPtPerVuniCfgTable", &mefServiceOvcEndPtPerVuniCfgTable_mapper,
		mefServiceOvcEndPtPerVuniCfgTable_oid, OID_LENGTH (mefServiceOvcEndPtPerVuniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: mefServiceVuniCfgIndex */,
		ASN_UNSIGNED /* index: mefServiceOvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEOVCENDPTPERVUNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceOvcEndPtPerVuniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceOvcEndPtPerVuniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceOvcEndPtPerVuniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceOvcEndPtPerVuniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceOvcEndPtPerVuniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceOvcEndPtPerVuniCfgEntry_t, oBTreeNode);
	register mefServiceOvcEndPtPerVuniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceOvcEndPtPerVuniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32VuniCfgIndex < pEntry2->u32VuniCfgIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32VuniCfgIndex == pEntry2->u32VuniCfgIndex && pEntry1->u32OvcCfgIndex < pEntry2->u32OvcCfgIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32VuniCfgIndex == pEntry2->u32VuniCfgIndex && pEntry1->u32OvcCfgIndex == pEntry2->u32OvcCfgIndex) ? 0: 1;
}

xBTree_t oMefServiceOvcEndPtPerVuniCfgTable_BTree = xBTree_initInline (&mefServiceOvcEndPtPerVuniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceOvcEndPtPerVuniCfgEntry_t *
mefServiceOvcEndPtPerVuniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex)
{
	register mefServiceOvcEndPtPerVuniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32VuniCfgIndex = u32VuniCfgIndex;
	poEntry->u32OvcCfgIndex = u32OvcCfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Role = mefServiceOvcEndPtPerVuniCfgRole_root_c;
	/*poEntry->au8CeVlanMap = "1:4095"*/;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree);
	return poEntry;
}

mefServiceOvcEndPtPerVuniCfgEntry_t *
mefServiceOvcEndPtPerVuniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex)
{
	register mefServiceOvcEndPtPerVuniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32VuniCfgIndex = u32VuniCfgIndex;
	poTmpEntry->u32OvcCfgIndex = u32OvcCfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerVuniCfgEntry_t, oBTreeNode);
}

mefServiceOvcEndPtPerVuniCfgEntry_t *
mefServiceOvcEndPtPerVuniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex)
{
	register mefServiceOvcEndPtPerVuniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32VuniCfgIndex = u32VuniCfgIndex;
	poTmpEntry->u32OvcCfgIndex = u32OvcCfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceOvcEndPtPerVuniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceOvcEndPtPerVuniCfgTable_removeEntry (mefServiceOvcEndPtPerVuniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceOvcEndPtPerVuniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceOvcEndPtPerVuniCfgTable_BTree);
	return mefServiceOvcEndPtPerVuniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceOvcEndPtPerVuniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerVuniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceOvcEndPtPerVuniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VuniCfgIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32OvcCfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceOvcEndPtPerVuniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceOvcEndPtPerVuniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceOvcEndPtPerVuniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = mefServiceOvcEndPtPerVuniCfgTable_getByIndex (
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

/* mefServiceOvcEndPtPerVuniCfgTable table mapper */
int
mefServiceOvcEndPtPerVuniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceOvcEndPtPerVuniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGROLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Role);
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGCEVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8CeVlanMap, table_entry->u16CeVlanMap_len);
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGCEVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8CeVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGEGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceOvcEndPtPerVuniCfgTable_createEntry (
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerVuniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Role))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Role, sizeof (table_entry->i32Role));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Role = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGCEVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8CeVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16CeVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8CeVlanMap, sizeof (table_entry->au8CeVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8CeVlanMap, 0, sizeof (table_entry->au8CeVlanMap));
				memcpy (table_entry->au8CeVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16CeVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceOvcEndPtPerVuniCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROLE:
				memcpy (&table_entry->i32Role, pvOldDdata, sizeof (table_entry->i32Role));
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGCEVLANMAP:
				memcpy (table_entry->au8CeVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16CeVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceOvcEndPtPerVuniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceOvcEndPtPerVuniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS:
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
					mefServiceOvcEndPtPerVuniCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
