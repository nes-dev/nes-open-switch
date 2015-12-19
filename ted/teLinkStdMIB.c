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
#include "teLinkStdMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid teLinkStdMIB_oid[] = {1,3,6,1,2,1,10,200};
static oid teAdminGroupTable_oid[] = {1,3,6,1,2,1,122,1,1,9};

static oid teLinkTable_oid[] = {1,3,6,1,2,1,10,200,1,1};
static oid teLinkSwCapTable_oid[] = {1,3,6,1,2,1,10,200,1,2};
static oid teLinkSrlgTable_oid[] = {1,3,6,1,2,1,10,200,1,3};
static oid teLinkBandwidthTable_oid[] = {1,3,6,1,2,1,10,200,1,4};
static oid componentLinkTable_oid[] = {1,3,6,1,2,1,10,200,1,5};
static oid componentLinkSwCapTable_oid[] = {1,3,6,1,2,1,10,200,1,6};
static oid componentLinkBandwidthTable_oid[] = {1,3,6,1,2,1,10,200,1,7};



/**
 *	initialize teLinkStdMIB group mapper
 */
void
teLinkStdMIB_init (void)
{
	extern oid teLinkStdMIB_oid[];
	extern oid teAdminGroupTable_oid[];
	
	DEBUGMSGTL (("teLinkStdMIB", "Initializing\n"));
	
	
	/* register teLinkStdMIB group table mappers */
	teLinkTable_init ();
	teLinkSwCapTable_init ();
	teLinkSrlgTable_init ();
	teLinkBandwidthTable_init ();
	componentLinkTable_init ();
	componentLinkSwCapTable_init ();
	componentLinkBandwidthTable_init ();
	teAdminGroupTable_init ();
	
	/* register teLinkStdMIB modules */
	sysORTable_createRegister ("teLinkStdMIB", teLinkStdMIB_oid, OID_LENGTH (teLinkStdMIB_oid));
	sysORTable_createRegister ("teAdminGroupTable", teAdminGroupTable_oid, OID_LENGTH (teAdminGroupTable_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize teLinkTable table mapper **/
void
teLinkTable_init (void)
{
	extern oid teLinkTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"teLinkTable", &teLinkTable_mapper,
		teLinkTable_oid, OID_LENGTH (teLinkTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = TELINKADDRESSTYPE;
	table_info->max_column = TELINKSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &teLinkTable_getFirst;
	iinfo->get_next_data_point = &teLinkTable_getNext;
	iinfo->get_data_point = &teLinkTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
teLinkTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teLinkEntry_t *pEntry1 = xBTree_entry (pNode1, teLinkEntry_t, oBTreeNode);
	register teLinkEntry_t *pEntry2 = xBTree_entry (pNode2, teLinkEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oTeLinkTable_BTree = xBTree_initInline (&teLinkTable_BTreeNodeCmp);

/* create a new row in the table */
teLinkEntry_t *
teLinkTable_createEntry (
	uint32_t u32IfIndex)
{
	register teLinkEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTeLinkTable_BTree);
	return poEntry;
}

teLinkEntry_t *
teLinkTable_getByIndex (
	uint32_t u32IfIndex)
{
	register teLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTeLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkEntry_t, oBTreeNode);
}

teLinkEntry_t *
teLinkTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register teLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTeLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
teLinkTable_removeEntry (teLinkEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTeLinkTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
teLinkTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTeLinkTable_BTree);
	return teLinkTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
teLinkTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, teLinkEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTeLinkTable_BTree);
	return put_index_data;
}

bool
teLinkTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = teLinkTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* teLinkTable table mapper */
int
teLinkTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	teLinkEntry_t *table_entry;
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKADDRESSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddressType);
				break;
			case TELINKLOCALIPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LocalIpAddr, table_entry->u16LocalIpAddr_len);
				break;
			case TELINKREMOTEIPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RemoteIpAddr, table_entry->u16RemoteIpAddr_len);
				break;
			case TELINKMETRIC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Metric);
				break;
			case TELINKMAXRESBANDWIDTH:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxResBandwidth, sizeof (table_entry->au8MaxResBandwidth));
				break;
			case TELINKPROTECTIONTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ProtectionType);
				break;
			case TELINKWORKINGPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WorkingPriority);
				break;
			case TELINKRESOURCECLASS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ResourceClass);
				break;
			case TELINKREMOTEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RemoteId);
				break;
			case TELINKLOCALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32LocalId);
				break;
			case TELINKROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case TELINKSTORAGETYPE:
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKADDRESSTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKLOCALIPADDR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LocalIpAddr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKREMOTEIPADDR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8RemoteIpAddr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKMETRIC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKPROTECTIONTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKWORKINGPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKRESOURCECLASS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKREMOTEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKLOCALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSTORAGETYPE:
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case TELINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = teLinkTable_createEntry (
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkTable_removeEntry (table_entry);
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKADDRESSTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AddressType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AddressType, sizeof (table_entry->i32AddressType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AddressType = *request->requestvb->val.integer;
				break;
			case TELINKLOCALIPADDR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LocalIpAddr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LocalIpAddr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LocalIpAddr, sizeof (table_entry->au8LocalIpAddr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LocalIpAddr, 0, sizeof (table_entry->au8LocalIpAddr));
				memcpy (table_entry->au8LocalIpAddr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LocalIpAddr_len = request->requestvb->val_len;
				break;
			case TELINKREMOTEIPADDR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8RemoteIpAddr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16RemoteIpAddr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8RemoteIpAddr, sizeof (table_entry->au8RemoteIpAddr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8RemoteIpAddr, 0, sizeof (table_entry->au8RemoteIpAddr));
				memcpy (table_entry->au8RemoteIpAddr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16RemoteIpAddr_len = request->requestvb->val_len;
				break;
			case TELINKMETRIC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Metric))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Metric, sizeof (table_entry->u32Metric));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Metric = *request->requestvb->val.integer;
				break;
			case TELINKPROTECTIONTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ProtectionType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ProtectionType, sizeof (table_entry->i32ProtectionType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ProtectionType = *request->requestvb->val.integer;
				break;
			case TELINKWORKINGPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WorkingPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WorkingPriority, sizeof (table_entry->u32WorkingPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WorkingPriority = *request->requestvb->val.integer;
				break;
			case TELINKRESOURCECLASS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ResourceClass))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ResourceClass, sizeof (table_entry->u32ResourceClass));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ResourceClass = *request->requestvb->val.integer;
				break;
			case TELINKREMOTEID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RemoteId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RemoteId, sizeof (table_entry->u32RemoteId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RemoteId = *request->requestvb->val.integer;
				break;
			case TELINKLOCALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LocalId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LocalId, sizeof (table_entry->u32LocalId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LocalId = *request->requestvb->val.integer;
				break;
			case TELINKSTORAGETYPE:
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int teLinkTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKADDRESSTYPE:
				memcpy (&table_entry->i32AddressType, pvOldDdata, sizeof (table_entry->i32AddressType));
				break;
			case TELINKLOCALIPADDR:
				memcpy (table_entry->au8LocalIpAddr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LocalIpAddr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case TELINKREMOTEIPADDR:
				memcpy (table_entry->au8RemoteIpAddr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16RemoteIpAddr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case TELINKMETRIC:
				memcpy (&table_entry->u32Metric, pvOldDdata, sizeof (table_entry->u32Metric));
				break;
			case TELINKPROTECTIONTYPE:
				memcpy (&table_entry->i32ProtectionType, pvOldDdata, sizeof (table_entry->i32ProtectionType));
				break;
			case TELINKWORKINGPRIORITY:
				memcpy (&table_entry->u32WorkingPriority, pvOldDdata, sizeof (table_entry->u32WorkingPriority));
				break;
			case TELINKRESOURCECLASS:
				memcpy (&table_entry->u32ResourceClass, pvOldDdata, sizeof (table_entry->u32ResourceClass));
				break;
			case TELINKREMOTEID:
				memcpy (&table_entry->u32RemoteId, pvOldDdata, sizeof (table_entry->u32RemoteId));
				break;
			case TELINKLOCALID:
				memcpy (&table_entry->u32LocalId, pvOldDdata, sizeof (table_entry->u32LocalId));
				break;
			case TELINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case TELINKSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (teLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKROWSTATUS:
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
					teLinkTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize teLinkSwCapTable table mapper **/
void
teLinkSwCapTable_init (void)
{
	extern oid teLinkSwCapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"teLinkSwCapTable", &teLinkSwCapTable_mapper,
		teLinkSwCapTable_oid, OID_LENGTH (teLinkSwCapTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: teLinkSwCapId */,
		0);
	table_info->min_column = TELINKSWCAPTYPE;
	table_info->max_column = TELINKSWCAPSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &teLinkSwCapTable_getFirst;
	iinfo->get_next_data_point = &teLinkSwCapTable_getNext;
	iinfo->get_data_point = &teLinkSwCapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
teLinkSwCapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teLinkSwCapEntry_t *pEntry1 = xBTree_entry (pNode1, teLinkSwCapEntry_t, oBTreeNode);
	register teLinkSwCapEntry_t *pEntry2 = xBTree_entry (pNode2, teLinkSwCapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

static int8_t
teLinkSwCapTable_SwCap_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teLinkSwCapEntry_t *pEntry1 = xBTree_entry (pNode1, teLinkSwCapEntry_t, oSwCap_BTreeNode);
	register teLinkSwCapEntry_t *pEntry2 = xBTree_entry (pNode2, teLinkSwCapEntry_t, oSwCap_BTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->oK.i32Type < pEntry2->oK.i32Type) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->oK.i32Type == pEntry2->oK.i32Type && pEntry1->oK.i32Encoding < pEntry2->oK.i32Encoding) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->oK.i32Type == pEntry2->oK.i32Type && pEntry1->oK.i32Encoding == pEntry2->oK.i32Encoding) ? 0: 1;
}

xBTree_t oTeLinkSwCapTable_BTree = xBTree_initInline (&teLinkSwCapTable_BTreeNodeCmp);
xBTree_t oTeLinkSwCapTable_SwCap_BTree = xBTree_initInline (&teLinkSwCapTable_SwCap_BTreeNodeCmp);

/* create a new row in the table */
teLinkSwCapEntry_t *
teLinkSwCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register teLinkSwCapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkSwCapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTeLinkSwCapTable_BTree);
	return poEntry;
}

teLinkSwCapEntry_t *
teLinkSwCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register teLinkSwCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTeLinkSwCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkSwCapEntry_t, oBTreeNode);
}

teLinkSwCapEntry_t *
teLinkSwCapTable_SwCap_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	int32_t i32Encoding)
{
	register teLinkSwCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->oK.i32Type = i32Type;
	poTmpEntry->oK.i32Encoding = i32Encoding;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oSwCap_BTreeNode, &oTeLinkSwCapTable_SwCap_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkSwCapEntry_t, oSwCap_BTreeNode);
}

teLinkSwCapEntry_t *
teLinkSwCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register teLinkSwCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTeLinkSwCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkSwCapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
teLinkSwCapTable_removeEntry (teLinkSwCapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkSwCapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTeLinkSwCapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
teLinkSwCapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTeLinkSwCapTable_BTree);
	return teLinkSwCapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
teLinkSwCapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkSwCapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, teLinkSwCapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTeLinkSwCapTable_BTree);
	return put_index_data;
}

bool
teLinkSwCapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkSwCapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = teLinkSwCapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* teLinkSwCapTable table mapper */
int
teLinkSwCapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	teLinkSwCapEntry_t *table_entry;
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case TELINKSWCAPENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Encoding);
				break;
			case TELINKSWCAPMINLSPBANDWIDTH:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MinLspBandwidth, sizeof (table_entry->au8MinLspBandwidth));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO0:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[0], sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[1], sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[2], sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[3], sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO4:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[4], sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO5:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[5], sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO6:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[6], sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO7:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[7], sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				break;
			case TELINKSWCAPINTERFACEMTU:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32InterfaceMtu);
				break;
			case TELINKSWCAPINDICATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Indication);
				break;
			case TELINKSWCAPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case TELINKSWCAPSTORAGETYPE:
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMINLSPBANDWIDTH:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MinLspBandwidth));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO0:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO1:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO2:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO3:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO4:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO5:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO6:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO7:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPINTERFACEMTU:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPINDICATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSWCAPSTORAGETYPE:
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = teLinkSwCapTable_createEntry (
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkSwCapTable_removeEntry (table_entry);
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPTYPE:
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
			case TELINKSWCAPENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Encoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Encoding, sizeof (table_entry->i32Encoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Encoding = *request->requestvb->val.integer;
				break;
			case TELINKSWCAPMINLSPBANDWIDTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8MinLspBandwidth))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8MinLspBandwidth, sizeof (table_entry->au8MinLspBandwidth));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MinLspBandwidth, 0, sizeof (table_entry->au8MinLspBandwidth));
				memcpy (table_entry->au8MinLspBandwidth, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO0:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[0]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[0]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[0], sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[0], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[0], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[1]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[1]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[1], sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[1], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[1], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[2]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[2]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[2], sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[2], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[2], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[3]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[3]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[3], sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[3], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[3], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[4]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[4]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[4], sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[4], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[4], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[5]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[5]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[5], sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[5], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[5], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO6:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[6]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[6]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[6], sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[6], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[6], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO7:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[7]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[7]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[7], sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[7], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[7], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case TELINKSWCAPINTERFACEMTU:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32InterfaceMtu))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32InterfaceMtu, sizeof (table_entry->u32InterfaceMtu));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32InterfaceMtu = *request->requestvb->val.integer;
				break;
			case TELINKSWCAPINDICATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Indication))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Indication, sizeof (table_entry->i32Indication));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Indication = *request->requestvb->val.integer;
				break;
			case TELINKSWCAPSTORAGETYPE:
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int teLinkSwCapTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case TELINKSWCAPENCODING:
				memcpy (&table_entry->i32Encoding, pvOldDdata, sizeof (table_entry->i32Encoding));
				break;
			case TELINKSWCAPMINLSPBANDWIDTH:
				memcpy (table_entry->au8MinLspBandwidth, pvOldDdata, sizeof (table_entry->au8MinLspBandwidth));
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO0:
				memcpy (table_entry->au8MaxLspBandwidthPrio[0], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO1:
				memcpy (table_entry->au8MaxLspBandwidthPrio[1], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO2:
				memcpy (table_entry->au8MaxLspBandwidthPrio[2], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO3:
				memcpy (table_entry->au8MaxLspBandwidthPrio[3], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO4:
				memcpy (table_entry->au8MaxLspBandwidthPrio[4], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO5:
				memcpy (table_entry->au8MaxLspBandwidthPrio[5], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO6:
				memcpy (table_entry->au8MaxLspBandwidthPrio[6], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPMAXLSPBANDWIDTHPRIO7:
				memcpy (table_entry->au8MaxLspBandwidthPrio[7], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case TELINKSWCAPINTERFACEMTU:
				memcpy (&table_entry->u32InterfaceMtu, pvOldDdata, sizeof (table_entry->u32InterfaceMtu));
				break;
			case TELINKSWCAPINDICATION:
				memcpy (&table_entry->i32Indication, pvOldDdata, sizeof (table_entry->i32Indication));
				break;
			case TELINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkSwCapTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case TELINKSWCAPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (teLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSWCAPROWSTATUS:
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
					teLinkSwCapTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize teLinkSrlgTable table mapper **/
void
teLinkSrlgTable_init (void)
{
	extern oid teLinkSrlgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"teLinkSrlgTable", &teLinkSrlgTable_mapper,
		teLinkSrlgTable_oid, OID_LENGTH (teLinkSrlgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: teLinkSrlg */,
		0);
	table_info->min_column = TELINKSRLGROWSTATUS;
	table_info->max_column = TELINKSRLGSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &teLinkSrlgTable_getFirst;
	iinfo->get_next_data_point = &teLinkSrlgTable_getNext;
	iinfo->get_data_point = &teLinkSrlgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
teLinkSrlgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teLinkSrlgEntry_t *pEntry1 = xBTree_entry (pNode1, teLinkSrlgEntry_t, oBTreeNode);
	register teLinkSrlgEntry_t *pEntry2 = xBTree_entry (pNode2, teLinkSrlgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Srlg < pEntry2->u32Srlg) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Srlg == pEntry2->u32Srlg) ? 0: 1;
}

xBTree_t oTeLinkSrlgTable_BTree = xBTree_initInline (&teLinkSrlgTable_BTreeNodeCmp);

/* create a new row in the table */
teLinkSrlgEntry_t *
teLinkSrlgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Srlg)
{
	register teLinkSrlgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Srlg = u32Srlg;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkSrlgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTeLinkSrlgTable_BTree);
	return poEntry;
}

teLinkSrlgEntry_t *
teLinkSrlgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Srlg)
{
	register teLinkSrlgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Srlg = u32Srlg;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTeLinkSrlgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkSrlgEntry_t, oBTreeNode);
}

teLinkSrlgEntry_t *
teLinkSrlgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Srlg)
{
	register teLinkSrlgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Srlg = u32Srlg;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTeLinkSrlgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkSrlgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
teLinkSrlgTable_removeEntry (teLinkSrlgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkSrlgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTeLinkSrlgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
teLinkSrlgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTeLinkSrlgTable_BTree);
	return teLinkSrlgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
teLinkSrlgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkSrlgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, teLinkSrlgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Srlg);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTeLinkSrlgTable_BTree);
	return put_index_data;
}

bool
teLinkSrlgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkSrlgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = teLinkSrlgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* teLinkSrlgTable table mapper */
int
teLinkSrlgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	teLinkSrlgEntry_t *table_entry;
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case TELINKSRLGSTORAGETYPE:
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKSRLGSTORAGETYPE:
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = teLinkSrlgTable_createEntry (
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkSrlgTable_removeEntry (table_entry);
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSRLGSTORAGETYPE:
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int teLinkSrlgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkSrlgTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case TELINKSRLGSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (teLinkSrlgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKSRLGROWSTATUS:
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
					teLinkSrlgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize teLinkBandwidthTable table mapper **/
void
teLinkBandwidthTable_init (void)
{
	extern oid teLinkBandwidthTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"teLinkBandwidthTable", &teLinkBandwidthTable_mapper,
		teLinkBandwidthTable_oid, OID_LENGTH (teLinkBandwidthTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: teLinkBandwidthPriority */,
		0);
	table_info->min_column = TELINKBANDWIDTHUNRESERVED;
	table_info->max_column = TELINKBANDWIDTHSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &teLinkBandwidthTable_getFirst;
	iinfo->get_next_data_point = &teLinkBandwidthTable_getNext;
	iinfo->get_data_point = &teLinkBandwidthTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
teLinkBandwidthTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teLinkBandwidthEntry_t *pEntry1 = xBTree_entry (pNode1, teLinkBandwidthEntry_t, oBTreeNode);
	register teLinkBandwidthEntry_t *pEntry2 = xBTree_entry (pNode2, teLinkBandwidthEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Priority < pEntry2->u32Priority) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Priority == pEntry2->u32Priority) ? 0: 1;
}

xBTree_t oTeLinkBandwidthTable_BTree = xBTree_initInline (&teLinkBandwidthTable_BTreeNodeCmp);

/* create a new row in the table */
teLinkBandwidthEntry_t *
teLinkBandwidthTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register teLinkBandwidthEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Priority = u32Priority;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree);
	return poEntry;
}

teLinkBandwidthEntry_t *
teLinkBandwidthTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register teLinkBandwidthEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Priority = u32Priority;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkBandwidthEntry_t, oBTreeNode);
}

teLinkBandwidthEntry_t *
teLinkBandwidthTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register teLinkBandwidthEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Priority = u32Priority;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teLinkBandwidthEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
teLinkBandwidthTable_removeEntry (teLinkBandwidthEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
teLinkBandwidthTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTeLinkBandwidthTable_BTree);
	return teLinkBandwidthTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
teLinkBandwidthTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkBandwidthEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, teLinkBandwidthEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Priority);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTeLinkBandwidthTable_BTree);
	return put_index_data;
}

bool
teLinkBandwidthTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teLinkBandwidthEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = teLinkBandwidthTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* teLinkBandwidthTable table mapper */
int
teLinkBandwidthTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	teLinkBandwidthEntry_t *table_entry;
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHUNRESERVED:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Unreserved, sizeof (table_entry->au8Unreserved));
				break;
			case TELINKBANDWIDTHROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case TELINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TELINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = teLinkBandwidthTable_createEntry (
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkBandwidthTable_removeEntry (table_entry);
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int teLinkBandwidthTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teLinkBandwidthTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case TELINKBANDWIDTHSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (teLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TELINKBANDWIDTHROWSTATUS:
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
					teLinkBandwidthTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize componentLinkTable table mapper **/
void
componentLinkTable_init (void)
{
	extern oid componentLinkTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"componentLinkTable", &componentLinkTable_mapper,
		componentLinkTable_oid, OID_LENGTH (componentLinkTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = COMPONENTLINKMAXRESBANDWIDTH;
	table_info->max_column = COMPONENTLINKSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &componentLinkTable_getFirst;
	iinfo->get_next_data_point = &componentLinkTable_getNext;
	iinfo->get_data_point = &componentLinkTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
componentLinkTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register componentLinkEntry_t *pEntry1 = xBTree_entry (pNode1, componentLinkEntry_t, oBTreeNode);
	register componentLinkEntry_t *pEntry2 = xBTree_entry (pNode2, componentLinkEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oComponentLinkTable_BTree = xBTree_initInline (&componentLinkTable_BTreeNodeCmp);

/* create a new row in the table */
componentLinkEntry_t *
componentLinkTable_createEntry (
	uint32_t u32IfIndex)
{
	register componentLinkEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oComponentLinkTable_BTree);
	return poEntry;
}

componentLinkEntry_t *
componentLinkTable_getByIndex (
	uint32_t u32IfIndex)
{
	register componentLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oComponentLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkEntry_t, oBTreeNode);
}

componentLinkEntry_t *
componentLinkTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register componentLinkEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oComponentLinkTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
componentLinkTable_removeEntry (componentLinkEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oComponentLinkTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
componentLinkTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oComponentLinkTable_BTree);
	return componentLinkTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
componentLinkTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, componentLinkEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oComponentLinkTable_BTree);
	return put_index_data;
}

bool
componentLinkTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = componentLinkTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* componentLinkTable table mapper */
int
componentLinkTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	componentLinkEntry_t *table_entry;
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKMAXRESBANDWIDTH:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxResBandwidth, sizeof (table_entry->au8MaxResBandwidth));
				break;
			case COMPONENTLINKPREFERREDPROTECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PreferredProtection);
				break;
			case COMPONENTLINKCURRENTPROTECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CurrentProtection);
				break;
			case COMPONENTLINKROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case COMPONENTLINKSTORAGETYPE:
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKMAXRESBANDWIDTH:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxResBandwidth));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKPREFERREDPROTECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSTORAGETYPE:
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = componentLinkTable_createEntry (
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkTable_removeEntry (table_entry);
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKMAXRESBANDWIDTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8MaxResBandwidth))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8MaxResBandwidth, sizeof (table_entry->au8MaxResBandwidth));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxResBandwidth, 0, sizeof (table_entry->au8MaxResBandwidth));
				memcpy (table_entry->au8MaxResBandwidth, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKPREFERREDPROTECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PreferredProtection))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PreferredProtection, sizeof (table_entry->i32PreferredProtection));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PreferredProtection = *request->requestvb->val.integer;
				break;
			case COMPONENTLINKSTORAGETYPE:
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int componentLinkTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKMAXRESBANDWIDTH:
				memcpy (table_entry->au8MaxResBandwidth, pvOldDdata, sizeof (table_entry->au8MaxResBandwidth));
				break;
			case COMPONENTLINKPREFERREDPROTECTION:
				memcpy (&table_entry->i32PreferredProtection, pvOldDdata, sizeof (table_entry->i32PreferredProtection));
				break;
			case COMPONENTLINKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case COMPONENTLINKSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (componentLinkEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKROWSTATUS:
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
					componentLinkTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize componentLinkSwCapTable table mapper **/
void
componentLinkSwCapTable_init (void)
{
	extern oid componentLinkSwCapTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"componentLinkSwCapTable", &componentLinkSwCapTable_mapper,
		componentLinkSwCapTable_oid, OID_LENGTH (componentLinkSwCapTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: componentLinkSwCapId */,
		0);
	table_info->min_column = COMPONENTLINKSWCAPTYPE;
	table_info->max_column = COMPONENTLINKSWCAPSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &componentLinkSwCapTable_getFirst;
	iinfo->get_next_data_point = &componentLinkSwCapTable_getNext;
	iinfo->get_data_point = &componentLinkSwCapTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
componentLinkSwCapTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register componentLinkSwCapEntry_t *pEntry1 = xBTree_entry (pNode1, componentLinkSwCapEntry_t, oBTreeNode);
	register componentLinkSwCapEntry_t *pEntry2 = xBTree_entry (pNode2, componentLinkSwCapEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oComponentLinkSwCapTable_BTree = xBTree_initInline (&componentLinkSwCapTable_BTreeNodeCmp);

/* create a new row in the table */
componentLinkSwCapEntry_t *
componentLinkSwCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register componentLinkSwCapEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree);
	return poEntry;
}

componentLinkSwCapEntry_t *
componentLinkSwCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register componentLinkSwCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkSwCapEntry_t, oBTreeNode);
}

componentLinkSwCapEntry_t *
componentLinkSwCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id)
{
	register componentLinkSwCapEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkSwCapEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
componentLinkSwCapTable_removeEntry (componentLinkSwCapEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
componentLinkSwCapTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oComponentLinkSwCapTable_BTree);
	return componentLinkSwCapTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
componentLinkSwCapTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkSwCapEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, componentLinkSwCapEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oComponentLinkSwCapTable_BTree);
	return put_index_data;
}

bool
componentLinkSwCapTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkSwCapEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = componentLinkSwCapTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* componentLinkSwCapTable table mapper */
int
componentLinkSwCapTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	componentLinkSwCapEntry_t *table_entry;
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case COMPONENTLINKSWCAPENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Encoding);
				break;
			case COMPONENTLINKSWCAPMINLSPBANDWIDTH:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MinLspBandwidth, sizeof (table_entry->au8MinLspBandwidth));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO0:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[0], sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[1], sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[2], sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[3], sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO4:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[4], sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO5:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[5], sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO6:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[6], sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO7:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MaxLspBandwidthPrio[7], sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				break;
			case COMPONENTLINKSWCAPINTERFACEMTU:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32InterfaceMtu);
				break;
			case COMPONENTLINKSWCAPINDICATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Indication);
				break;
			case COMPONENTLINKSWCAPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case COMPONENTLINKSWCAPSTORAGETYPE:
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPENCODING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMINLSPBANDWIDTH:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MinLspBandwidth));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO0:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO1:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO2:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO3:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO4:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO5:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO6:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO7:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPINTERFACEMTU:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPINDICATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKSWCAPSTORAGETYPE:
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = componentLinkSwCapTable_createEntry (
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkSwCapTable_removeEntry (table_entry);
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPTYPE:
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
			case COMPONENTLINKSWCAPENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Encoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Encoding, sizeof (table_entry->i32Encoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Encoding = *request->requestvb->val.integer;
				break;
			case COMPONENTLINKSWCAPMINLSPBANDWIDTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8MinLspBandwidth))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8MinLspBandwidth, sizeof (table_entry->au8MinLspBandwidth));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MinLspBandwidth, 0, sizeof (table_entry->au8MinLspBandwidth));
				memcpy (table_entry->au8MinLspBandwidth, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO0:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[0]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[0]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[0], sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[0], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[0]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[0], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[1]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[1]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[1], sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[1], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[1]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[1], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[2]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[2]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[2], sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[2], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[2]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[2], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[3]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[3]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[3], sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[3], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[3]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[3], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[4]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[4]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[4], sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[4], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[4]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[4], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[5]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[5]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[5], sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[5], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[5]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[5], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO6:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[6]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[6]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[6], sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[6], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[6]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[6], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO7:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MaxLspBandwidthPrio[7]))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = sizeof (table_entry->au8MaxLspBandwidthPrio[7]);
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MaxLspBandwidthPrio[7], sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MaxLspBandwidthPrio[7], 0, sizeof (table_entry->au8MaxLspBandwidthPrio[7]));
				memcpy (table_entry->au8MaxLspBandwidthPrio[7], request->requestvb->val.string, request->requestvb->val_len);
				break;
			case COMPONENTLINKSWCAPINTERFACEMTU:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32InterfaceMtu))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32InterfaceMtu, sizeof (table_entry->u32InterfaceMtu));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32InterfaceMtu = *request->requestvb->val.integer;
				break;
			case COMPONENTLINKSWCAPINDICATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Indication))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Indication, sizeof (table_entry->i32Indication));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Indication = *request->requestvb->val.integer;
				break;
			case COMPONENTLINKSWCAPSTORAGETYPE:
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int componentLinkSwCapTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case COMPONENTLINKSWCAPENCODING:
				memcpy (&table_entry->i32Encoding, pvOldDdata, sizeof (table_entry->i32Encoding));
				break;
			case COMPONENTLINKSWCAPMINLSPBANDWIDTH:
				memcpy (table_entry->au8MinLspBandwidth, pvOldDdata, sizeof (table_entry->au8MinLspBandwidth));
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO0:
				memcpy (table_entry->au8MaxLspBandwidthPrio[0], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO1:
				memcpy (table_entry->au8MaxLspBandwidthPrio[1], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO2:
				memcpy (table_entry->au8MaxLspBandwidthPrio[2], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO3:
				memcpy (table_entry->au8MaxLspBandwidthPrio[3], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO4:
				memcpy (table_entry->au8MaxLspBandwidthPrio[4], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO5:
				memcpy (table_entry->au8MaxLspBandwidthPrio[5], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO6:
				memcpy (table_entry->au8MaxLspBandwidthPrio[6], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO7:
				memcpy (table_entry->au8MaxLspBandwidthPrio[7], ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				break;
			case COMPONENTLINKSWCAPINTERFACEMTU:
				memcpy (&table_entry->u32InterfaceMtu, pvOldDdata, sizeof (table_entry->u32InterfaceMtu));
				break;
			case COMPONENTLINKSWCAPINDICATION:
				memcpy (&table_entry->i32Indication, pvOldDdata, sizeof (table_entry->i32Indication));
				break;
			case COMPONENTLINKSWCAPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkSwCapTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case COMPONENTLINKSWCAPSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (componentLinkSwCapEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKSWCAPROWSTATUS:
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
					componentLinkSwCapTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize componentLinkBandwidthTable table mapper **/
void
componentLinkBandwidthTable_init (void)
{
	extern oid componentLinkBandwidthTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"componentLinkBandwidthTable", &componentLinkBandwidthTable_mapper,
		componentLinkBandwidthTable_oid, OID_LENGTH (componentLinkBandwidthTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: componentLinkBandwidthPriority */,
		0);
	table_info->min_column = COMPONENTLINKBANDWIDTHUNRESERVED;
	table_info->max_column = COMPONENTLINKBANDWIDTHSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &componentLinkBandwidthTable_getFirst;
	iinfo->get_next_data_point = &componentLinkBandwidthTable_getNext;
	iinfo->get_data_point = &componentLinkBandwidthTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
componentLinkBandwidthTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register componentLinkBandwidthEntry_t *pEntry1 = xBTree_entry (pNode1, componentLinkBandwidthEntry_t, oBTreeNode);
	register componentLinkBandwidthEntry_t *pEntry2 = xBTree_entry (pNode2, componentLinkBandwidthEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Priority < pEntry2->u32Priority) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32Priority == pEntry2->u32Priority) ? 0: 1;
}

xBTree_t oComponentLinkBandwidthTable_BTree = xBTree_initInline (&componentLinkBandwidthTable_BTreeNodeCmp);

/* create a new row in the table */
componentLinkBandwidthEntry_t *
componentLinkBandwidthTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register componentLinkBandwidthEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32Priority = u32Priority;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree);
	return poEntry;
}

componentLinkBandwidthEntry_t *
componentLinkBandwidthTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register componentLinkBandwidthEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Priority = u32Priority;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkBandwidthEntry_t, oBTreeNode);
}

componentLinkBandwidthEntry_t *
componentLinkBandwidthTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority)
{
	register componentLinkBandwidthEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32Priority = u32Priority;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, componentLinkBandwidthEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
componentLinkBandwidthTable_removeEntry (componentLinkBandwidthEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
componentLinkBandwidthTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oComponentLinkBandwidthTable_BTree);
	return componentLinkBandwidthTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
componentLinkBandwidthTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkBandwidthEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, componentLinkBandwidthEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Priority);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oComponentLinkBandwidthTable_BTree);
	return put_index_data;
}

bool
componentLinkBandwidthTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	componentLinkBandwidthEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = componentLinkBandwidthTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* componentLinkBandwidthTable table mapper */
int
componentLinkBandwidthTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	componentLinkBandwidthEntry_t *table_entry;
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHUNRESERVED:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Unreserved, sizeof (table_entry->au8Unreserved));
				break;
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case COMPONENTLINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case COMPONENTLINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = componentLinkBandwidthTable_createEntry (
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkBandwidthTable_removeEntry (table_entry);
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHSTORAGETYPE:
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int componentLinkBandwidthTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					componentLinkBandwidthTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case COMPONENTLINKBANDWIDTHSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (componentLinkBandwidthEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case COMPONENTLINKBANDWIDTHROWSTATUS:
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
					componentLinkBandwidthTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize teAdminGroupTable table mapper **/
void
teAdminGroupTable_init (void)
{
	extern oid teAdminGroupTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"teAdminGroupTable", &teAdminGroupTable_mapper,
		teAdminGroupTable_oid, OID_LENGTH (teAdminGroupTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: teAdminGroupNumber */,
		0);
	table_info->min_column = TEADMINGROUPNAME;
	table_info->max_column = TEADMINGROUPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &teAdminGroupTable_getFirst;
	iinfo->get_next_data_point = &teAdminGroupTable_getNext;
	iinfo->get_data_point = &teAdminGroupTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
teAdminGroupTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register teAdminGroupEntry_t *pEntry1 = xBTree_entry (pNode1, teAdminGroupEntry_t, oBTreeNode);
	register teAdminGroupEntry_t *pEntry2 = xBTree_entry (pNode2, teAdminGroupEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Number < pEntry2->i32Number) ? -1:
		(pEntry1->i32Number == pEntry2->i32Number) ? 0: 1;
}

xBTree_t oTeAdminGroupTable_BTree = xBTree_initInline (&teAdminGroupTable_BTreeNodeCmp);

/* create a new row in the table */
teAdminGroupEntry_t *
teAdminGroupTable_createEntry (
	int32_t i32Number)
{
	register teAdminGroupEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Number = i32Number;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTeAdminGroupTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTeAdminGroupTable_BTree);
	return poEntry;
}

teAdminGroupEntry_t *
teAdminGroupTable_getByIndex (
	int32_t i32Number)
{
	register teAdminGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Number = i32Number;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTeAdminGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teAdminGroupEntry_t, oBTreeNode);
}

teAdminGroupEntry_t *
teAdminGroupTable_getNextIndex (
	int32_t i32Number)
{
	register teAdminGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Number = i32Number;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTeAdminGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, teAdminGroupEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
teAdminGroupTable_removeEntry (teAdminGroupEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTeAdminGroupTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTeAdminGroupTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
teAdminGroupTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTeAdminGroupTable_BTree);
	return teAdminGroupTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
teAdminGroupTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teAdminGroupEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, teAdminGroupEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Number);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTeAdminGroupTable_BTree);
	return put_index_data;
}

bool
teAdminGroupTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	teAdminGroupEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = teAdminGroupTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* teAdminGroupTable table mapper */
int
teAdminGroupTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	teAdminGroupEntry_t *table_entry;
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case TEADMINGROUPROWSTATUS:
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case TEADMINGROUPROWSTATUS:
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = teAdminGroupTable_createEntry (
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teAdminGroupTable_removeEntry (table_entry);
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPNAME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Name))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Name_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Name, sizeof (table_entry->au8Name));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Name, 0, sizeof (table_entry->au8Name));
				memcpy (table_entry->au8Name, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Name_len = request->requestvb->val_len;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int teAdminGroupTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case TEADMINGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					teAdminGroupTable_removeEntry (table_entry);
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
			table_entry = (teAdminGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TEADMINGROUPROWSTATUS:
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
					teAdminGroupTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
