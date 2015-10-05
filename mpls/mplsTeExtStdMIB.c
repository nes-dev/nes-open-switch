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
#include "mplsTeStdMIB.h"
#include "mplsTeExtStdMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mplsTeExtStdMIB_oid[] = {1,3,6,1,2,1,10,166,20};

static oid mplsTunnelExtTable_oid[] = {1,3,6,1,2,1,10,166,20,0,5};



/**
 *	initialize mplsTeExtStdMIB group mapper
 */
void
mplsTeExtStdMIB_init (void)
{
	extern oid mplsTeExtStdMIB_oid[];
	
	DEBUGMSGTL (("mplsTeExtStdMIB", "Initializing\n"));
	
	
	/* register mplsTeExtStdMIB group table mappers */
	mplsTunnelExtTable_init ();
	
	/* register mplsTeExtStdMIB modules */
	sysORTable_createRegister ("mplsTeExtStdMIB", mplsTeExtStdMIB_oid, OID_LENGTH (mplsTeExtStdMIB_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize mplsTunnelExtTable table mapper **/
void
mplsTunnelExtTable_init (void)
{
	extern oid mplsTunnelExtTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsTunnelExtTable", &mplsTunnelExtTable_mapper,
		mplsTunnelExtTable_oid, OID_LENGTH (mplsTunnelExtTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mplsTunnelIndex */,
		ASN_UNSIGNED /* index: mplsTunnelInstance */,
		ASN_UNSIGNED /* index: mplsTunnelIngressLSRId */,
		ASN_UNSIGNED /* index: mplsTunnelEgressLSRId */,
		0);
	table_info->min_column = MPLSTUNNELEXTOPPOSITEDIRPTR;
	table_info->max_column = MPLSTUNNELEXTEGRESSLSRLOCALIDVALID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsTunnelExtTable_getFirst;
	iinfo->get_next_data_point = &mplsTunnelExtTable_getNext;
	iinfo->get_data_point = &mplsTunnelExtTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
mplsTunnelExtEntry_t *
mplsTunnelExtTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelExtEntry_t *poEntry = NULL;
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poTunnel->oX;
	
	poEntry->u8OppositeDirTnlValid = mplsTunnelExtOppositeDirTnlValid_false_c;
	poEntry->u8DestTnlValid = mplsTunnelExtDestTnlValid_false_c;
	poEntry->u8IngressLSRLocalIdValid = mplsTunnelExtIngressLSRLocalIdValid_false_c;
	poEntry->u8EgressLSRLocalIdValid = mplsTunnelExtEgressLSRLocalIdValid_false_c;
	
	return poEntry;
}

mplsTunnelExtEntry_t *
mplsTunnelExtTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getByIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnel->oX;
}

mplsTunnelExtEntry_t *
mplsTunnelExtTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId)
{
	register mplsTunnelEntry_t *poTunnel = NULL;
	
	if ((poTunnel = mplsTunnelTable_getNextIndex (u32Index, u32Instance, u32IngressLSRId, u32EgressLSRId)) == NULL)
	{
		return NULL;
	}
	
	return &poTunnel->oX;
}

/* remove a row from the table */
void
mplsTunnelExtTable_removeEntry (mplsTunnelExtEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsTunnelExtTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsTunnelTable_BTree);
	return mplsTunnelExtTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsTunnelExtTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsTunnelEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Instance);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32IngressLSRId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32EgressLSRId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsTunnelTable_BTree);
	return put_index_data;
}

bool
mplsTunnelExtTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsTunnelEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = mplsTunnelTable_getByIndex (
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

/* mplsTunnelExtTable table mapper */
int
mplsTunnelExtTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsTunnelExtEntry_t *table_entry;
	register mplsTunnelEntry_t *poEntry = NULL;
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELEXTOPPOSITEDIRPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoOppositeDirPtr, table_entry->u16OppositeDirPtr_len);
				break;
			case MPLSTUNNELEXTOPPOSITEDIRTNLVALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8OppositeDirTnlValid);
				break;
			case MPLSTUNNELEXTDESTTNLINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DestTnlIndex);
				break;
			case MPLSTUNNELEXTDESTTNLLSPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DestTnlLspIndex);
				break;
			case MPLSTUNNELEXTDESTTNLVALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8DestTnlValid);
				break;
			case MPLSTUNNELEXTINGRESSLSRLOCALIDVALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8IngressLSRLocalIdValid);
				break;
			case MPLSTUNNELEXTEGRESSLSRLOCALIDVALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8EgressLSRLocalIdValid);
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELEXTOPPOSITEDIRPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoOppositeDirPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTOPPOSITEDIRTNLVALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTDESTTNLINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTDESTTNLLSPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTDESTTNLVALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTINGRESSLSRLOCALIDVALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSTUNNELEXTEGRESSLSRLOCALIDVALID:
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
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELEXTOPPOSITEDIRPTR:
			case MPLSTUNNELEXTOPPOSITEDIRTNLVALID:
			case MPLSTUNNELEXTDESTTNLINDEX:
			case MPLSTUNNELEXTDESTTNLLSPINDEX:
			case MPLSTUNNELEXTDESTTNLVALID:
			case MPLSTUNNELEXTINGRESSLSRLOCALIDVALID:
			case MPLSTUNNELEXTEGRESSLSRLOCALIDVALID:
				if (poEntry->u8RowStatus == xRowStatus_active_c || poEntry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELEXTOPPOSITEDIRPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoOppositeDirPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16OppositeDirPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoOppositeDirPtr, sizeof (table_entry->aoOppositeDirPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoOppositeDirPtr, 0, sizeof (table_entry->aoOppositeDirPtr));
				memcpy (table_entry->aoOppositeDirPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16OppositeDirPtr_len = request->requestvb->val_len;
				break;
			case MPLSTUNNELEXTOPPOSITEDIRTNLVALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8OppositeDirTnlValid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8OppositeDirTnlValid, sizeof (table_entry->u8OppositeDirTnlValid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8OppositeDirTnlValid = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXTDESTTNLINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32DestTnlIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32DestTnlIndex, sizeof (table_entry->u32DestTnlIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32DestTnlIndex = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXTDESTTNLLSPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32DestTnlLspIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32DestTnlLspIndex, sizeof (table_entry->u32DestTnlLspIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32DestTnlLspIndex = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXTDESTTNLVALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8DestTnlValid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8DestTnlValid, sizeof (table_entry->u8DestTnlValid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8DestTnlValid = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXTINGRESSLSRLOCALIDVALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8IngressLSRLocalIdValid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8IngressLSRLocalIdValid, sizeof (table_entry->u8IngressLSRLocalIdValid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8IngressLSRLocalIdValid = *request->requestvb->val.integer;
				break;
			case MPLSTUNNELEXTEGRESSLSRLOCALIDVALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8EgressLSRLocalIdValid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8EgressLSRLocalIdValid, sizeof (table_entry->u8EgressLSRLocalIdValid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8EgressLSRLocalIdValid = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsTunnelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case MPLSTUNNELEXTOPPOSITEDIRPTR:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->aoOppositeDirPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16OppositeDirPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case MPLSTUNNELEXTOPPOSITEDIRTNLVALID:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8OppositeDirTnlValid, pvOldDdata, sizeof (table_entry->u8OppositeDirTnlValid));
				}
				break;
			case MPLSTUNNELEXTDESTTNLINDEX:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32DestTnlIndex, pvOldDdata, sizeof (table_entry->u32DestTnlIndex));
				}
				break;
			case MPLSTUNNELEXTDESTTNLLSPINDEX:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32DestTnlLspIndex, pvOldDdata, sizeof (table_entry->u32DestTnlLspIndex));
				}
				break;
			case MPLSTUNNELEXTDESTTNLVALID:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8DestTnlValid, pvOldDdata, sizeof (table_entry->u8DestTnlValid));
				}
				break;
			case MPLSTUNNELEXTINGRESSLSRLOCALIDVALID:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8IngressLSRLocalIdValid, pvOldDdata, sizeof (table_entry->u8IngressLSRLocalIdValid));
				}
				break;
			case MPLSTUNNELEXTEGRESSLSRLOCALIDVALID:
				if (pvOldDdata == table_entry)
				{
					mplsTunnelExtTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u8EgressLSRLocalIdValid, pvOldDdata, sizeof (table_entry->u8EgressLSRLocalIdValid));
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
