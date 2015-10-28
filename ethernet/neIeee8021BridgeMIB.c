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
#include "ethernetUtils.h"
#include "neIeee8021BridgeMIB.h"
#include "ieee8021BridgeMib.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid neIeee8021BridgeMIB_oid[] = {1,3,6,1,4,1,36969,71};

static oid neIeee8021BridgeBaseTable_oid[] = {1,3,6,1,4,1,36969,71,1,1};
static oid neIeee8021BridgeBasePortTable_oid[] = {1,3,6,1,4,1,36969,71,1,2};
static oid neIeee8021QBridgeVlanCurrentTable_oid[] = {1,3,6,1,4,1,36969,71,1,3};



/**
 *	initialize neIeee8021BridgeMIB group mapper
 */
void
neIeee8021BridgeMIB_init (void)
{
	extern oid neIeee8021BridgeMIB_oid[];
	
	DEBUGMSGTL (("neIeee8021BridgeMIB", "Initializing\n"));
	
	
	/* register neIeee8021BridgeMIB group table mappers */
	neIeee8021BridgeBaseTable_init ();
	neIeee8021BridgeBasePortTable_init ();
	neIeee8021QBridgeVlanCurrentTable_init ();
	
	/* register neIeee8021BridgeMIB modules */
	sysORTable_createRegister ("neIeee8021BridgeMIB", neIeee8021BridgeMIB_oid, OID_LENGTH (neIeee8021BridgeMIB_oid));
}


/**
 *	table mapper(s) & helper(s)
 */
/** initialize neIeee8021BridgeBaseTable table mapper **/
void
neIeee8021BridgeBaseTable_init (void)
{
	extern oid neIeee8021BridgeBaseTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021BridgeBaseTable", &neIeee8021BridgeBaseTable_mapper,
		neIeee8021BridgeBaseTable_oid, OID_LENGTH (neIeee8021BridgeBaseTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBaseComponentId */,
		0);
	table_info->min_column = NEIEEE8021BRIDGEBASECHASSISID;
	table_info->max_column = NEIEEE8021BRIDGEBASEOPERSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021BridgeBaseTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021BridgeBaseTable_getNext;
	iinfo->get_data_point = &neIeee8021BridgeBaseTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neIeee8021BridgeBaseEntry_t *
neIeee8021BridgeBaseTable_createEntry (
	uint32_t u32ComponentId)
{
	register neIeee8021BridgeBaseEntry_t *poEntry = NULL;
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poComponent->oNe;
	
	poEntry->u32ChassisId = 2;
	poEntry->u32NumPortsMax = 32;
	poEntry->i32OperState = neIeee8021BridgeBaseOperState_disabled_c;
	
	return poEntry;
}

neIeee8021BridgeBaseEntry_t *
neIeee8021BridgeBaseTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oNe;
}

neIeee8021BridgeBaseEntry_t *
neIeee8021BridgeBaseTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getNextIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oNe;
}

/* remove a row from the table */
void
neIeee8021BridgeBaseTable_removeEntry (neIeee8021BridgeBaseEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	poEntry->pu8Ports != NULL ? xBuffer_free (poEntry->pu8Ports): false;
	return;
}

bool
neIeee8021BridgeBaseRowStatus_handler (
	neIeee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus)
{
	return true;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021BridgeBaseTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBaseTable_BTree);
	return neIeee8021BridgeBaseTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021BridgeBaseTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021BridgeBaseEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBaseTable_BTree);
	return put_index_data;
}

bool
neIeee8021BridgeBaseTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021BridgeBaseTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIeee8021BridgeBaseTable table mapper */
int
neIeee8021BridgeBaseTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021BridgeBaseEntry_t *table_entry;
	register ieee8021BridgeBaseEntry_t *poEntry = NULL;
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASECHASSISID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ChassisId);
				break;
			case NEIEEE8021BRIDGEBASENUMPORTSMAX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NumPortsMax);
				break;
			case NEIEEE8021BRIDGEBASEPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8Ports, table_entry->u16Ports_len);
				break;
			case NEIEEE8021BRIDGEBASEADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, table_entry->u16AdminFlags_len);
				break;
			case NEIEEE8021BRIDGEBASEOPERSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperState);
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASECHASSISID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIEEE8021BRIDGEBASENUMPORTSMAX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIEEE8021BRIDGEBASEADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASECHASSISID:
			case NEIEEE8021BRIDGEBASENUMPORTSMAX:
			case NEIEEE8021BRIDGEBASEADMINFLAGS:
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASECHASSISID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ChassisId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ChassisId, sizeof (table_entry->u32ChassisId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ChassisId = *request->requestvb->val.integer;
				break;
			case NEIEEE8021BRIDGEBASENUMPORTSMAX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32NumPortsMax))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32NumPortsMax, sizeof (table_entry->u32NumPortsMax));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32NumPortsMax = *request->requestvb->val.integer;
				break;
			case NEIEEE8021BRIDGEBASEADMINFLAGS:
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
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASECHASSISID:
				memcpy (&table_entry->u32ChassisId, pvOldDdata, sizeof (table_entry->u32ChassisId));
				break;
			case NEIEEE8021BRIDGEBASENUMPORTSMAX:
				memcpy (&table_entry->u32NumPortsMax, pvOldDdata, sizeof (table_entry->u32NumPortsMax));
				break;
			case NEIEEE8021BRIDGEBASEADMINFLAGS:
				memcpy (table_entry->au8AdminFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AdminFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIeee8021BridgeBasePortTable table mapper **/
void
neIeee8021BridgeBasePortTable_init (void)
{
	extern oid neIeee8021BridgeBasePortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021BridgeBasePortTable", &neIeee8021BridgeBasePortTable_mapper,
		neIeee8021BridgeBasePortTable_oid, OID_LENGTH (neIeee8021BridgeBasePortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = NEIEEE8021BRIDGEBASEPORTADMINFLAGS;
	table_info->max_column = NEIEEE8021BRIDGEBASEPORTOPERSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021BridgeBasePortTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021BridgeBasePortTable_getNext;
	iinfo->get_data_point = &neIeee8021BridgeBasePortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neIeee8021BridgeBasePortEntry_t *
neIeee8021BridgeBasePortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Port)
{
	register neIeee8021BridgeBasePortEntry_t *poEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poPort = NULL;
	
	if ((poPort = ieee8021BridgeBasePortTable_getByIndex (u32ComponentId, u32Port)) == NULL)
	{
		return NULL;
	}
	poEntry = &poPort->oNe;
	
	poEntry->i32OperState = neIeee8021BridgeBasePortOperState_disabled_c;
	
	return poEntry;
}

neIeee8021BridgeBasePortEntry_t *
neIeee8021BridgeBasePortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port)
{
	register ieee8021BridgeBasePortEntry_t *poPort = NULL;
	
	if ((poPort = ieee8021BridgeBasePortTable_getByIndex (u32ComponentId, u32Port)) == NULL)
	{
		return NULL;
	}
	
	return &poPort->oNe;
}

neIeee8021BridgeBasePortEntry_t *
neIeee8021BridgeBasePortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port)
{
	register ieee8021BridgeBasePortEntry_t *poPort = NULL;
	
	if ((poPort = ieee8021BridgeBasePortTable_getNextIndex (u32ComponentId, u32Port)) == NULL)
	{
		return NULL;
	}
	
	return &poPort->oNe;
}

/* remove a row from the table */
void
neIeee8021BridgeBasePortTable_removeEntry (neIeee8021BridgeBasePortEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021BridgeBasePortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBasePortTable_BTree);
	return neIeee8021BridgeBasePortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021BridgeBasePortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBasePortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021BridgeBasePortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Port);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBasePortTable_BTree);
	return put_index_data;
}

bool
neIeee8021BridgeBasePortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBasePortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021BridgeBasePortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

bool
neIeee8021BridgeBasePortAdminFlags_handler (
	neIeee8021BridgeBasePortEntry_t *poEntry, uint8_t *pu8AdminFlags, bool bForce)
{
	register bool bRetCode = false;
	register ieee8021BridgeBasePortEntry_t *poPort = ieee8021BridgeBasePortTable_getByNeEntry (poEntry);
	
	if (memcmp (poEntry->au8AdminFlags, pu8AdminFlags, sizeof (poEntry->au8AdminFlags)) == 0 && !bForce)
	{
		goto neIeee8021BridgeBasePortAdminFlags_handler_success;
	}
	
	if (!neIeee8021BridgeBasePortAdminFlags_update (poPort, pu8AdminFlags))
	{
		goto neIeee8021BridgeBasePortAdminFlags_handler_cleanup;
	}
	
	!bForce ? memcpy (poEntry->au8AdminFlags, pu8AdminFlags, sizeof (poEntry->au8AdminFlags)): false;
	
neIeee8021BridgeBasePortAdminFlags_handler_success:
	
	bRetCode = true;
	
neIeee8021BridgeBasePortAdminFlags_handler_cleanup:
	
	return bRetCode;
}

/* neIeee8021BridgeBasePortTable table mapper */
int
neIeee8021BridgeBasePortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021BridgeBasePortEntry_t *table_entry;
	register ieee8021BridgeBasePortEntry_t *poEntry = NULL;
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
			poEntry = (ieee8021BridgeBasePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASEPORTADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, table_entry->u16AdminFlags_len);
				break;
			case NEIEEE8021BRIDGEBASEPORTOPERSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperState);
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
			poEntry = (ieee8021BridgeBasePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASEPORTADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
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
			poEntry = (ieee8021BridgeBasePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASEPORTADMINFLAGS:
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
			poEntry = (ieee8021BridgeBasePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASEPORTADMINFLAGS:
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
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ieee8021BridgeBasePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021BRIDGEBASEPORTADMINFLAGS:
				memcpy (table_entry->au8AdminFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AdminFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIeee8021QBridgeVlanCurrentTable table mapper **/
void
neIeee8021QBridgeVlanCurrentTable_init (void)
{
	extern oid neIeee8021QBridgeVlanCurrentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIeee8021QBridgeVlanCurrentTable", &neIeee8021QBridgeVlanCurrentTable_mapper,
		neIeee8021QBridgeVlanCurrentTable_oid, OID_LENGTH (neIeee8021QBridgeVlanCurrentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_TIMETICKS /* index: ieee8021QBridgeVlanTimeMark */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanIndex */,
		0);
	table_info->min_column = NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS;
	table_info->max_column = NEIEEE8021QBRIDGEVLANCURRENTIFINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIeee8021QBridgeVlanCurrentTable_getFirst;
	iinfo->get_next_data_point = &neIeee8021QBridgeVlanCurrentTable_getNext;
	iinfo->get_data_point = &neIeee8021QBridgeVlanCurrentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neIeee8021QBridgeVlanCurrentEntry_t *
neIeee8021QBridgeVlanCurrentTable_createEntry (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register neIeee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	register ieee8021QBridgeVlanCurrentEntry_t *poVlan = NULL;
	
	if ((poVlan = ieee8021QBridgeVlanCurrentTable_getByIndex (u32TimeMark, u32ComponentId, u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poVlan->oNe;
	
	poEntry->i32OperState = neIeee8021QBridgeVlanCurrentOperState_disabled_c;
	
	return poEntry;
}

neIeee8021QBridgeVlanCurrentEntry_t *
neIeee8021QBridgeVlanCurrentTable_getByIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poVlan = NULL;
	
	if ((poVlan = ieee8021QBridgeVlanCurrentTable_getByIndex (u32TimeMark, u32ComponentId, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poVlan->oNe;
}

neIeee8021QBridgeVlanCurrentEntry_t *
neIeee8021QBridgeVlanCurrentTable_getNextIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poVlan = NULL;
	
	if ((poVlan = ieee8021QBridgeVlanCurrentTable_getNextIndex (u32TimeMark, u32ComponentId, u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poVlan->oNe;
}

/* remove a row from the table */
void
neIeee8021QBridgeVlanCurrentTable_removeEntry (neIeee8021QBridgeVlanCurrentEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIeee8021QBridgeVlanCurrentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBaseTable_BTree);
	return neIeee8021QBridgeVlanCurrentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIeee8021QBridgeVlanCurrentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_TIMETICKS, poEntry->u32TimeMark);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBaseTable_BTree);
	return put_index_data;
}

bool
neIeee8021QBridgeVlanCurrentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeVlanCurrentTable_getByIndex (
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

/* neIeee8021QBridgeVlanCurrentTable table mapper */
int
neIeee8021QBridgeVlanCurrentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIeee8021QBridgeVlanCurrentEntry_t *table_entry;
	register ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
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
			poEntry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, table_entry->u16AdminFlags_len);
				break;
			case NEIEEE8021QBRIDGEVLANCURRENTOPERSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperState);
				break;
			case NEIEEE8021QBRIDGEVLANCURRENTLEARNT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8Learnt, table_entry->u16Learnt_len);
				break;
			case NEIEEE8021QBRIDGEVLANCURRENTIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
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
			poEntry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
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
			poEntry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS:
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
			poEntry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS:
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
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIEEE8021QBRIDGEVLANCURRENTADMINFLAGS:
				memcpy (table_entry->au8AdminFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AdminFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
