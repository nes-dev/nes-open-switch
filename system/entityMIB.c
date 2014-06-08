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
#include "entityMIB.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



/* array length = OID_LENGTH + 1 */
static oid entityGeneral_oid[] = {1,3,6,1,2,1,47,1,4,1};

static oid entPhysicalTable_oid[] = {1,3,6,1,2,1,47,1,1,1};
static oid entLogicalTable_oid[] = {1,3,6,1,2,1,47,1,2,1};
static oid entLPMappingTable_oid[] = {1,3,6,1,2,1,47,1,3,1};
static oid entAliasMappingTable_oid[] = {1,3,6,1,2,1,47,1,3,2};
static oid entPhysicalContainsTable_oid[] = {1,3,6,1,2,1,47,1,3,3};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid entConfigChange_oid[] = {1,3,6,1,2,1,47,2,0,1};



/**
 *	initialize entityMIB group mapper
 */
void
entityMIB_init (void)
{
	extern oid entityGeneral_oid[];
	
	DEBUGMSGTL (("entityMIB", "Initializing\n"));
	
	/* register entityGeneral scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"entityGeneral_mapper", &entityGeneral_mapper,
			entityGeneral_oid, OID_LENGTH (entityGeneral_oid) - 1,
			HANDLER_CAN_RONLY
		),
		ENTLASTCHANGETIME,
		ENTLASTCHANGETIME
	);
	
	
	/* register entityMIB group table mappers */
	entPhysicalTable_init ();
	entLogicalTable_init ();
	entLPMappingTable_init ();
	entAliasMappingTable_init ();
	entPhysicalContainsTable_init ();
}


/**
 *	scalar mapper(s)
 */
entityGeneral_t oEntityGeneral;

/** entityGeneral scalar mapper **/
int
entityGeneral_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid entityGeneral_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (entityGeneral_oid) - 1])
			{
			case ENTLASTCHANGETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, oEntityGeneral.u32LastChangeTime);
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
/** initialize entPhysicalTable table mapper **/
void
entPhysicalTable_init (void)
{
	extern oid entPhysicalTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"entPhysicalTable", &entPhysicalTable_mapper,
		entPhysicalTable_oid, OID_LENGTH (entPhysicalTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: entPhysicalIndex */,
		0);
	table_info->min_column = ENTPHYSICALDESCR;
	table_info->max_column = ENTPHYSICALURIS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &entPhysicalTable_getFirst;
	iinfo->get_next_data_point = &entPhysicalTable_getNext;
	iinfo->get_data_point = &entPhysicalTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
entPhysicalTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register entPhysicalEntry_t *pEntry1 = xBTree_entry (pNode1, entPhysicalEntry_t, oBTreeNode);
	register entPhysicalEntry_t *pEntry2 = xBTree_entry (pNode2, entPhysicalEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Index < pEntry2->i32Index) ? -1:
		(pEntry1->i32Index == pEntry2->i32Index) ? 0: 1;
}

xBTree_t oEntPhysicalTable_BTree = xBTree_initInline (&entPhysicalTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entPhysicalEntry_t *
entPhysicalTable_createEntry (
	int32_t i32Index)
{
	entPhysicalEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (entPhysicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Index = i32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oEntPhysicalTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oEntPhysicalTable_BTree);
	return poEntry;
}

entPhysicalEntry_t *
entPhysicalTable_getByIndex (
	int32_t i32Index)
{
	register entPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entPhysicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oEntPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entPhysicalEntry_t, oBTreeNode);
}

entPhysicalEntry_t *
entPhysicalTable_getNextIndex (
	int32_t i32Index)
{
	register entPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entPhysicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oEntPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entPhysicalEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
entPhysicalTable_removeEntry (entPhysicalEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oEntPhysicalTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oEntPhysicalTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entPhysicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oEntPhysicalTable_BTree);
	return entPhysicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entPhysicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entPhysicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, entPhysicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oEntPhysicalTable_BTree);
	return put_index_data;
}

bool
entPhysicalTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entPhysicalEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = entPhysicalTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* entPhysicalTable table mapper */
int
entPhysicalTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	entPhysicalEntry_t *table_entry;
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
			table_entry = (entPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTPHYSICALDESCR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Descr, table_entry->u16Descr_len);
				break;
			case ENTPHYSICALVENDORTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoVendorType, table_entry->u16VendorType_len);
				break;
			case ENTPHYSICALCONTAINEDIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ContainedIn);
				break;
			case ENTPHYSICALCLASS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Class);
				break;
			case ENTPHYSICALPARENTRELPOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ParentRelPos);
				break;
			case ENTPHYSICALNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case ENTPHYSICALHARDWAREREV:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8HardwareRev, table_entry->u16HardwareRev_len);
				break;
			case ENTPHYSICALFIRMWAREREV:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8FirmwareRev, table_entry->u16FirmwareRev_len);
				break;
			case ENTPHYSICALSOFTWAREREV:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SoftwareRev, table_entry->u16SoftwareRev_len);
				break;
			case ENTPHYSICALSERIALNUM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SerialNum, table_entry->u16SerialNum_len);
				break;
			case ENTPHYSICALMFGNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MfgName, table_entry->u16MfgName_len);
				break;
			case ENTPHYSICALMODELNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ModelName, table_entry->u16ModelName_len);
				break;
			case ENTPHYSICALALIAS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Alias, table_entry->u16Alias_len);
				break;
			case ENTPHYSICALASSETID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AssetID, table_entry->u16AssetID_len);
				break;
			case ENTPHYSICALISFRU:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IsFRU);
				break;
			case ENTPHYSICALMFGDATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MfgDate, table_entry->u16MfgDate_len);
				break;
			case ENTPHYSICALURIS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Uris, table_entry->u16Uris_len);
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
			table_entry = (entPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ENTPHYSICALSERIALNUM:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SerialNum));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ENTPHYSICALALIAS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Alias));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ENTPHYSICALASSETID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AssetID));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case ENTPHYSICALURIS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Uris));
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
			table_entry = (entPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (entPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case ENTPHYSICALSERIALNUM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SerialNum))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SerialNum_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SerialNum, sizeof (table_entry->au8SerialNum));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SerialNum, 0, sizeof (table_entry->au8SerialNum));
				memcpy (table_entry->au8SerialNum, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SerialNum_len = request->requestvb->val_len;
				break;
			case ENTPHYSICALALIAS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Alias))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Alias_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Alias, sizeof (table_entry->au8Alias));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Alias, 0, sizeof (table_entry->au8Alias));
				memcpy (table_entry->au8Alias, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Alias_len = request->requestvb->val_len;
				break;
			case ENTPHYSICALASSETID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8AssetID))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16AssetID_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8AssetID, sizeof (table_entry->au8AssetID));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AssetID, 0, sizeof (table_entry->au8AssetID));
				memcpy (table_entry->au8AssetID, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16AssetID_len = request->requestvb->val_len;
				break;
			case ENTPHYSICALURIS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Uris))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Uris_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Uris, sizeof (table_entry->au8Uris));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Uris, 0, sizeof (table_entry->au8Uris));
				memcpy (table_entry->au8Uris, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Uris_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (entPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTPHYSICALSERIALNUM:
				memcpy (table_entry->au8SerialNum, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SerialNum_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ENTPHYSICALALIAS:
				memcpy (table_entry->au8Alias, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Alias_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ENTPHYSICALASSETID:
				memcpy (table_entry->au8AssetID, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16AssetID_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case ENTPHYSICALURIS:
				memcpy (table_entry->au8Uris, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Uris_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize entLogicalTable table mapper **/
void
entLogicalTable_init (void)
{
	extern oid entLogicalTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"entLogicalTable", &entLogicalTable_mapper,
		entLogicalTable_oid, OID_LENGTH (entLogicalTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: entLogicalIndex */,
		0);
	table_info->min_column = ENTLOGICALDESCR;
	table_info->max_column = ENTLOGICALCONTEXTNAME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &entLogicalTable_getFirst;
	iinfo->get_next_data_point = &entLogicalTable_getNext;
	iinfo->get_data_point = &entLogicalTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
entLogicalTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register entLogicalEntry_t *pEntry1 = xBTree_entry (pNode1, entLogicalEntry_t, oBTreeNode);
	register entLogicalEntry_t *pEntry2 = xBTree_entry (pNode2, entLogicalEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Index < pEntry2->i32Index) ? -1:
		(pEntry1->i32Index == pEntry2->i32Index) ? 0: 1;
}

xBTree_t oEntLogicalTable_BTree = xBTree_initInline (&entLogicalTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entLogicalEntry_t *
entLogicalTable_createEntry (
	int32_t i32Index)
{
	entLogicalEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (entLogicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Index = i32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oEntLogicalTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oEntLogicalTable_BTree);
	return poEntry;
}

entLogicalEntry_t *
entLogicalTable_getByIndex (
	int32_t i32Index)
{
	register entLogicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entLogicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oEntLogicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entLogicalEntry_t, oBTreeNode);
}

entLogicalEntry_t *
entLogicalTable_getNextIndex (
	int32_t i32Index)
{
	register entLogicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entLogicalEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oEntLogicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entLogicalEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
entLogicalTable_removeEntry (entLogicalEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oEntLogicalTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oEntLogicalTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entLogicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oEntLogicalTable_BTree);
	return entLogicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entLogicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entLogicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, entLogicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oEntLogicalTable_BTree);
	return put_index_data;
}

bool
entLogicalTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entLogicalEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = entLogicalTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* entLogicalTable table mapper */
int
entLogicalTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	entLogicalEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (entLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTLOGICALDESCR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Descr, table_entry->u16Descr_len);
				break;
			case ENTLOGICALTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoType, table_entry->u16Type_len);
				break;
			case ENTLOGICALCOMMUNITY:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Community, table_entry->u16Community_len);
				break;
			case ENTLOGICALTADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TAddress, table_entry->u16TAddress_len);
				break;
			case ENTLOGICALTDOMAIN:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoTDomain, table_entry->u16TDomain_len);
				break;
			case ENTLOGICALCONTEXTENGINEID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ContextEngineID, table_entry->u16ContextEngineID_len);
				break;
			case ENTLOGICALCONTEXTNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ContextName, table_entry->u16ContextName_len);
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

/** initialize entLPMappingTable table mapper **/
void
entLPMappingTable_init (void)
{
	extern oid entLPMappingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"entLPMappingTable", &entLPMappingTable_mapper,
		entLPMappingTable_oid, OID_LENGTH (entLPMappingTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: entLogicalIndex */,
		ASN_INTEGER /* index: entLPPhysicalIndex */,
		0);
	table_info->min_column = ENTLPPHYSICALINDEX;
	table_info->max_column = ENTLPPHYSICALINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &entLPMappingTable_getFirst;
	iinfo->get_next_data_point = &entLPMappingTable_getNext;
	iinfo->get_data_point = &entLPMappingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
entLPMappingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register entLPMappingEntry_t *pEntry1 = xBTree_entry (pNode1, entLPMappingEntry_t, oBTreeNode);
	register entLPMappingEntry_t *pEntry2 = xBTree_entry (pNode2, entLPMappingEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32LogicalIndex < pEntry2->i32LogicalIndex) ||
		(pEntry1->i32LogicalIndex == pEntry2->i32LogicalIndex && pEntry1->i32LPPhysicalIndex < pEntry2->i32LPPhysicalIndex) ? -1:
		(pEntry1->i32LogicalIndex == pEntry2->i32LogicalIndex && pEntry1->i32LPPhysicalIndex == pEntry2->i32LPPhysicalIndex) ? 0: 1;
}

xBTree_t oEntLPMappingTable_BTree = xBTree_initInline (&entLPMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entLPMappingEntry_t *
entLPMappingTable_createEntry (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex)
{
	entLPMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (entLPMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32LogicalIndex = i32LogicalIndex;
	poEntry->i32LPPhysicalIndex = i32LPPhysicalIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oEntLPMappingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oEntLPMappingTable_BTree);
	return poEntry;
}

entLPMappingEntry_t *
entLPMappingTable_getByIndex (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex)
{
	register entLPMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entLPMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LogicalIndex = i32LogicalIndex;
	poTmpEntry->i32LPPhysicalIndex = i32LPPhysicalIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oEntLPMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entLPMappingEntry_t, oBTreeNode);
}

entLPMappingEntry_t *
entLPMappingTable_getNextIndex (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex)
{
	register entLPMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entLPMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LogicalIndex = i32LogicalIndex;
	poTmpEntry->i32LPPhysicalIndex = i32LPPhysicalIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oEntLPMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entLPMappingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
entLPMappingTable_removeEntry (entLPMappingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oEntLPMappingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oEntLPMappingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entLPMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oEntLPMappingTable_BTree);
	return entLPMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entLPMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entLPMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, entLPMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LogicalIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LPPhysicalIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oEntLPMappingTable_BTree);
	return put_index_data;
}

bool
entLPMappingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entLPMappingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = entLPMappingTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* entLPMappingTable table mapper */
int
entLPMappingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	entLPMappingEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (entLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTLPPHYSICALINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LPPhysicalIndex);
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

/** initialize entAliasMappingTable table mapper **/
void
entAliasMappingTable_init (void)
{
	extern oid entAliasMappingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"entAliasMappingTable", &entAliasMappingTable_mapper,
		entAliasMappingTable_oid, OID_LENGTH (entAliasMappingTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: entPhysicalIndex */,
		ASN_INTEGER /* index: entAliasLogicalIndexOrZero */,
		0);
	table_info->min_column = ENTALIASMAPPINGIDENTIFIER;
	table_info->max_column = ENTALIASMAPPINGIDENTIFIER;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &entAliasMappingTable_getFirst;
	iinfo->get_next_data_point = &entAliasMappingTable_getNext;
	iinfo->get_data_point = &entAliasMappingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
entAliasMappingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register entAliasMappingEntry_t *pEntry1 = xBTree_entry (pNode1, entAliasMappingEntry_t, oBTreeNode);
	register entAliasMappingEntry_t *pEntry2 = xBTree_entry (pNode2, entAliasMappingEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32PhysicalIndex < pEntry2->i32PhysicalIndex) ||
		(pEntry1->i32PhysicalIndex == pEntry2->i32PhysicalIndex && pEntry1->i32AliasLogicalIndexOrZero < pEntry2->i32AliasLogicalIndexOrZero) ? -1:
		(pEntry1->i32PhysicalIndex == pEntry2->i32PhysicalIndex && pEntry1->i32AliasLogicalIndexOrZero == pEntry2->i32AliasLogicalIndexOrZero) ? 0: 1;
}

xBTree_t oEntAliasMappingTable_BTree = xBTree_initInline (&entAliasMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entAliasMappingEntry_t *
entAliasMappingTable_createEntry (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero)
{
	entAliasMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (entAliasMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32PhysicalIndex = i32PhysicalIndex;
	poEntry->i32AliasLogicalIndexOrZero = i32AliasLogicalIndexOrZero;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oEntAliasMappingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oEntAliasMappingTable_BTree);
	return poEntry;
}

entAliasMappingEntry_t *
entAliasMappingTable_getByIndex (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero)
{
	register entAliasMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entAliasMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32PhysicalIndex = i32PhysicalIndex;
	poTmpEntry->i32AliasLogicalIndexOrZero = i32AliasLogicalIndexOrZero;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oEntAliasMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entAliasMappingEntry_t, oBTreeNode);
}

entAliasMappingEntry_t *
entAliasMappingTable_getNextIndex (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero)
{
	register entAliasMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entAliasMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32PhysicalIndex = i32PhysicalIndex;
	poTmpEntry->i32AliasLogicalIndexOrZero = i32AliasLogicalIndexOrZero;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oEntAliasMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entAliasMappingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
entAliasMappingTable_removeEntry (entAliasMappingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oEntAliasMappingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oEntAliasMappingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entAliasMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oEntAliasMappingTable_BTree);
	return entAliasMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entAliasMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entAliasMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, entAliasMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PhysicalIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32AliasLogicalIndexOrZero);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oEntAliasMappingTable_BTree);
	return put_index_data;
}

bool
entAliasMappingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entAliasMappingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = entAliasMappingTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* entAliasMappingTable table mapper */
int
entAliasMappingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	entAliasMappingEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (entAliasMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTALIASMAPPINGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoIdentifier, table_entry->u16Identifier_len);
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

/** initialize entPhysicalContainsTable table mapper **/
void
entPhysicalContainsTable_init (void)
{
	extern oid entPhysicalContainsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"entPhysicalContainsTable", &entPhysicalContainsTable_mapper,
		entPhysicalContainsTable_oid, OID_LENGTH (entPhysicalContainsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: entPhysicalIndex */,
		ASN_INTEGER /* index: entPhysicalChildIndex */,
		0);
	table_info->min_column = ENTPHYSICALCHILDINDEX;
	table_info->max_column = ENTPHYSICALCHILDINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &entPhysicalContainsTable_getFirst;
	iinfo->get_next_data_point = &entPhysicalContainsTable_getNext;
	iinfo->get_data_point = &entPhysicalContainsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
entPhysicalContainsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register entPhysicalContainsEntry_t *pEntry1 = xBTree_entry (pNode1, entPhysicalContainsEntry_t, oBTreeNode);
	register entPhysicalContainsEntry_t *pEntry2 = xBTree_entry (pNode2, entPhysicalContainsEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Index < pEntry2->i32Index) ||
		(pEntry1->i32Index == pEntry2->i32Index && pEntry1->i32ChildIndex < pEntry2->i32ChildIndex) ? -1:
		(pEntry1->i32Index == pEntry2->i32Index && pEntry1->i32ChildIndex == pEntry2->i32ChildIndex) ? 0: 1;
}

xBTree_t oEntPhysicalContainsTable_BTree = xBTree_initInline (&entPhysicalContainsTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entPhysicalContainsEntry_t *
entPhysicalContainsTable_createEntry (
	int32_t i32Index,
	int32_t i32ChildIndex)
{
	entPhysicalContainsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (entPhysicalContainsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Index = i32Index;
	poEntry->i32ChildIndex = i32ChildIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree);
	return poEntry;
}

entPhysicalContainsEntry_t *
entPhysicalContainsTable_getByIndex (
	int32_t i32Index,
	int32_t i32ChildIndex)
{
	register entPhysicalContainsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entPhysicalContainsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	poTmpEntry->i32ChildIndex = i32ChildIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entPhysicalContainsEntry_t, oBTreeNode);
}

entPhysicalContainsEntry_t *
entPhysicalContainsTable_getNextIndex (
	int32_t i32Index,
	int32_t i32ChildIndex)
{
	register entPhysicalContainsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (entPhysicalContainsEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Index = i32Index;
	poTmpEntry->i32ChildIndex = i32ChildIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, entPhysicalContainsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
entPhysicalContainsTable_removeEntry (entPhysicalContainsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entPhysicalContainsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oEntPhysicalContainsTable_BTree);
	return entPhysicalContainsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entPhysicalContainsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entPhysicalContainsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, entPhysicalContainsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32ChildIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oEntPhysicalContainsTable_BTree);
	return put_index_data;
}

bool
entPhysicalContainsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	entPhysicalContainsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = entPhysicalContainsTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* entPhysicalContainsTable table mapper */
int
entPhysicalContainsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	entPhysicalContainsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (entPhysicalContainsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case ENTPHYSICALCHILDINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ChildIndex);
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


/**
 *	notification mapper(s)
 */
int
entConfigChange_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid entConfigChange_oid[];
	netsnmp_variable_list *var_list = NULL;
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) entConfigChange_oid, sizeof (entConfigChange_oid));
		
		
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
