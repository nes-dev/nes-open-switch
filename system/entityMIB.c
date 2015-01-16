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
#include "system/systemMIB.h"
#include "if/ifMIB.h"
#include "entityMIB.h"
#include "systemUtils.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid entityMIB_oid[] = {1,3,6,1,2,1,47};
static oid neEntityMIB_oid[] = {1,3,6,1,4,1,36969,70};

static oid entityGeneral_oid[] = {1,3,6,1,2,1,47,1,4};

static oid entPhysicalTable_oid[] = {1,3,6,1,2,1,47,1,1,1};
static oid entLogicalTable_oid[] = {1,3,6,1,2,1,47,1,2,1};
static oid entLPMappingTable_oid[] = {1,3,6,1,2,1,47,1,3,1};
static oid entAliasMappingTable_oid[] = {1,3,6,1,2,1,47,1,3,2};
static oid entPhysicalContainsTable_oid[] = {1,3,6,1,2,1,47,1,3,3};
static oid neEntPhysicalTable_oid[] = {1,3,6,1,4,1,36969,70,1,1};
static oid neEntLogicalTable_oid[] = {1,3,6,1,4,1,36969,70,1,2};
static oid neEntLPMappingTable_oid[] = {1,3,6,1,4,1,36969,70,1,3};
static oid neEntPortTable_oid[] = {1,3,6,1,4,1,36969,70,1,4};
static oid neEntChassisPortTable_oid[] = {1,3,6,1,4,1,36969,70,1,5};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid entConfigChange_oid[] = {1,3,6,1,2,1,47,2,0,1};


#if 0
static bool entPhysicalTable_getChassis (
	uint32_t u32PhysicalIndex, uint32_t u32ContainedIn, int32_t i32Class,
	uint32_t *pu32ChassisIndex);
#endif


/**
 *	initialize entityMIB group mapper
 */
void
entityMIB_init (void)
{
	extern oid entityMIB_oid[];
	extern oid neEntityMIB_oid[];
	extern oid entityGeneral_oid[];
	
	DEBUGMSGTL (("entityMIB", "Initializing\n"));
	
	/* register entityGeneral scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"entityGeneral_mapper", &entityGeneral_mapper,
			entityGeneral_oid, OID_LENGTH (entityGeneral_oid),
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
	neEntPhysicalTable_init ();
	neEntLogicalTable_init ();
	neEntLPMappingTable_init ();
	neEntPortTable_init ();
	neEntChassisPortTable_init ();
	
	/* register entityMIB modules */
	sysORTable_createRegister ("entityMIB", entityMIB_oid, OID_LENGTH (entityMIB_oid));
	sysORTable_createRegister ("neEntityMIB", neEntityMIB_oid, OID_LENGTH (neEntityMIB_oid));
}


/**
 *	scalar mapper(s)
 */
entityGeneral_t oEntityGeneral =
{
	.oLock = xRwLock_initInline (),
};

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
		ASN_UNSIGNED /* index: entPhysicalIndex */,
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

/* create a new row in the (unsorted) table */
entPhysicalEntry_t *
entPhysicalTable_createEntry (
	uint32_t u32Index)
{
	register entPhysicalEntry_t *poEntry = NULL;
	register neEntPhysicalEntry_t *poPhysical = NULL;
	
	if ((poPhysical = neEntPhysicalTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poPhysical->oPhy;
	
	return poEntry;
}

entPhysicalEntry_t *
entPhysicalTable_getByIndex (
	uint32_t u32Index)
{
	register neEntPhysicalEntry_t *poPhysical = NULL;
	
	if ((poPhysical = neEntPhysicalTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poPhysical->oPhy;
}

entPhysicalEntry_t *
entPhysicalTable_getNextIndex (
	uint32_t u32Index)
{
	register neEntPhysicalEntry_t *poPhysical = NULL;
	
	if ((poPhysical = neEntPhysicalTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poPhysical->oPhy;
}

/* remove a row from the table */
void
entPhysicalTable_removeEntry (entPhysicalEntry_t *poEntry)
{
	return;
}

bool
entPhysicalTable_getChassis (
	uint32_t u32PhysicalIndex, uint32_t u32ContainedIn, int32_t i32Class,
	uint32_t *pu32ChassisIndex)
{
	xUnused (u32PhysicalIndex);
	
	if (i32Class == entPhysicalClass_stack_c ||
		i32Class == entPhysicalClass_chassis_c ||
		u32ContainedIn == 0)
	{
		return false;
	}
	
	register neEntPhysicalEntry_t *poContainer = NULL;
	
	while (
		u32ContainedIn != 0 &&
		(poContainer = neEntPhysicalTable_getByIndex (u32ContainedIn)) != NULL &&
		poContainer->oPhy.i32Class != entPhysicalClass_chassis_c)
	{
		u32ContainedIn = poContainer->oPhy.u32ContainedIn;
	}
	
	if (poContainer == NULL || poContainer->oPhy.i32Class != entPhysicalClass_chassis_c)
	{
		return false;
	}
	
	*pu32ChassisIndex = poContainer->u32Index;
	return true;
}

bool
entPhysicalTable_createEntity (
	uint32_t u32Index,
	entPhysicalEntry_t *poInEntry)
{
	register bool bRetCode = false;
	register neEntPhysicalEntry_t *poEntry = NULL;
	
	xRwLock_wrLock (&oEntityGeneral.oLock);
	
	if ((poEntry = neEntPhysicalTable_getByIndex (u32Index)) != NULL)
	{
		if (poInEntry->i32Class != 0 && poEntry->oPhy.i32Class != 0 && poEntry->oPhy.i32Class != poInEntry->i32Class)
		{
			goto entPhysicalTable_createEntity_cleanup;
		}
	}
	else
	{
		if ((poEntry = neEntPhysicalTable_createExt (u32Index)) == NULL)
		{
			goto entPhysicalTable_createEntity_cleanup;
		}
// 		memcpy (poEntry, poInEntry, sizeof (*poEntry));	/* TODO */
	}
	
	poInEntry->i32Class != 0 ? (poEntry->i32Class = poInEntry->i32Class): false;
	poInEntry->u32ContainedIn != 0 ? (poEntry->u32ContainedIn = poInEntry->u32ContainedIn): false;
	poInEntry->i32ParentRelPos != 0 ? (poEntry->i32ParentRelPos = poInEntry->i32ParentRelPos): false;
	if (poInEntry->au8MfgName[0] != 0 && poInEntry->u16MfgName_len != 0)
	{
		memcpy (poEntry->au8MfgName, poInEntry->au8MfgName, poInEntry->u16MfgName_len);
		poEntry->u16MfgName_len = poInEntry->u16MfgName_len;
	}
	if (poInEntry->au8SerialNum[0] != 0 && poInEntry->u16SerialNum_len != 0)
	{
		memcpy (poEntry->au8SerialNum, poInEntry->au8SerialNum, poInEntry->u16SerialNum_len);
		poEntry->u16SerialNum_len = poInEntry->u16SerialNum_len;
	}
	
	if (!neEntPhysicalRowStatus_handler (poEntry, xRowStatus_active_c))
	{
		goto entPhysicalTable_createEntity_cleanup;
	}
	
	bRetCode = true;
	
entPhysicalTable_createEntity_cleanup:
	
	xRwLock_unlock (&oEntityGeneral.oLock);
	!bRetCode ? entPhysicalTable_removeEntity (u32Index): false;
	
	return bRetCode;
}

bool
entPhysicalTable_removeEntity (
	uint32_t u32Index)
{
	register bool bRetCode = false;
	register neEntPhysicalEntry_t *poEntry = NULL;
	
	xRwLock_wrLock (&oEntityGeneral.oLock);
	
	if ((poEntry = neEntPhysicalTable_getByIndex (u32Index)) != NULL)
	{
		goto entPhysicalTable_removeEntity_cleanup;
	}
	
	if (!neEntPhysicalRowStatus_handler (poEntry, xRowStatus_destroy_c))
	{
		goto entPhysicalTable_removeEntity_cleanup;
	}
	neEntPhysicalTable_removeEntry (poEntry);
	
	bRetCode = true;
	
entPhysicalTable_removeEntity_cleanup:
	
	xRwLock_unlock (&oEntityGeneral.oLock);
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entPhysicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntPhysicalTable_BTree);
	return entPhysicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entPhysicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPhysicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntPhysicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) &poEntry->oPhy;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree);
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
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ContainedIn);
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
		ASN_UNSIGNED /* index: entLogicalIndex */,
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

/* create a new row in the (unsorted) table */
entLogicalEntry_t *
entLogicalTable_createEntry (
	uint32_t u32Index)
{
	register entLogicalEntry_t *poEntry = NULL;
	register neEntLogicalEntry_t *poLogical = NULL;
	
	if ((poLogical = neEntLogicalTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poLogical->oLog;
	
	return poEntry;
}

entLogicalEntry_t *
entLogicalTable_getByIndex (
	uint32_t u32Index)
{
	register neEntLogicalEntry_t *poLogical = NULL;
	
	if ((poLogical = neEntLogicalTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poLogical->oLog;
}

entLogicalEntry_t *
entLogicalTable_getNextIndex (
	uint32_t u32Index)
{
	register neEntLogicalEntry_t *poLogical = NULL;
	
	if ((poLogical = neEntLogicalTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poLogical->oLog;
}

/* remove a row from the table */
void
entLogicalTable_removeEntry (entLogicalEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entLogicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntLogicalTable_BTree);
	return entLogicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entLogicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLogicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntLogicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree);
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
		ASN_UNSIGNED /* index: entLogicalIndex */,
		ASN_UNSIGNED /* index: entLPPhysicalIndex */,
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

/* create a new row in the (unsorted) table */
entLPMappingEntry_t *
entLPMappingTable_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register entLPMappingEntry_t *poEntry = NULL;
	register neEntLPMappingEntry_t *poLPMapping = NULL;
	
	if ((poLPMapping = neEntLPMappingTable_getByIndex (u32LogicalIndex, u32PhysicalIndex)) == NULL)
	{
		return NULL;
	}
	poEntry = &poLPMapping->oLp;
	
	return poEntry;
}

entLPMappingEntry_t *
entLPMappingTable_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register neEntLPMappingEntry_t *poLPMapping = NULL;
	
	if ((poLPMapping = neEntLPMappingTable_getByIndex (u32LogicalIndex, u32PhysicalIndex)) == NULL)
	{
		return NULL;
	}
	
	return &poLPMapping->oLp;
}

entLPMappingEntry_t *
entLPMappingTable_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register neEntLPMappingEntry_t *poLPMapping = NULL;
	
	if ((poLPMapping = neEntLPMappingTable_getNextIndex (u32LogicalIndex, u32PhysicalIndex)) == NULL)
	{
		return NULL;
	}
	
	return &poLPMapping->oLp;
}

/* remove a row from the table */
void
entLPMappingTable_removeEntry (entLPMappingEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
entLPMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntLPMappingTable_BTree);
	return entLPMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
entLPMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLPMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntLPMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LogicalIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PhysicalIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree);
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
			
			register neEntLPMappingEntry_t *poLPMapping = neEntLPMappingTable_getByLpEntry (table_entry);
			
			switch (table_info->colnum)
			{
			case ENTLPPHYSICALINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, poLPMapping->u32PhysicalIndex);
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
		ASN_UNSIGNED /* index: entPhysicalIndex */,
		ASN_UNSIGNED /* index: entAliasLogicalIndexOrZero */,
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
		(pEntry1->u32PhysicalIndex < pEntry2->u32PhysicalIndex) ||
		(pEntry1->u32PhysicalIndex == pEntry2->u32PhysicalIndex && pEntry1->u32LogicalIndexOrZero < pEntry2->u32LogicalIndexOrZero) ? -1:
		(pEntry1->u32PhysicalIndex == pEntry2->u32PhysicalIndex && pEntry1->u32LogicalIndexOrZero == pEntry2->u32LogicalIndexOrZero) ? 0: 1;
}

xBTree_t oEntAliasMappingTable_BTree = xBTree_initInline (&entAliasMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entAliasMappingEntry_t *
entAliasMappingTable_createEntry (
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero)
{
	register entAliasMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32PhysicalIndex = u32PhysicalIndex;
	poEntry->u32LogicalIndexOrZero = u32LogicalIndexOrZero;
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
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero)
{
	register entAliasMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	poTmpEntry->u32LogicalIndexOrZero = u32LogicalIndexOrZero;
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
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero)
{
	register entAliasMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	poTmpEntry->u32LogicalIndexOrZero = u32LogicalIndexOrZero;
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
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PhysicalIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LogicalIndexOrZero);
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
		ASN_UNSIGNED /* index: entPhysicalIndex */,
		ASN_UNSIGNED /* index: entPhysicalChildIndex */,
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
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32ChildIndex < pEntry2->u32ChildIndex) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32ChildIndex == pEntry2->u32ChildIndex) ? 0: 1;
}

xBTree_t oEntPhysicalContainsTable_BTree = xBTree_initInline (&entPhysicalContainsTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
entPhysicalContainsEntry_t *
entPhysicalContainsTable_createEntry (
	uint32_t u32Index,
	uint32_t u32ChildIndex)
{
	register entPhysicalContainsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->u32ChildIndex = u32ChildIndex;
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
	uint32_t u32Index,
	uint32_t u32ChildIndex)
{
	register entPhysicalContainsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32ChildIndex = u32ChildIndex;
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
	uint32_t u32Index,
	uint32_t u32ChildIndex)
{
	register entPhysicalContainsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32ChildIndex = u32ChildIndex;
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
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ChildIndex);
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
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ChildIndex);
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

/** initialize neEntPhysicalTable table mapper **/
void
neEntPhysicalTable_init (void)
{
	extern oid neEntPhysicalTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neEntPhysicalTable", &neEntPhysicalTable_mapper,
		neEntPhysicalTable_oid, OID_LENGTH (neEntPhysicalTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: entPhysicalIndex */,
		0);
	table_info->min_column = NEENTPHYSICALCONTAINEDIN;
	table_info->max_column = NEENTPHYSICALSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neEntPhysicalTable_getFirst;
	iinfo->get_next_data_point = &neEntPhysicalTable_getNext;
	iinfo->get_data_point = &neEntPhysicalTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neEntPhysicalTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntPhysicalEntry_t *pEntry1 = xBTree_entry (pNode1, neEntPhysicalEntry_t, oBTreeNode);
	register neEntPhysicalEntry_t *pEntry2 = xBTree_entry (pNode2, neEntPhysicalEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static int8_t
neEntPhysicalTable_SerialNum_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntPhysicalEntry_t *pEntry1 = xBTree_entry (pNode1, neEntPhysicalEntry_t, oBTreeNode);
	register neEntPhysicalEntry_t *pEntry2 = xBTree_entry (pNode2, neEntPhysicalEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8MfgName, pEntry2->au8MfgName, pEntry1->u16MfgName_len, pEntry2->u16MfgName_len) == -1) ||
		(xBinCmp (pEntry1->au8MfgName, pEntry2->au8MfgName, pEntry1->u16MfgName_len, pEntry2->u16MfgName_len) == 0 && xBinCmp (pEntry1->au8SerialNum, pEntry2->au8SerialNum, pEntry1->u16SerialNum_len, pEntry2->u16SerialNum_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8MfgName, pEntry2->au8MfgName, pEntry1->u16MfgName_len, pEntry2->u16MfgName_len) == 0 && xBinCmp (pEntry1->au8SerialNum, pEntry2->au8SerialNum, pEntry1->u16SerialNum_len, pEntry2->u16SerialNum_len) == 0) ? 0: 1;
}

xBTree_t oNeEntPhysicalTable_BTree = xBTree_initInline (&neEntPhysicalTable_BTreeNodeCmp);
xBTree_t oNeEntPhysicalTable_SerialNum_BTree = xBTree_initInline (&neEntPhysicalTable_SerialNum_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
neEntPhysicalEntry_t *
neEntPhysicalTable_createEntry (
	uint32_t u32Index)
{
	register neEntPhysicalEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neEntPhysicalStorageType_nonVolatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree);
	return poEntry;
}

bool
neEntPhysicalTable_linkSerialNum (neEntPhysicalEntry_t *poEntry)
{
	register neEntPhysicalEntry_t *poTmpEntry = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return false;
	}
	
	memcpy (poTmpEntry->au8MfgName, poEntry->au8MfgName, poEntry->u16MfgName_len);
	poTmpEntry->u16MfgName_len = poEntry->u16MfgName_len;
	memcpy (poTmpEntry->au8SerialNum, poEntry->au8SerialNum, poEntry->u16SerialNum_len);
	poTmpEntry->u16SerialNum_len = poEntry->u16SerialNum_len;
	if (xBTree_nodeFind (&poTmpEntry->oSerialNum_BTreeNode, &oNeEntPhysicalTable_SerialNum_BTree) != NULL)
	{
		xBuffer_free (poTmpEntry);
		return false;
	}
	xBuffer_free (poTmpEntry);
	
	xBTree_nodeAdd (&poEntry->oSerialNum_BTreeNode, &oNeEntPhysicalTable_SerialNum_BTree);
	return true;
}

neEntPhysicalEntry_t *
neEntPhysicalTable_getByIndex (
	uint32_t u32Index)
{
	register neEntPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeEntPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntPhysicalEntry_t, oBTreeNode);
}

neEntPhysicalEntry_t *
neEntPhysicalTable_getBySerialNum (
	uint8_t *pu8MfgName, size_t u16MfgName_len,
	uint8_t *pu8SerialNum, size_t u16SerialNum_len)
{
	register neEntPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8MfgName, pu8MfgName, u16MfgName_len);
	poTmpEntry->u16MfgName_len = u16MfgName_len;
	memcpy (poTmpEntry->au8SerialNum, pu8SerialNum, u16SerialNum_len);
	poTmpEntry->u16SerialNum_len = u16SerialNum_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oSerialNum_BTreeNode, &oNeEntPhysicalTable_SerialNum_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntPhysicalEntry_t, oSerialNum_BTreeNode);
}

neEntPhysicalEntry_t *
neEntPhysicalTable_getNextIndex (
	uint32_t u32Index)
{
	register neEntPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeEntPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntPhysicalEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neEntPhysicalTable_removeEntry (neEntPhysicalEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree);
	xBTree_nodeRemove (&poEntry->oSerialNum_BTreeNode, &oNeEntPhysicalTable_SerialNum_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

neEntPhysicalEntry_t *
neEntPhysicalTable_createExt (
	uint32_t u32Index)
{
	neEntPhysicalEntry_t *poEntry = NULL;
	
	poEntry = neEntPhysicalTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto neEntPhysicalTable_createExt_cleanup;
	}
	
	if (!neEntPhysicalTable_createHier (poEntry))
	{
		neEntPhysicalTable_removeEntry (poEntry);
		poEntry = NULL;
		goto neEntPhysicalTable_createExt_cleanup;
	}
	
	oEntityGeneral.u32LastChangeTime++;	/* TODO */
	
neEntPhysicalTable_createExt_cleanup:
	
	return poEntry;
}

bool
neEntPhysicalTable_removeExt (neEntPhysicalEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!neEntPhysicalTable_removeHier (poEntry))
	{
		goto neEntPhysicalTable_removeExt_cleanup;
	}
	neEntPhysicalTable_removeEntry (poEntry);
	
	oEntityGeneral.u32LastChangeTime--;	/* TODO */
	bRetCode = true;
	
neEntPhysicalTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
neEntPhysicalTable_createHier (
	neEntPhysicalEntry_t *poEntry)
{
	if (entPhysicalTable_getByIndex (poEntry->u32Index) == NULL &&
		entPhysicalTable_createEntry (poEntry->u32Index) == NULL)
	{
		goto neEntPhysicalTable_createHier_cleanup;
	}
	
	return true;
	
	
neEntPhysicalTable_createHier_cleanup:
	
	neEntPhysicalTable_removeHier (poEntry);
	return false;
}

bool
neEntPhysicalTable_removeHier (
	neEntPhysicalEntry_t *poEntry)
{
	register entPhysicalEntry_t *poEntPhysicalEntry = NULL;
	
	if ((poEntPhysicalEntry = entPhysicalTable_getByIndex (poEntry->u32Index)) != NULL)
	{
		entPhysicalTable_removeEntry (poEntPhysicalEntry);
	}
	
	return true;
}

bool
neEntPhysicalRowStatus_handler (
	neEntPhysicalEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (poEntry->u8RowStatus == xRowStatus_active_c)
		{
			break;
		}
		
		if (poEntry->pOldEntry != NULL)
		{
			if (poEntry->pOldEntry->i32Class == neEntPhysicalClass_port_c && poEntry->pOldEntry->i32Class != poEntry->i32Class)
			{
				register neEntPortEntry_t *poNeEntPortEntry = NULL;
				
				if ((poNeEntPortEntry = neEntPortTable_getByIndex (poEntry->u32Index)) != NULL &&
					!neEntPortRowStatus_handler (poNeEntPortEntry, xRowStatus_destroy_c | xRowStatus_fromParent_c))
				{
					goto neEntPhysicalRowStatus_handler_cleanup;
				}
				
				if (poNeEntPortEntry != NULL)
				{
					neEntPortTable_removeEntry (poNeEntPortEntry);
				}
			}
			
			if (poEntry->pOldEntry->u32ContainedIn != 0 && poEntry->pOldEntry->u32ContainedIn != poEntry->u32ContainedIn)
			{
				if (poEntry->pOldEntry->i32Class == neEntPhysicalClass_port_c)
				{
					register neEntChassisPortEntry_t *poNeEntChassisPortEntry = NULL;
					
					if ((poNeEntChassisPortEntry = neEntChassisPortTable_getByIndex (poEntry->pOldEntry->u32ChassisIndex, poEntry->u32Index)) != NULL)
					{
						neEntChassisPortTable_removeEntry (poNeEntChassisPortEntry);
					}
				}
				
				register entPhysicalContainsEntry_t *poEntPhysicalContainsEntry = NULL;
				
				if ((poEntPhysicalContainsEntry = entPhysicalContainsTable_getByIndex (poEntry->pOldEntry->u32ContainedIn, poEntry->u32Index)) != NULL)
				{
					entPhysicalContainsTable_removeEntry (poEntPhysicalContainsEntry);
				}
			}
		}
		
		if (poEntry->u32ContainedIn != 0 &&
			entPhysicalContainsTable_createEntry (poEntry->u32ContainedIn, poEntry->u32Index) == NULL)
		{
			goto neEntPhysicalRowStatus_handler_cleanup;
		}
		
		if (poEntry->i32Class == neEntPhysicalClass_port_c && poEntry->u32ContainedIn != 0)
		{
			uint32_t u32ChassisIndex = 0;
			
			if (entPhysicalTable_getChassis (poEntry->u32Index, poEntry->u32ContainedIn, poEntry->i32Class, &u32ChassisIndex) &&
				neEntChassisPortTable_createEntry (u32ChassisIndex, poEntry->u32Index) == NULL)
			{
				goto neEntPhysicalRowStatus_handler_cleanup;
			}
			poEntry->u32ChassisIndex = u32ChassisIndex;
		}
		
		if (poEntry->i32Class == neEntPhysicalClass_port_c)
		{
			register neEntPortEntry_t *poNeEntPortEntry = NULL;
			
			if ((poNeEntPortEntry = neEntPortTable_getByIndex (poEntry->u32Index)) != NULL &&
				!neEntPortRowStatus_handler (poNeEntPortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto neEntPhysicalRowStatus_handler_cleanup;
			}
			
			if (poNeEntPortEntry == NULL &&
				neEntPortTable_createEntry (poEntry->u32Index) == NULL)
			{
				goto neEntPhysicalRowStatus_handler_cleanup;
			}
		}
		
		/* TODO */
		poEntry->oPhy.u32ContainedIn = poEntry->u32ContainedIn;
		poEntry->oPhy.i32Class = poEntry->i32Class;
		
		poEntry->u8RowStatus = xRowStatus_active_c;
		
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
		
	case xRowStatus_notInService_c:
		if (poEntry->u8RowStatus == xRowStatus_notInService_c)
		{
			break;
		}
		
		if (poEntry->pOldEntry == NULL &&
			(poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
		{
			goto neEntPhysicalRowStatus_handler_cleanup;
		}
		
		if (poEntry->i32Class == neEntPhysicalClass_port_c)
		{
			register neEntPortEntry_t *poNeEntPortEntry = NULL;
			
			if ((poNeEntPortEntry = neEntPortTable_getByIndex (poEntry->u32Index)) != NULL &&
				!neEntPortRowStatus_handler (poNeEntPortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto neEntPhysicalRowStatus_handler_cleanup;
			}
		}
		
		/* TODO */
		
		memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		poEntry->u8RowStatus = xRowStatus_notReady_c;
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (poEntry->i32Class == neEntPhysicalClass_port_c)
		{
			register neEntPortEntry_t *poNeEntPortEntry = NULL;
			
			if ((poNeEntPortEntry = neEntPortTable_getByIndex (poEntry->u32Index)) != NULL &&
				!neEntPortRowStatus_handler (poNeEntPortEntry, u8RowStatus | xRowStatus_fromParent_c))
			{
				goto neEntPhysicalRowStatus_handler_cleanup;
			}
			
			if (poNeEntPortEntry != NULL)
			{
				neEntPortTable_removeEntry (poNeEntPortEntry);
			}
		}
		
		if (poEntry->i32Class == neEntPhysicalClass_port_c && poEntry->u32ContainedIn != 0)
		{
			register neEntChassisPortEntry_t *poNeEntChassisPortEntry = NULL;
			
			if (poEntry->u32ChassisIndex != 0 &&
				(poNeEntChassisPortEntry = neEntChassisPortTable_getByIndex (poEntry->u32ChassisIndex, poEntry->u32Index)) != NULL)
			{
				neEntChassisPortTable_removeEntry (poNeEntChassisPortEntry);
			}
		}
		
		if (poEntry->u32ContainedIn != 0)
		{
			register entPhysicalContainsEntry_t *poEntPhysicalContainsEntry = NULL;
			
			if ((poEntPhysicalContainsEntry = entPhysicalContainsTable_getByIndex (poEntry->u32ContainedIn, poEntry->u32Index)) != NULL)
			{
				entPhysicalContainsTable_removeEntry (poEntPhysicalContainsEntry);
			}
		}
		
		/* TODO */
		
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
// neEntPhysicalRowStatus_handler_success:
	
	return true;
	
	
neEntPhysicalRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neEntPhysicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntPhysicalTable_BTree);
	return neEntPhysicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neEntPhysicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPhysicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntPhysicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntPhysicalTable_BTree);
	return put_index_data;
}

bool
neEntPhysicalTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPhysicalEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neEntPhysicalTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neEntPhysicalTable table mapper */
int
neEntPhysicalTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neEntPhysicalEntry_t *table_entry;
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALCONTAINEDIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ContainedIn);
				break;
			case NEENTPHYSICALCLASS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Class);
				break;
			case NEENTPHYSICALPARENTRELPOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ParentRelPos);
				break;
			case NEENTPHYSICALROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEENTPHYSICALSTORAGETYPE:
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALCONTAINEDIN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPHYSICALCLASS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPHYSICALPARENTRELPOS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPHYSICALROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPHYSICALSTORAGETYPE:
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neEntPhysicalTable_createExt (
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntPhysicalTable_removeExt (table_entry);
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALCONTAINEDIN:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ContainedIn))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ContainedIn, sizeof (table_entry->u32ContainedIn));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ContainedIn = *request->requestvb->val.integer;
				break;
			case NEENTPHYSICALCLASS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Class))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Class, sizeof (table_entry->i32Class));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Class = *request->requestvb->val.integer;
				break;
			case NEENTPHYSICALPARENTRELPOS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ParentRelPos))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ParentRelPos, sizeof (table_entry->i32ParentRelPos));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ParentRelPos = *request->requestvb->val.integer;
				break;
			case NEENTPHYSICALSTORAGETYPE:
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neEntPhysicalRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALCONTAINEDIN:
				memcpy (&table_entry->u32ContainedIn, pvOldDdata, sizeof (table_entry->u32ContainedIn));
				break;
			case NEENTPHYSICALCLASS:
				memcpy (&table_entry->i32Class, pvOldDdata, sizeof (table_entry->i32Class));
				break;
			case NEENTPHYSICALPARENTRELPOS:
				memcpy (&table_entry->i32ParentRelPos, pvOldDdata, sizeof (table_entry->i32ParentRelPos));
				break;
			case NEENTPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntPhysicalTable_removeExt (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEENTPHYSICALSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neEntPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPHYSICALROWSTATUS:
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
					neEntPhysicalTable_removeExt (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neEntLogicalTable table mapper **/
void
neEntLogicalTable_init (void)
{
	extern oid neEntLogicalTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neEntLogicalTable", &neEntLogicalTable_mapper,
		neEntLogicalTable_oid, OID_LENGTH (neEntLogicalTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: entLogicalIndex */,
		0);
	table_info->min_column = NEENTLOGICALROWSTATUS;
	table_info->max_column = NEENTLOGICALSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neEntLogicalTable_getFirst;
	iinfo->get_next_data_point = &neEntLogicalTable_getNext;
	iinfo->get_data_point = &neEntLogicalTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neEntLogicalTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntLogicalEntry_t *pEntry1 = xBTree_entry (pNode1, neEntLogicalEntry_t, oBTreeNode);
	register neEntLogicalEntry_t *pEntry2 = xBTree_entry (pNode2, neEntLogicalEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oNeEntLogicalTable_BTree = xBTree_initInline (&neEntLogicalTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
neEntLogicalEntry_t *
neEntLogicalTable_createEntry (
	uint32_t u32Index)
{
	register neEntLogicalEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neEntLogicalStorageType_nonVolatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree);
	return poEntry;
}

neEntLogicalEntry_t *
neEntLogicalTable_getByIndex (
	uint32_t u32Index)
{
	register neEntLogicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeEntLogicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntLogicalEntry_t, oBTreeNode);
}

neEntLogicalEntry_t *
neEntLogicalTable_getNextIndex (
	uint32_t u32Index)
{
	register neEntLogicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeEntLogicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntLogicalEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neEntLogicalTable_removeEntry (neEntLogicalEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neEntLogicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntLogicalTable_BTree);
	return neEntLogicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neEntLogicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLogicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntLogicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntLogicalTable_BTree);
	return put_index_data;
}

bool
neEntLogicalTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLogicalEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neEntLogicalTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neEntLogicalTable table mapper */
int
neEntLogicalTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neEntLogicalEntry_t *table_entry;
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEENTLOGICALSTORAGETYPE:
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTLOGICALSTORAGETYPE:
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neEntLogicalTable_createEntry (
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntLogicalTable_removeEntry (table_entry);
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALSTORAGETYPE:
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neEntLogicalTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntLogicalTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEENTLOGICALSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neEntLogicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLOGICALROWSTATUS:
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
					neEntLogicalTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neEntLPMappingTable table mapper **/
void
neEntLPMappingTable_init (void)
{
	extern oid neEntLPMappingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neEntLPMappingTable", &neEntLPMappingTable_mapper,
		neEntLPMappingTable_oid, OID_LENGTH (neEntLPMappingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: entLogicalIndex */,
		ASN_UNSIGNED /* index: entLPPhysicalIndex */,
		0);
	table_info->min_column = NEENTLPMAPPINGROWSTATUS;
	table_info->max_column = NEENTLPMAPPINGSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neEntLPMappingTable_getFirst;
	iinfo->get_next_data_point = &neEntLPMappingTable_getNext;
	iinfo->get_data_point = &neEntLPMappingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neEntLPMappingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntLPMappingEntry_t *pEntry1 = xBTree_entry (pNode1, neEntLPMappingEntry_t, oBTreeNode);
	register neEntLPMappingEntry_t *pEntry2 = xBTree_entry (pNode2, neEntLPMappingEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32LogicalIndex < pEntry2->u32LogicalIndex) ||
		(pEntry1->u32LogicalIndex == pEntry2->u32LogicalIndex && pEntry1->u32PhysicalIndex < pEntry2->u32PhysicalIndex) ? -1:
		(pEntry1->u32LogicalIndex == pEntry2->u32LogicalIndex && pEntry1->u32PhysicalIndex == pEntry2->u32PhysicalIndex) ? 0: 1;
}

xBTree_t oNeEntLPMappingTable_BTree = xBTree_initInline (&neEntLPMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
neEntLPMappingEntry_t *
neEntLPMappingTable_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register neEntLPMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32LogicalIndex = u32LogicalIndex;
	poEntry->u32PhysicalIndex = u32PhysicalIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neEntLPMappingStorageType_nonVolatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree);
	return poEntry;
}

neEntLPMappingEntry_t *
neEntLPMappingTable_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register neEntLPMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LogicalIndex = u32LogicalIndex;
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeEntLPMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntLPMappingEntry_t, oBTreeNode);
}

neEntLPMappingEntry_t *
neEntLPMappingTable_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex)
{
	register neEntLPMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LogicalIndex = u32LogicalIndex;
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeEntLPMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntLPMappingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neEntLPMappingTable_removeEntry (neEntLPMappingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neEntLPMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntLPMappingTable_BTree);
	return neEntLPMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neEntLPMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLPMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntLPMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LogicalIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PhysicalIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntLPMappingTable_BTree);
	return put_index_data;
}

bool
neEntLPMappingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntLPMappingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neEntLPMappingTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neEntLPMappingTable table mapper */
int
neEntLPMappingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neEntLPMappingEntry_t *table_entry;
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEENTLPMAPPINGSTORAGETYPE:
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTLPMAPPINGSTORAGETYPE:
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neEntLPMappingTable_createEntry (
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntLPMappingTable_removeEntry (table_entry);
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGSTORAGETYPE:
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neEntLPMappingTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntLPMappingTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEENTLPMAPPINGSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neEntLPMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTLPMAPPINGROWSTATUS:
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
					neEntLPMappingTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neEntPortTable table mapper **/
void
neEntPortTable_init (void)
{
	extern oid neEntPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neEntPortTable", &neEntPortTable_mapper,
		neEntPortTable_oid, OID_LENGTH (neEntPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: entPhysicalIndex */,
		0);
	table_info->min_column = NEENTPORTCHASSISINDEX;
	table_info->max_column = NEENTPORTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neEntPortTable_getFirst;
	iinfo->get_next_data_point = &neEntPortTable_getNext;
	iinfo->get_data_point = &neEntPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neEntPortData_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntPortData_t *pEntry1 = xBTree_entry (pNode1, neEntPortData_t, oBTreeNode);
	register neEntPortData_t *pEntry2 = xBTree_entry (pNode2, neEntPortData_t, oBTreeNode);
	
	return
		(pEntry1->u32PhysicalIndex < pEntry2->u32PhysicalIndex) ? -1:
		(pEntry1->u32PhysicalIndex == pEntry2->u32PhysicalIndex) ? 0: 1;
}

static int8_t
neEntPortData_If_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntPortData_t *pEntry1 = xBTree_entry (pNode1, neEntPortData_t, oBTreeNode);
	register neEntPortData_t *pEntry2 = xBTree_entry (pNode2, neEntPortData_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

static int8_t
neEntPortData_Map_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neEntPortData_t *pEntry1 = xBTree_entry (pNode1, neEntPortData_t, oBTreeNode);
	register neEntPortData_t *pEntry2 = xBTree_entry (pNode2, neEntPortData_t, oBTreeNode);
	
	return
		(pEntry1->u32ChassisIndex < pEntry2->u32ChassisIndex) ||
		(pEntry1->u32ChassisIndex == pEntry2->u32ChassisIndex && pEntry1->u32PortIndex < pEntry2->u32PortIndex) ? -1:
		(pEntry1->u32ChassisIndex == pEntry2->u32ChassisIndex && pEntry1->u32PortIndex == pEntry2->u32PortIndex) ? 0: 1;
}

static xBTree_t oNeEntPortData_BTree = xBTree_initInline (&neEntPortData_BTreeNodeCmp);
static xBTree_t oNeEntPortData_If_BTree = xBTree_initInline (&neEntPortData_If_BTreeNodeCmp);
static xBTree_t oNeEntPortData_Map_BTree = xBTree_initInline (&neEntPortData_Map_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
neEntPortData_t *
neEntPortData_createEntry (
	uint32_t u32PhysicalIndex)
{
	register neEntPortData_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32PhysicalIndex = u32PhysicalIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntPortData_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32ChassisIndex = 0;
	poEntry->u32PortIndex = 0;
	poEntry->u32IfIndex = 0;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeEntPortData_BTree);
	return poEntry;
}

neEntPortData_t *
neEntPortData_getByIndex (
	uint32_t u32PhysicalIndex)
{
	register neEntPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeEntPortData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntPortData_t, oBTreeNode);
}

neEntPortData_t *
neEntPortData_getNextIndex (
	uint32_t u32PhysicalIndex)
{
	register neEntPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeEntPortData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neEntPortData_t, oBTreeNode);
}

/* remove a row from the table */
void
neEntPortData_removeEntry (neEntPortData_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeEntPortData_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeEntPortData_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* create a new row in the (unsorted) table */
neEntPortEntry_t *
neEntPortTable_createEntry (
	uint32_t u32PhysicalIndex)
{
	register neEntPortEntry_t *poEntry = NULL;
	register neEntPortData_t *poNeEntPort = NULL;
	
	if ((poNeEntPort = neEntPortData_createEntry (u32PhysicalIndex)) == NULL)
	{
		return NULL;
	}
	poEntry = &poNeEntPort->oPort;
	
	poEntry->u32ChassisIndex = 0;
	poEntry->u32PortIndex = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBitmap_setBit (poNeEntPort->au8Flags, neEntPortFlags_portCreated_c, 1); 
	return poEntry;
}

neEntPortEntry_t *
neEntPortTable_getByIndex (
	uint32_t u32PhysicalIndex)
{
	register neEntPortData_t *poNeEntPort = NULL;
	
	if ((poNeEntPort = neEntPortData_getByIndex (u32PhysicalIndex)) == NULL ||
		!xBitmap_getBit (poNeEntPort->au8Flags, neEntPortFlags_portCreated_c))
	{
		return NULL;
	}
	
	return &poNeEntPort->oPort;
}

neEntPortEntry_t *
neEntPortTable_getNextIndex (
	uint32_t u32PhysicalIndex)
{
	register neEntPortData_t *poNeEntPort = NULL;
	
	if ((poNeEntPort = neEntPortData_getNextIndex (u32PhysicalIndex)) == NULL ||
		!xBitmap_getBit (poNeEntPort->au8Flags, neEntPortFlags_portCreated_c))
	{
		return NULL;
	}
	
	return &poNeEntPort->oPort;
}

/* remove a row from the table */
void
neEntPortTable_removeEntry (neEntPortEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	neEntPortData_removeEntry (neEntPortData_getByPortEntry (poEntry));
	return;
}

bool
neEntPortRowStatus_handler (
	neEntPortEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
	case xRowStatus_active_c | xRowStatus_fromParent_c:
	{
		if (poEntry->u8RowStatus == xRowStatus_active_c || u8RowStatus & xRowStatus_fromParent_c)
		{
			goto neEntPortRowStatus_handler_success;
		}
		if (poEntry->u32IfIndex == 0)
		{
			if (u8RowStatus & xRowStatus_fromParent_c)
			{
				goto neEntPortRowStatus_handler_success;
			}
			else
			{
				goto neEntPortRowStatus_handler_cleanup;
			}
		}
		
		if (poEntry->pOldEntry != NULL &&
			poEntry->pOldEntry->u32IfIndex != 0 && poEntry->pOldEntry->u32IfIndex != poEntry->u32IfIndex)
		{
			if (!neEntPortRowStatus_update (poEntry->pOldEntry, xRowStatus_destroy_c) ||
				!ifData_removeReference (poEntry->pOldEntry->u32IfIndex, false, true, false))
			{
				goto neEntPortRowStatus_handler_cleanup;
			}
			
			xBTree_nodeRemove (&poEntry->oIf_BTreeNode, &oNeEntPortData_If_BTree);
		}
		
		ifData_t *poIfData = NULL;
		
		if (!ifData_createReference (poEntry->u32IfIndex, 0, 0, false, true, false, &poIfData))
		{
			goto neEntPortRowStatus_handler_cleanup;
		}
		poEntry->i32Type = poIfData->oIf.i32Type;
		
		if (poEntry->pOldEntry == NULL ||
			poEntry->pOldEntry->u32IfIndex != poEntry->u32IfIndex)
		{
			xBTree_nodeAdd (&poEntry->oIf_BTreeNode, &oNeEntPortData_If_BTree);
		}
		
		if (!neEntPortRowStatus_update (poEntry, u8RowStatus & xRowStatus_mask_c))
		{
			goto neEntPortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_active_c;
		
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
	}
	
	case xRowStatus_notInService_c:
	case xRowStatus_notInService_c | xRowStatus_fromParent_c:
		if (poEntry->u8RowStatus == xRowStatus_notInService_c ||
			(u8RowStatus & xRowStatus_fromParent_c && (poEntry->u8RowStatus != xRowStatus_active_c)))
		{
			goto neEntPortRowStatus_handler_success;
		}
		
		if (poEntry->pOldEntry == NULL &&
			(poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
		{
			goto neEntPortRowStatus_handler_cleanup;
		}
		
		if (!neEntPortRowStatus_update (poEntry, u8RowStatus & xRowStatus_mask_c) ||
			!ifData_removeReference (poEntry->u32IfIndex, false, true, false))
		{
			goto neEntPortRowStatus_handler_cleanup;
		}
		
		memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		
		poEntry->u8RowStatus =
			u8RowStatus & xRowStatus_fromParent_c && (poEntry->u8RowStatus == xRowStatus_active_c) ?
				xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto neEntPortRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
	case xRowStatus_destroy_c | xRowStatus_fromParent_c:
		if (poEntry->u8RowStatus == xRowStatus_active_c)
		{
			if (!neEntPortRowStatus_update (poEntry, u8RowStatus & xRowStatus_mask_c) ||
				!ifData_removeReference (poEntry->u32IfIndex, false, true, true))
			{
				goto neEntPortRowStatus_handler_cleanup;
			}
		}
		else if (
			poEntry->pOldEntry != NULL && poEntry->pOldEntry->u32IfIndex != 0)
		{
			if (!neEntPortRowStatus_update (poEntry->pOldEntry, u8RowStatus & xRowStatus_mask_c))
			{
				goto neEntPortRowStatus_handler_cleanup;
			}
		}
		
		xBTree_nodeRemove (&poEntry->oIf_BTreeNode, &oNeEntPortData_If_BTree);
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
	}
	
neEntPortRowStatus_handler_success:
	
	return true;
	
	
neEntPortRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neEntPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntPortData_BTree);
	return neEntPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neEntPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PhysicalIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeEntPortData_BTree);
	return put_index_data;
}

bool
neEntPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neEntPortTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neEntPortTable table mapper */
int
neEntPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neEntPortEntry_t *table_entry;
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPORTCHASSISINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ChassisIndex);
				break;
			case NEENTPORTPORTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PortIndex);
				break;
			case NEENTPORTIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case NEENTPORTIFTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IfType);
				break;
			case NEENTPORTROWSTATUS:
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPORTCHASSISINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPORTPORTINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPORTIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPORTIFTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEENTPORTROWSTATUS:
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEENTPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neEntPortTable_createEntry (
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
			
			switch (table_info->colnum)
			{
			case NEENTPORTCHASSISINDEX:
			case NEENTPORTPORTINDEX:
			case NEENTPORTIFINDEX:
			case NEENTPORTIFTYPE:
				if (table_entry->u8RowStatus == xRowStatus_active_c || table_entry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_FREE:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntPortTable_removeEntry (table_entry);
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPORTCHASSISINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ChassisIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ChassisIndex, sizeof (table_entry->u32ChassisIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ChassisIndex = *request->requestvb->val.integer;
				break;
			case NEENTPORTPORTINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PortIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PortIndex, sizeof (table_entry->u32PortIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PortIndex = *request->requestvb->val.integer;
				break;
			case NEENTPORTIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IfIndex, sizeof (table_entry->u32IfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IfIndex = *request->requestvb->val.integer;
				break;
			case NEENTPORTIFTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32IfType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32IfType, sizeof (table_entry->i32IfType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32IfType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neEntPortRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEENTPORTCHASSISINDEX:
				memcpy (&table_entry->u32ChassisIndex, pvOldDdata, sizeof (table_entry->u32ChassisIndex));
				break;
			case NEENTPORTPORTINDEX:
				memcpy (&table_entry->u32PortIndex, pvOldDdata, sizeof (table_entry->u32PortIndex));
				break;
			case NEENTPORTIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case NEENTPORTIFTYPE:
				memcpy (&table_entry->i32IfType, pvOldDdata, sizeof (table_entry->i32IfType));
				break;
			case NEENTPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neEntPortTable_removeEntry (table_entry);
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
			table_entry = (neEntPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEENTPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					neEntPortTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neEntChassisPortTable table mapper **/
void
neEntChassisPortTable_init (void)
{
	extern oid neEntChassisPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neEntChassisPortTable", &neEntChassisPortTable_mapper,
		neEntChassisPortTable_oid, OID_LENGTH (neEntChassisPortTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neEntChassisPortChassisIndex */,
		ASN_UNSIGNED /* index: neEntChassisPortIndex */,
		0);
	table_info->min_column = NEENTCHASSISPORTENTINDEX;
	table_info->max_column = NEENTCHASSISPORTENTINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neEntChassisPortTable_getFirst;
	iinfo->get_next_data_point = &neEntChassisPortTable_getNext;
	iinfo->get_data_point = &neEntChassisPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the (unsorted) table */
neEntChassisPortEntry_t *
neEntChassisPortTable_createEntry (
	uint32_t u32ChassisIndex,
	uint32_t u32Index)
{
	return NULL;
}

neEntChassisPortEntry_t *
neEntChassisPortTable_getByIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32Index)
{
	register neEntPortData_t *poNeEntPortData = NULL;
	
	if ((poNeEntPortData = neEntPortData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poNeEntPortData->au8Flags, ifFlags_ifCreated_c))
	{
		return NULL;
	}
	
	return &poNeEntPortData->oMap;
}

neEntChassisPortEntry_t *
neEntChassisPortTable_getNextIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32Index)
{
	register neEntPortData_t *poNeEntPortData = NULL;
	
	if ((poNeEntPortData = neEntPortData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poNeEntPortData->au8Flags, ifFlags_ifCreated_c))
	{
		return NULL;
	}
	
	return &poNeEntPortData->oMap;
}

/* remove a row from the table */
void
neEntChassisPortTable_removeEntry (neEntChassisPortEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neEntChassisPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeEntPortData_Map_BTree);
	return neEntChassisPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neEntChassisPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neEntPortData_t, oMap_BTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ChassisIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PortIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oMap_BTreeNode, &oNeEntPortData_Map_BTree);
	return put_index_data;
}

bool
neEntChassisPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neEntChassisPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neEntChassisPortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neEntChassisPortTable table mapper */
int
neEntChassisPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neEntChassisPortEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neEntChassisPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			register neEntPortData_t *poNeEntPortData = neEntPortData_getByMapEntry (table_entry);
			
			switch (table_info->colnum)
			{
			case NEENTCHASSISPORTENTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, poNeEntPortData->u32PhysicalIndex);
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
