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
#include "ifUtils.h"
#include "ifMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/freeRange.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/sync.h"
#include "lib/snmp.h"
#include "lib/time.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid interfaces_oid[] = {1,3,6,1,2,1,2};
static oid ifMIB_oid[] = {1,3,6,1,2,1,31};
static oid neIfMIB_oid[] = {1,3,6,1,4,1,36969,61};

static oid ifMIBObjects_oid[] = {1,3,6,1,2,1,31,1};

static oid ifTable_oid[] = {1,3,6,1,2,1,2,2};
static oid ifXTable_oid[] = {1,3,6,1,2,1,31,1,1};
static oid ifStackTable_oid[] = {1,3,6,1,2,1,31,1,2};
static oid ifRcvAddressTable_oid[] = {1,3,6,1,2,1,31,1,4};
static oid neIfTable_oid[] = {1,3,6,1,4,1,36969,61,1,1};
static oid neIfEntTable_oid[] = {1,3,6,1,4,1,36969,61,1,2};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid linkDown_oid[] = {1,3,6,1,6,3,1,1,5,3};
static oid linkUp_oid[] = {1,3,6,1,6,3,1,1,5,4};



/**
 *	initialize ifMIB group mapper
 */
void
ifMIB_init (void)
{
	extern oid interfaces_oid[];
	extern oid ifMIB_oid[];
	extern oid neIfMIB_oid[];
	extern oid ifMIBObjects_oid[];
	
	DEBUGMSGTL (("ifMIB", "Initializing\n"));
	
	/* register interfaces scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"interfaces_mapper", &interfaces_mapper,
			interfaces_oid, OID_LENGTH (interfaces_oid),
			HANDLER_CAN_RONLY
		),
		IFNUMBER,
		IFNUMBER
	);
	
	/* register ifMIBObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ifMIBObjects_mapper", &ifMIBObjects_mapper,
			ifMIBObjects_oid, OID_LENGTH (ifMIBObjects_oid),
			HANDLER_CAN_RONLY
		),
		IFTABLELASTCHANGE,
		IFSTACKLASTCHANGE
	);
	
	
	/* register ifMIB group table mappers */
	ifTable_init ();
	ifXTable_init ();
	ifStackTable_init ();
	ifRcvAddressTable_init ();
	neIfTable_init ();
	neIfEntTable_init ();
	
	/* register ifMIB modules */
	sysORTable_createRegister ("interfaces", interfaces_oid, OID_LENGTH (interfaces_oid));
	sysORTable_createRegister ("ifMIB", ifMIB_oid, OID_LENGTH (ifMIB_oid));
	sysORTable_createRegister ("neIfMIB", neIfMIB_oid, OID_LENGTH (neIfMIB_oid));
}


/**
 *	scalar mapper(s)
 */
interfaces_t oInterfaces =
{
	.oIfLock = xRwLock_initInline (),
};

/** interfaces scalar mapper **/
int
interfaces_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid interfaces_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (interfaces_oid)])
			{
			case IFNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oInterfaces.i32Number);
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

ifMIBObjects_t oIfMIBObjects;

/** ifMIBObjects scalar mapper **/
int
ifMIBObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid ifMIBObjects_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ifMIBObjects_oid)])
			{
			case IFTABLELASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, (uint32_t) (xTime_centiTime (xTime_typeMono_c) - oIfMIBObjects.u32TableLastChange));
				break;
			case IFSTACKLASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, (uint32_t) (xTime_centiTime (xTime_typeMono_c) - oIfMIBObjects.u32StackLastChange));
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
/** initialize ifTable table mapper **/
void
ifTable_init (void)
{
	extern oid ifTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ifTable", &ifTable_mapper,
		ifTable_oid, OID_LENGTH (ifTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = IFINDEX;
	table_info->max_column = IFOUTERRORS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ifTable_getFirst;
	iinfo->get_next_data_point = &ifTable_getNext;
	iinfo->get_data_point = &ifTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ifTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifEntry_t *pEntry1 = xBTree_entry (pNode1, ifEntry_t, oBTreeNode);
	register ifEntry_t *pEntry2 = xBTree_entry (pNode2, ifEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIfTable_BTree = xBTree_initInline (&ifTable_BTreeNodeCmp);
static xFreeRange_t oIfIndex_FreeRange = xFreeRange_initInline ();

/* create a new row in the table */
ifEntry_t *
ifTable_createEntry (
	uint32_t u32Index)
{
	register ifEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIfTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AdminStatus = ifAdminStatus_down_c;
	poEntry->i32OperStatus = xOperStatus_notPresent_c;
	
	xRwLock_init (&poEntry->oLock, NULL);
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIfTable_BTree);
	return poEntry;
}

ifEntry_t *
ifTable_getByIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifEntry_t, oBTreeNode);
}

ifEntry_t *
ifTable_getNextIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ifTable_removeEntry (ifEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIfTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIfTable_BTree);
	xRwLock_destroy (&poEntry->oLock);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ifEntry_t *
ifTable_createExt (
	uint32_t u32Index)
{
	ifEntry_t *poEntry = NULL;
	
	poEntry = ifTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto ifTable_createExt_cleanup;
	}
	
	if (!ifTable_createHier (poEntry))
	{
		ifTable_removeEntry (poEntry);
		poEntry = NULL;
		goto ifTable_createExt_cleanup;
	}
	
	oInterfaces.i32Number++;
	oIfMIBObjects.u32TableLastChange = xTime_centiTime (xTime_typeMono_c);
	
ifTable_createExt_cleanup:
	
	return poEntry;
}

bool
ifTable_removeExt (ifEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!ifTable_removeHier (poEntry))
	{
		goto ifTable_removeExt_cleanup;
	}
	ifTable_removeEntry (poEntry);
	bRetCode = true;
	
	oInterfaces.i32Number--;
	oIfMIBObjects.u32TableLastChange = xTime_centiTime (xTime_typeMono_c);
	
ifTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
ifTable_createHier (
	ifEntry_t *poEntry)
{
	register bool bRetCode = false;
	register bool bStackLocked = false;
	
	if (ifXTable_createEntry (poEntry->u32Index) == NULL)
	{
		goto ifTable_createHier_cleanup;
	}
	
	ifStack_wrLock ();
	bStackLocked = true;
	
	{
		register ifStackEntry_t *poLowerStackEntry = NULL;
		
		if ((poLowerStackEntry = ifStackTable_getByIndex (poEntry->u32Index, 0)) == NULL &&
			(poLowerStackEntry = ifStackTable_getNextIndex (poEntry->u32Index, 0)) != NULL &&
			poLowerStackEntry->u32HigherLayer != poEntry->u32Index)
		{
			if ((poLowerStackEntry = ifStackTable_createExt (poEntry->u32Index, 0)) == NULL)
			{
				goto ifTable_createHier_cleanup;
			}
			
			poLowerStackEntry->u8Status = ifStackStatus_active_c;
		}
	}
	
	{
		register ifStackEntry_t *poUpperStackEntry = NULL;
		
		if ((poUpperStackEntry = ifStackTable_getByIndex (0, poEntry->u32Index)) == NULL &&
			(poUpperStackEntry = ifStackTable_LToH_getNextIndex (0, poEntry->u32Index)) != NULL &&
			poUpperStackEntry->u32LowerLayer != poEntry->u32Index)
		{
			if ((poUpperStackEntry = ifStackTable_createExt (0, poEntry->u32Index)) == NULL)
			{
				goto ifTable_createHier_cleanup;
			}
			
			poUpperStackEntry->u8Status = ifStackStatus_active_c;
		}
	}
	
	ifStack_unLock ();
	bStackLocked = false;
	
	{
		register ifRcvAddressEntry_t *poIfRcvAddressEntry = NULL;
		uint8_t au8Address[sizeof (poIfRcvAddressEntry->au8Address)] = {0};
		size_t u16Address_len = 0;
		
		while (
			(poIfRcvAddressEntry = ifRcvAddressTable_getNextIndex (poEntry->u32Index, au8Address, u16Address_len)) != NULL &&
			poIfRcvAddressEntry->u32Index == poEntry->u32Index)
		{
			memcpy (au8Address, poIfRcvAddressEntry->au8Address, sizeof (au8Address));
			u16Address_len = sizeof (poIfRcvAddressEntry->au8Address);
			
			ifRcvAddressTable_removeEntry (poIfRcvAddressEntry);
		}
	}
	
	bRetCode = true;
	
ifTable_createHier_cleanup:
	
	bStackLocked ? ifStack_unLock (): false;
	!bRetCode ? ifTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
ifTable_removeHier (
	ifEntry_t *poEntry)
{
	register bool bStackLocked = false;
	register uint32_t u32Index = 0;
	
	ifStack_wrLock ();
	bStackLocked = true;
	
	{
		register ifStackEntry_t *poUpperStackEntry = NULL;
		
		if ((poUpperStackEntry = ifStackTable_getByIndex (0, poEntry->u32Index)) != NULL)
		{
			ifStackTable_removeExt (poUpperStackEntry);
		}
		u32Index = 0;
		while (
			(poUpperStackEntry = ifStackTable_LToH_getNextIndex (u32Index, poEntry->u32Index)) != NULL &&
			poUpperStackEntry->u32LowerLayer == poEntry->u32Index)
		{
			u32Index = poUpperStackEntry->u32HigherLayer;
			ifStackTable_removeExt (poUpperStackEntry);
		}
	}
	
	{
		register ifStackEntry_t *poLowerStackEntry = NULL;
		
		if ((poLowerStackEntry = ifStackTable_getByIndex (poEntry->u32Index, 0)) != NULL)
		{
			ifStackTable_removeExt (poLowerStackEntry);
		}
		u32Index = 0;
		while (
			(poLowerStackEntry = ifStackTable_getNextIndex (poEntry->u32Index, u32Index)) != NULL &&
			poLowerStackEntry->u32HigherLayer == poEntry->u32Index)
		{
			u32Index = poLowerStackEntry->u32LowerLayer;
			ifStackTable_removeExt (poLowerStackEntry);
		}
	}
	
	ifStack_unLock ();
	bStackLocked = false;
	
	ifXTable_removeEntry (&poEntry->oX);
	
	bStackLocked ? ifStack_unLock (): false;
	return true;
}

bool
ifTable_getByIndexExt (
	uint32_t u32Index, bool bWrLock,
	ifEntry_t **ppoEntry)
{
	register ifEntry_t *poEntry = NULL;
	
	ifTable_rdLock ();
	
	if ((poEntry = ifTable_getByIndex (u32Index)) == NULL)
	{
		goto ifTable_getByIndexExt_cleanup;
	}
	
	if (ppoEntry != NULL)
	{
		bWrLock ? ifEntry_wrLock (poEntry): ifEntry_rdLock (poEntry);
		*ppoEntry = poEntry;
	}
	
ifTable_getByIndexExt_cleanup:
	
	ifTable_unLock ();
	return poEntry != NULL;
}

bool
ifTable_createReference (
	uint32_t u32IfIndex,
	int32_t i32Type,
	int32_t i32AdminStatus,
	bool bCreate, bool bReference, bool bActivate,
	ifEntry_t **ppoEntry)
{
	register bool bRetCode = false;
	register ifEntry_t *poEntry = NULL;
	
	if (u32IfIndex == ifIndex_zero_c &&
		(i32Type == 0 || !bCreate || ppoEntry == NULL))
	{
		goto ifTable_createReference_cleanup;
	}
	
	
	bCreate ? ifTable_wrLock (): ifTable_rdLock ();
	
	if (u32IfIndex != ifIndex_zero_c && (poEntry = ifTable_getByIndex (u32IfIndex)) != NULL)
	{
		if (i32Type != 0 && poEntry->i32Type != 0 && poEntry->i32Type != i32Type)
		{
			poEntry = NULL;
			goto ifTable_createReference_ifUnlock;
		}
	}
	else if (bCreate)
	{
		register neIfEntry_t *poNeIfEntry = NULL;
		
		if (u32IfIndex == ifIndex_zero_c &&
			!xFreeRange_getFreeIndex (&oIfIndex_FreeRange, false, 0, 0, &u32IfIndex))
		{
			goto ifTable_createReference_ifUnlock;
		}
		
		if ((poNeIfEntry = neIfTable_createExt (u32IfIndex)) == NULL)
		{
			goto ifTable_createReference_ifUnlock;
		}
		
		poEntry = ifTable_getByNeEntry (poNeIfEntry);
	}
	else
	{
		goto ifTable_createReference_ifUnlock;
	}
	
	ifEntry_wrLock (poEntry);
	
ifTable_createReference_ifUnlock:
	ifTable_unLock ();
	if (poEntry == NULL)
	{
		goto ifTable_createReference_cleanup;
	}
	
	i32Type != 0 ? (poEntry->oNe.i32Type = i32Type): false;
	i32AdminStatus != 0 ? (poEntry->i32AdminStatus = i32AdminStatus): false;
	
	if (bReference)
	{
		ifNumReferences_increment (poEntry);
	}
	if (bActivate && !neIfRowStatus_handler (&poEntry->oNe, xRowStatus_active_c))
	{
		goto ifTable_createReference_cleanup;
	}
	
	if (ppoEntry != NULL)
	{
		*ppoEntry = poEntry;
		poEntry = NULL;
	}
	
	bRetCode = true;
	
ifTable_createReference_cleanup:
	
	poEntry != NULL ? ifEntry_unLock (poEntry): false;
	!bRetCode && u32IfIndex != ifIndex_zero_c ? ifTable_removeReference (u32IfIndex, bCreate, bReference, bActivate): false;
	return bRetCode;
}

bool
ifTable_removeReference (
	uint32_t u32IfIndex,
	bool bCreate, bool bReference, bool bActivate)
{
	register bool bRetCode = false;
	register ifEntry_t *poEntry = NULL;
	
	bCreate ? ifTable_wrLock (): ifTable_rdLock ();
	
	if ((poEntry = ifTable_getByIndex (u32IfIndex)) == NULL)
	{
		goto ifTable_removeReference_success;
	}
	ifEntry_wrLock (poEntry);
	
	if (bActivate && !neIfRowStatus_handler (&poEntry->oNe, xRowStatus_destroy_c))
	{
		goto ifTable_removeReference_cleanup;
	}
	if (bReference)
	{
		ifNumReferences_decrement (poEntry);
	}
	if (bCreate && poEntry->u32NumReferences == 0)
	{
		xBTree_nodeRemove (&poEntry->oBTreeNode, &oIfTable_BTree);
		ifEntry_unLock (poEntry);
		
		register ifEntry_t *poTmpEntry = poEntry;
		
		poEntry = NULL;
		if (!neIfTable_removeExt (&poTmpEntry->oNe))
		{
			goto ifTable_removeReference_cleanup;
		}
	}
	
ifTable_removeReference_success:
	
	bRetCode = true;
	
ifTable_removeReference_cleanup:
	
	poEntry != NULL ? ifEntry_unLock (poEntry): false;
	ifTable_unLock ();
	return bRetCode;
}

bool
ifAdminStatus_handler (
	ifEntry_t *poEntry,
	int32_t i32AdminStatus, bool bPropagate)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = i32AdminStatus & xAdminStatus_mask_c;
	
	if (poEntry->i32AdminStatus == u8RealStatus && !bPropagate)
	{
		goto ifAdminStatus_handler_success;
	}
	if (!xRowStatus_isActive (poEntry->oNe.u8RowStatus) && (i32AdminStatus & ~xAdminStatus_mask_c))
	{
		poEntry->i32AdminStatus = i32AdminStatus;
		goto ifAdminStatus_handler_success;
	}
	
	switch (u8RealStatus)
	{
	case xAdminStatus_up_c:
		poEntry->i32AdminStatus = u8RealStatus;
		
		if (!ifAdminStatus_update (poEntry, u8RealStatus, bPropagate))
		{
			goto ifAdminStatus_handler_cleanup;
		}
		break;
		
	case xAdminStatus_down_c:
		if (!ifAdminStatus_update (poEntry, u8RealStatus, bPropagate))
		{
			goto ifAdminStatus_handler_cleanup;
		}
		
		i32AdminStatus & xAdminStatus_fromParent_c ? false: (poEntry->i32AdminStatus = u8RealStatus);
		break;
		
	case xAdminStatus_testing_c:
		if (!ifAdminStatus_update (poEntry, u8RealStatus, bPropagate))
		{
			goto ifAdminStatus_handler_cleanup;
		}
		
		poEntry->i32AdminStatus = u8RealStatus;
		break;
	}
	
ifAdminStatus_handler_success:
	
	bRetCode = true;
	
ifAdminStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ifTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIfTable_BTree);
	return ifTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ifTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ifEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIfTable_BTree);
	return put_index_data;
}

bool
ifTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ifTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ifTable table mapper */
int
ifTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ifEntry_t *table_entry;
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
			table_entry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32Index);
				break;
			case IFDESCR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Descr, table_entry->u16Descr_len);
				break;
			case IFTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case IFMTU:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Mtu);
				break;
			case IFSPEED:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32Speed);
				break;
			case IFPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
				break;
			case IFADMINSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminStatus);
				break;
			case IFOPERSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperStatus);
				break;
			case IFLASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, (uint32_t) (xTime_centiTime (xTime_typeMono_c) - table_entry->u32LastChange));
				break;
			case IFINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InOctets);
				break;
			case IFINUCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InUcastPkts);
				break;
			case IFINDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InDiscards);
				break;
			case IFINERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InErrors);
				break;
			case IFINUNKNOWNPROTOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InUnknownProtos);
				break;
			case IFOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutOctets);
				break;
			case IFOUTUCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutUcastPkts);
				break;
			case IFOUTDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutDiscards);
				break;
			case IFOUTERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutErrors);
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
			table_entry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFADMINSTATUS:
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
			table_entry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFADMINSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminStatus, sizeof (table_entry->i32AdminStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				if (!ifAdminStatus_handler (table_entry, *request->requestvb->val.integer, false))
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_GENERR);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFADMINSTATUS:
				memcpy (&table_entry->i32AdminStatus, pvOldDdata, sizeof (table_entry->i32AdminStatus));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ifXTable table mapper **/
void
ifXTable_init (void)
{
	extern oid ifXTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ifXTable", &ifXTable_mapper,
		ifXTable_oid, OID_LENGTH (ifXTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = IFNAME;
	table_info->max_column = IFCOUNTERDISCONTINUITYTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ifXTable_getFirst;
	iinfo->get_next_data_point = &ifXTable_getNext;
	iinfo->get_data_point = &ifXTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
ifXEntry_t *
ifXTable_createEntry (
	uint32_t u32Index)
{
	register ifXEntry_t *poEntry = NULL;
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poIfEntry->oX;
	
	poEntry->i32LinkUpDownTrapEnable = ifLinkUpDownTrapEnable_disabled_c;
	poEntry->u8PromiscuousMode = ifPromiscuousMode_false_c;
	poEntry->u8ConnectorPresent = ifConnectorPresent_false_c;
	
	return poEntry;
}

ifXEntry_t *
ifXTable_getByIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poIfEntry->oX;
}

ifXEntry_t *
ifXTable_getNextIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poIfEntry->oX;
}

/* remove a row from the table */
void
ifXTable_removeEntry (ifXEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ifXTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIfTable_BTree);
	return ifXTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ifXTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ifEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIfTable_BTree);
	return put_index_data;
}

bool
ifXTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ifTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ifXTable table mapper */
int
ifXTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ifXEntry_t *table_entry;
	register ifEntry_t *poEntry;
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case IFNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case IFINMULTICASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMulticastPkts);
				break;
			case IFINBROADCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InBroadcastPkts);
				break;
			case IFOUTMULTICASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMulticastPkts);
				break;
			case IFOUTBROADCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutBroadcastPkts);
				break;
			case IFHCINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInOctets);
				break;
			case IFHCINUCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInUcastPkts);
				break;
			case IFHCINMULTICASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInMulticastPkts);
				break;
			case IFHCINBROADCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInBroadcastPkts);
				break;
			case IFHCOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutOctets);
				break;
			case IFHCOUTUCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutUcastPkts);
				break;
			case IFHCOUTMULTICASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutMulticastPkts);
				break;
			case IFHCOUTBROADCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutBroadcastPkts);
				break;
			case IFLINKUPDOWNTRAPENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LinkUpDownTrapEnable);
				break;
			case IFHIGHSPEED:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32HighSpeed);
				break;
			case IFPROMISCUOUSMODE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8PromiscuousMode);
				break;
			case IFCONNECTORPRESENT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8ConnectorPresent);
				break;
			case IFALIAS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Alias, table_entry->u16Alias_len);
				break;
			case IFCOUNTERDISCONTINUITYTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32CounterDiscontinuityTime);
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case IFLINKUPDOWNTRAPENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IFPROMISCUOUSMODE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IFALIAS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Alias));
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oX;
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case IFLINKUPDOWNTRAPENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LinkUpDownTrapEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LinkUpDownTrapEnable, sizeof (table_entry->i32LinkUpDownTrapEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LinkUpDownTrapEnable = *request->requestvb->val.integer;
				break;
			case IFPROMISCUOUSMODE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8PromiscuousMode))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8PromiscuousMode, sizeof (table_entry->u8PromiscuousMode));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8PromiscuousMode = *request->requestvb->val.integer;
				break;
			case IFALIAS:
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
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oX;
			
			switch (table_info->colnum)
			{
			case IFLINKUPDOWNTRAPENABLE:
				memcpy (&table_entry->i32LinkUpDownTrapEnable, pvOldDdata, sizeof (table_entry->i32LinkUpDownTrapEnable));
				break;
			case IFPROMISCUOUSMODE:
				memcpy (&table_entry->u8PromiscuousMode, pvOldDdata, sizeof (table_entry->u8PromiscuousMode));
				break;
			case IFALIAS:
				memcpy (table_entry->au8Alias, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Alias_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ifStackTable table mapper **/
void
ifStackTable_init (void)
{
	extern oid ifStackTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ifStackTable", &ifStackTable_mapper,
		ifStackTable_oid, OID_LENGTH (ifStackTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifStackHigherLayer */,
		ASN_INTEGER /* index: ifStackLowerLayer */,
		0);
	table_info->min_column = IFSTACKSTATUS;
	table_info->max_column = IFSTACKSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ifStackTable_getFirst;
	iinfo->get_next_data_point = &ifStackTable_getNext;
	iinfo->get_data_point = &ifStackTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ifStackTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifStackEntry_t *pEntry1 = xBTree_entry (pNode1, ifStackEntry_t, oBTreeNode);
	register ifStackEntry_t *pEntry2 = xBTree_entry (pNode2, ifStackEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32HigherLayer < pEntry2->u32HigherLayer) ||
		(pEntry1->u32HigherLayer == pEntry2->u32HigherLayer && pEntry1->u32LowerLayer < pEntry2->u32LowerLayer) ? -1:
		(pEntry1->u32HigherLayer == pEntry2->u32HigherLayer && pEntry1->u32LowerLayer == pEntry2->u32LowerLayer) ? 0: 1;
}

static int8_t
ifStackTable_LToH_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifStackEntry_t *pEntry1 = xBTree_entry (pNode1, ifStackEntry_t, oLToH_BTreeNode);
	register ifStackEntry_t *pEntry2 = xBTree_entry (pNode2, ifStackEntry_t, oLToH_BTreeNode);
	
	return
		(pEntry1->u32LowerLayer < pEntry2->u32LowerLayer) ||
		(pEntry1->u32LowerLayer == pEntry2->u32LowerLayer && pEntry1->u32HigherLayer < pEntry2->u32HigherLayer) ? -1:
		(pEntry1->u32LowerLayer == pEntry2->u32LowerLayer && pEntry1->u32HigherLayer == pEntry2->u32HigherLayer) ? 0: 1;
}

xBTree_t oIfStackTable_BTree = xBTree_initInline (&ifStackTable_BTreeNodeCmp);
xBTree_t oIfStackTable_LToH_BTree = xBTree_initInline (&ifStackTable_LToH_BTreeNodeCmp);

/* create a new row in the table */
ifStackEntry_t *
ifStackTable_createEntry (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register ifStackEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32HigherLayer = u32HigherLayer;
	poEntry->u32LowerLayer = u32LowerLayer;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIfStackTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIfStackTable_BTree);
	xBTree_nodeAdd (&poEntry->oLToH_BTreeNode, &oIfStackTable_LToH_BTree);
	return poEntry;
}

ifStackEntry_t *
ifStackTable_getByIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register ifStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32HigherLayer = u32HigherLayer;
	poTmpEntry->u32LowerLayer = u32LowerLayer;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIfStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifStackEntry_t, oBTreeNode);
}

ifStackEntry_t *
ifStackTable_getNextIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register ifStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32HigherLayer = u32HigherLayer;
	poTmpEntry->u32LowerLayer = u32LowerLayer;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIfStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifStackEntry_t, oBTreeNode);
}

ifStackEntry_t *
ifStackTable_LToH_getNextIndex (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register ifStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ifStackEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32HigherLayer = u32HigherLayer;
	poTmpEntry->u32LowerLayer = u32LowerLayer;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oLToH_BTreeNode, &oIfStackTable_LToH_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifStackEntry_t, oLToH_BTreeNode);
}

/* remove a row from the table */
void
ifStackTable_removeEntry (ifStackEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIfStackTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIfStackTable_BTree);
	xBTree_nodeRemove (&poEntry->oLToH_BTreeNode, &oIfStackTable_LToH_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

bool
ifStackTable_createRegister (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register bool bRetCode = false;
	register bool bIfLocked = false;
	register ifStackEntry_t *poEntry = NULL;
	
	if (u32HigherLayer == 0 || u32LowerLayer == 0)
	{
		return false;
	}
	
	ifStack_wrLock ();
	
	if ((poEntry = ifStackTable_getByIndex (u32HigherLayer, u32LowerLayer)) == NULL &&
		(poEntry = ifStackTable_createExt (u32HigherLayer, u32LowerLayer)) == NULL)
	{
		goto ifStackTable_createRegister_cleanup;
	}
	
	ifTable_rdLock ();
	bIfLocked = true;
	
	if (!ifStackStatus_handler (poEntry, xRowStatus_active_c))
	{
		goto ifStackTable_createRegister_cleanup;
	}
	
	bRetCode = true;
	
ifStackTable_createRegister_cleanup:
	
	bIfLocked ? ifTable_unLock (): false;
	ifStack_unLock ();
	
	return bRetCode;
}

bool
ifStackTable_removeRegister (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	register bool bRetCode = false;
	register bool bIfLocked = false;
	register ifStackEntry_t *poEntry = NULL;
	
	if (u32HigherLayer == 0 || u32LowerLayer == 0)
	{
		return false;
	}
	
	ifStack_wrLock ();
	
	if ((poEntry = ifStackTable_getByIndex (u32HigherLayer, u32LowerLayer)) == NULL)
	{
		goto ifStackTable_removeRegister_cleanup;
	}
	
	ifTable_rdLock ();
	bIfLocked = true;
	
	if (!ifStackStatus_handler (poEntry, xRowStatus_destroy_c))
	{
		goto ifStackTable_removeRegister_cleanup;
	}
	
	ifTable_unLock ();
	bIfLocked = false;
	
	if (!ifStackTable_removeExt (poEntry))
	{
		goto ifStackTable_removeRegister_cleanup;
	}
	
	bRetCode = true;
	
ifStackTable_removeRegister_cleanup:
	
	bIfLocked ? ifTable_unLock (): false;
	ifStack_unLock ();
	
	return bRetCode;
}

ifStackEntry_t *
ifStackTable_createExt (
	uint32_t u32HigherLayer,
	uint32_t u32LowerLayer)
{
	ifStackEntry_t *poEntry = NULL;
	
	poEntry = ifStackTable_createEntry (
		u32HigherLayer,
		u32LowerLayer);
	if (poEntry == NULL)
	{
		goto ifStackTable_createExt_cleanup;
	}
	
	if (!ifStackTable_createHier (poEntry))
	{
		ifStackTable_removeEntry (poEntry);
		poEntry = NULL;
		goto ifStackTable_createExt_cleanup;
	}
	
	oIfMIBObjects.u32StackLastChange = xTime_centiTime (xTime_typeMono_c);
	
ifStackTable_createExt_cleanup:
	
	return poEntry;
}

bool
ifStackTable_removeExt (ifStackEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!ifStackTable_removeHier (poEntry))
	{
		goto ifStackTable_removeExt_cleanup;
	}
	ifStackTable_removeEntry (poEntry);
	bRetCode = true;
	
	oIfMIBObjects.u32StackLastChange = xTime_centiTime (xTime_typeMono_c);
	
ifStackTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
ifStackTable_createHier (
	ifStackEntry_t *poEntry)
{
	register ifStackEntry_t *poLowerStackEntry = NULL;
	register ifStackEntry_t *poUpperStackEntry = NULL;
	
	if (poEntry->u32HigherLayer == 0 || poEntry->u32LowerLayer == 0)
	{
		return true;
	}
	
	if ((poUpperStackEntry = ifStackTable_getByIndex (poEntry->u32HigherLayer, 0)) != NULL)
	{
		ifStackTable_removeEntry (poUpperStackEntry);
	}
	
	if ((poLowerStackEntry = ifStackTable_getByIndex (0, poEntry->u32LowerLayer)) != NULL)
	{
		ifStackTable_removeEntry (poLowerStackEntry);
	}
	
	return true;
}

bool
ifStackTable_removeHier (
	ifStackEntry_t *poEntry)
{
	register ifStackEntry_t *poLowerStackEntry = NULL;
	register ifStackEntry_t *poUpperStackEntry = NULL;
	
	if (poEntry->u32HigherLayer == 0 || poEntry->u32LowerLayer == 0)
	{
		return true;
	}
	
	if ((poLowerStackEntry = ifStackTable_LToH_getNextIndex (poEntry->u32LowerLayer, 0)) == NULL ||
		poLowerStackEntry->u32LowerLayer != poEntry->u32LowerLayer)
	{
		ifStackTable_createEntry (0, poEntry->u32LowerLayer);
	}
	
	if ((poUpperStackEntry = ifStackTable_getNextIndex (poEntry->u32HigherLayer, 0)) == NULL ||
		poUpperStackEntry->u32HigherLayer != poEntry->u32HigherLayer)
	{
		ifStackTable_createEntry (poEntry->u32HigherLayer, 0);
	}
	
	return true;
}

bool
ifStackStatus_handler (
	ifStackEntry_t *poEntry, uint8_t u8Status)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8Status & xRowStatus_mask_c;
	register ifEntry_t *poHigherIfEntry = NULL;
	register ifEntry_t *poLowerIfEntry = NULL;
	
	if (poEntry->u32HigherLayer == 0 || poEntry->u32LowerLayer == 0)
	{
		goto ifStackStatus_handler_cleanup;
	}
	if ((poHigherIfEntry = ifTable_getByIndex (poEntry->u32HigherLayer)) == NULL ||
		(poLowerIfEntry = ifTable_getByIndex (poEntry->u32LowerLayer)) == NULL)
	{
		goto ifStackStatus_handler_cleanup;
	}
	
	if (poEntry->u8Status == u8RealStatus)
	{
		goto ifStackStatus_handler_success;
	}
	
	switch (u8RealStatus)
	{
	default:
		goto ifStackStatus_handler_cleanup;
		
	case xRowStatus_active_c:
	case xRowStatus_createAndGo_c:
		if (poEntry->u8Status == xRowStatus_active_c)
		{
			goto ifStackStatus_handler_success;
		}
		
		if (!ifType_stackModify (poHigherIfEntry, poLowerIfEntry, ifTypeStack_actionAdd_c, false))
		{
			goto ifStackStatus_handler_cleanup;
		}
		
		/* TODO */
		poEntry->u8Status = xRowStatus_active_c;
		break;
		
	case xRowStatus_destroy_c:
	case xRowStatus_notInService_c:
		if (poEntry->u8Status == xRowStatus_notInService_c)
		{
			goto ifStackStatus_handler_success;
		}
		
		if (!ifType_stackModify (poHigherIfEntry, poLowerIfEntry, ifTypeStack_actionRemove_c, false))
		{
			goto ifStackStatus_handler_cleanup;
		}
		
		/* TODO */
		
	case xRowStatus_createAndWait_c:
		poEntry->u8Status = xRowStatus_notInService_c;
		break;
	}
	
ifStackStatus_handler_success:
	
	oIfMIBObjects.u32StackLastChange = xTime_centiTime (xTime_typeMono_c);
	bRetCode = true;
	
ifStackStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ifStackTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIfStackTable_BTree);
	return ifStackTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ifStackTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifStackEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ifStackEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32HigherLayer);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32LowerLayer);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIfStackTable_BTree);
	return put_index_data;
}

bool
ifStackTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifStackEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ifStackTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ifStackTable table mapper */
int
ifStackTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ifStackEntry_t *table_entry;
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (*idx1->val.integer == 0 || *idx2->val.integer == 0)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ifStackTable_createExt (
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ifStackTable_removeExt (table_entry);
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!ifStackStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ifStackTable_removeExt (table_entry);
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
			table_entry = (ifStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFSTACKSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					ifStackTable_removeExt (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ifRcvAddressTable table mapper **/
void
ifRcvAddressTable_init (void)
{
	extern oid ifRcvAddressTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ifRcvAddressTable", &ifRcvAddressTable_mapper,
		ifRcvAddressTable_oid, OID_LENGTH (ifRcvAddressTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_OCTET_STR /* index: ifRcvAddressAddress */,
		0);
	table_info->min_column = IFRCVADDRESSSTATUS;
	table_info->max_column = IFRCVADDRESSTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ifRcvAddressTable_getFirst;
	iinfo->get_next_data_point = &ifRcvAddressTable_getNext;
	iinfo->get_data_point = &ifRcvAddressTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ifRcvAddressTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifRcvAddressEntry_t *pEntry1 = xBTree_entry (pNode1, ifRcvAddressEntry_t, oBTreeNode);
	register ifRcvAddressEntry_t *pEntry2 = xBTree_entry (pNode2, ifRcvAddressEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, sizeof (pEntry1->au8Address), sizeof (pEntry2->au8Address)) == -1) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, sizeof (pEntry1->au8Address), sizeof (pEntry2->au8Address)) == 0) ? 0: 1;
}

xBTree_t oIfRcvAddressTable_BTree = xBTree_initInline (&ifRcvAddressTable_BTreeNodeCmp);

/* create a new row in the table */
ifRcvAddressEntry_t *
ifRcvAddressTable_createEntry (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ifRcvAddressEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIfRcvAddressTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8Status = xRowStatus_notInService_c;
	poEntry->i32Type = ifRcvAddressType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIfRcvAddressTable_BTree);
	return poEntry;
}

ifRcvAddressEntry_t *
ifRcvAddressTable_getByIndex (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ifRcvAddressEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIfRcvAddressTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifRcvAddressEntry_t, oBTreeNode);
}

ifRcvAddressEntry_t *
ifRcvAddressTable_getNextIndex (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ifRcvAddressEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIfRcvAddressTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifRcvAddressEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ifRcvAddressTable_removeEntry (ifRcvAddressEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIfRcvAddressTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIfRcvAddressTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

bool
ifRcvAddressTable_createRegister (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register bool bRetCode = false;
	register ifRcvAddressEntry_t *poEntry = NULL;
	
	if (u32Index == ifIndex_zero_c ||
		pau8Address == NULL || u16Address_len == 0)
	{
		return false;
	}
	
	ifTable_rdLock ();
	
	if (ifTable_getByIndex (u32Index) == NULL)
	{
		goto ifRcvAddressTable_createRegister_cleanup;
	}
	
	if ((poEntry = ifRcvAddressTable_getByIndex (u32Index, pau8Address, u16Address_len)) == NULL &&
		(poEntry = ifRcvAddressTable_createEntry (u32Index, pau8Address, u16Address_len)) == NULL)
	{
		goto ifRcvAddressTable_createRegister_cleanup;
	}
	poEntry->u8Status = xRowStatus_active_c;
	
	ifRcvAddressNumReferences_increment (poEntry);
	bRetCode = true;
	
ifRcvAddressTable_createRegister_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}

bool
ifRcvAddressTable_removeRegister (
	uint32_t u32Index,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register bool bRetCode = false;
	register ifRcvAddressEntry_t *poEntry = NULL;
	
	ifTable_rdLock ();
	
	if ((poEntry = ifRcvAddressTable_getByIndex (u32Index, pau8Address, u16Address_len)) == NULL)
	{
		goto ifRcvAddressTable_removeRegister_cleanup;
	}
	
	ifRcvAddressNumReferences_decrement (poEntry);
	if (poEntry->u32NumReferences == 0)
	{
		ifRcvAddressTable_removeEntry (poEntry);
	}
	
	bRetCode = true;
	
ifRcvAddressTable_removeRegister_cleanup:
	
	ifTable_unLock ();
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ifRcvAddressTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIfRcvAddressTable_BTree);
	return ifRcvAddressTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ifRcvAddressTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifRcvAddressEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ifRcvAddressEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, sizeof (poEntry->au8Address));
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIfRcvAddressTable_BTree);
	return put_index_data;
}

bool
ifRcvAddressTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifRcvAddressEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ifRcvAddressTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ifRcvAddressTable table mapper */
int
ifRcvAddressTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ifRcvAddressEntry_t *table_entry;
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8Status);
				break;
			case IFRCVADDRESSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IFRCVADDRESSTYPE:
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ifRcvAddressTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len);
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ifRcvAddressTable_removeEntry (table_entry);
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSTYPE:
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
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ifRcvAddressTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ifRcvAddressTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case IFRCVADDRESSTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ifRcvAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IFRCVADDRESSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_ACTIVE:
					table_entry->u8Status = RS_ACTIVE;
					break;
					
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				case RS_NOTINSERVICE:
					table_entry->u8Status = RS_NOTINSERVICE;
					break;
					
				case RS_DESTROY:
					ifRcvAddressTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIfTable table mapper **/
void
neIfTable_init (void)
{
	extern oid neIfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIfTable", &neIfTable_mapper,
		neIfTable_oid, OID_LENGTH (neIfTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = NEIFNAME;
	table_info->max_column = NEIFSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIfTable_getFirst;
	iinfo->get_next_data_point = &neIfTable_getNext;
	iinfo->get_data_point = &neIfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
	xFreeRange_createRange (&oIfIndex_FreeRange, ifIndex_start_c, ifIndex_end_c);
}

/* create a new row in the table */
neIfEntry_t *
neIfTable_createEntry (
	uint32_t u32Index)
{
	register neIfEntry_t *poEntry = NULL;
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_createExt (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poIfEntry->oNe;
	
	/*poEntry->au8Name = ""*/;
	/*poEntry->au8Descr = ""*/;
	/*poEntry->au8PhysAddress = 0*/;
	xBitmap_setBitsRev (poEntry->au8AdminFlags, 4, 1, neIfAdminFlags_speed100Mbps_c, neIfAdminFlags_autoNeg_c, neIfAdminFlags_macLearn_c, neIfAdminFlags_macFwd_c);
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neIfStorageType_volatile_c;
	
	return poEntry;
}

neIfEntry_t *
neIfTable_getByIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poIfEntry->oNe;
}

neIfEntry_t *
neIfTable_getNextIndex (
	uint32_t u32Index)
{
	register ifEntry_t *poIfEntry = NULL;
	
	if ((poIfEntry = ifTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poIfEntry->oNe;
}

/* remove a row from the table */
void
neIfTable_removeEntry (neIfEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	ifTable_removeExt (ifTable_getByNeEntry (poEntry));
	return;
}

neIfEntry_t *
neIfTable_createExt (
	uint32_t u32Index)
{
	neIfEntry_t *poEntry = NULL;
	
	poEntry = neIfTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto neIfTable_createExt_cleanup;
	}
	
	if (!neIfTable_createHier (poEntry))
	{
		neIfTable_removeEntry (poEntry);
		poEntry = NULL;
		goto neIfTable_createExt_cleanup;
	}
	
neIfTable_createExt_cleanup:
	
	return poEntry;
}

bool
neIfTable_removeExt (neIfEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ifEntry_t *poIfEntry = ifTable_getByNeEntry (poEntry);
	
	if (poIfEntry->u32NumReferences > 0)
	{
		goto neIfTable_removeExt_success;
	}
	
	if (!neIfTable_removeHier (poEntry))
	{
		goto neIfTable_removeExt_cleanup;
	}
	neIfTable_removeEntry (poEntry);
	
neIfTable_removeExt_success:
	
	bRetCode = true;
	
neIfTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
neIfTable_createHier (
	neIfEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ifEntry_t *poIfEntry = ifTable_getByNeEntry (poEntry);
	
	if (!xFreeRange_allocateIndex (&oIfIndex_FreeRange, poIfEntry->u32Index))
	{
		goto neIfTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
neIfTable_createHier_cleanup:
	
	!bRetCode ? neIfTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
neIfTable_removeHier (
	neIfEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ifEntry_t *poIfEntry = ifTable_getByNeEntry (poEntry);
	
	if (!xFreeRange_removeIndex (&oIfIndex_FreeRange, poIfEntry->u32Index))
	{
		goto neIfTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
neIfTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
neIfAdminFlags_handler (
	neIfEntry_t *poEntry, uint8_t *pu8AdminFlags, bool bPropagate)
{
	register bool bRetCode = false;
	
	if (memcmp (poEntry->au8AdminFlags, pu8AdminFlags, sizeof (poEntry->au8AdminFlags)) == 0 && !bPropagate)
	{
		goto neIfAdminFlags_handler_success;
	}
	
	!bPropagate ? memcpy (poEntry->au8AdminFlags, pu8AdminFlags, sizeof (poEntry->au8AdminFlags)): false;
	
neIfAdminFlags_handler_success:
	
	bRetCode = true;
	
	return bRetCode;
}

bool
neIfRowStatus_handler (
	neIfEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ifEntry_t *poIfEntry = ifTable_getByNeEntry (poEntry);
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto neIfRowStatus_handler_success;
	}
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!neIfRowStatus_update (poIfEntry, u8RealStatus))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		
		if (!ifAdminStatus_handler (poIfEntry, poIfEntry->i32AdminStatus, true))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		break;
		
	case xRowStatus_notInService_c:
		if (!ifAdminStatus_handler (poIfEntry, xAdminStatus_down_c | xAdminStatus_fromParent_c, false))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		
		if (!neIfRowStatus_update (poIfEntry, u8RealStatus))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_createAndGo_c:
		goto neIfRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
	case xRowStatus_destroy_c:
		if (!ifAdminStatus_handler (poIfEntry, xAdminStatus_down_c | xAdminStatus_fromParent_c, false))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		
		if (!neIfRowStatus_update (poIfEntry, u8RealStatus))
		{
			goto neIfRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
neIfRowStatus_handler_success:
	
	bRetCode = true;
	
neIfRowStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIfTable_BTree);
	return neIfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIfTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ifEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIfTable_BTree);
	return put_index_data;
}

bool
neIfTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ifEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ifTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIfTable table mapper */
int
neIfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIfEntry_t *table_entry;
	register ifEntry_t *poEntry;
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case NEIFDESCR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Descr, table_entry->u16Descr_len);
				break;
			case NEIFTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case NEIFMTU:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Mtu);
				break;
			case NEIFSPEED:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Speed, sizeof (table_entry->au8Speed));
				break;
			case NEIFPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
				break;
			case NEIFADMINFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8AdminFlags, sizeof (table_entry->au8AdminFlags));
				break;
			case NEIFOPERFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8OperFlags, sizeof (table_entry->au8OperFlags));
				break;
			case NEIFROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEIFSTORAGETYPE:
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFDESCR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Descr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFMTU:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFSPEED:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Speed));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PhysAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFADMINFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8AdminFlags));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIFSTORAGETYPE:
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neIfTable_createExt (
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
			case NEIFNAME:
			case NEIFDESCR:
			case NEIFTYPE:
			case NEIFMTU:
			case NEIFSPEED:
			case NEIFPHYSADDRESS:
			case NEIFADMINFLAGS:
			case NEIFSTORAGETYPE:
				if (table_entry->u8RowStatus == xRowStatus_active_c || table_entry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIfTable_removeExt (table_entry);
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFNAME:
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
			case NEIFDESCR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Descr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Descr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Descr, sizeof (table_entry->au8Descr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Descr, 0, sizeof (table_entry->au8Descr));
				memcpy (table_entry->au8Descr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Descr_len = request->requestvb->val_len;
				break;
			case NEIFTYPE:
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
			case NEIFMTU:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Mtu))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Mtu, sizeof (table_entry->i32Mtu));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Mtu = *request->requestvb->val.integer;
				break;
			case NEIFSPEED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8Speed))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8Speed, sizeof (table_entry->au8Speed));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Speed, 0, sizeof (table_entry->au8Speed));
				memcpy (table_entry->au8Speed, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case NEIFPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8PhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PhysAddress, 0, sizeof (table_entry->au8PhysAddress));
				memcpy (table_entry->au8PhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case NEIFADMINFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->au8AdminFlags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, table_entry->au8AdminFlags, sizeof (table_entry->au8AdminFlags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8AdminFlags, 0, sizeof (table_entry->au8AdminFlags));
				memcpy (table_entry->au8AdminFlags, request->requestvb->val.string, request->requestvb->val_len);
				break;
			case NEIFSTORAGETYPE:
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neIfRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEIFDESCR:
				memcpy (table_entry->au8Descr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Descr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEIFTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case NEIFMTU:
				memcpy (&table_entry->i32Mtu, pvOldDdata, sizeof (table_entry->i32Mtu));
				break;
			case NEIFSPEED:
				memcpy (table_entry->au8Speed, pvOldDdata, sizeof (table_entry->au8Speed));
				break;
			case NEIFPHYSADDRESS:
				memcpy (table_entry->au8PhysAddress, pvOldDdata, sizeof (table_entry->au8PhysAddress));
				break;
			case NEIFADMINFLAGS:
				memcpy (table_entry->au8AdminFlags, pvOldDdata, sizeof (table_entry->au8AdminFlags));
				break;
			case NEIFROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIfTable_removeExt (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEIFSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (ifEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oNe;
			
			switch (table_info->colnum)
			{
			case NEIFROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					neIfTable_removeExt (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIfEntTable table mapper **/
void
neIfEntTable_init (void)
{
	extern oid neIfEntTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIfEntTable", &neIfEntTable_mapper,
		neIfEntTable_oid, OID_LENGTH (neIfEntTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: neIfEntPhysicalIndex */,
		0);
	table_info->min_column = NEIFENTCHASSISINDEX;
	table_info->max_column = NEIFENTCHASSISINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIfEntTable_getFirst;
	iinfo->get_next_data_point = &neIfEntTable_getNext;
	iinfo->get_data_point = &neIfEntTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIfEntTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIfEntEntry_t *pEntry1 = xBTree_entry (pNode1, neIfEntEntry_t, oBTreeNode);
	register neIfEntEntry_t *pEntry2 = xBTree_entry (pNode2, neIfEntEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32PhysicalIndex < pEntry2->u32PhysicalIndex) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32PhysicalIndex == pEntry2->u32PhysicalIndex) ? 0: 1;
}

xBTree_t oNeIfEntTable_BTree = xBTree_initInline (&neIfEntTable_BTreeNodeCmp);

/* create a new row in the table */
neIfEntEntry_t *
neIfEntTable_createEntry (
	uint32_t u32Index,
	uint32_t u32PhysicalIndex)
{
	register neIfEntEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	poEntry->u32PhysicalIndex = u32PhysicalIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIfEntTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIfEntTable_BTree);
	return poEntry;
}

neIfEntEntry_t *
neIfEntTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32PhysicalIndex)
{
	register neIfEntEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIfEntTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIfEntEntry_t, oBTreeNode);
}

neIfEntEntry_t *
neIfEntTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32PhysicalIndex)
{
	register neIfEntEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32PhysicalIndex = u32PhysicalIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIfEntTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIfEntEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIfEntTable_removeEntry (neIfEntEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIfEntTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIfEntTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIfEntTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIfEntTable_BTree);
	return neIfEntTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIfEntTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIfEntEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIfEntEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PhysicalIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIfEntTable_BTree);
	return put_index_data;
}

bool
neIfEntTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIfEntEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIfEntTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIfEntTable table mapper */
int
neIfEntTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIfEntEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neIfEntEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIFENTCHASSISINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ChassisIndex);
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
linkDown_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid linkDown_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid ifIndex_oid[] = {1,3,6,1,2,1,2,2,1,1, /* insert index here */};
	oid ifAdminStatus_oid[] = {1,3,6,1,2,1,2,2,1,7, /* insert index here */};
	oid ifOperStatus_oid[] = {1,3,6,1,2,1,2,2,1,8, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) linkDown_oid, sizeof (linkDown_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		ifIndex_oid, OID_LENGTH (ifIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ifAdminStatus_oid, OID_LENGTH (ifAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ifOperStatus_oid, OID_LENGTH (ifOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifOperStatus */
		NULL, 0);
		
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

int
linkUp_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid linkUp_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid ifIndex_oid[] = {1,3,6,1,2,1,2,2,1,1, /* insert index here */};
	oid ifAdminStatus_oid[] = {1,3,6,1,2,1,2,2,1,7, /* insert index here */};
	oid ifOperStatus_oid[] = {1,3,6,1,2,1,2,2,1,8, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) linkUp_oid, sizeof (linkUp_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		ifIndex_oid, OID_LENGTH (ifIndex_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifIndex */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ifAdminStatus_oid, OID_LENGTH (ifAdminStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifAdminStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		ifOperStatus_oid, OID_LENGTH (ifOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for ifOperStatus */
		NULL, 0);
		
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
