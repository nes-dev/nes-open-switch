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
#include "lagMIB.h"
#include "lagUtils.h"
#include "if/ifMIB.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid lagMIB_oid[] = {1,2,840,10006,300,43};
static oid neLagMIB_oid[] = {1,3,6,1,4,1,36969,71};

/* array length = OID_LENGTH + 1 */
static oid lagMIBObjects_oid[] = {1,2,840,10006,300,43,1,3};

static oid dot3adAggTable_oid[] = {1,2,840,10006,300,43,1,1,1};
static oid dot3adAggPortListTable_oid[] = {1,2,840,10006,300,43,1,1,2};
static oid dot3adAggPortTable_oid[] = {1,2,840,10006,300,43,1,2,1};
static oid dot3adAggPortStatsTable_oid[] = {1,2,840,10006,300,43,1,2,2};
static oid dot3adAggPortDebugTable_oid[] = {1,2,840,10006,300,43,1,2,3};
static oid dot3adAggPortXTable_oid[] = {1,2,840,10006,300,43,1,2,4};
static oid neAggTable_oid[] = {1,3,6,1,4,1,36969,71,1,1};
static oid neAggPortListTable_oid[] = {1,3,6,1,4,1,36969,71,1,2};
static oid neAggPortTable_oid[] = {1,3,6,1,4,1,36969,71,1,3};



/**
 *	initialize lagMIB group mapper
 */
void
lagMIB_init (void)
{
	extern oid lagMIB_oid[];
	extern oid neLagMIB_oid[];
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
	neAggTable_init ();
	neAggPortListTable_init ();
	neAggPortTable_init ();
	
	/* register lagMIB modules */
	sysORTable_createRegister ("lagMIB", lagMIB_oid, OID_LENGTH (lagMIB_oid));
	sysORTable_createRegister ("neLagMIB", neLagMIB_oid, OID_LENGTH (neLagMIB_oid));
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
dot3adAggData_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggData_t *pEntry1 = xBTree_entry (pNode1, dot3adAggData_t, oBTreeNode);
	register dot3adAggData_t *pEntry2 = xBTree_entry (pNode2, dot3adAggData_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static int8_t
dot3adAggData_Group_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggData_t *pEntry1 = xBTree_entry (pNode1, dot3adAggData_t, oBTreeNode);
	register dot3adAggData_t *pEntry2 = xBTree_entry (pNode2, dot3adAggData_t, oBTreeNode);
	
	return
		(pEntry1->i32GroupType < pEntry2->i32GroupType) ||
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex < pEntry2->u32GroupIndex) ||
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex == pEntry2->u32GroupIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex == pEntry2->u32GroupIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static xBTree_t oDot3adAggData_BTree = xBTree_initInline (&dot3adAggData_BTreeNodeCmp);
static xBTree_t oDot3adAggData_Group_BTree = xBTree_initInline (&dot3adAggData_Group_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggData_t *
dot3adAggData_createEntry (
	uint32_t u32Index)
{
	register dot3adAggData_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggData_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggData_BTree);
	return poEntry;
}

dot3adAggData_t *
dot3adAggData_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggData_t, oBTreeNode);
}

dot3adAggData_t *
dot3adAggData_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggData_t, oBTreeNode);
}

dot3adAggData_t *
dot3adAggData_Group_getByIndex (
	int32_t i32GroupType,
	uint32_t u32GroupIndex,
	uint32_t u32Index)
{
	register dot3adAggData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32GroupType = i32GroupType;
	poTmpEntry->u32GroupIndex = u32GroupIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oGroup_BTreeNode, &oDot3adAggData_Group_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggData_t, oBTreeNode);
}

dot3adAggData_t *
dot3adAggData_Group_getNextIndex (
	int32_t i32GroupType,
	uint32_t u32GroupIndex,
	uint32_t u32Index)
{
	register dot3adAggData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32GroupType = i32GroupType;
	poTmpEntry->u32GroupIndex = u32GroupIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oGroup_BTreeNode, &oDot3adAggData_Group_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggData_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggData_removeEntry (dot3adAggData_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggData_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggData_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* create a new row in the (unsorted) table */
dot3adAggEntry_t *
dot3adAggTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_aggCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poDot3adAggData->au8Flags, dot3adAggFlags_aggCreated_c, 1);
	return &poDot3adAggData->oAgg;
}

dot3adAggEntry_t *
dot3adAggTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_aggCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oAgg;
}

dot3adAggEntry_t *
dot3adAggTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_aggCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oAgg;
}

/* remove a row from the table */
void
dot3adAggTable_removeEntry (dot3adAggEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByAggEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggData->au8Flags, dot3adAggFlags_aggCreated_c, 0);
	return;
}

dot3adAggEntry_t *
dot3adAggTable_createExt (
	uint32_t u32Index)
{
	dot3adAggEntry_t *poEntry = NULL;
	
	poEntry = dot3adAggTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto dot3adAggTable_createExt_cleanup;
	}
	
	if (!dot3adAggTable_createHier (poEntry))
	{
		dot3adAggTable_removeEntry (poEntry);
		poEntry = NULL;
		goto dot3adAggTable_createExt_cleanup;
	}
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
dot3adAggTable_createExt_cleanup:
	return poEntry;
}

bool
dot3adAggTable_removeExt (dot3adAggEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!dot3adAggTable_removeHier (poEntry))
	{
		goto dot3adAggTable_removeExt_cleanup;
	}
	dot3adAggTable_removeEntry (poEntry);
	bRetCode = true;
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
dot3adAggTable_removeExt_cleanup:
	return bRetCode;
}

bool
dot3adAggTable_createHier (
	dot3adAggEntry_t *poEntry)
{
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByAggEntry (poEntry);
	
	if (!ifData_createReference (poDot3adAggData->u32Index, ifType_ieee8023adLag_c, true, true, true, NULL))
	{
		goto dot3adAggTable_createHier_cleanup;
	}
	
	if (dot3adAggPortListTable_getByIndex (poDot3adAggData->u32Index) == NULL &&
		dot3adAggPortListTable_createEntry (poDot3adAggData->u32Index) == NULL)
	{
		goto dot3adAggTable_createHier_cleanup;
	}
	
	return true;
	
	
dot3adAggTable_createHier_cleanup:
	
	dot3adAggTable_removeHier (poEntry);
	return false;
}

bool
dot3adAggTable_removeHier (
	dot3adAggEntry_t *poEntry)
{
	register bool bRetCode = false;
	register dot3adAggPortListEntry_t *poDot3adAggPortListEntry = NULL;
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByAggEntry (poEntry);
	
	if ((poDot3adAggPortListEntry = dot3adAggPortListTable_getByIndex (poDot3adAggData->u32Index)) != NULL)
	{
		dot3adAggPortListTable_removeEntry (poDot3adAggPortListEntry);
	}
	
	if (!ifData_removeReference (poDot3adAggData->u32Index, true, true, true))
	{
		goto dot3adAggTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
dot3adAggTable_removeHier_cleanup:
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggData_BTree);
	return dot3adAggTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggData_BTree);
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
			
			register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByAggEntry (table_entry);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGACTORSYSTEMPRIORITY:
			case DOT3ADAGGCOLLECTORMAXDELAY:
				if (poDot3adAggData->oNe.u8RowStatus == xRowStatus_active_c || poDot3adAggData->oNe.u8RowStatus == xRowStatus_notReady_c)
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

/* create a new row in the (unsorted) table */
dot3adAggPortListEntry_t *
dot3adAggPortListTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_portListCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poDot3adAggData->au8Flags, dot3adAggFlags_portListCreated_c, 1);
	return &poDot3adAggData->oPortList;
}

dot3adAggPortListEntry_t *
dot3adAggPortListTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_portListCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oPortList;
}

dot3adAggPortListEntry_t *
dot3adAggPortListTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_portListCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oPortList;
}

/* remove a row from the table */
void
dot3adAggPortListTable_removeEntry (dot3adAggPortListEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByPortListEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggData->au8Flags, dot3adAggFlags_portListCreated_c, 0);
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggData_BTree);
	return dot3adAggPortListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggData_BTree);
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
dot3adAggPortData_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortData_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortData_t, oBTreeNode);
	register dot3adAggPortData_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortData_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static int8_t
dot3adAggPortData_Group_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot3adAggPortData_t *pEntry1 = xBTree_entry (pNode1, dot3adAggPortData_t, oBTreeNode);
	register dot3adAggPortData_t *pEntry2 = xBTree_entry (pNode2, dot3adAggPortData_t, oBTreeNode);
	
	return
		(pEntry1->i32GroupType < pEntry2->i32GroupType) ||
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex < pEntry2->u32GroupIndex) ||
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex == pEntry2->u32GroupIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->i32GroupType == pEntry2->i32GroupType && pEntry1->u32GroupIndex == pEntry2->u32GroupIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static xBTree_t oDot3adAggPortData_BTree = xBTree_initInline (&dot3adAggPortData_BTreeNodeCmp);
static xBTree_t oDot3adAggPortData_Group_BTree = xBTree_initInline (&dot3adAggPortData_Group_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot3adAggPortData_t *
dot3adAggPortData_createEntry (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32OperStatus = xOperStatus_notPresent_c;
	poEntry->i32Selection = dot3adAggPortSelection_none_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
	return poEntry;
}

dot3adAggPortData_t *
dot3adAggPortData_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortData_t, oBTreeNode);
}

dot3adAggPortData_t *
dot3adAggPortData_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortData_t, oBTreeNode);
}

dot3adAggPortData_t *
dot3adAggPortData_Group_getByIndex (
	int32_t i32GroupType,
	uint32_t u32GroupIndex,
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32GroupType = i32GroupType;
	poTmpEntry->u32GroupIndex = u32GroupIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot3adAggPortData_Group_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortData_t, oBTreeNode);
}

dot3adAggPortData_t *
dot3adAggPortData_Group_getNextIndex (
	int32_t i32GroupType,
	uint32_t u32GroupIndex,
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32GroupType = i32GroupType;
	poTmpEntry->u32GroupIndex = u32GroupIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot3adAggPortData_Group_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot3adAggPortData_t, oBTreeNode);
}

/* remove a row from the table */
void
dot3adAggPortData_removeEntry (dot3adAggPortData_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* create a new row in the (unsorted) table */
dot3adAggPortEntry_t *
dot3adAggPortTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portCreated_c, 1);
	return &poDot3adAggPortData->oPort;
}

dot3adAggPortEntry_t *
dot3adAggPortTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oPort;
}

dot3adAggPortEntry_t *
dot3adAggPortTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oPort;
}

/* remove a row from the table */
void
dot3adAggPortTable_removeEntry (dot3adAggPortEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portCreated_c, 0);
	return;
}

dot3adAggPortEntry_t *
dot3adAggPortTable_createExt (
	uint32_t u32Index)
{
	dot3adAggPortEntry_t *poEntry = NULL;
	
	poEntry = dot3adAggPortTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto dot3adAggPortTable_createExt_cleanup;
	}
	
	if (!dot3adAggPortTable_createHier (poEntry))
	{
		dot3adAggPortTable_removeEntry (poEntry);
		poEntry = NULL;
		goto dot3adAggPortTable_createExt_cleanup;
	}
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
dot3adAggPortTable_createExt_cleanup:
	return poEntry;
}

bool
dot3adAggPortTable_removeExt (dot3adAggPortEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!dot3adAggPortTable_removeHier (poEntry))
	{
		goto dot3adAggPortTable_removeExt_cleanup;
	}
	dot3adAggPortTable_removeEntry (poEntry);
	bRetCode = true;
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
dot3adAggPortTable_removeExt_cleanup:
	return bRetCode;
}

bool
dot3adAggPortTable_createHier (
	dot3adAggPortEntry_t *poEntry)
{
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortEntry (poEntry);
	
	if (!ifData_createReference (poDot3adAggPortData->u32Index, 0, false, true, false, NULL))
	{
		goto dot3adAggPortTable_createHier_cleanup;
	}
	
	if (dot3adAggPortStatsTable_getByIndex (poDot3adAggPortData->u32Index) == NULL &&
		dot3adAggPortStatsTable_createEntry (poDot3adAggPortData->u32Index) == NULL)
	{
		goto dot3adAggPortTable_createHier_cleanup;
	}
	
	if (dot3adAggPortDebugTable_getByIndex (poDot3adAggPortData->u32Index) == NULL &&
		dot3adAggPortDebugTable_createEntry (poDot3adAggPortData->u32Index) == NULL)
	{
		goto dot3adAggPortTable_createHier_cleanup;
	}
	
	if (dot3adAggPortXTable_getByIndex (poDot3adAggPortData->u32Index) == NULL &&
		dot3adAggPortXTable_createEntry (poDot3adAggPortData->u32Index) == NULL)
	{
		goto dot3adAggPortTable_createHier_cleanup;
	}
	
	return true;
	
	
dot3adAggPortTable_createHier_cleanup:
	
	dot3adAggPortTable_removeHier (poEntry);
	return false;
}

bool
dot3adAggPortTable_removeHier (
	dot3adAggPortEntry_t *poEntry)
{
	register bool bRetCode = false;
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortEntry (poEntry);
	
	{
		register dot3adAggPortXEntry_t *poDot3adAggPortXEntry = NULL;
		
		if ((poDot3adAggPortXEntry = dot3adAggPortXTable_getByIndex (poDot3adAggPortData->u32Index)) != NULL)
		{
			dot3adAggPortXTable_removeEntry (poDot3adAggPortXEntry);
		}
	}
	
	{
		register dot3adAggPortDebugEntry_t *poDot3adAggPortDebugEntry = NULL;
		
		if ((poDot3adAggPortDebugEntry = dot3adAggPortDebugTable_getByIndex (poDot3adAggPortData->u32Index)) != NULL)
		{
			dot3adAggPortDebugTable_removeEntry (poDot3adAggPortDebugEntry);
		}
	}
	
	{
		register dot3adAggPortStatsEntry_t *poDot3adAggPortStatsEntry = NULL;
		
		if ((poDot3adAggPortStatsEntry = dot3adAggPortStatsTable_getByIndex (poDot3adAggPortData->u32Index)) != NULL)
		{
			dot3adAggPortStatsTable_removeEntry (poDot3adAggPortStatsEntry);
		}
	}
	
	if (!ifData_removeReference (poDot3adAggPortData->u32Index, false, true, false))
	{
		goto dot3adAggPortTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
dot3adAggPortTable_removeHier_cleanup:
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortData_BTree);
	return dot3adAggPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
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
			
			register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortEntry (table_entry);
			
			switch (table_info->colnum)
			{
			case DOT3ADAGGPORTACTORADMINKEY:
			case DOT3ADAGGPORTACTOROPERKEY:
			case DOT3ADAGGPORTPARTNERADMINSYSTEMPRIORITY:
			case DOT3ADAGGPORTPARTNERADMINSYSTEMID:
			case DOT3ADAGGPORTPARTNERADMINKEY:
			case DOT3ADAGGPORTACTORPORTPRIORITY:
			case DOT3ADAGGPORTPARTNERADMINPORT:
			case DOT3ADAGGPORTPARTNERADMINPORTPRIORITY:
			case DOT3ADAGGPORTACTORADMINSTATE:
			case DOT3ADAGGPORTPARTNERADMINSTATE:
				if (poDot3adAggPortData->oNe.u8RowStatus == xRowStatus_active_c || poDot3adAggPortData->oNe.u8RowStatus == xRowStatus_notReady_c)
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

/* create a new row in the (unsorted) table */
dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_statsCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_statsCreated_c, 1);
	return &poDot3adAggPortData->oStats;
}

dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_statsCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oStats;
}

dot3adAggPortStatsEntry_t *
dot3adAggPortStatsTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_statsCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oStats;
}

/* remove a row from the table */
void
dot3adAggPortStatsTable_removeEntry (dot3adAggPortStatsEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByStatsEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_statsCreated_c, 0);
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortData_BTree);
	return dot3adAggPortStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
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

/* create a new row in the (unsorted) table */
dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_debugCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_debugCreated_c, 1);
	return &poDot3adAggPortData->oDebug;
}

dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_debugCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oDebug;
}

dot3adAggPortDebugEntry_t *
dot3adAggPortDebugTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_debugCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oDebug;
}

/* remove a row from the table */
void
dot3adAggPortDebugTable_removeEntry (dot3adAggPortDebugEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByDebugEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_debugCreated_c, 0);
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortDebugTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortData_BTree);
	return dot3adAggPortDebugTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortDebugTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
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

/* create a new row in the (unsorted) table */
dot3adAggPortXEntry_t *
dot3adAggPortXTable_createEntry (
	uint32_t u32Index)
{
	register dot3adAggPortXEntry_t *poEntry = NULL;
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portXCreated_c))
	{
		return NULL;
	}
	poEntry = &poDot3adAggPortData->oPortX;
	
	/*poEntry->au8ProtocolDA = 1652522221570*/;
	memcpy (poEntry->au8ProtocolDA, IeeeEui_slowProtocolsMulticast, sizeof (poEntry->au8ProtocolDA));
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portXCreated_c, 1);
	return poEntry;
}

dot3adAggPortXEntry_t *
dot3adAggPortXTable_getByIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portXCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oPortX;
}

dot3adAggPortXEntry_t *
dot3adAggPortXTable_getNextIndex (
	uint32_t u32Index)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getNextIndex (u32Index)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portXCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oPortX;
}

/* remove a row from the table */
void
dot3adAggPortXTable_removeEntry (dot3adAggPortXEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByPortXEntry (poEntry);
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_portXCreated_c, 0);
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot3adAggPortXTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortData_BTree);
	return dot3adAggPortXTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot3adAggPortXTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
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

/** initialize neAggTable table mapper **/
void
neAggTable_init (void)
{
	extern oid neAggTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neAggTable", &neAggTable_mapper,
		neAggTable_oid, OID_LENGTH (neAggTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggIndex */,
		0);
	table_info->min_column = NEAGGGROUPTYPE;
	table_info->max_column = NEAGGSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neAggTable_getFirst;
	iinfo->get_next_data_point = &neAggTable_getNext;
	iinfo->get_data_point = &neAggTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the (unsorted) table */
neAggEntry_t *
neAggTable_createEntry (
	uint32_t u32Dot3adAggIndex)
{
	register neAggEntry_t *poEntry = NULL;
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_createEntry (u32Dot3adAggIndex)) == NULL)
	{
		return NULL;
	}
	poEntry = &poDot3adAggData->oNe;
	
	poEntry->i32GroupType = neAggGroupType_none_c;
	poEntry->u32GroupIndex = 0;
	/*poEntry->au8SpeedMax = 0*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neAggStorageType_nonVolatile_c;
	
	xBitmap_setBit (poDot3adAggData->au8Flags, dot3adAggFlags_neCreated_c, 1); 
	return poEntry;
}

neAggEntry_t *
neAggTable_getByIndex (
	uint32_t u32Dot3adAggIndex)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getByIndex (u32Dot3adAggIndex)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oNe;
}

neAggEntry_t *
neAggTable_getNextIndex (
	uint32_t u32Dot3adAggIndex)
{
	register dot3adAggData_t *poDot3adAggData = NULL;
	
	if ((poDot3adAggData = dot3adAggData_getNextIndex (u32Dot3adAggIndex)) == NULL ||
		!xBitmap_getBit (poDot3adAggData->au8Flags, dot3adAggFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggData->oNe;
}

/* remove a row from the table */
void
neAggTable_removeEntry (neAggEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	dot3adAggData_removeEntry (dot3adAggData_getByNeEntry (poEntry));
	return;
}

neAggEntry_t *
neAggTable_createExt (
	uint32_t u32Dot3adAggIndex)
{
	neAggEntry_t *poEntry = NULL;
	
	poEntry = neAggTable_createEntry (
		u32Dot3adAggIndex);
	if (poEntry == NULL)
	{
		goto neAggTable_createExt_cleanup;
	}
	
	if (!neAggTable_createHier (poEntry))
	{
		neAggTable_removeEntry (poEntry);
		poEntry = NULL;
		goto neAggTable_createExt_cleanup;
	}
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
neAggTable_createExt_cleanup:
	return poEntry;
}

bool
neAggTable_removeExt (neAggEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!neAggTable_removeHier (poEntry))
	{
		goto neAggTable_removeExt_cleanup;
	}
	neAggTable_removeEntry (poEntry);
	bRetCode = true;
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
neAggTable_removeExt_cleanup:
	return bRetCode;
}

bool
neAggTable_createHier (
	neAggEntry_t *poEntry)
{
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByNeEntry (poEntry);
	
	if (dot3adAggTable_getByIndex (poDot3adAggData->u32Index) == NULL &&
		dot3adAggTable_createExt (poDot3adAggData->u32Index) == NULL)
	{
		goto neAggTable_createHier_cleanup;
	}
	
	return true;
	
	
neAggTable_createHier_cleanup:
	
	neAggTable_removeHier (poEntry);
	return false;
}

bool
neAggTable_removeHier (
	neAggEntry_t *poEntry)
{
	register bool bRetCode = false;
	register dot3adAggEntry_t *poDot3adAggEntry = NULL;
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByNeEntry (poEntry);
	
	if ((poDot3adAggEntry = dot3adAggTable_getByIndex (poDot3adAggData->u32Index)) != NULL &&
		!dot3adAggTable_removeExt (poDot3adAggEntry))
	{
		goto neAggTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
neAggTable_removeHier_cleanup:
	return bRetCode;
}

bool
neAggRowStatus_handler (
	neAggEntry_t *poEntry, uint8_t u8RowStatus)
{
	register dot3adAggData_t *poDot3adAggData = dot3adAggData_getByNeEntry (poEntry);
	
	if (poEntry->u8RowStatus == u8RowStatus)
	{
		goto neAggRowStatus_handler_success;
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		
		{
			register uint32_t u32Index = 0;
			register dot3adAggPortData_t *poDot3adAggPortData = NULL;
			
			while (
				(poDot3adAggPortData = dot3adAggPortData_Group_getNextIndex (poDot3adAggData->i32GroupType, poDot3adAggData->u32GroupIndex, u32Index)) != NULL &&
				poDot3adAggPortData->i32GroupType == poDot3adAggData->i32GroupType && poDot3adAggPortData->u32GroupIndex == poDot3adAggData->u32GroupIndex)
			{
				u32Index = poDot3adAggPortData->u32Index;
				
				if (!neAggPortRowStatus_handler (&poDot3adAggPortData->oNe, u8RowStatus | xRowStatus_fromParent_c))
				{
					goto neAggRowStatus_handler_cleanup;
				}
			}
		}
		
		if (!neAggRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_active_c;
		break;
		
	case xRowStatus_notInService_c:
		{
			register uint32_t u32Index = 0;
			register dot3adAggPortData_t *poDot3adAggPortData = NULL;
			
			while (
				(poDot3adAggPortData = dot3adAggPortData_Group_getNextIndex (poDot3adAggData->i32GroupType, poDot3adAggData->u32GroupIndex, u32Index)) != NULL &&
				poDot3adAggPortData->i32GroupType == poDot3adAggData->i32GroupType && poDot3adAggPortData->u32GroupIndex == poDot3adAggData->u32GroupIndex)
			{
				u32Index = poDot3adAggPortData->u32Index;
				
				if (!neAggPortRowStatus_handler (&poDot3adAggPortData->oNe, u8RowStatus | xRowStatus_fromParent_c))
				{
					goto neAggRowStatus_handler_cleanup;
				}
			}
		}
		
		if (!neAggRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto neAggRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		{
			register uint32_t u32Index = 0;
			register dot3adAggPortData_t *poDot3adAggPortData = NULL;
			
			while (
				(poDot3adAggPortData = dot3adAggPortData_Group_getNextIndex (poDot3adAggData->i32GroupType, poDot3adAggData->u32GroupIndex, u32Index)) != NULL &&
				poDot3adAggPortData->i32GroupType == poDot3adAggData->i32GroupType && poDot3adAggPortData->u32GroupIndex == poDot3adAggData->u32GroupIndex)
			{
				u32Index = poDot3adAggPortData->u32Index;
				
				if (!neAggPortRowStatus_handler (&poDot3adAggPortData->oNe, u8RowStatus | xRowStatus_fromParent_c))
				{
					goto neAggRowStatus_handler_cleanup;
				}
			}
		}
		
		if (!neAggRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
neAggRowStatus_handler_success:
	
	return true;
	
	
neAggRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neAggTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggData_BTree);
	return neAggTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neAggTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggData_BTree);
	return put_index_data;
}

bool
neAggTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neAggEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neAggTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neAggTable table mapper */
int
neAggTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neAggEntry_t *table_entry;
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGGROUPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32GroupType);
				break;
			case NEAGGGROUPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32GroupIndex);
				break;
			case NEAGGSPEEDMAX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SpeedMax, table_entry->u16SpeedMax_len);
				break;
			case NEAGGROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEAGGSTORAGETYPE:
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGGROUPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGGROUPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGSPEEDMAX:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SpeedMax));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGSTORAGETYPE:
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEAGGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neAggTable_createEntry (
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neAggTable_removeEntry (table_entry);
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGGROUPTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32GroupType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32GroupType, sizeof (table_entry->i32GroupType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32GroupType = *request->requestvb->val.integer;
				break;
			case NEAGGGROUPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32GroupIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32GroupIndex, sizeof (table_entry->u32GroupIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32GroupIndex = *request->requestvb->val.integer;
				break;
			case NEAGGSPEEDMAX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SpeedMax))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SpeedMax_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SpeedMax, sizeof (table_entry->au8SpeedMax));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SpeedMax, 0, sizeof (table_entry->au8SpeedMax));
				memcpy (table_entry->au8SpeedMax, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SpeedMax_len = request->requestvb->val_len;
				break;
			case NEAGGSTORAGETYPE:
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neAggRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGGROUPTYPE:
				memcpy (&table_entry->i32GroupType, pvOldDdata, sizeof (table_entry->i32GroupType));
				break;
			case NEAGGGROUPINDEX:
				memcpy (&table_entry->u32GroupIndex, pvOldDdata, sizeof (table_entry->u32GroupIndex));
				break;
			case NEAGGSPEEDMAX:
				memcpy (table_entry->au8SpeedMax, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16SpeedMax_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEAGGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neAggTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEAGGSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neAggEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					neAggTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neAggPortListTable table mapper **/
void
neAggPortListTable_init (void)
{
	extern oid neAggPortListTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neAggPortListTable", &neAggPortListTable_mapper,
		neAggPortListTable_oid, OID_LENGTH (neAggPortListTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggIndex */,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = NEAGGPORTSELECTION;
	table_info->max_column = NEAGGPORTSELECTION;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neAggPortListTable_getFirst;
	iinfo->get_next_data_point = &neAggPortListTable_getNext;
	iinfo->get_data_point = &neAggPortListTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neAggPortListTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neAggPortListEntry_t *pEntry1 = xBTree_entry (pNode1, neAggPortListEntry_t, oBTreeNode);
	register neAggPortListEntry_t *pEntry2 = xBTree_entry (pNode2, neAggPortListEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Dot3adAggIndex < pEntry2->u32Dot3adAggIndex) ||
		(pEntry1->u32Dot3adAggIndex == pEntry2->u32Dot3adAggIndex && pEntry1->u32Dot3adAggPortIndex < pEntry2->u32Dot3adAggPortIndex) ? -1:
		(pEntry1->u32Dot3adAggIndex == pEntry2->u32Dot3adAggIndex && pEntry1->u32Dot3adAggPortIndex == pEntry2->u32Dot3adAggPortIndex) ? 0: 1;
}

xBTree_t oNeAggPortListTable_BTree = xBTree_initInline (&neAggPortListTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
neAggPortListEntry_t *
neAggPortListTable_createEntry (
	uint32_t u32Dot3adAggIndex,
	uint32_t u32Dot3adAggPortIndex)
{
	register neAggPortListEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Dot3adAggIndex = u32Dot3adAggIndex;
	poEntry->u32Dot3adAggPortIndex = u32Dot3adAggPortIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeAggPortListTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeAggPortListTable_BTree);
	return poEntry;
}

neAggPortListEntry_t *
neAggPortListTable_getByIndex (
	uint32_t u32Dot3adAggIndex,
	uint32_t u32Dot3adAggPortIndex)
{
	register neAggPortListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Dot3adAggIndex = u32Dot3adAggIndex;
	poTmpEntry->u32Dot3adAggPortIndex = u32Dot3adAggPortIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeAggPortListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neAggPortListEntry_t, oBTreeNode);
}

neAggPortListEntry_t *
neAggPortListTable_getNextIndex (
	uint32_t u32Dot3adAggIndex,
	uint32_t u32Dot3adAggPortIndex)
{
	register neAggPortListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Dot3adAggIndex = u32Dot3adAggIndex;
	poTmpEntry->u32Dot3adAggPortIndex = u32Dot3adAggPortIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeAggPortListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neAggPortListEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neAggPortListTable_removeEntry (neAggPortListEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeAggPortListTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeAggPortListTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neAggPortListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeAggPortListTable_BTree);
	return neAggPortListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neAggPortListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neAggPortListEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neAggPortListEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Dot3adAggIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Dot3adAggPortIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeAggPortListTable_BTree);
	return put_index_data;
}

bool
neAggPortListTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neAggPortListEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neAggPortListTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neAggPortListTable table mapper */
int
neAggPortListTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neAggPortListEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neAggPortListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGPORTSELECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Selection);
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

/** initialize neAggPortTable table mapper **/
void
neAggPortTable_init (void)
{
	extern oid neAggPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neAggPortTable", &neAggPortTable_mapper,
		neAggPortTable_oid, OID_LENGTH (neAggPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: dot3adAggPortIndex */,
		0);
	table_info->min_column = NEAGGPORTGROUPTYPE;
	table_info->max_column = NEAGGPORTSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neAggPortTable_getFirst;
	iinfo->get_next_data_point = &neAggPortTable_getNext;
	iinfo->get_data_point = &neAggPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the (unsorted) table */
neAggPortEntry_t *
neAggPortTable_createEntry (
	uint32_t u32Dot3adAggPortIndex)
{
	register neAggPortEntry_t *poEntry = NULL;
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_createEntry (u32Dot3adAggPortIndex)) == NULL)
	{
		return NULL;
	}
	poEntry = &poDot3adAggPortData->oNe;
	
	poEntry->i32GroupType = neAggPortGroupType_none_c;
	poEntry->u32GroupIndex = 0;
	xBitmap_setBitsRev (poEntry->au8Flags, 2, 1, neAggPortFlags_lacp_c, neAggPortFlags_lacpActive_c);
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neAggPortStorageType_nonVolatile_c;
	
	xBitmap_setBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_neCreated_c, 1); 
	return poEntry;
}

neAggPortEntry_t *
neAggPortTable_getByIndex (
	uint32_t u32Dot3adAggPortIndex)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getByIndex (u32Dot3adAggPortIndex)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oNe;
}

neAggPortEntry_t *
neAggPortTable_getNextIndex (
	uint32_t u32Dot3adAggPortIndex)
{
	register dot3adAggPortData_t *poDot3adAggPortData = NULL;
	
	if ((poDot3adAggPortData = dot3adAggPortData_getNextIndex (u32Dot3adAggPortIndex)) == NULL ||
		!xBitmap_getBit (poDot3adAggPortData->au8Flags, dot3adAggPortFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poDot3adAggPortData->oNe;
}

/* remove a row from the table */
void
neAggPortTable_removeEntry (neAggPortEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	dot3adAggPortData_removeEntry (dot3adAggPortData_getByNeEntry (poEntry));
	return;
}

neAggPortEntry_t *
neAggPortTable_createExt (
	uint32_t u32Dot3adAggPortIndex)
{
	neAggPortEntry_t *poEntry = NULL;
	
	poEntry = neAggPortTable_createEntry (
		u32Dot3adAggPortIndex);
	if (poEntry == NULL)
	{
		goto neAggPortTable_createExt_cleanup;
	}
	
	if (!neAggPortTable_createHier (poEntry))
	{
		neAggPortTable_removeEntry (poEntry);
		poEntry = NULL;
		goto neAggPortTable_createExt_cleanup;
	}
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
neAggPortTable_createExt_cleanup:
	return poEntry;
}

bool
neAggPortTable_removeExt (neAggPortEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!neAggPortTable_removeHier (poEntry))
	{
		goto neAggPortTable_removeExt_cleanup;
	}
	neAggPortTable_removeEntry (poEntry);
	bRetCode = true;
	
	oLagMIBObjects.u32Dot3adTablesLastChanged++;	/* TODO */
	
	
neAggPortTable_removeExt_cleanup:
	return bRetCode;
}

bool
neAggPortTable_createHier (
	neAggPortEntry_t *poEntry)
{
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByNeEntry (poEntry);
	
	if (dot3adAggPortTable_getByIndex (poDot3adAggPortData->u32Index) == NULL &&
		dot3adAggPortTable_createExt (poDot3adAggPortData->u32Index) == NULL)
	{
		goto neAggPortTable_createHier_cleanup;
	}
	
	return true;
	
	
neAggPortTable_createHier_cleanup:
	
	neAggPortTable_removeHier (poEntry);
	return false;
}

bool
neAggPortTable_removeHier (
	neAggPortEntry_t *poEntry)
{
	register bool bRetCode = false;
	register dot3adAggPortEntry_t *poDot3adAggPortEntry = NULL;
	register dot3adAggPortData_t *poDot3adAggPortData = dot3adAggPortData_getByNeEntry (poEntry);
	
	if ((poDot3adAggPortEntry = dot3adAggPortTable_getByIndex (poDot3adAggPortData->u32Index)) != NULL &&
		!dot3adAggPortTable_removeExt (poDot3adAggPortEntry))
	{
		goto neAggPortTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
neAggPortTable_removeHier_cleanup:
	return bRetCode;
}

bool
neAggPortRowStatus_handler (
	neAggPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	if (poEntry->u8RowStatus == u8RowStatus)
	{
		goto neAggPortRowStatus_handler_success;
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		/* TODO */
		
		if (!neAggPortRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggPortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_active_c;
		break;
		
	case xRowStatus_notInService_c:
		if (!neAggPortRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggPortRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_active_c;
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!neAggPortRowStatus_update (poEntry, u8RowStatus))
		{
			goto neAggPortRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
neAggPortRowStatus_handler_success:
	
	return true;
	
	
neAggPortRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neAggPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot3adAggPortData_BTree);
	return neAggPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neAggPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot3adAggPortData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot3adAggPortData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot3adAggPortData_BTree);
	return put_index_data;
}

bool
neAggPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neAggPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neAggPortTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neAggPortTable table mapper */
int
neAggPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neAggPortEntry_t *table_entry;
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGPORTGROUPTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32GroupType);
				break;
			case NEAGGPORTGROUPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32GroupIndex);
				break;
			case NEAGGPORTFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Flags, table_entry->u16Flags_len);
				break;
			case NEAGGPORTROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEAGGPORTSTORAGETYPE:
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGPORTGROUPTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGPORTGROUPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGPORTFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Flags));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGPORTROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEAGGPORTSTORAGETYPE:
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEAGGPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neAggPortTable_createEntry (
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neAggPortTable_removeEntry (table_entry);
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGPORTGROUPTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32GroupType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32GroupType, sizeof (table_entry->i32GroupType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32GroupType = *request->requestvb->val.integer;
				break;
			case NEAGGPORTGROUPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32GroupIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32GroupIndex, sizeof (table_entry->u32GroupIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32GroupIndex = *request->requestvb->val.integer;
				break;
			case NEAGGPORTFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Flags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Flags_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Flags, sizeof (table_entry->au8Flags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Flags, 0, sizeof (table_entry->au8Flags));
				memcpy (table_entry->au8Flags, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Flags_len = request->requestvb->val_len;
				break;
			case NEAGGPORTSTORAGETYPE:
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neAggPortRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEAGGPORTGROUPTYPE:
				memcpy (&table_entry->i32GroupType, pvOldDdata, sizeof (table_entry->i32GroupType));
				break;
			case NEAGGPORTGROUPINDEX:
				memcpy (&table_entry->u32GroupIndex, pvOldDdata, sizeof (table_entry->u32GroupIndex));
				break;
			case NEAGGPORTFLAGS:
				memcpy (table_entry->au8Flags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Flags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEAGGPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neAggPortTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEAGGPORTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neAggPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEAGGPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					neAggPortTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
