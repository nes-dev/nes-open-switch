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
#include "ipForward.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ipForward_oid[] = {1,3,6,1,2,1,4,24};

static oid inetCidrRouteTable_oid[] = {1,3,6,1,2,1,4,24,7};



/**
 *	initialize ipForward group mapper
 */
void
ipForward_init (void)
{
	extern oid ipForward_oid[];
	
	DEBUGMSGTL (("ipForward", "Initializing\n"));
	
	/* register ipForward scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ipForward_mapper", &ipForward_mapper,
			ipForward_oid, OID_LENGTH (ipForward_oid),
			HANDLER_CAN_RONLY
		),
		INETCIDRROUTENUMBER,
		INETCIDRROUTEDISCARDS
	);
	
	
	/* register ipForward group table mappers */
	inetCidrRouteTable_init ();
	
	/* register ipForward modules */
	sysORTable_createRegister ("ipForward", ipForward_oid, OID_LENGTH (ipForward_oid));
}


/**
 *	scalar mapper(s)
 */
ipForward_t oIpForward;

/** ipForward scalar mapper **/
int
ipForward_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ipForward_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ipForward_oid) - 1])
			{
			case INETCIDRROUTENUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, oIpForward.u32InetCidrRouteNumber);
				break;
			case INETCIDRROUTEDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oIpForward.u32InetCidrRouteDiscards);
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
/** initialize inetCidrRouteTable table mapper **/
void
inetCidrRouteTable_init (void)
{
	extern oid inetCidrRouteTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"inetCidrRouteTable", &inetCidrRouteTable_mapper,
		inetCidrRouteTable_oid, OID_LENGTH (inetCidrRouteTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: inetCidrRouteDestType */,
		ASN_OCTET_STR /* index: inetCidrRouteDest */,
		ASN_UNSIGNED /* index: inetCidrRoutePfxLen */,
		ASN_OBJECT_ID /* index: inetCidrRoutePolicy */,
		ASN_INTEGER /* index: inetCidrRouteNextHopType */,
		ASN_OCTET_STR /* index: inetCidrRouteNextHop */,
		0);
	table_info->min_column = INETCIDRROUTEIFINDEX;
	table_info->max_column = INETCIDRROUTESTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &inetCidrRouteTable_getFirst;
	iinfo->get_next_data_point = &inetCidrRouteTable_getNext;
	iinfo->get_data_point = &inetCidrRouteTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
inetCidrRouteTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register inetCidrRouteEntry_t *pEntry1 = xBTree_entry (pNode1, inetCidrRouteEntry_t, oBTreeNode);
	register inetCidrRouteEntry_t *pEntry2 = xBTree_entry (pNode2, inetCidrRouteEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32DestType < pEntry2->i32DestType) ||
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == -1) ||
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32PfxLen < pEntry2->u32PfxLen) ||
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32PfxLen == pEntry2->u32PfxLen && xOidCmp (pEntry1->aoPolicy, pEntry2->aoPolicy, pEntry1->u16Policy_len, pEntry2->u16Policy_len) == -1) ||
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32PfxLen == pEntry2->u32PfxLen && xOidCmp (pEntry1->aoPolicy, pEntry2->aoPolicy, pEntry1->u16Policy_len, pEntry2->u16Policy_len) == 0 && pEntry1->i32NextHopType < pEntry2->i32NextHopType) ||
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32PfxLen == pEntry2->u32PfxLen && xOidCmp (pEntry1->aoPolicy, pEntry2->aoPolicy, pEntry1->u16Policy_len, pEntry2->u16Policy_len) == 0 && pEntry1->i32NextHopType == pEntry2->i32NextHopType && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == -1) ? -1:
		(pEntry1->i32DestType == pEntry2->i32DestType && xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32PfxLen == pEntry2->u32PfxLen && xOidCmp (pEntry1->aoPolicy, pEntry2->aoPolicy, pEntry1->u16Policy_len, pEntry2->u16Policy_len) == 0 && pEntry1->i32NextHopType == pEntry2->i32NextHopType && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0) ? 0: 1;
}

xBTree_t oInetCidrRouteTable_BTree = xBTree_initInline (&inetCidrRouteTable_BTreeNodeCmp);

/* create a new row in the table */
inetCidrRouteEntry_t *
inetCidrRouteTable_createEntry (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len)
{
	register inetCidrRouteEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32DestType = i32DestType;
	memcpy (poEntry->au8Dest, pau8Dest, u16Dest_len);
	poEntry->u16Dest_len = u16Dest_len;
	poEntry->u32PfxLen = u32PfxLen;
	memcpy (poEntry->aoPolicy, paoPolicy, u16Policy_len);
	poEntry->u16Policy_len = u16Policy_len;
	poEntry->i32NextHopType = i32NextHopType;
	memcpy (poEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poEntry->u16NextHop_len = u16NextHop_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oInetCidrRouteTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32NextHopAS = 0;
	poEntry->i32Metric1 = -1;
	poEntry->i32Metric2 = -1;
	poEntry->i32Metric3 = -1;
	poEntry->i32Metric4 = -1;
	poEntry->i32Metric5 = -1;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oInetCidrRouteTable_BTree);
	return poEntry;
}

inetCidrRouteEntry_t *
inetCidrRouteTable_getByIndex (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len)
{
	register inetCidrRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32DestType = i32DestType;
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32PfxLen = u32PfxLen;
	memcpy (poTmpEntry->aoPolicy, paoPolicy, u16Policy_len);
	poTmpEntry->u16Policy_len = u16Policy_len;
	poTmpEntry->i32NextHopType = i32NextHopType;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oInetCidrRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, inetCidrRouteEntry_t, oBTreeNode);
}

inetCidrRouteEntry_t *
inetCidrRouteTable_getNextIndex (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len)
{
	register inetCidrRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32DestType = i32DestType;
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32PfxLen = u32PfxLen;
	memcpy (poTmpEntry->aoPolicy, paoPolicy, u16Policy_len);
	poTmpEntry->u16Policy_len = u16Policy_len;
	poTmpEntry->i32NextHopType = i32NextHopType;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oInetCidrRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, inetCidrRouteEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
inetCidrRouteTable_removeEntry (inetCidrRouteEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oInetCidrRouteTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oInetCidrRouteTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
inetCidrRouteTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oInetCidrRouteTable_BTree);
	return inetCidrRouteTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
inetCidrRouteTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	inetCidrRouteEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, inetCidrRouteEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32DestType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Dest, poEntry->u16Dest_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32PfxLen);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->aoPolicy, poEntry->u16Policy_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32NextHopType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8NextHop, poEntry->u16NextHop_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oInetCidrRouteTable_BTree);
	return put_index_data;
}

bool
inetCidrRouteTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	inetCidrRouteEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	register netsnmp_variable_list *idx6 = idx5->next_variable;
	
	poEntry = inetCidrRouteTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer,
		(void*) idx4->val.string, idx4->val_len,
		*idx5->val.integer,
		(void*) idx6->val.string, idx6->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* inetCidrRouteTable table mapper */
int
inetCidrRouteTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	inetCidrRouteEntry_t *table_entry;
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTEIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case INETCIDRROUTETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case INETCIDRROUTEPROTO:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Proto);
				break;
			case INETCIDRROUTEAGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32Age);
				break;
			case INETCIDRROUTENEXTHOPAS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NextHopAS);
				break;
			case INETCIDRROUTEMETRIC1:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Metric1);
				break;
			case INETCIDRROUTEMETRIC2:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Metric2);
				break;
			case INETCIDRROUTEMETRIC3:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Metric3);
				break;
			case INETCIDRROUTEMETRIC4:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Metric4);
				break;
			case INETCIDRROUTEMETRIC5:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Metric5);
				break;
			case INETCIDRROUTESTATUS:
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTEIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTENEXTHOPAS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTEMETRIC1:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTEMETRIC2:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTEMETRIC3:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTEMETRIC4:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTEMETRIC5:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case INETCIDRROUTESTATUS:
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			register netsnmp_variable_list *idx5 = idx4->next_variable;
			register netsnmp_variable_list *idx6 = idx5->next_variable;
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTESTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = inetCidrRouteTable_createEntry (
						*idx1->val.integer,
						(void*) idx2->val.string, idx2->val_len,
						*idx3->val.integer,
						(void*) idx4->val.string, idx4->val_len,
						*idx5->val.integer,
						(void*) idx6->val.string, idx6->val_len);
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTESTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					inetCidrRouteTable_removeEntry (table_entry);
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTEIFINDEX:
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
			case INETCIDRROUTETYPE:
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
			case INETCIDRROUTENEXTHOPAS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32NextHopAS))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32NextHopAS, sizeof (table_entry->u32NextHopAS));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32NextHopAS = *request->requestvb->val.integer;
				break;
			case INETCIDRROUTEMETRIC1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Metric1))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Metric1, sizeof (table_entry->i32Metric1));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Metric1 = *request->requestvb->val.integer;
				break;
			case INETCIDRROUTEMETRIC2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Metric2))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Metric2, sizeof (table_entry->i32Metric2));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Metric2 = *request->requestvb->val.integer;
				break;
			case INETCIDRROUTEMETRIC3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Metric3))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Metric3, sizeof (table_entry->i32Metric3));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Metric3 = *request->requestvb->val.integer;
				break;
			case INETCIDRROUTEMETRIC4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Metric4))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Metric4, sizeof (table_entry->i32Metric4));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Metric4 = *request->requestvb->val.integer;
				break;
			case INETCIDRROUTEMETRIC5:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Metric5))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Metric5, sizeof (table_entry->i32Metric5));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Metric5 = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTESTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int inetCidrRouteTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTEIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case INETCIDRROUTETYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case INETCIDRROUTENEXTHOPAS:
				memcpy (&table_entry->u32NextHopAS, pvOldDdata, sizeof (table_entry->u32NextHopAS));
				break;
			case INETCIDRROUTEMETRIC1:
				memcpy (&table_entry->i32Metric1, pvOldDdata, sizeof (table_entry->i32Metric1));
				break;
			case INETCIDRROUTEMETRIC2:
				memcpy (&table_entry->i32Metric2, pvOldDdata, sizeof (table_entry->i32Metric2));
				break;
			case INETCIDRROUTEMETRIC3:
				memcpy (&table_entry->i32Metric3, pvOldDdata, sizeof (table_entry->i32Metric3));
				break;
			case INETCIDRROUTEMETRIC4:
				memcpy (&table_entry->i32Metric4, pvOldDdata, sizeof (table_entry->i32Metric4));
				break;
			case INETCIDRROUTEMETRIC5:
				memcpy (&table_entry->i32Metric5, pvOldDdata, sizeof (table_entry->i32Metric5));
				break;
			case INETCIDRROUTESTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					inetCidrRouteTable_removeEntry (table_entry);
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
			table_entry = (inetCidrRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case INETCIDRROUTESTATUS:
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
					inetCidrRouteTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
