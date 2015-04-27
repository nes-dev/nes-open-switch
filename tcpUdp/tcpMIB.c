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
#include "tcpMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid tcp_oid[] = {1,3,6,1,2,1,6};
static oid tcpMIB_oid[] = {1,3,6,1,2,1,49};

static oid tcpConnectionTable_oid[] = {1,3,6,1,2,1,6,19};
static oid tcpListenerTable_oid[] = {1,3,6,1,2,1,6,20};



/**
 *	initialize tcpMIB group mapper
 */
void
tcpMIB_init (void)
{
	extern oid tcp_oid[];
	extern oid tcpMIB_oid[];
	
	DEBUGMSGTL (("tcpMIB", "Initializing\n"));
	
	/* register tcp scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"tcp_mapper", &tcp_mapper,
			tcp_oid, OID_LENGTH (tcp_oid),
			HANDLER_CAN_RONLY
		),
		TCPRTOALGORITHM,
		TCPHCOUTSEGS
	);
	
	
	/* register tcpMIB group table mappers */
	tcpConnectionTable_init ();
	tcpListenerTable_init ();
	
	/* register tcpMIB modules */
	sysORTable_createRegister ("tcp", tcp_oid, OID_LENGTH (tcp_oid));
	sysORTable_createRegister ("tcpMIB", tcpMIB_oid, OID_LENGTH (tcpMIB_oid));
}


/**
 *	scalar mapper(s)
 */
tcp_t oTcp;

/** tcp scalar mapper **/
int
tcp_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid tcp_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (tcp_oid) - 1])
			{
			case TCPRTOALGORITHM:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oTcp.i32RtoAlgorithm);
				break;
			case TCPRTOMIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oTcp.i32RtoMin);
				break;
			case TCPRTOMAX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oTcp.i32RtoMax);
				break;
			case TCPMAXCONN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oTcp.i32MaxConn);
				break;
			case TCPACTIVEOPENS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32ActiveOpens);
				break;
			case TCPPASSIVEOPENS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32PassiveOpens);
				break;
			case TCPATTEMPTFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32AttemptFails);
				break;
			case TCPESTABRESETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32EstabResets);
				break;
			case TCPCURRESTAB:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, oTcp.u32CurrEstab);
				break;
			case TCPINSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32InSegs);
				break;
			case TCPOUTSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32OutSegs);
				break;
			case TCPRETRANSSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32RetransSegs);
				break;
			case TCPINERRS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32InErrs);
				break;
			case TCPOUTRSTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oTcp.u32OutRsts);
				break;
			case TCPHCINSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, oTcp.u64HCInSegs);
				break;
			case TCPHCOUTSEGS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, oTcp.u64HCOutSegs);
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
/** initialize tcpConnectionTable table mapper **/
void
tcpConnectionTable_init (void)
{
	extern oid tcpConnectionTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"tcpConnectionTable", &tcpConnectionTable_mapper,
		tcpConnectionTable_oid, OID_LENGTH (tcpConnectionTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: tcpConnectionLocalAddressType */,
		ASN_OCTET_STR /* index: tcpConnectionLocalAddress */,
		ASN_UNSIGNED /* index: tcpConnectionLocalPort */,
		ASN_INTEGER /* index: tcpConnectionRemAddressType */,
		ASN_OCTET_STR /* index: tcpConnectionRemAddress */,
		ASN_UNSIGNED /* index: tcpConnectionRemPort */,
		0);
	table_info->min_column = TCPCONNECTIONSTATE;
	table_info->max_column = TCPCONNECTIONPROCESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &tcpConnectionTable_getFirst;
	iinfo->get_next_data_point = &tcpConnectionTable_getNext;
	iinfo->get_data_point = &tcpConnectionTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
tcpConnectionTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register tcpConnectionEntry_t *pEntry1 = xBTree_entry (pNode1, tcpConnectionEntry_t, oBTreeNode);
	register tcpConnectionEntry_t *pEntry2 = xBTree_entry (pNode2, tcpConnectionEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32LocalAddressType < pEntry2->i32LocalAddressType) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == -1) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort < pEntry2->u32LocalPort) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemAddressType < pEntry2->i32RemAddressType) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemAddressType == pEntry2->i32RemAddressType && xBinCmp (pEntry1->au8RemAddress, pEntry2->au8RemAddress, pEntry1->u16RemAddress_len, pEntry2->u16RemAddress_len) == -1) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemAddressType == pEntry2->i32RemAddressType && xBinCmp (pEntry1->au8RemAddress, pEntry2->au8RemAddress, pEntry1->u16RemAddress_len, pEntry2->u16RemAddress_len) == 0 && pEntry1->u32RemPort < pEntry2->u32RemPort) ? -1:
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemAddressType == pEntry2->i32RemAddressType && xBinCmp (pEntry1->au8RemAddress, pEntry2->au8RemAddress, pEntry1->u16RemAddress_len, pEntry2->u16RemAddress_len) == 0 && pEntry1->u32RemPort == pEntry2->u32RemPort) ? 0: 1;
}

xBTree_t oTcpConnectionTable_BTree = xBTree_initInline (&tcpConnectionTable_BTreeNodeCmp);

/* create a new row in the table */
tcpConnectionEntry_t *
tcpConnectionTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort)
{
	tcpConnectionEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (tcpConnectionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poEntry->u16LocalAddress_len = u16LocalAddress_len;
	poEntry->u32LocalPort = u32LocalPort;
	poEntry->i32RemAddressType = i32RemAddressType;
	memcpy (poEntry->au8RemAddress, pau8RemAddress, u16RemAddress_len);
	poEntry->u16RemAddress_len = u16RemAddress_len;
	poEntry->u32RemPort = u32RemPort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTcpConnectionTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTcpConnectionTable_BTree);
	return poEntry;
}

tcpConnectionEntry_t *
tcpConnectionTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort)
{
	register tcpConnectionEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (tcpConnectionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	poTmpEntry->i32RemAddressType = i32RemAddressType;
	memcpy (poTmpEntry->au8RemAddress, pau8RemAddress, u16RemAddress_len);
	poTmpEntry->u16RemAddress_len = u16RemAddress_len;
	poTmpEntry->u32RemPort = u32RemPort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTcpConnectionTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, tcpConnectionEntry_t, oBTreeNode);
}

tcpConnectionEntry_t *
tcpConnectionTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort)
{
	register tcpConnectionEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (tcpConnectionEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	poTmpEntry->i32RemAddressType = i32RemAddressType;
	memcpy (poTmpEntry->au8RemAddress, pau8RemAddress, u16RemAddress_len);
	poTmpEntry->u16RemAddress_len = u16RemAddress_len;
	poTmpEntry->u32RemPort = u32RemPort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTcpConnectionTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, tcpConnectionEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
tcpConnectionTable_removeEntry (tcpConnectionEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTcpConnectionTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTcpConnectionTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
tcpConnectionTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTcpConnectionTable_BTree);
	return tcpConnectionTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
tcpConnectionTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	tcpConnectionEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, tcpConnectionEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LocalAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LocalPort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32RemAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8RemAddress, poEntry->u16RemAddress_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32RemPort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTcpConnectionTable_BTree);
	return put_index_data;
}

bool
tcpConnectionTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	tcpConnectionEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	register netsnmp_variable_list *idx6 = idx5->next_variable;
	
	poEntry = tcpConnectionTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer,
		*idx4->val.integer,
		(void*) idx5->val.string, idx5->val_len,
		*idx6->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* tcpConnectionTable table mapper */
int
tcpConnectionTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	tcpConnectionEntry_t *table_entry;
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
			table_entry = (tcpConnectionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TCPCONNECTIONSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case TCPCONNECTIONPROCESS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Process);
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
			table_entry = (tcpConnectionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TCPCONNECTIONSTATE:
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
			table_entry = (tcpConnectionEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (tcpConnectionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case TCPCONNECTIONSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32State))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32State, sizeof (table_entry->i32State));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32State = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (tcpConnectionEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TCPCONNECTIONSTATE:
				memcpy (&table_entry->i32State, pvOldDdata, sizeof (table_entry->i32State));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize tcpListenerTable table mapper **/
void
tcpListenerTable_init (void)
{
	extern oid tcpListenerTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"tcpListenerTable", &tcpListenerTable_mapper,
		tcpListenerTable_oid, OID_LENGTH (tcpListenerTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: tcpListenerLocalAddressType */,
		ASN_OCTET_STR /* index: tcpListenerLocalAddress */,
		ASN_UNSIGNED /* index: tcpListenerLocalPort */,
		0);
	table_info->min_column = TCPLISTENERPROCESS;
	table_info->max_column = TCPLISTENERPROCESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &tcpListenerTable_getFirst;
	iinfo->get_next_data_point = &tcpListenerTable_getNext;
	iinfo->get_data_point = &tcpListenerTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
tcpListenerTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register tcpListenerEntry_t *pEntry1 = xBTree_entry (pNode1, tcpListenerEntry_t, oBTreeNode);
	register tcpListenerEntry_t *pEntry2 = xBTree_entry (pNode2, tcpListenerEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32LocalAddressType < pEntry2->i32LocalAddressType) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == -1) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort < pEntry2->u32LocalPort) ? -1:
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort) ? 0: 1;
}

xBTree_t oTcpListenerTable_BTree = xBTree_initInline (&tcpListenerTable_BTreeNodeCmp);

/* create a new row in the table */
tcpListenerEntry_t *
tcpListenerTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort)
{
	tcpListenerEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (tcpListenerEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poEntry->u16LocalAddress_len = u16LocalAddress_len;
	poEntry->u32LocalPort = u32LocalPort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oTcpListenerTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oTcpListenerTable_BTree);
	return poEntry;
}

tcpListenerEntry_t *
tcpListenerTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort)
{
	register tcpListenerEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (tcpListenerEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oTcpListenerTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, tcpListenerEntry_t, oBTreeNode);
}

tcpListenerEntry_t *
tcpListenerTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort)
{
	register tcpListenerEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (tcpListenerEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oTcpListenerTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, tcpListenerEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
tcpListenerTable_removeEntry (tcpListenerEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oTcpListenerTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oTcpListenerTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
tcpListenerTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oTcpListenerTable_BTree);
	return tcpListenerTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
tcpListenerTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	tcpListenerEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, tcpListenerEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LocalAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LocalPort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oTcpListenerTable_BTree);
	return put_index_data;
}

bool
tcpListenerTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	tcpListenerEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = tcpListenerTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* tcpListenerTable table mapper */
int
tcpListenerTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	tcpListenerEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (tcpListenerEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case TCPLISTENERPROCESS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Process);
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
