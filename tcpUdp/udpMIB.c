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
#include "udpMIB.h"

#include "system_ext.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid udp_oid[] = {1,3,6,1,2,1,7};
static oid udpMIB_oid[] = {1,3,6,1,2,1,50};

static oid udpEndpointTable_oid[] = {1,3,6,1,2,1,7,7};



/**
 *	initialize udpMIB group mapper
 */
void
udpMIB_init (void)
{
	extern oid udp_oid[];
	extern oid udpMIB_oid[];
	
	DEBUGMSGTL (("udpMIB", "Initializing\n"));
	
	/* register udp scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"udp_mapper", &udp_mapper,
			udp_oid, OID_LENGTH (udp_oid),
			HANDLER_CAN_RONLY
		),
		UDPINDATAGRAMS,
		UDPHCOUTDATAGRAMS
	);
	
	
	/* register udpMIB group table mappers */
	udpEndpointTable_init ();
	
	/* register udpMIB modules */
	sysORTable_createRegister ("udp", udp_oid, OID_LENGTH (udp_oid));
	sysORTable_createRegister ("udpMIB", udpMIB_oid, OID_LENGTH (udpMIB_oid));
}


/**
 *	scalar mapper(s)
 */
udp_t oUdp;

/** udp scalar mapper **/
int
udp_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid udp_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (udp_oid) - 1])
			{
			case UDPINDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUdp.u32InDatagrams);
				break;
			case UDPNOPORTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUdp.u32NoPorts);
				break;
			case UDPINERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUdp.u32InErrors);
				break;
			case UDPOUTDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, oUdp.u32OutDatagrams);
				break;
			case UDPHCINDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, oUdp.u64HCInDatagrams);
				break;
			case UDPHCOUTDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, oUdp.u64HCOutDatagrams);
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
/** initialize udpEndpointTable table mapper **/
void
udpEndpointTable_init (void)
{
	extern oid udpEndpointTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"udpEndpointTable", &udpEndpointTable_mapper,
		udpEndpointTable_oid, OID_LENGTH (udpEndpointTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: udpEndpointLocalAddressType */,
		ASN_OCTET_STR /* index: udpEndpointLocalAddress */,
		ASN_UNSIGNED /* index: udpEndpointLocalPort */,
		ASN_INTEGER /* index: udpEndpointRemoteAddressType */,
		ASN_OCTET_STR /* index: udpEndpointRemoteAddress */,
		ASN_UNSIGNED /* index: udpEndpointRemotePort */,
		ASN_UNSIGNED /* index: udpEndpointInstance */,
		0);
	table_info->min_column = UDPENDPOINTPROCESS;
	table_info->max_column = UDPENDPOINTPROCESS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &udpEndpointTable_getFirst;
	iinfo->get_next_data_point = &udpEndpointTable_getNext;
	iinfo->get_data_point = &udpEndpointTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
udpEndpointTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register udpEndpointEntry_t *pEntry1 = xBTree_entry (pNode1, udpEndpointEntry_t, oBTreeNode);
	register udpEndpointEntry_t *pEntry2 = xBTree_entry (pNode2, udpEndpointEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32LocalAddressType < pEntry2->i32LocalAddressType) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == -1) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort < pEntry2->u32LocalPort) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemoteAddressType < pEntry2->i32RemoteAddressType) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemoteAddressType == pEntry2->i32RemoteAddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == -1) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemoteAddressType == pEntry2->i32RemoteAddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == 0 && pEntry1->u32RemotePort < pEntry2->u32RemotePort) ||
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemoteAddressType == pEntry2->i32RemoteAddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == 0 && pEntry1->u32RemotePort == pEntry2->u32RemotePort && pEntry1->u32Instance < pEntry2->u32Instance) ? -1:
		(pEntry1->i32LocalAddressType == pEntry2->i32LocalAddressType && xBinCmp (pEntry1->au8LocalAddress, pEntry2->au8LocalAddress, pEntry1->u16LocalAddress_len, pEntry2->u16LocalAddress_len) == 0 && pEntry1->u32LocalPort == pEntry2->u32LocalPort && pEntry1->i32RemoteAddressType == pEntry2->i32RemoteAddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == 0 && pEntry1->u32RemotePort == pEntry2->u32RemotePort && pEntry1->u32Instance == pEntry2->u32Instance) ? 0: 1;
}

xBTree_t oUdpEndpointTable_BTree = xBTree_initInline (&udpEndpointTable_BTreeNodeCmp);

/* create a new row in the table */
udpEndpointEntry_t *
udpEndpointTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance)
{
	udpEndpointEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (udpEndpointEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poEntry->u16LocalAddress_len = u16LocalAddress_len;
	poEntry->u32LocalPort = u32LocalPort;
	poEntry->i32RemoteAddressType = i32RemoteAddressType;
	memcpy (poEntry->au8RemoteAddress, pau8RemoteAddress, u16RemoteAddress_len);
	poEntry->u16RemoteAddress_len = u16RemoteAddress_len;
	poEntry->u32RemotePort = u32RemotePort;
	poEntry->u32Instance = u32Instance;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oUdpEndpointTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oUdpEndpointTable_BTree);
	return poEntry;
}

udpEndpointEntry_t *
udpEndpointTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance)
{
	register udpEndpointEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (udpEndpointEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	poTmpEntry->i32RemoteAddressType = i32RemoteAddressType;
	memcpy (poTmpEntry->au8RemoteAddress, pau8RemoteAddress, u16RemoteAddress_len);
	poTmpEntry->u16RemoteAddress_len = u16RemoteAddress_len;
	poTmpEntry->u32RemotePort = u32RemotePort;
	poTmpEntry->u32Instance = u32Instance;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oUdpEndpointTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, udpEndpointEntry_t, oBTreeNode);
}

udpEndpointEntry_t *
udpEndpointTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance)
{
	register udpEndpointEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (udpEndpointEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32LocalAddressType = i32LocalAddressType;
	memcpy (poTmpEntry->au8LocalAddress, pau8LocalAddress, u16LocalAddress_len);
	poTmpEntry->u16LocalAddress_len = u16LocalAddress_len;
	poTmpEntry->u32LocalPort = u32LocalPort;
	poTmpEntry->i32RemoteAddressType = i32RemoteAddressType;
	memcpy (poTmpEntry->au8RemoteAddress, pau8RemoteAddress, u16RemoteAddress_len);
	poTmpEntry->u16RemoteAddress_len = u16RemoteAddress_len;
	poTmpEntry->u32RemotePort = u32RemotePort;
	poTmpEntry->u32Instance = u32Instance;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oUdpEndpointTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, udpEndpointEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
udpEndpointTable_removeEntry (udpEndpointEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oUdpEndpointTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oUdpEndpointTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
udpEndpointTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oUdpEndpointTable_BTree);
	return udpEndpointTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
udpEndpointTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	udpEndpointEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, udpEndpointEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32LocalAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LocalPort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32RemoteAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8RemoteAddress, poEntry->u16RemoteAddress_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32RemotePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Instance);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oUdpEndpointTable_BTree);
	return put_index_data;
}

bool
udpEndpointTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	udpEndpointEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	register netsnmp_variable_list *idx6 = idx5->next_variable;
	register netsnmp_variable_list *idx7 = idx6->next_variable;
	
	poEntry = udpEndpointTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len,
		*idx3->val.integer,
		*idx4->val.integer,
		(void*) idx5->val.string, idx5->val_len,
		*idx6->val.integer,
		*idx7->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* udpEndpointTable table mapper */
int
udpEndpointTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	udpEndpointEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (udpEndpointEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case UDPENDPOINTPROCESS:
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
