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
#include "ieee8021PbbMib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021PbbMib_oid[] = {1,3,111,2,802,1,1,9};

/* array length = OID_LENGTH + 1 */
static oid ieee8021PbbBackboneEdgeBridgeObjects_oid[] = {1,3,111,2,802,1,1,9,1,1,1,1};

static oid ieee8021PbbVipTable_oid[] = {1,3,111,2,802,1,1,9,1,1,2};
static oid ieee8021PbbISidToVipTable_oid[] = {1,3,111,2,802,1,1,9,1,1,3};
static oid ieee8021PbbPipTable_oid[] = {1,3,111,2,802,1,1,9,1,1,4};
static oid ieee8021PbbPipPriorityTable_oid[] = {1,3,111,2,802,1,1,9,1,1,5};
static oid ieee8021PbbPipDecodingTable_oid[] = {1,3,111,2,802,1,1,9,1,1,6};
static oid ieee8021PbbPipEncodingTable_oid[] = {1,3,111,2,802,1,1,9,1,1,7};
static oid ieee8021PbbVipToPipMappingTable_oid[] = {1,3,111,2,802,1,1,9,1,1,8};
static oid ieee8021PbbCBPServiceMappingTable_oid[] = {1,3,111,2,802,1,1,9,1,1,9};
static oid ieee8021PbbCbpTable_oid[] = {1,3,111,2,802,1,1,9,1,1,10};



/**
 *	initialize ieee8021PbbMib group mapper
 */
void
ieee8021PbbMib_init (void)
{
	extern oid ieee8021PbbMib_oid[];
	extern oid ieee8021PbbBackboneEdgeBridgeObjects_oid[];
	
	DEBUGMSGTL (("ieee8021PbbMib", "Initializing\n"));
	
	/* register ieee8021PbbBackboneEdgeBridgeObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ieee8021PbbBackboneEdgeBridgeObjects_mapper", &ieee8021PbbBackboneEdgeBridgeObjects_mapper,
			ieee8021PbbBackboneEdgeBridgeObjects_oid, OID_LENGTH (ieee8021PbbBackboneEdgeBridgeObjects_oid) - 1,
			HANDLER_CAN_RWRITE
		),
		IEEE8021PBBBACKBONEEDGEBRIDGEADDRESS,
		IEEE8021PBBNEXTAVAILABLEPIPIFINDEX
	);
	
	
	/* register ieee8021PbbMib group table mappers */
	ieee8021PbbVipTable_init ();
	ieee8021PbbISidToVipTable_init ();
	ieee8021PbbPipTable_init ();
	ieee8021PbbPipPriorityTable_init ();
	ieee8021PbbPipDecodingTable_init ();
	ieee8021PbbPipEncodingTable_init ();
	ieee8021PbbVipToPipMappingTable_init ();
	ieee8021PbbCBPServiceMappingTable_init ();
	ieee8021PbbCbpTable_init ();
	
	/* register ieee8021PbbMib modules */
	sysORTable_createRegister ("ieee8021PbbMib", ieee8021PbbMib_oid, OID_LENGTH (ieee8021PbbMib_oid));
}


/**
 *	scalar mapper(s)
 */
ieee8021PbbBackboneEdgeBridgeObjects_t oIeee8021PbbBackboneEdgeBridgeObjects;

/** ieee8021PbbBackboneEdgeBridgeObjects scalar mapper **/
int
ieee8021PbbBackboneEdgeBridgeObjects_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ieee8021PbbBackboneEdgeBridgeObjects_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021PbbBackboneEdgeBridgeObjects_oid) - 1])
			{
			case IEEE8021PBBBACKBONEEDGEBRIDGEADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021PbbBackboneEdgeBridgeObjects.au8BackboneEdgeBridgeAddress, oIeee8021PbbBackboneEdgeBridgeObjects.u16BackboneEdgeBridgeAddress_len);
				break;
			case IEEE8021PBBBACKBONEEDGEBRIDGENAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oIeee8021PbbBackboneEdgeBridgeObjects.au8BackboneEdgeBridgeName, oIeee8021PbbBackboneEdgeBridgeObjects.u16BackboneEdgeBridgeName_len);
				break;
			case IEEE8021PBBNUMBEROFICOMPONENTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIeee8021PbbBackboneEdgeBridgeObjects.u32NumberOfIComponents);
				break;
			case IEEE8021PBBNUMBEROFBCOMPONENTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIeee8021PbbBackboneEdgeBridgeObjects.u32NumberOfBComponents);
				break;
			case IEEE8021PBBNUMBEROFBEBPORTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oIeee8021PbbBackboneEdgeBridgeObjects.u32NumberOfBebPorts);
				break;
			case IEEE8021PBBNEXTAVAILABLEPIPIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIeee8021PbbBackboneEdgeBridgeObjects.u32NextAvailablePipIfIndex);
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				continue;
			}
		}
		break;
		
	/*
	 * SET REQUEST
	 *
	 * multiple states in the transaction.  See:
	 * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
	 */
	case MODE_SET_RESERVE1:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021PbbBackboneEdgeBridgeObjects_oid) - 1])
			{
			case IEEE8021PBBBACKBONEEDGEBRIDGENAME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_OCTET_STR);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				continue;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021PbbBackboneEdgeBridgeObjects_oid) - 1])
			{
			case IEEE8021PBBBACKBONEEDGEBRIDGENAME:
				/* XXX: perform the value change here */
				memset (oIeee8021PbbBackboneEdgeBridgeObjects.au8BackboneEdgeBridgeName, 0, sizeof (oIeee8021PbbBackboneEdgeBridgeObjects.au8BackboneEdgeBridgeName));
				memcpy (oIeee8021PbbBackboneEdgeBridgeObjects.au8BackboneEdgeBridgeName, request->requestvb->val.string, request->requestvb->val_len);
				oIeee8021PbbBackboneEdgeBridgeObjects.u16BackboneEdgeBridgeName_len = request->requestvb->val_len;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021PbbBackboneEdgeBridgeObjects_oid) - 1])
			{
			case IEEE8021PBBBACKBONEEDGEBRIDGENAME:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
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
/** initialize ieee8021PbbVipTable table mapper **/
void
ieee8021PbbVipTable_init (void)
{
	extern oid ieee8021PbbVipTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbVipTable", &ieee8021PbbVipTable_mapper,
		ieee8021PbbVipTable_oid, OID_LENGTH (ieee8021PbbVipTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBBVIPPIPIFINDEX;
	table_info->max_column = IEEE8021PBBVIPENABLECONNECTIONID;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbVipTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbVipTable_getNext;
	iinfo->get_data_point = &ieee8021PbbVipTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbVipTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbVipEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbVipEntry_t, oBTreeNode);
	register ieee8021PbbVipEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbVipEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbbVipTable_BTree = xBTree_initInline (&ieee8021PbbVipTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbVipEntry_t *
ieee8021PbbVipTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021PbbVipEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32PipIfIndex = 0;
	poEntry->u32ISid = 1;
	/*poEntry->au8DefaultDstBMAC = 131046834177*/;
	/*poEntry->au8Type = ieee8021PbbVipType_{ egress , ingress }_c*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->i32EnableConnectionId = ieee8021PbbVipEnableConnectionId_true_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree);
	return poEntry;
}

ieee8021PbbVipEntry_t *
ieee8021PbbVipTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbVipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbVipEntry_t, oBTreeNode);
}

ieee8021PbbVipEntry_t *
ieee8021PbbVipTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbVipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbVipEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbVipTable_removeEntry (ieee8021PbbVipEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbVipTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbVipTable_BTree);
	return ieee8021PbbVipTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbVipTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbVipEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbVipEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbVipTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbVipTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbVipEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbVipTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbVipTable table mapper */
int
ieee8021PbbVipTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbVipEntry_t *table_entry;
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPPIPIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32PipIfIndex);
				break;
			case IEEE8021PBBVIPISID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ISid);
				break;
			case IEEE8021PBBVIPDEFAULTDSTBMAC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DefaultDstBMAC, table_entry->u16DefaultDstBMAC_len);
				break;
			case IEEE8021PBBVIPTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
				break;
			case IEEE8021PBBVIPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case IEEE8021PBBVIPENABLECONNECTIONID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableConnectionId);
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPISID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBVIPTYPE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Type));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBVIPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBVIPENABLECONNECTIONID:
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbVipTable_createEntry (
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbVipTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPISID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ISid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ISid, sizeof (table_entry->u32ISid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ISid = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBVIPTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Type))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Type_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Type, sizeof (table_entry->au8Type));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Type, 0, sizeof (table_entry->au8Type));
				memcpy (table_entry->au8Type, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Type_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBVIPENABLECONNECTIONID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableConnectionId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableConnectionId, sizeof (table_entry->i32EnableConnectionId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableConnectionId = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbVipTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPISID:
				memcpy (&table_entry->u32ISid, pvOldDdata, sizeof (table_entry->u32ISid));
				break;
			case IEEE8021PBBVIPTYPE:
				memcpy (table_entry->au8Type, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Type_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBVIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbVipTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case IEEE8021PBBVIPENABLECONNECTIONID:
				memcpy (&table_entry->i32EnableConnectionId, pvOldDdata, sizeof (table_entry->i32EnableConnectionId));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPROWSTATUS:
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
					ieee8021PbbVipTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbISidToVipTable table mapper **/
void
ieee8021PbbISidToVipTable_init (void)
{
	extern oid ieee8021PbbISidToVipTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbISidToVipTable", &ieee8021PbbISidToVipTable_mapper,
		ieee8021PbbISidToVipTable_oid, OID_LENGTH (ieee8021PbbISidToVipTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021PbbISidToVipISid */,
		0);
	table_info->min_column = IEEE8021PBBISIDTOVIPCOMPONENTID;
	table_info->max_column = IEEE8021PBBISIDTOVIPPORT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbISidToVipTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbISidToVipTable_getNext;
	iinfo->get_data_point = &ieee8021PbbISidToVipTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbISidToVipTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbISidToVipEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbISidToVipEntry_t, oBTreeNode);
	register ieee8021PbbISidToVipEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbISidToVipEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ISid < pEntry2->u32ISid) ? -1:
		(pEntry1->u32ISid == pEntry2->u32ISid) ? 0: 1;
}

xBTree_t oIeee8021PbbISidToVipTable_BTree = xBTree_initInline (&ieee8021PbbISidToVipTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbISidToVipEntry_t *
ieee8021PbbISidToVipTable_createEntry (
	uint32_t u32ISid)
{
	ieee8021PbbISidToVipEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbISidToVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ISid = u32ISid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree);
	return poEntry;
}

ieee8021PbbISidToVipEntry_t *
ieee8021PbbISidToVipTable_getByIndex (
	uint32_t u32ISid)
{
	register ieee8021PbbISidToVipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbISidToVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ISid = u32ISid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbISidToVipEntry_t, oBTreeNode);
}

ieee8021PbbISidToVipEntry_t *
ieee8021PbbISidToVipTable_getNextIndex (
	uint32_t u32ISid)
{
	register ieee8021PbbISidToVipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbISidToVipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ISid = u32ISid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbISidToVipEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbISidToVipTable_removeEntry (ieee8021PbbISidToVipEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbISidToVipTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbISidToVipTable_BTree);
	return ieee8021PbbISidToVipTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbISidToVipTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbISidToVipEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbISidToVipEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ISid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbISidToVipTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbISidToVipTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbISidToVipEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021PbbISidToVipTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbISidToVipTable table mapper */
int
ieee8021PbbISidToVipTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbISidToVipEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbISidToVipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBISIDTOVIPCOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ComponentId);
				break;
			case IEEE8021PBBISIDTOVIPPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Port);
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

/** initialize ieee8021PbbPipTable table mapper **/
void
ieee8021PbbPipTable_init (void)
{
	extern oid ieee8021PbbPipTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbPipTable", &ieee8021PbbPipTable_mapper,
		ieee8021PbbPipTable_oid, OID_LENGTH (ieee8021PbbPipTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021PbbPipIfIndex */,
		0);
	table_info->min_column = IEEE8021PBBPIPBMACADDRESS;
	table_info->max_column = IEEE8021PBBPIPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbPipTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbPipTable_getNext;
	iinfo->get_data_point = &ieee8021PbbPipTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbPipTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbPipEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbPipEntry_t, oBTreeNode);
	register ieee8021PbbPipEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbPipEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIeee8021PbbPipTable_BTree = xBTree_initInline (&ieee8021PbbPipTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbPipEntry_t *
ieee8021PbbPipTable_createEntry (
	uint32_t u32IfIndex)
{
	ieee8021PbbPipEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Name = 0*/;
	/*poEntry->au8VipMap = 0*/;
	/*poEntry->au8VipMap1 = 0*/;
	/*poEntry->au8VipMap2 = 0*/;
	/*poEntry->au8VipMap3 = 0*/;
	/*poEntry->au8VipMap4 = 0*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree);
	return poEntry;
}

ieee8021PbbPipEntry_t *
ieee8021PbbPipTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ieee8021PbbPipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipEntry_t, oBTreeNode);
}

ieee8021PbbPipEntry_t *
ieee8021PbbPipTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ieee8021PbbPipEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbPipTable_removeEntry (ieee8021PbbPipEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbPipTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbPipTable_BTree);
	return ieee8021PbbPipTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbPipTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbPipEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbPipTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbPipTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021PbbPipTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbPipTable table mapper */
int
ieee8021PbbPipTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbPipEntry_t *table_entry;
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPBMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8BMACAddress, table_entry->u16BMACAddress_len);
				break;
			case IEEE8021PBBPIPNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case IEEE8021PBBPIPICOMPONENTID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IComponentId);
				break;
			case IEEE8021PBBPIPVIPMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8VipMap, table_entry->u16VipMap_len);
				break;
			case IEEE8021PBBPIPVIPMAP1:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8VipMap1, table_entry->u16VipMap1_len);
				break;
			case IEEE8021PBBPIPVIPMAP2:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8VipMap2, table_entry->u16VipMap2_len);
				break;
			case IEEE8021PBBPIPVIPMAP3:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8VipMap3, table_entry->u16VipMap3_len);
				break;
			case IEEE8021PBBPIPVIPMAP4:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8VipMap4, table_entry->u16VipMap4_len);
				break;
			case IEEE8021PBBPIPROWSTATUS:
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPBMACADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8BMACAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPVIPMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8VipMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPVIPMAP1:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8VipMap1));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPVIPMAP2:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8VipMap2));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPVIPMAP3:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8VipMap3));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPVIPMAP4:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8VipMap4));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPROWSTATUS:
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbPipTable_createEntry (
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbPipTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPBMACADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8BMACAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16BMACAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8BMACAddress, sizeof (table_entry->au8BMACAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8BMACAddress, 0, sizeof (table_entry->au8BMACAddress));
				memcpy (table_entry->au8BMACAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16BMACAddress_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBPIPNAME:
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
			case IEEE8021PBBPIPVIPMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8VipMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16VipMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8VipMap, sizeof (table_entry->au8VipMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8VipMap, 0, sizeof (table_entry->au8VipMap));
				memcpy (table_entry->au8VipMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16VipMap_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBPIPVIPMAP1:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8VipMap1))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16VipMap1_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8VipMap1, sizeof (table_entry->au8VipMap1));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8VipMap1, 0, sizeof (table_entry->au8VipMap1));
				memcpy (table_entry->au8VipMap1, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16VipMap1_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBPIPVIPMAP2:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8VipMap2))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16VipMap2_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8VipMap2, sizeof (table_entry->au8VipMap2));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8VipMap2, 0, sizeof (table_entry->au8VipMap2));
				memcpy (table_entry->au8VipMap2, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16VipMap2_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBPIPVIPMAP3:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8VipMap3))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16VipMap3_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8VipMap3, sizeof (table_entry->au8VipMap3));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8VipMap3, 0, sizeof (table_entry->au8VipMap3));
				memcpy (table_entry->au8VipMap3, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16VipMap3_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBPIPVIPMAP4:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8VipMap4))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16VipMap4_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8VipMap4, sizeof (table_entry->au8VipMap4));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8VipMap4, 0, sizeof (table_entry->au8VipMap4));
				memcpy (table_entry->au8VipMap4, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16VipMap4_len = request->requestvb->val_len;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbPipTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPBMACADDRESS:
				memcpy (table_entry->au8BMACAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16BMACAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPVIPMAP:
				memcpy (table_entry->au8VipMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16VipMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPVIPMAP1:
				memcpy (table_entry->au8VipMap1, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16VipMap1_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPVIPMAP2:
				memcpy (table_entry->au8VipMap2, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16VipMap2_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPVIPMAP3:
				memcpy (table_entry->au8VipMap3, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16VipMap3_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPVIPMAP4:
				memcpy (table_entry->au8VipMap4, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16VipMap4_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBPIPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbPipTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbPipEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPROWSTATUS:
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
					ieee8021PbbPipTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbPipPriorityTable table mapper **/
void
ieee8021PbbPipPriorityTable_init (void)
{
	extern oid ieee8021PbbPipPriorityTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbPipPriorityTable", &ieee8021PbbPipPriorityTable_mapper,
		ieee8021PbbPipPriorityTable_oid, OID_LENGTH (ieee8021PbbPipPriorityTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021PbbPipIfIndex */,
		0);
	table_info->min_column = IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION;
	table_info->max_column = IEEE8021PBBPIPREQUIREDROPENCODING;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbPipPriorityTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbPipPriorityTable_getNext;
	iinfo->get_data_point = &ieee8021PbbPipPriorityTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbPipPriorityTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbPipPriorityEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbPipPriorityEntry_t, oBTreeNode);
	register ieee8021PbbPipPriorityEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbPipPriorityEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIeee8021PbbPipPriorityTable_BTree = xBTree_initInline (&ieee8021PbbPipPriorityTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbPipPriorityEntry_t *
ieee8021PbbPipPriorityTable_createEntry (
	uint32_t u32IfIndex)
{
	ieee8021PbbPipPriorityEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipPriorityEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32RequireDropEncoding = ieee8021PbbPipRequireDropEncoding_false_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree);
	return poEntry;
}

ieee8021PbbPipPriorityEntry_t *
ieee8021PbbPipPriorityTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ieee8021PbbPipPriorityEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipPriorityEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipPriorityEntry_t, oBTreeNode);
}

ieee8021PbbPipPriorityEntry_t *
ieee8021PbbPipPriorityTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ieee8021PbbPipPriorityEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipPriorityEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipPriorityEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbPipPriorityTable_removeEntry (ieee8021PbbPipPriorityEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbPipPriorityTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbPipPriorityTable_BTree);
	return ieee8021PbbPipPriorityTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbPipPriorityTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipPriorityEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbPipPriorityEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbPipPriorityTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbPipPriorityTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipPriorityEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021PbbPipPriorityTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbPipPriorityTable table mapper */
int
ieee8021PbbPipPriorityTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbPipPriorityEntry_t *table_entry;
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
			table_entry = (ieee8021PbbPipPriorityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CodePointSelection);
				break;
			case IEEE8021PBBPIPUSEDEI:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UseDEI);
				break;
			case IEEE8021PBBPIPREQUIREDROPENCODING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RequireDropEncoding);
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
			table_entry = (ieee8021PbbPipPriorityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPUSEDEI:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPREQUIREDROPENCODING:
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
			table_entry = (ieee8021PbbPipPriorityEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021PbbPipPriorityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CodePointSelection))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CodePointSelection, sizeof (table_entry->i32CodePointSelection));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CodePointSelection = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBPIPUSEDEI:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UseDEI))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UseDEI, sizeof (table_entry->i32UseDEI));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UseDEI = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBPIPREQUIREDROPENCODING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RequireDropEncoding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RequireDropEncoding, sizeof (table_entry->i32RequireDropEncoding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RequireDropEncoding = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbbPipPriorityEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION:
				memcpy (&table_entry->i32CodePointSelection, pvOldDdata, sizeof (table_entry->i32CodePointSelection));
				break;
			case IEEE8021PBBPIPUSEDEI:
				memcpy (&table_entry->i32UseDEI, pvOldDdata, sizeof (table_entry->i32UseDEI));
				break;
			case IEEE8021PBBPIPREQUIREDROPENCODING:
				memcpy (&table_entry->i32RequireDropEncoding, pvOldDdata, sizeof (table_entry->i32RequireDropEncoding));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbPipDecodingTable table mapper **/
void
ieee8021PbbPipDecodingTable_init (void)
{
	extern oid ieee8021PbbPipDecodingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbPipDecodingTable", &ieee8021PbbPipDecodingTable_mapper,
		ieee8021PbbPipDecodingTable_oid, OID_LENGTH (ieee8021PbbPipDecodingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021PbbPipIfIndex */,
		ASN_INTEGER /* index: ieee8021PbbPipDecodingPriorityCodePointRow */,
		ASN_INTEGER /* index: ieee8021PbbPipDecodingPriorityCodePoint */,
		0);
	table_info->min_column = IEEE8021PBBPIPDECODINGPRIORITY;
	table_info->max_column = IEEE8021PBBPIPDECODINGDROPELIGIBLE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbPipDecodingTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbPipDecodingTable_getNext;
	iinfo->get_data_point = &ieee8021PbbPipDecodingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbPipDecodingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbPipDecodingEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbPipDecodingEntry_t, oBTreeNode);
	register ieee8021PbbPipDecodingEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbPipDecodingEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow < pEntry2->i32PriorityCodePointRow) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow == pEntry2->i32PriorityCodePointRow && pEntry1->i32PriorityCodePoint < pEntry2->i32PriorityCodePoint) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow == pEntry2->i32PriorityCodePointRow && pEntry1->i32PriorityCodePoint == pEntry2->i32PriorityCodePoint) ? 0: 1;
}

xBTree_t oIeee8021PbbPipDecodingTable_BTree = xBTree_initInline (&ieee8021PbbPipDecodingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbPipDecodingEntry_t *
ieee8021PbbPipDecodingTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint)
{
	ieee8021PbbPipDecodingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipDecodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree);
	return poEntry;
}

ieee8021PbbPipDecodingEntry_t *
ieee8021PbbPipDecodingTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint)
{
	register ieee8021PbbPipDecodingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipDecodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poTmpEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipDecodingEntry_t, oBTreeNode);
}

ieee8021PbbPipDecodingEntry_t *
ieee8021PbbPipDecodingTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint)
{
	register ieee8021PbbPipDecodingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipDecodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poTmpEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipDecodingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbPipDecodingTable_removeEntry (ieee8021PbbPipDecodingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbPipDecodingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbPipDecodingTable_BTree);
	return ieee8021PbbPipDecodingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbPipDecodingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipDecodingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbPipDecodingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PriorityCodePointRow);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PriorityCodePoint);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbPipDecodingTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbPipDecodingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipDecodingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbbPipDecodingTable_getByIndex (
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

/* ieee8021PbbPipDecodingTable table mapper */
int
ieee8021PbbPipDecodingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbPipDecodingEntry_t *table_entry;
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
			table_entry = (ieee8021PbbPipDecodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPDECODINGPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Priority);
				break;
			case IEEE8021PBBPIPDECODINGDROPELIGIBLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32DropEligible);
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
			table_entry = (ieee8021PbbPipDecodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPDECODINGPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBPIPDECODINGDROPELIGIBLE:
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
			table_entry = (ieee8021PbbPipDecodingEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021PbbPipDecodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPDECODINGPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Priority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Priority, sizeof (table_entry->u32Priority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Priority = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBPIPDECODINGDROPELIGIBLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32DropEligible))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32DropEligible, sizeof (table_entry->i32DropEligible));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32DropEligible = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbbPipDecodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPDECODINGPRIORITY:
				memcpy (&table_entry->u32Priority, pvOldDdata, sizeof (table_entry->u32Priority));
				break;
			case IEEE8021PBBPIPDECODINGDROPELIGIBLE:
				memcpy (&table_entry->i32DropEligible, pvOldDdata, sizeof (table_entry->i32DropEligible));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbPipEncodingTable table mapper **/
void
ieee8021PbbPipEncodingTable_init (void)
{
	extern oid ieee8021PbbPipEncodingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbPipEncodingTable", &ieee8021PbbPipEncodingTable_mapper,
		ieee8021PbbPipEncodingTable_oid, OID_LENGTH (ieee8021PbbPipEncodingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ieee8021PbbPipIfIndex */,
		ASN_INTEGER /* index: ieee8021PbbPipEncodingPriorityCodePointRow */,
		ASN_INTEGER /* index: ieee8021PbbPipEncodingPriorityCodePoint */,
		ASN_INTEGER /* index: ieee8021PbbPipEncodingDropEligible */,
		0);
	table_info->min_column = IEEE8021PBBPIPENCODINGPRIORITY;
	table_info->max_column = IEEE8021PBBPIPENCODINGPRIORITY;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbPipEncodingTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbPipEncodingTable_getNext;
	iinfo->get_data_point = &ieee8021PbbPipEncodingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbPipEncodingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbPipEncodingEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbPipEncodingEntry_t, oBTreeNode);
	register ieee8021PbbPipEncodingEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbPipEncodingEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow < pEntry2->i32PriorityCodePointRow) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow == pEntry2->i32PriorityCodePointRow && pEntry1->i32PriorityCodePoint < pEntry2->i32PriorityCodePoint) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow == pEntry2->i32PriorityCodePointRow && pEntry1->i32PriorityCodePoint == pEntry2->i32PriorityCodePoint && pEntry1->i32DropEligible < pEntry2->i32DropEligible) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32PriorityCodePointRow == pEntry2->i32PriorityCodePointRow && pEntry1->i32PriorityCodePoint == pEntry2->i32PriorityCodePoint && pEntry1->i32DropEligible == pEntry2->i32DropEligible) ? 0: 1;
}

xBTree_t oIeee8021PbbPipEncodingTable_BTree = xBTree_initInline (&ieee8021PbbPipEncodingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbPipEncodingEntry_t *
ieee8021PbbPipEncodingTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible)
{
	ieee8021PbbPipEncodingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEncodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	poEntry->i32DropEligible = i32DropEligible;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree);
	return poEntry;
}

ieee8021PbbPipEncodingEntry_t *
ieee8021PbbPipEncodingTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible)
{
	register ieee8021PbbPipEncodingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEncodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poTmpEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	poTmpEntry->i32DropEligible = i32DropEligible;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipEncodingEntry_t, oBTreeNode);
}

ieee8021PbbPipEncodingEntry_t *
ieee8021PbbPipEncodingTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible)
{
	register ieee8021PbbPipEncodingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbPipEncodingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32PriorityCodePointRow = i32PriorityCodePointRow;
	poTmpEntry->i32PriorityCodePoint = i32PriorityCodePoint;
	poTmpEntry->i32DropEligible = i32DropEligible;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbPipEncodingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbPipEncodingTable_removeEntry (ieee8021PbbPipEncodingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbPipEncodingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbPipEncodingTable_BTree);
	return ieee8021PbbPipEncodingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbPipEncodingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipEncodingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbPipEncodingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PriorityCodePointRow);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32PriorityCodePoint);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32DropEligible);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbPipEncodingTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbPipEncodingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbPipEncodingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = ieee8021PbbPipEncodingTable_getByIndex (
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

/* ieee8021PbbPipEncodingTable table mapper */
int
ieee8021PbbPipEncodingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbPipEncodingEntry_t *table_entry;
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
			table_entry = (ieee8021PbbPipEncodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPENCODINGPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Priority);
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
			table_entry = (ieee8021PbbPipEncodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPENCODINGPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
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
			table_entry = (ieee8021PbbPipEncodingEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021PbbPipEncodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPENCODINGPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Priority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Priority, sizeof (table_entry->u32Priority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Priority = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021PbbPipEncodingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBPIPENCODINGPRIORITY:
				memcpy (&table_entry->u32Priority, pvOldDdata, sizeof (table_entry->u32Priority));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbVipToPipMappingTable table mapper **/
void
ieee8021PbbVipToPipMappingTable_init (void)
{
	extern oid ieee8021PbbVipToPipMappingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbVipToPipMappingTable", &ieee8021PbbVipToPipMappingTable_mapper,
		ieee8021PbbVipToPipMappingTable_oid, OID_LENGTH (ieee8021PbbVipToPipMappingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX;
	table_info->max_column = IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbVipToPipMappingTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbVipToPipMappingTable_getNext;
	iinfo->get_data_point = &ieee8021PbbVipToPipMappingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbVipToPipMappingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbVipToPipMappingEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbVipToPipMappingEntry_t, oBTreeNode);
	register ieee8021PbbVipToPipMappingEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbVipToPipMappingEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbbVipToPipMappingTable_BTree = xBTree_initInline (&ieee8021PbbVipToPipMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbVipToPipMappingEntry_t *
ieee8021PbbVipToPipMappingTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021PbbVipToPipMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipToPipMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree);
	return poEntry;
}

ieee8021PbbVipToPipMappingEntry_t *
ieee8021PbbVipToPipMappingTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbVipToPipMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipToPipMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbVipToPipMappingEntry_t, oBTreeNode);
}

ieee8021PbbVipToPipMappingEntry_t *
ieee8021PbbVipToPipMappingTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbVipToPipMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbVipToPipMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbVipToPipMappingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbVipToPipMappingTable_removeEntry (ieee8021PbbVipToPipMappingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbVipToPipMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbVipToPipMappingTable_BTree);
	return ieee8021PbbVipToPipMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbVipToPipMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbVipToPipMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbVipToPipMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbVipToPipMappingTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbVipToPipMappingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbVipToPipMappingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbVipToPipMappingTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbVipToPipMappingTable table mapper */
int
ieee8021PbbVipToPipMappingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbVipToPipMappingEntry_t *table_entry;
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32PipIfIndex);
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbVipToPipMappingTable_createEntry (
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbVipToPipMappingTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PipIfIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PipIfIndex, sizeof (table_entry->u32PipIfIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PipIfIndex = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGSTORAGETYPE:
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbVipToPipMappingTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX:
				memcpy (&table_entry->u32PipIfIndex, pvOldDdata, sizeof (table_entry->u32PipIfIndex));
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbVipToPipMappingTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbVipToPipMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS:
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
					ieee8021PbbVipToPipMappingTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbCBPServiceMappingTable table mapper **/
void
ieee8021PbbCBPServiceMappingTable_init (void)
{
	extern oid ieee8021PbbCBPServiceMappingTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbCBPServiceMappingTable", &ieee8021PbbCBPServiceMappingTable_mapper,
		ieee8021PbbCBPServiceMappingTable_oid, OID_LENGTH (ieee8021PbbCBPServiceMappingTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_UNSIGNED /* index: ieee8021PbbCBPServiceMappingBackboneSid */,
		0);
	table_info->min_column = IEEE8021PBBCBPSERVICEMAPPINGBVID;
	table_info->max_column = IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbCBPServiceMappingTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbCBPServiceMappingTable_getNext;
	iinfo->get_data_point = &ieee8021PbbCBPServiceMappingTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbCBPServiceMappingTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbCBPServiceMappingEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbCBPServiceMappingEntry_t, oBTreeNode);
	register ieee8021PbbCBPServiceMappingEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbCBPServiceMappingEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32BackboneSid < pEntry2->u32BackboneSid) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32BackboneSid == pEntry2->u32BackboneSid) ? 0: 1;
}

xBTree_t oIeee8021PbbCBPServiceMappingTable_BTree = xBTree_initInline (&ieee8021PbbCBPServiceMappingTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbCBPServiceMappingEntry_t *
ieee8021PbbCBPServiceMappingTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid)
{
	ieee8021PbbCBPServiceMappingEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCBPServiceMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32BackboneSid = u32BackboneSid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32LocalSid = 1;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree);
	return poEntry;
}

ieee8021PbbCBPServiceMappingEntry_t *
ieee8021PbbCBPServiceMappingTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid)
{
	register ieee8021PbbCBPServiceMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCBPServiceMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32BackboneSid = u32BackboneSid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbCBPServiceMappingEntry_t, oBTreeNode);
}

ieee8021PbbCBPServiceMappingEntry_t *
ieee8021PbbCBPServiceMappingTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid)
{
	register ieee8021PbbCBPServiceMappingEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCBPServiceMappingEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32BackboneSid = u32BackboneSid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbCBPServiceMappingEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbCBPServiceMappingTable_removeEntry (ieee8021PbbCBPServiceMappingEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbCBPServiceMappingTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbCBPServiceMappingTable_BTree);
	return ieee8021PbbCBPServiceMappingTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbCBPServiceMappingTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbCBPServiceMappingEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbCBPServiceMappingEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BackboneSid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbCBPServiceMappingTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbCBPServiceMappingTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbCBPServiceMappingEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021PbbCBPServiceMappingTable_getByIndex (
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

/* ieee8021PbbCBPServiceMappingTable table mapper */
int
ieee8021PbbCBPServiceMappingTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbCBPServiceMappingEntry_t *table_entry;
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGBVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32BVid);
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGDEFAULTBACKBONEDEST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DefaultBackboneDest, table_entry->u16DefaultBackboneDest_len);
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGLOCALSID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LocalSid);
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGBVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGDEFAULTBACKBONEDEST:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8DefaultBackboneDest));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGTYPE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Type));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGLOCALSID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbCBPServiceMappingTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						*idx3->val.integer);
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbCBPServiceMappingTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGBVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32BVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32BVid, sizeof (table_entry->i32BVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32BVid = *request->requestvb->val.integer;
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGDEFAULTBACKBONEDEST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8DefaultBackboneDest))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16DefaultBackboneDest_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8DefaultBackboneDest, sizeof (table_entry->au8DefaultBackboneDest));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8DefaultBackboneDest, 0, sizeof (table_entry->au8DefaultBackboneDest));
				memcpy (table_entry->au8DefaultBackboneDest, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16DefaultBackboneDest_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Type))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Type_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Type, sizeof (table_entry->au8Type));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Type, 0, sizeof (table_entry->au8Type));
				memcpy (table_entry->au8Type, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Type_len = request->requestvb->val_len;
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGLOCALSID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LocalSid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LocalSid, sizeof (table_entry->u32LocalSid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LocalSid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbCBPServiceMappingTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGBVID:
				memcpy (&table_entry->i32BVid, pvOldDdata, sizeof (table_entry->i32BVid));
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGDEFAULTBACKBONEDEST:
				memcpy (table_entry->au8DefaultBackboneDest, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16DefaultBackboneDest_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGTYPE:
				memcpy (table_entry->au8Type, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Type_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGLOCALSID:
				memcpy (&table_entry->u32LocalSid, pvOldDdata, sizeof (table_entry->u32LocalSid));
				break;
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbCBPServiceMappingTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbCBPServiceMappingEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS:
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
					ieee8021PbbCBPServiceMappingTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021PbbCbpTable table mapper **/
void
ieee8021PbbCbpTable_init (void)
{
	extern oid ieee8021PbbCbpTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021PbbCbpTable", &ieee8021PbbCbpTable_mapper,
		ieee8021PbbCbpTable_oid, OID_LENGTH (ieee8021PbbCbpTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021PBBCBPROWSTATUS;
	table_info->max_column = IEEE8021PBBCBPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021PbbCbpTable_getFirst;
	iinfo->get_next_data_point = &ieee8021PbbCbpTable_getNext;
	iinfo->get_data_point = &ieee8021PbbCbpTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021PbbCbpTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021PbbCbpEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021PbbCbpEntry_t, oBTreeNode);
	register ieee8021PbbCbpEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021PbbCbpEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021PbbCbpTable_BTree = xBTree_initInline (&ieee8021PbbCbpTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
ieee8021PbbCbpEntry_t *
ieee8021PbbCbpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021PbbCbpEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCbpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree);
	return poEntry;
}

ieee8021PbbCbpEntry_t *
ieee8021PbbCbpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbCbpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCbpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbCbpEntry_t, oBTreeNode);
}

ieee8021PbbCbpEntry_t *
ieee8021PbbCbpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021PbbCbpEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021PbbCbpEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021PbbCbpEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021PbbCbpTable_removeEntry (ieee8021PbbCbpEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021PbbCbpTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021PbbCbpTable_BTree);
	return ieee8021PbbCbpTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021PbbCbpTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbCbpEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021PbbCbpEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021PbbCbpTable_BTree);
	return put_index_data;
}

bool
ieee8021PbbCbpTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021PbbCbpEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021PbbCbpTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021PbbCbpTable table mapper */
int
ieee8021PbbCbpTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021PbbCbpEntry_t *table_entry;
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021PbbCbpTable_createEntry (
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbCbpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021PbbCbpTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021PbbCbpTable_removeEntry (table_entry);
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
			table_entry = (ieee8021PbbCbpEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021PBBCBPROWSTATUS:
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
					ieee8021PbbCbpTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
