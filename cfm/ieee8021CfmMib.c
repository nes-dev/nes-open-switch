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
#include "ieee8021CfmMib.h"

#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021CfmMib_oid[] = {1,3,111,2,802,1,1,8};

static oid dot1agCfmDefaultMd_oid[] = {1,3,111,2,802,1,1,8,1,2};
static oid dot1agCfmMd_oid[] = {1,3,111,2,802,1,1,8,1,5};

static oid dot1agCfmMdTable_oid[] = {1,3,111,2,802,1,1,8,1,5,2};
static oid dot1agCfmMaNetTable_oid[] = {1,3,111,2,802,1,1,8,1,6,1};
static oid dot1agCfmMaMepListTable_oid[] = {1,3,111,2,802,1,1,8,1,6,3};
static oid dot1agCfmMepTable_oid[] = {1,3,111,2,802,1,1,8,1,7,1};
static oid dot1agCfmLtrTable_oid[] = {1,3,111,2,802,1,1,8,1,7,2};
static oid dot1agCfmMepDbTable_oid[] = {1,3,111,2,802,1,1,8,1,7,3};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid dot1agCfmFaultAlarm_oid[] = {1,3,111,2,802,1,1,8,0,1};



/**
 *	initialize ieee8021CfmMib group mapper
 */
void
ieee8021CfmMib_init (void)
{
	extern oid ieee8021CfmMib_oid[];
	extern oid dot1agCfmDefaultMd_oid[];
	extern oid dot1agCfmMd_oid[];
	
	DEBUGMSGTL (("ieee8021CfmMib", "Initializing\n"));
	
	/* register dot1agCfmDefaultMd scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"dot1agCfmDefaultMd_mapper", &dot1agCfmDefaultMd_mapper,
			dot1agCfmDefaultMd_oid, OID_LENGTH (dot1agCfmDefaultMd_oid),
			HANDLER_CAN_RWRITE
		),
		DOT1AGCFMDEFAULTMDDEFLEVEL,
		DOT1AGCFMDEFAULTMDDEFIDPERMISSION
	);
	
	/* register dot1agCfmMd scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"dot1agCfmMd_mapper", &dot1agCfmMd_mapper,
			dot1agCfmMd_oid, OID_LENGTH (dot1agCfmMd_oid),
			HANDLER_CAN_RONLY
		),
		DOT1AGCFMMDTABLENEXTINDEX,
		DOT1AGCFMMDTABLENEXTINDEX
	);
	
	
	/* register ieee8021CfmMib group table mappers */
	dot1agCfmMdTable_init ();
	dot1agCfmMaNetTable_init ();
	dot1agCfmMaMepListTable_init ();
	dot1agCfmMepTable_init ();
	dot1agCfmLtrTable_init ();
	dot1agCfmMepDbTable_init ();
	
	/* register ieee8021CfmMib modules */
	sysORTable_createRegister ("ieee8021CfmMib", ieee8021CfmMib_oid, OID_LENGTH (ieee8021CfmMib_oid));
}


/**
 *	scalar mapper(s)
 */
dot1agCfmDefaultMd_t oDot1agCfmDefaultMd;

/** dot1agCfmDefaultMd scalar mapper **/
int
dot1agCfmDefaultMd_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid dot1agCfmDefaultMd_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (dot1agCfmDefaultMd_oid) - 1])
			{
			case DOT1AGCFMDEFAULTMDDEFLEVEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oDot1agCfmDefaultMd.i32DefLevel);
				break;
			case DOT1AGCFMDEFAULTMDDEFMHFCREATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oDot1agCfmDefaultMd.i32DefMhfCreation);
				break;
			case DOT1AGCFMDEFAULTMDDEFIDPERMISSION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oDot1agCfmDefaultMd.i32DefIdPermission);
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
			switch (request->requestvb->name[OID_LENGTH (dot1agCfmDefaultMd_oid) - 1])
			{
			case DOT1AGCFMDEFAULTMDDEFLEVEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFMHFCREATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFIDPERMISSION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
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
			switch (request->requestvb->name[OID_LENGTH (dot1agCfmDefaultMd_oid) - 1])
			{
			case DOT1AGCFMDEFAULTMDDEFLEVEL:
				/* XXX: perform the value change here */
				oDot1agCfmDefaultMd.i32DefLevel = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFMHFCREATION:
				/* XXX: perform the value change here */
				oDot1agCfmDefaultMd.i32DefMhfCreation = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFIDPERMISSION:
				/* XXX: perform the value change here */
				oDot1agCfmDefaultMd.i32DefIdPermission = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (dot1agCfmDefaultMd_oid) - 1])
			{
			case DOT1AGCFMDEFAULTMDDEFLEVEL:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFMHFCREATION:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case DOT1AGCFMDEFAULTMDDEFIDPERMISSION:
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

dot1agCfmMd_t oDot1agCfmMd;

/** dot1agCfmMd scalar mapper **/
int
dot1agCfmMd_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid dot1agCfmMd_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (dot1agCfmMd_oid) - 1])
			{
			case DOT1AGCFMMDTABLENEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oDot1agCfmMd.u32TableNextIndex);
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
/** initialize dot1agCfmMdTable table mapper **/
void
dot1agCfmMdTable_init (void)
{
	extern oid dot1agCfmMdTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmMdTable", &dot1agCfmMdTable_mapper,
		dot1agCfmMdTable_oid, OID_LENGTH (dot1agCfmMdTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		0);
	table_info->min_column = DOT1AGCFMMDFORMAT;
	table_info->max_column = DOT1AGCFMMDROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmMdTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmMdTable_getNext;
	iinfo->get_data_point = &dot1agCfmMdTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmMdTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmMdEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmMdEntry_t, oBTreeNode);
	register dot1agCfmMdEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmMdEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oDot1agCfmMdTable_BTree = xBTree_initInline (&dot1agCfmMdTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmMdEntry_t *
dot1agCfmMdTable_createEntry (
	uint32_t u32Index)
{
	dot1agCfmMdEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMdTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Format = dot1agCfmMdFormat_charString_c;
	/*poEntry->au8Name = "DEFAULT"*/;
	poEntry->i32MdLevel = 0;
	poEntry->i32MhfCreation = dot1agCfmMdMhfCreation_defMHFnone_c;
	poEntry->i32MhfIdPermission = dot1agCfmMdMhfIdPermission_sendIdNone_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmMdTable_BTree);
	return poEntry;
}

dot1agCfmMdEntry_t *
dot1agCfmMdTable_getByIndex (
	uint32_t u32Index)
{
	register dot1agCfmMdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmMdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMdEntry_t, oBTreeNode);
}

dot1agCfmMdEntry_t *
dot1agCfmMdTable_getNextIndex (
	uint32_t u32Index)
{
	register dot1agCfmMdEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMdEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmMdTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMdEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmMdTable_removeEntry (dot1agCfmMdEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMdTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmMdTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmMdTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmMdTable_BTree);
	return dot1agCfmMdTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmMdTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMdEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmMdEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmMdTable_BTree);
	return put_index_data;
}

bool
dot1agCfmMdTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMdEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = dot1agCfmMdTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot1agCfmMdTable table mapper */
int
dot1agCfmMdTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmMdEntry_t *table_entry;
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDFORMAT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Format);
				break;
			case DOT1AGCFMMDNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case DOT1AGCFMMDMDLEVEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MdLevel);
				break;
			case DOT1AGCFMMDMHFCREATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MhfCreation);
				break;
			case DOT1AGCFMMDMHFIDPERMISSION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MhfIdPermission);
				break;
			case DOT1AGCFMMDMANEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaNextIndex);
				break;
			case DOT1AGCFMMDROWSTATUS:
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDFORMAT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMDNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMDMDLEVEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMDMHFCREATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMDMHFIDPERMISSION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMDROWSTATUS:
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = dot1agCfmMdTable_createEntry (
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMdTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDFORMAT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Format))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Format, sizeof (table_entry->i32Format));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Format = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMDNAME:
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
			case DOT1AGCFMMDMDLEVEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MdLevel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MdLevel, sizeof (table_entry->i32MdLevel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MdLevel = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMDMHFCREATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MhfCreation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MhfCreation, sizeof (table_entry->i32MhfCreation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MhfCreation = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMDMHFIDPERMISSION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MhfIdPermission))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MhfIdPermission, sizeof (table_entry->i32MhfIdPermission));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MhfIdPermission = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int dot1agCfmMdTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDFORMAT:
				memcpy (&table_entry->i32Format, pvOldDdata, sizeof (table_entry->i32Format));
				break;
			case DOT1AGCFMMDNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMDMDLEVEL:
				memcpy (&table_entry->i32MdLevel, pvOldDdata, sizeof (table_entry->i32MdLevel));
				break;
			case DOT1AGCFMMDMHFCREATION:
				memcpy (&table_entry->i32MhfCreation, pvOldDdata, sizeof (table_entry->i32MhfCreation));
				break;
			case DOT1AGCFMMDMHFIDPERMISSION:
				memcpy (&table_entry->i32MhfIdPermission, pvOldDdata, sizeof (table_entry->i32MhfIdPermission));
				break;
			case DOT1AGCFMMDROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMdTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMdEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMDROWSTATUS:
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
					dot1agCfmMdTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot1agCfmMaNetTable table mapper **/
void
dot1agCfmMaNetTable_init (void)
{
	extern oid dot1agCfmMaNetTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmMaNetTable", &dot1agCfmMaNetTable_mapper,
		dot1agCfmMaNetTable_oid, OID_LENGTH (dot1agCfmMaNetTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		0);
	table_info->min_column = DOT1AGCFMMANETFORMAT;
	table_info->max_column = DOT1AGCFMMANETROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmMaNetTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmMaNetTable_getNext;
	iinfo->get_data_point = &dot1agCfmMaNetTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmMaNetTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmMaNetEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmMaNetEntry_t, oBTreeNode);
	register dot1agCfmMaNetEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmMaNetEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32MdIndex < pEntry2->u32MdIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex < pEntry2->u32MaIndex) ? -1:
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex) ? 0: 1;
}

xBTree_t oDot1agCfmMaNetTable_BTree = xBTree_initInline (&dot1agCfmMaNetTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmMaNetEntry_t *
dot1agCfmMaNetTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex)
{
	dot1agCfmMaNetEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32MdIndex = u32MdIndex;
	poEntry->u32MaIndex = u32MaIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32CcmInterval = dot1agCfmMaNetCcmInterval_interval1s_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree);
	return poEntry;
}

dot1agCfmMaNetEntry_t *
dot1agCfmMaNetTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex)
{
	register dot1agCfmMaNetEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMaNetEntry_t, oBTreeNode);
}

dot1agCfmMaNetEntry_t *
dot1agCfmMaNetTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex)
{
	register dot1agCfmMaNetEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaNetEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMaNetEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmMaNetTable_removeEntry (dot1agCfmMaNetEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmMaNetTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmMaNetTable_BTree);
	return dot1agCfmMaNetTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmMaNetTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMaNetEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmMaNetEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MaIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmMaNetTable_BTree);
	return put_index_data;
}

bool
dot1agCfmMaNetTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMaNetEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = dot1agCfmMaNetTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot1agCfmMaNetTable table mapper */
int
dot1agCfmMaNetTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmMaNetEntry_t *table_entry;
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETFORMAT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Format);
				break;
			case DOT1AGCFMMANETNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case DOT1AGCFMMANETCCMINTERVAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CcmInterval);
				break;
			case DOT1AGCFMMANETROWSTATUS:
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETFORMAT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMANETNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMANETCCMINTERVAL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMANETROWSTATUS:
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = dot1agCfmMaNetTable_createEntry (
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMaNetTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETFORMAT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Format))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Format, sizeof (table_entry->i32Format));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Format = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMANETNAME:
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
			case DOT1AGCFMMANETCCMINTERVAL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CcmInterval))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CcmInterval, sizeof (table_entry->i32CcmInterval));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CcmInterval = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int dot1agCfmMaNetTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETFORMAT:
				memcpy (&table_entry->i32Format, pvOldDdata, sizeof (table_entry->i32Format));
				break;
			case DOT1AGCFMMANETNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMANETCCMINTERVAL:
				memcpy (&table_entry->i32CcmInterval, pvOldDdata, sizeof (table_entry->i32CcmInterval));
				break;
			case DOT1AGCFMMANETROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMaNetTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMaNetEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMANETROWSTATUS:
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
					dot1agCfmMaNetTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot1agCfmMaMepListTable table mapper **/
void
dot1agCfmMaMepListTable_init (void)
{
	extern oid dot1agCfmMaMepListTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmMaMepListTable", &dot1agCfmMaMepListTable_mapper,
		dot1agCfmMaMepListTable_oid, OID_LENGTH (dot1agCfmMaMepListTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaMepListIdentifier */,
		0);
	table_info->min_column = DOT1AGCFMMAMEPLISTROWSTATUS;
	table_info->max_column = DOT1AGCFMMAMEPLISTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmMaMepListTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmMaMepListTable_getNext;
	iinfo->get_data_point = &dot1agCfmMaMepListTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmMaMepListTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmMaMepListEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmMaMepListEntry_t, oBTreeNode);
	register dot1agCfmMaMepListEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmMaMepListEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32MdIndex < pEntry2->u32MdIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex < pEntry2->u32MaIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32Identifier < pEntry2->u32Identifier) ? -1:
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32Identifier == pEntry2->u32Identifier) ? 0: 1;
}

xBTree_t oDot1agCfmMaMepListTable_BTree = xBTree_initInline (&dot1agCfmMaMepListTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmMaMepListEntry_t *
dot1agCfmMaMepListTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	dot1agCfmMaMepListEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaMepListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32MdIndex = u32MdIndex;
	poEntry->u32MaIndex = u32MaIndex;
	poEntry->u32Identifier = u32Identifier;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree);
	return poEntry;
}

dot1agCfmMaMepListEntry_t *
dot1agCfmMaMepListTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	register dot1agCfmMaMepListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaMepListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32Identifier = u32Identifier;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMaMepListEntry_t, oBTreeNode);
}

dot1agCfmMaMepListEntry_t *
dot1agCfmMaMepListTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	register dot1agCfmMaMepListEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMaMepListEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32Identifier = u32Identifier;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMaMepListEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmMaMepListTable_removeEntry (dot1agCfmMaMepListEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmMaMepListTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmMaMepListTable_BTree);
	return dot1agCfmMaMepListTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmMaMepListTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMaMepListEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmMaMepListEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MaIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Identifier);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmMaMepListTable_BTree);
	return put_index_data;
}

bool
dot1agCfmMaMepListTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMaMepListEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = dot1agCfmMaMepListTable_getByIndex (
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

/* dot1agCfmMaMepListTable table mapper */
int
dot1agCfmMaMepListTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmMaMepListEntry_t *table_entry;
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = dot1agCfmMaMepListTable_createEntry (
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMaMepListTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int dot1agCfmMaMepListTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMaMepListTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMaMepListEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMAMEPLISTROWSTATUS:
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
					dot1agCfmMaMepListTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot1agCfmMepTable table mapper **/
void
dot1agCfmMepTable_init (void)
{
	extern oid dot1agCfmMepTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmMepTable", &dot1agCfmMepTable_mapper,
		dot1agCfmMepTable_oid, OID_LENGTH (dot1agCfmMepTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMepIdentifier */,
		0);
	table_info->min_column = DOT1AGCFMMEPIFINDEX;
	table_info->max_column = DOT1AGCFMMEPPBBTEMISMATCHSINCERESET;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmMepTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmMepTable_getNext;
	iinfo->get_data_point = &dot1agCfmMepTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmMepTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmMepEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmMepEntry_t, oBTreeNode);
	register dot1agCfmMepEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmMepEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32MdIndex < pEntry2->u32MdIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex < pEntry2->u32MaIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32Identifier < pEntry2->u32Identifier) ? -1:
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32Identifier == pEntry2->u32Identifier) ? 0: 1;
}

xBTree_t oDot1agCfmMepTable_BTree = xBTree_initInline (&dot1agCfmMepTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmMepEntry_t *
dot1agCfmMepTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	dot1agCfmMepEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32MdIndex = u32MdIndex;
	poEntry->u32MaIndex = u32MaIndex;
	poEntry->u32Identifier = u32Identifier;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMepTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32PrimaryVid = 0;
	poEntry->i32Active = dot1agCfmMepActive_false_c;
	poEntry->i32FngState = dot1agCfmMepFngState_fngReset_c;
	poEntry->i32CciEnabled = dot1agCfmMepCciEnabled_false_c;
	poEntry->i32LowPrDef = dot1agCfmMepLowPrDef_macRemErrXcon_c;
	poEntry->i32FngAlarmTime = 250;
	poEntry->i32FngResetTime = 1000;
	poEntry->i32TransmitLbmStatus = dot1agCfmMepTransmitLbmStatus_false_c;
	poEntry->i32TransmitLbmMessages = 1;
	poEntry->i32TransmitLbmVlanDropEnable = dot1agCfmMepTransmitLbmVlanDropEnable_false_c;
	poEntry->i32TransmitLbmResultOK = dot1agCfmMepTransmitLbmResultOK_true_c;
	poEntry->i32TransmitLtmStatus = dot1agCfmMepTransmitLtmStatus_true_c;
	/*poEntry->au8TransmitLtmFlags = dot1agCfmMepTransmitLtmFlags_{ useFDBonly }_c*/;
	poEntry->u32TransmitLtmTtl = 64;
	poEntry->i32TransmitLtmResult = dot1agCfmMepTransmitLtmResult_true_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->i32PbbTeCanReportPbbTePresence = dot1agCfmMepPbbTeCanReportPbbTePresence_false_c;
	poEntry->i32PbbTeMismatchAlarm = dot1agCfmMepPbbTeMismatchAlarm_false_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmMepTable_BTree);
	return poEntry;
}

dot1agCfmMepEntry_t *
dot1agCfmMepTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	register dot1agCfmMepEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32Identifier = u32Identifier;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmMepTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMepEntry_t, oBTreeNode);
}

dot1agCfmMepEntry_t *
dot1agCfmMepTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier)
{
	register dot1agCfmMepEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32Identifier = u32Identifier;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmMepTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMepEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmMepTable_removeEntry (dot1agCfmMepEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMepTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmMepTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmMepTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmMepTable_BTree);
	return dot1agCfmMepTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmMepTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMepEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmMepEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MaIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Identifier);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmMepTable_BTree);
	return put_index_data;
}

bool
dot1agCfmMepTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMepEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = dot1agCfmMepTable_getByIndex (
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

/* dot1agCfmMepTable table mapper */
int
dot1agCfmMepTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmMepEntry_t *table_entry;
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case DOT1AGCFMMEPDIRECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Direction);
				break;
			case DOT1AGCFMMEPPRIMARYVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PrimaryVid);
				break;
			case DOT1AGCFMMEPACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Active);
				break;
			case DOT1AGCFMMEPFNGSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32FngState);
				break;
			case DOT1AGCFMMEPCCIENABLED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CciEnabled);
				break;
			case DOT1AGCFMMEPCCMLTMPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CcmLtmPriority);
				break;
			case DOT1AGCFMMEPMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MacAddress, table_entry->u16MacAddress_len);
				break;
			case DOT1AGCFMMEPLOWPRDEF:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32LowPrDef);
				break;
			case DOT1AGCFMMEPFNGALARMTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32FngAlarmTime);
				break;
			case DOT1AGCFMMEPFNGRESETTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32FngResetTime);
				break;
			case DOT1AGCFMMEPHIGHESTPRDEFECT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32HighestPrDefect);
				break;
			case DOT1AGCFMMEPDEFECTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Defects, table_entry->u16Defects_len);
				break;
			case DOT1AGCFMMEPERRORCCMLASTFAILURE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ErrorCcmLastFailure, table_entry->u16ErrorCcmLastFailure_len);
				break;
			case DOT1AGCFMMEPXCONCCMLASTFAILURE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8XconCcmLastFailure, table_entry->u16XconCcmLastFailure_len);
				break;
			case DOT1AGCFMMEPCCMSEQUENCEERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32CcmSequenceErrors);
				break;
			case DOT1AGCFMMEPCCISENTCCMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32CciSentCcms);
				break;
			case DOT1AGCFMMEPNEXTLBMTRANSID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32NextLbmTransId);
				break;
			case DOT1AGCFMMEPLBRIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LbrIn);
				break;
			case DOT1AGCFMMEPLBRINOUTOFORDER:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LbrInOutOfOrder);
				break;
			case DOT1AGCFMMEPLBRBADMSDU:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LbrBadMsdu);
				break;
			case DOT1AGCFMMEPLTMNEXTSEQNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LtmNextSeqNumber);
				break;
			case DOT1AGCFMMEPUNEXPLTRIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32UnexpLtrIn);
				break;
			case DOT1AGCFMMEPLBROUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32LbrOut);
				break;
			case DOT1AGCFMMEPTRANSMITLBMSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmStatus);
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransmitLbmDestMacAddress, table_entry->u16TransmitLbmDestMacAddress_len);
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMEPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TransmitLbmDestMepId);
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTISMEPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmDestIsMepId);
				break;
			case DOT1AGCFMMEPTRANSMITLBMMESSAGES:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmMessages);
				break;
			case DOT1AGCFMMEPTRANSMITLBMDATATLV:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransmitLbmDataTlv, table_entry->u16TransmitLbmDataTlv_len);
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANPRIORITY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmVlanPriority);
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANDROPENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmVlanDropEnable);
				break;
			case DOT1AGCFMMEPTRANSMITLBMRESULTOK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLbmResultOK);
				break;
			case DOT1AGCFMMEPTRANSMITLBMSEQNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TransmitLbmSeqNumber);
				break;
			case DOT1AGCFMMEPTRANSMITLTMSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLtmStatus);
				break;
			case DOT1AGCFMMEPTRANSMITLTMFLAGS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransmitLtmFlags, table_entry->u16TransmitLtmFlags_len);
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransmitLtmTargetMacAddress, table_entry->u16TransmitLtmTargetMacAddress_len);
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMEPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TransmitLtmTargetMepId);
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETISMEPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLtmTargetIsMepId);
				break;
			case DOT1AGCFMMEPTRANSMITLTMTTL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TransmitLtmTtl);
				break;
			case DOT1AGCFMMEPTRANSMITLTMRESULT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TransmitLtmResult);
				break;
			case DOT1AGCFMMEPTRANSMITLTMSEQNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TransmitLtmSeqNumber);
				break;
			case DOT1AGCFMMEPTRANSMITLTMEGRESSIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8TransmitLtmEgressIdentifier, table_entry->u16TransmitLtmEgressIdentifier_len);
				break;
			case DOT1AGCFMMEPROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case DOT1AGCFMMEPPBBTECANREPORTPBBTEPRESENCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbbTeCanReportPbbTePresence);
				break;
			case DOT1AGCFMMEPPBBTETRAFFICMISMATCHDEFECT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbbTeTrafficMismatchDefect);
				break;
			case DOT1AGCFMMEPPBBTRANSMITLBMLTMREVERSEVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PbbTransmitLbmLtmReverseVid);
				break;
			case DOT1AGCFMMEPPBBTEMISMATCHALARM:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbbTeMismatchAlarm);
				break;
			case DOT1AGCFMMEPPBBTELOCALMISMATCHDEFECT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbbTeLocalMismatchDefect);
				break;
			case DOT1AGCFMMEPPBBTEMISMATCHSINCERESET:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PbbTeMismatchSinceReset);
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPDIRECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPPRIMARYVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPACTIVE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPCCIENABLED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPCCMLTMPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPLOWPRDEF:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPFNGALARMTIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPFNGRESETTIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMSTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMACADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransmitLbmDestMacAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMEPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTISMEPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMMESSAGES:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMDATATLV:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransmitLbmDataTlv));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANPRIORITY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANDROPENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMSTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMFLAGS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransmitLtmFlags));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMACADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransmitLtmTargetMacAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMEPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETISMEPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMTTL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPTRANSMITLTMEGRESSIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8TransmitLtmEgressIdentifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPPBBTECANREPORTPBBTEPRESENCE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPPBBTRANSMITLBMLTMREVERSEVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case DOT1AGCFMMEPPBBTEMISMATCHALARM:
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = dot1agCfmMepTable_createEntry (
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMepTable_removeEntry (table_entry);
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPIFINDEX:
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
			case DOT1AGCFMMEPDIRECTION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Direction))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Direction, sizeof (table_entry->i32Direction));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Direction = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPPRIMARYVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PrimaryVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PrimaryVid, sizeof (table_entry->u32PrimaryVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PrimaryVid = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPACTIVE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Active))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Active, sizeof (table_entry->i32Active));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Active = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPCCIENABLED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CciEnabled))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CciEnabled, sizeof (table_entry->i32CciEnabled));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CciEnabled = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPCCMLTMPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CcmLtmPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CcmLtmPriority, sizeof (table_entry->u32CcmLtmPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CcmLtmPriority = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPLOWPRDEF:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32LowPrDef))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32LowPrDef, sizeof (table_entry->i32LowPrDef));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32LowPrDef = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPFNGALARMTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32FngAlarmTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32FngAlarmTime, sizeof (table_entry->i32FngAlarmTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32FngAlarmTime = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPFNGRESETTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32FngResetTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32FngResetTime, sizeof (table_entry->i32FngResetTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32FngResetTime = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLbmStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLbmStatus, sizeof (table_entry->i32TransmitLbmStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLbmStatus = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMACADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransmitLbmDestMacAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransmitLbmDestMacAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransmitLbmDestMacAddress, sizeof (table_entry->au8TransmitLbmDestMacAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransmitLbmDestMacAddress, 0, sizeof (table_entry->au8TransmitLbmDestMacAddress));
				memcpy (table_entry->au8TransmitLbmDestMacAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransmitLbmDestMacAddress_len = request->requestvb->val_len;
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMEPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TransmitLbmDestMepId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TransmitLbmDestMepId, sizeof (table_entry->u32TransmitLbmDestMepId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TransmitLbmDestMepId = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTISMEPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLbmDestIsMepId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLbmDestIsMepId, sizeof (table_entry->i32TransmitLbmDestIsMepId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLbmDestIsMepId = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMMESSAGES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLbmMessages))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLbmMessages, sizeof (table_entry->i32TransmitLbmMessages));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLbmMessages = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMDATATLV:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransmitLbmDataTlv))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransmitLbmDataTlv_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransmitLbmDataTlv, sizeof (table_entry->au8TransmitLbmDataTlv));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransmitLbmDataTlv, 0, sizeof (table_entry->au8TransmitLbmDataTlv));
				memcpy (table_entry->au8TransmitLbmDataTlv, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransmitLbmDataTlv_len = request->requestvb->val_len;
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANPRIORITY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLbmVlanPriority))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLbmVlanPriority, sizeof (table_entry->i32TransmitLbmVlanPriority));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLbmVlanPriority = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANDROPENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLbmVlanDropEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLbmVlanDropEnable, sizeof (table_entry->i32TransmitLbmVlanDropEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLbmVlanDropEnable = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLTMSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLtmStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLtmStatus, sizeof (table_entry->i32TransmitLtmStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLtmStatus = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLTMFLAGS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransmitLtmFlags))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransmitLtmFlags_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransmitLtmFlags, sizeof (table_entry->au8TransmitLtmFlags));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransmitLtmFlags, 0, sizeof (table_entry->au8TransmitLtmFlags));
				memcpy (table_entry->au8TransmitLtmFlags, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransmitLtmFlags_len = request->requestvb->val_len;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMACADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransmitLtmTargetMacAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransmitLtmTargetMacAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransmitLtmTargetMacAddress, sizeof (table_entry->au8TransmitLtmTargetMacAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransmitLtmTargetMacAddress, 0, sizeof (table_entry->au8TransmitLtmTargetMacAddress));
				memcpy (table_entry->au8TransmitLtmTargetMacAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransmitLtmTargetMacAddress_len = request->requestvb->val_len;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMEPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TransmitLtmTargetMepId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TransmitLtmTargetMepId, sizeof (table_entry->u32TransmitLtmTargetMepId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TransmitLtmTargetMepId = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETISMEPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TransmitLtmTargetIsMepId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TransmitLtmTargetIsMepId, sizeof (table_entry->i32TransmitLtmTargetIsMepId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TransmitLtmTargetIsMepId = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTTL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TransmitLtmTtl))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TransmitLtmTtl, sizeof (table_entry->u32TransmitLtmTtl));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TransmitLtmTtl = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPTRANSMITLTMEGRESSIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8TransmitLtmEgressIdentifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TransmitLtmEgressIdentifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8TransmitLtmEgressIdentifier, sizeof (table_entry->au8TransmitLtmEgressIdentifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8TransmitLtmEgressIdentifier, 0, sizeof (table_entry->au8TransmitLtmEgressIdentifier));
				memcpy (table_entry->au8TransmitLtmEgressIdentifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TransmitLtmEgressIdentifier_len = request->requestvb->val_len;
				break;
			case DOT1AGCFMMEPPBBTECANREPORTPBBTEPRESENCE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PbbTeCanReportPbbTePresence))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PbbTeCanReportPbbTePresence, sizeof (table_entry->i32PbbTeCanReportPbbTePresence));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PbbTeCanReportPbbTePresence = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPPBBTRANSMITLBMLTMREVERSEVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PbbTransmitLbmLtmReverseVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PbbTransmitLbmLtmReverseVid, sizeof (table_entry->u32PbbTransmitLbmLtmReverseVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PbbTransmitLbmLtmReverseVid = *request->requestvb->val.integer;
				break;
			case DOT1AGCFMMEPPBBTEMISMATCHALARM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PbbTeMismatchAlarm))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PbbTeMismatchAlarm, sizeof (table_entry->i32PbbTeMismatchAlarm));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PbbTeMismatchAlarm = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int dot1agCfmMepTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case DOT1AGCFMMEPDIRECTION:
				memcpy (&table_entry->i32Direction, pvOldDdata, sizeof (table_entry->i32Direction));
				break;
			case DOT1AGCFMMEPPRIMARYVID:
				memcpy (&table_entry->u32PrimaryVid, pvOldDdata, sizeof (table_entry->u32PrimaryVid));
				break;
			case DOT1AGCFMMEPACTIVE:
				memcpy (&table_entry->i32Active, pvOldDdata, sizeof (table_entry->i32Active));
				break;
			case DOT1AGCFMMEPCCIENABLED:
				memcpy (&table_entry->i32CciEnabled, pvOldDdata, sizeof (table_entry->i32CciEnabled));
				break;
			case DOT1AGCFMMEPCCMLTMPRIORITY:
				memcpy (&table_entry->u32CcmLtmPriority, pvOldDdata, sizeof (table_entry->u32CcmLtmPriority));
				break;
			case DOT1AGCFMMEPLOWPRDEF:
				memcpy (&table_entry->i32LowPrDef, pvOldDdata, sizeof (table_entry->i32LowPrDef));
				break;
			case DOT1AGCFMMEPFNGALARMTIME:
				memcpy (&table_entry->i32FngAlarmTime, pvOldDdata, sizeof (table_entry->i32FngAlarmTime));
				break;
			case DOT1AGCFMMEPFNGRESETTIME:
				memcpy (&table_entry->i32FngResetTime, pvOldDdata, sizeof (table_entry->i32FngResetTime));
				break;
			case DOT1AGCFMMEPTRANSMITLBMSTATUS:
				memcpy (&table_entry->i32TransmitLbmStatus, pvOldDdata, sizeof (table_entry->i32TransmitLbmStatus));
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMACADDRESS:
				memcpy (table_entry->au8TransmitLbmDestMacAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransmitLbmDestMacAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTMEPID:
				memcpy (&table_entry->u32TransmitLbmDestMepId, pvOldDdata, sizeof (table_entry->u32TransmitLbmDestMepId));
				break;
			case DOT1AGCFMMEPTRANSMITLBMDESTISMEPID:
				memcpy (&table_entry->i32TransmitLbmDestIsMepId, pvOldDdata, sizeof (table_entry->i32TransmitLbmDestIsMepId));
				break;
			case DOT1AGCFMMEPTRANSMITLBMMESSAGES:
				memcpy (&table_entry->i32TransmitLbmMessages, pvOldDdata, sizeof (table_entry->i32TransmitLbmMessages));
				break;
			case DOT1AGCFMMEPTRANSMITLBMDATATLV:
				memcpy (table_entry->au8TransmitLbmDataTlv, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransmitLbmDataTlv_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANPRIORITY:
				memcpy (&table_entry->i32TransmitLbmVlanPriority, pvOldDdata, sizeof (table_entry->i32TransmitLbmVlanPriority));
				break;
			case DOT1AGCFMMEPTRANSMITLBMVLANDROPENABLE:
				memcpy (&table_entry->i32TransmitLbmVlanDropEnable, pvOldDdata, sizeof (table_entry->i32TransmitLbmVlanDropEnable));
				break;
			case DOT1AGCFMMEPTRANSMITLTMSTATUS:
				memcpy (&table_entry->i32TransmitLtmStatus, pvOldDdata, sizeof (table_entry->i32TransmitLtmStatus));
				break;
			case DOT1AGCFMMEPTRANSMITLTMFLAGS:
				memcpy (table_entry->au8TransmitLtmFlags, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransmitLtmFlags_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMACADDRESS:
				memcpy (table_entry->au8TransmitLtmTargetMacAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransmitLtmTargetMacAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETMEPID:
				memcpy (&table_entry->u32TransmitLtmTargetMepId, pvOldDdata, sizeof (table_entry->u32TransmitLtmTargetMepId));
				break;
			case DOT1AGCFMMEPTRANSMITLTMTARGETISMEPID:
				memcpy (&table_entry->i32TransmitLtmTargetIsMepId, pvOldDdata, sizeof (table_entry->i32TransmitLtmTargetIsMepId));
				break;
			case DOT1AGCFMMEPTRANSMITLTMTTL:
				memcpy (&table_entry->u32TransmitLtmTtl, pvOldDdata, sizeof (table_entry->u32TransmitLtmTtl));
				break;
			case DOT1AGCFMMEPTRANSMITLTMEGRESSIDENTIFIER:
				memcpy (table_entry->au8TransmitLtmEgressIdentifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TransmitLtmEgressIdentifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case DOT1AGCFMMEPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					dot1agCfmMepTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case DOT1AGCFMMEPPBBTECANREPORTPBBTEPRESENCE:
				memcpy (&table_entry->i32PbbTeCanReportPbbTePresence, pvOldDdata, sizeof (table_entry->i32PbbTeCanReportPbbTePresence));
				break;
			case DOT1AGCFMMEPPBBTRANSMITLBMLTMREVERSEVID:
				memcpy (&table_entry->u32PbbTransmitLbmLtmReverseVid, pvOldDdata, sizeof (table_entry->u32PbbTransmitLbmLtmReverseVid));
				break;
			case DOT1AGCFMMEPPBBTEMISMATCHALARM:
				memcpy (&table_entry->i32PbbTeMismatchAlarm, pvOldDdata, sizeof (table_entry->i32PbbTeMismatchAlarm));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmMepEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPROWSTATUS:
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
					dot1agCfmMepTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize dot1agCfmLtrTable table mapper **/
void
dot1agCfmLtrTable_init (void)
{
	extern oid dot1agCfmLtrTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmLtrTable", &dot1agCfmLtrTable_mapper,
		dot1agCfmLtrTable_oid, OID_LENGTH (dot1agCfmLtrTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMepIdentifier */,
		ASN_UNSIGNED /* index: dot1agCfmLtrSeqNumber */,
		ASN_UNSIGNED /* index: dot1agCfmLtrReceiveOrder */,
		0);
	table_info->min_column = DOT1AGCFMLTRTTL;
	table_info->max_column = DOT1AGCFMLTRORGANIZATIONSPECIFICTLV;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmLtrTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmLtrTable_getNext;
	iinfo->get_data_point = &dot1agCfmLtrTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmLtrTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmLtrEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmLtrEntry_t, oBTreeNode);
	register dot1agCfmLtrEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmLtrEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32MdIndex < pEntry2->u32MdIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex < pEntry2->u32MaIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier < pEntry2->u32MepIdentifier) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier == pEntry2->u32MepIdentifier && pEntry1->u32SeqNumber < pEntry2->u32SeqNumber) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier == pEntry2->u32MepIdentifier && pEntry1->u32SeqNumber == pEntry2->u32SeqNumber && pEntry1->u32ReceiveOrder < pEntry2->u32ReceiveOrder) ? -1:
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier == pEntry2->u32MepIdentifier && pEntry1->u32SeqNumber == pEntry2->u32SeqNumber && pEntry1->u32ReceiveOrder == pEntry2->u32ReceiveOrder) ? 0: 1;
}

xBTree_t oDot1agCfmLtrTable_BTree = xBTree_initInline (&dot1agCfmLtrTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmLtrEntry_t *
dot1agCfmLtrTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder)
{
	dot1agCfmLtrEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmLtrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32MdIndex = u32MdIndex;
	poEntry->u32MaIndex = u32MaIndex;
	poEntry->u32MepIdentifier = u32MepIdentifier;
	poEntry->u32SeqNumber = u32SeqNumber;
	poEntry->u32ReceiveOrder = u32ReceiveOrder;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree);
	return poEntry;
}

dot1agCfmLtrEntry_t *
dot1agCfmLtrTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder)
{
	register dot1agCfmLtrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmLtrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32MepIdentifier = u32MepIdentifier;
	poTmpEntry->u32SeqNumber = u32SeqNumber;
	poTmpEntry->u32ReceiveOrder = u32ReceiveOrder;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmLtrEntry_t, oBTreeNode);
}

dot1agCfmLtrEntry_t *
dot1agCfmLtrTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder)
{
	register dot1agCfmLtrEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmLtrEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32MepIdentifier = u32MepIdentifier;
	poTmpEntry->u32SeqNumber = u32SeqNumber;
	poTmpEntry->u32ReceiveOrder = u32ReceiveOrder;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmLtrEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmLtrTable_removeEntry (dot1agCfmLtrEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmLtrTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmLtrTable_BTree);
	return dot1agCfmLtrTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmLtrTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmLtrEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmLtrEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MaIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MepIdentifier);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32SeqNumber);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ReceiveOrder);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmLtrTable_BTree);
	return put_index_data;
}

bool
dot1agCfmLtrTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmLtrEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = dot1agCfmLtrTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		*idx3->val.integer,
		*idx4->val.integer,
		*idx5->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* dot1agCfmLtrTable table mapper */
int
dot1agCfmLtrTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmLtrEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (dot1agCfmLtrEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMLTRTTL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Ttl);
				break;
			case DOT1AGCFMLTRFORWARDED:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Forwarded);
				break;
			case DOT1AGCFMLTRTERMINALMEP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TerminalMep);
				break;
			case DOT1AGCFMLTRLASTEGRESSIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LastEgressIdentifier, table_entry->u16LastEgressIdentifier_len);
				break;
			case DOT1AGCFMLTRNEXTEGRESSIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NextEgressIdentifier, table_entry->u16NextEgressIdentifier_len);
				break;
			case DOT1AGCFMLTRRELAY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Relay);
				break;
			case DOT1AGCFMLTRCHASSISIDSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ChassisIdSubtype);
				break;
			case DOT1AGCFMLTRCHASSISID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ChassisId, table_entry->u16ChassisId_len);
				break;
			case DOT1AGCFMLTRMANADDRESSDOMAIN:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoManAddressDomain, table_entry->u16ManAddressDomain_len);
				break;
			case DOT1AGCFMLTRMANADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ManAddress, table_entry->u16ManAddress_len);
				break;
			case DOT1AGCFMLTRINGRESS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Ingress);
				break;
			case DOT1AGCFMLTRINGRESSMAC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IngressMac, table_entry->u16IngressMac_len);
				break;
			case DOT1AGCFMLTRINGRESSPORTIDSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32IngressPortIdSubtype);
				break;
			case DOT1AGCFMLTRINGRESSPORTID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IngressPortId, table_entry->u16IngressPortId_len);
				break;
			case DOT1AGCFMLTREGRESS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Egress);
				break;
			case DOT1AGCFMLTREGRESSMAC:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EgressMac, table_entry->u16EgressMac_len);
				break;
			case DOT1AGCFMLTREGRESSPORTIDSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EgressPortIdSubtype);
				break;
			case DOT1AGCFMLTREGRESSPORTID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EgressPortId, table_entry->u16EgressPortId_len);
				break;
			case DOT1AGCFMLTRORGANIZATIONSPECIFICTLV:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8OrganizationSpecificTlv, table_entry->u16OrganizationSpecificTlv_len);
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

/** initialize dot1agCfmMepDbTable table mapper **/
void
dot1agCfmMepDbTable_init (void)
{
	extern oid dot1agCfmMepDbTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"dot1agCfmMepDbTable", &dot1agCfmMepDbTable_mapper,
		dot1agCfmMepDbTable_oid, OID_LENGTH (dot1agCfmMepDbTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: dot1agCfmMdIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMaIndex */,
		ASN_UNSIGNED /* index: dot1agCfmMepIdentifier */,
		ASN_UNSIGNED /* index: dot1agCfmMepDbRMepIdentifier */,
		0);
	table_info->min_column = DOT1AGCFMMEPDBRMEPSTATE;
	table_info->max_column = DOT1AGCFMMEPDBRMEPISACTIVE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &dot1agCfmMepDbTable_getFirst;
	iinfo->get_next_data_point = &dot1agCfmMepDbTable_getNext;
	iinfo->get_data_point = &dot1agCfmMepDbTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
dot1agCfmMepDbTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register dot1agCfmMepDbEntry_t *pEntry1 = xBTree_entry (pNode1, dot1agCfmMepDbEntry_t, oBTreeNode);
	register dot1agCfmMepDbEntry_t *pEntry2 = xBTree_entry (pNode2, dot1agCfmMepDbEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32MdIndex < pEntry2->u32MdIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex < pEntry2->u32MaIndex) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier < pEntry2->u32MepIdentifier) ||
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier == pEntry2->u32MepIdentifier && pEntry1->u32RMepIdentifier < pEntry2->u32RMepIdentifier) ? -1:
		(pEntry1->u32MdIndex == pEntry2->u32MdIndex && pEntry1->u32MaIndex == pEntry2->u32MaIndex && pEntry1->u32MepIdentifier == pEntry2->u32MepIdentifier && pEntry1->u32RMepIdentifier == pEntry2->u32RMepIdentifier) ? 0: 1;
}

xBTree_t oDot1agCfmMepDbTable_BTree = xBTree_initInline (&dot1agCfmMepDbTable_BTreeNodeCmp);

/* create a new row in the (unsorted) table */
dot1agCfmMepDbEntry_t *
dot1agCfmMepDbTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier)
{
	dot1agCfmMepDbEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepDbEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32MdIndex = u32MdIndex;
	poEntry->u32MaIndex = u32MaIndex;
	poEntry->u32MepIdentifier = u32MepIdentifier;
	poEntry->u32RMepIdentifier = u32RMepIdentifier;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32PortStatusTlv = dot1agCfmMepDbPortStatusTlv_psNoPortStateTLV_c;
	poEntry->i32InterfaceStatusTlv = dot1agCfmMepDbInterfaceStatusTlv_isNoInterfaceStatusTLV_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree);
	return poEntry;
}

dot1agCfmMepDbEntry_t *
dot1agCfmMepDbTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier)
{
	register dot1agCfmMepDbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepDbEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32MepIdentifier = u32MepIdentifier;
	poTmpEntry->u32RMepIdentifier = u32RMepIdentifier;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMepDbEntry_t, oBTreeNode);
}

dot1agCfmMepDbEntry_t *
dot1agCfmMepDbTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier)
{
	register dot1agCfmMepDbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (dot1agCfmMepDbEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32MdIndex = u32MdIndex;
	poTmpEntry->u32MaIndex = u32MaIndex;
	poTmpEntry->u32MepIdentifier = u32MepIdentifier;
	poTmpEntry->u32RMepIdentifier = u32RMepIdentifier;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, dot1agCfmMepDbEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
dot1agCfmMepDbTable_removeEntry (dot1agCfmMepDbEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
dot1agCfmMepDbTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oDot1agCfmMepDbTable_BTree);
	return dot1agCfmMepDbTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
dot1agCfmMepDbTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMepDbEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, dot1agCfmMepDbEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MdIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MaIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32MepIdentifier);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32RMepIdentifier);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oDot1agCfmMepDbTable_BTree);
	return put_index_data;
}

bool
dot1agCfmMepDbTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	dot1agCfmMepDbEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = dot1agCfmMepDbTable_getByIndex (
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

/* dot1agCfmMepDbTable table mapper */
int
dot1agCfmMepDbTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	dot1agCfmMepDbEntry_t *table_entry;
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
			table_entry = (dot1agCfmMepDbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPDBRMEPSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RMepState);
				break;
			case DOT1AGCFMMEPDBRMEPFAILEDOKTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32RMepFailedOkTime);
				break;
			case DOT1AGCFMMEPDBMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MacAddress, table_entry->u16MacAddress_len);
				break;
			case DOT1AGCFMMEPDBRDI:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Rdi);
				break;
			case DOT1AGCFMMEPDBPORTSTATUSTLV:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PortStatusTlv);
				break;
			case DOT1AGCFMMEPDBINTERFACESTATUSTLV:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32InterfaceStatusTlv);
				break;
			case DOT1AGCFMMEPDBCHASSISIDSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ChassisIdSubtype);
				break;
			case DOT1AGCFMMEPDBCHASSISID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ChassisId, table_entry->u16ChassisId_len);
				break;
			case DOT1AGCFMMEPDBMANADDRESSDOMAIN:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoManAddressDomain, table_entry->u16ManAddressDomain_len);
				break;
			case DOT1AGCFMMEPDBMANADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ManAddress, table_entry->u16ManAddress_len);
				break;
			case DOT1AGCFMMEPDBRMEPISACTIVE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32RMepIsActive);
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
			table_entry = (dot1agCfmMepDbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPDBRMEPISACTIVE:
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
			table_entry = (dot1agCfmMepDbEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (dot1agCfmMepDbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPDBRMEPISACTIVE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32RMepIsActive))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32RMepIsActive, sizeof (table_entry->i32RMepIsActive));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32RMepIsActive = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (dot1agCfmMepDbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case DOT1AGCFMMEPDBRMEPISACTIVE:
				memcpy (&table_entry->i32RMepIsActive, pvOldDdata, sizeof (table_entry->i32RMepIsActive));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}


/**
 *	notification mapper(s)
 */
int
dot1agCfmFaultAlarm_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid dot1agCfmFaultAlarm_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid dot1agCfmMepHighestPrDefect_oid[] = {1,3,111,2,802,1,1,8,1,7,1,1,13, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) dot1agCfmFaultAlarm_oid, sizeof (dot1agCfmFaultAlarm_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		dot1agCfmMepHighestPrDefect_oid, OID_LENGTH (dot1agCfmMepHighestPrDefect_oid),
		ASN_INTEGER,
		/* Set an appropriate value for dot1agCfmMepHighestPrDefect */
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
