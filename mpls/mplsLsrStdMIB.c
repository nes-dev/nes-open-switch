/*
 *  Copyright (c) 2008-2015
 *      NES Dev <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES RED Licensee, Version 1.0 (the "License"); you may
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
#include "mplsLsrStdMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mplsLsrStdMIB_oid[] = {1,3,6,1,2,1,10,166,2};
static oid gmplsLsrStdMIB_oid[] = {1,3,6,1,2,1,10,166,15};
static oid gmplsLabelStdMIB_oid[] = {1,3,6,1,2,1,10,166,16};

static oid mplsLsrObjects_oid[] = {1,3,6,1,2,1,10,166,2,1};
static oid gmplsLabelObjects_oid[] = {1,3,6,1,2,1,10,166,16,1};

static oid mplsInterfaceTable_oid[] = {1,3,6,1,2,1,10,166,2,1,1};
static oid mplsInterfacePerfTable_oid[] = {1,3,6,1,2,1,10,166,2,1,2};
static oid mplsInSegmentTable_oid[] = {1,3,6,1,2,1,10,166,2,1,4};
static oid mplsInSegmentPerfTable_oid[] = {1,3,6,1,2,1,10,166,2,1,5};
static oid mplsOutSegmentTable_oid[] = {1,3,6,1,2,1,10,166,2,1,7};
static oid mplsOutSegmentPerfTable_oid[] = {1,3,6,1,2,1,10,166,2,1,8};
static oid mplsXCTable_oid[] = {1,3,6,1,2,1,10,166,2,1,10};
static oid mplsLabelStackTable_oid[] = {1,3,6,1,2,1,10,166,2,1,13};
static oid gmplsInterfaceTable_oid[] = {1,3,6,1,2,1,10,166,15,1,1};
static oid gmplsInSegmentTable_oid[] = {1,3,6,1,2,1,10,166,15,1,2};
static oid gmplsOutSegmentTable_oid[] = {1,3,6,1,2,1,10,166,15,1,3};
static oid gmplsLabelTable_oid[] = {1,3,6,1,2,1,10,166,16,1,2};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid mplsXCUp_oid[] = {1,3,6,1,2,1,10,166,2,0,1};
static oid mplsXCDown_oid[] = {1,3,6,1,2,1,10,166,2,0,2};



/**
 *	initialize mplsLsrStdMIB group mapper
 */
void
mplsLsrStdMIB_init (void)
{
	extern oid mplsLsrStdMIB_oid[];
	extern oid gmplsLsrStdMIB_oid[];
	extern oid gmplsLabelStdMIB_oid[];
	extern oid mplsLsrObjects_oid[];
	extern oid gmplsLabelObjects_oid[];
	
	DEBUGMSGTL (("mplsLsrStdMIB", "Initializing\n"));
	
	/* register mplsLsrObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mplsLsrObjects_mapper", &mplsLsrObjects_mapper,
			mplsLsrObjects_oid, OID_LENGTH (mplsLsrObjects_oid),
			HANDLER_CAN_RWRITE
		),
		MPLSINSEGMENTINDEXNEXT,
		MPLSXCNOTIFICATIONSENABLE
	);
	
	/* register gmplsLabelObjects scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"gmplsLabelObjects_mapper", &gmplsLabelObjects_mapper,
			gmplsLabelObjects_oid, OID_LENGTH (gmplsLabelObjects_oid),
			HANDLER_CAN_RONLY
		),
		GMPLSLABELINDEXNEXT,
		GMPLSLABELINDEXNEXT
	);
	
	
	/* register mplsLsrStdMIB group table mappers */
	mplsInterfaceTable_init ();
	mplsInterfacePerfTable_init ();
	mplsInSegmentTable_init ();
	mplsInSegmentPerfTable_init ();
	mplsOutSegmentTable_init ();
	mplsOutSegmentPerfTable_init ();
	mplsXCTable_init ();
	mplsLabelStackTable_init ();
	gmplsInterfaceTable_init ();
	gmplsInSegmentTable_init ();
	gmplsOutSegmentTable_init ();
	gmplsLabelTable_init ();
	
	/* register mplsLsrStdMIB modules */
	sysORTable_createRegister ("mplsLsrStdMIB", mplsLsrStdMIB_oid, OID_LENGTH (mplsLsrStdMIB_oid));
	sysORTable_createRegister ("gmplsLsrStdMIB", gmplsLsrStdMIB_oid, OID_LENGTH (gmplsLsrStdMIB_oid));
	sysORTable_createRegister ("gmplsLabelStdMIB", gmplsLabelStdMIB_oid, OID_LENGTH (gmplsLabelStdMIB_oid));
}


/**
 *	scalar mapper(s)
 */
mplsLsrObjects_t oMplsLsrObjects;

/** mplsLsrObjects scalar mapper **/
int
mplsLsrObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid mplsLsrObjects_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mplsLsrObjects_oid)])
			{
			case MPLSINSEGMENTINDEXNEXT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsLsrObjects.au8InSegmentIndexNext, oMplsLsrObjects.u16InSegmentIndexNext_len);
				break;
			case MPLSOUTSEGMENTINDEXNEXT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsLsrObjects.au8OutSegmentIndexNext, oMplsLsrObjects.u16OutSegmentIndexNext_len);
				break;
			case MPLSXCINDEXNEXT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsLsrObjects.au8XCIndexNext, oMplsLsrObjects.u16XCIndexNext_len);
				break;
			case MPLSMAXLABELSTACKDEPTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMplsLsrObjects.u32MaxLabelStackDepth);
				break;
			case MPLSLABELSTACKINDEXNEXT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMplsLsrObjects.au8LabelStackIndexNext, oMplsLsrObjects.u16LabelStackIndexNext_len);
				break;
			case MPLSXCNOTIFICATIONSENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oMplsLsrObjects.u8XCNotificationsEnable);
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
			switch (request->requestvb->name[OID_LENGTH (mplsLsrObjects_oid)])
			{
			case MPLSXCNOTIFICATIONSENABLE:
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
			switch (request->requestvb->name[OID_LENGTH (mplsLsrObjects_oid)])
			{
			case MPLSXCNOTIFICATIONSENABLE:
				/* XXX: perform the value change here */
				oMplsLsrObjects.u8XCNotificationsEnable = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (mplsLsrObjects_oid)])
			{
			case MPLSXCNOTIFICATIONSENABLE:
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

gmplsLabelObjects_t oGmplsLabelObjects;

/** gmplsLabelObjects scalar mapper **/
int
gmplsLabelObjects_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid gmplsLabelObjects_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (gmplsLabelObjects_oid)])
			{
			case GMPLSLABELINDEXNEXT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oGmplsLabelObjects.u32IndexNext);
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
/** initialize mplsInterfaceTable table mapper **/
void
mplsInterfaceTable_init (void)
{
	extern oid mplsInterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsInterfaceTable", &mplsInterfaceTable_mapper,
		mplsInterfaceTable_oid, OID_LENGTH (mplsInterfaceTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: mplsInterfaceIndex */,
		0);
	table_info->min_column = MPLSINTERFACELABELMININ;
	table_info->max_column = MPLSINTERFACELABELPARTICIPATIONTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsInterfaceTable_getFirst;
	iinfo->get_next_data_point = &mplsInterfaceTable_getNext;
	iinfo->get_data_point = &mplsInterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsInterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsInterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, mplsInterfaceEntry_t, oBTreeNode);
	register mplsInterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, mplsInterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsInterfaceTable_BTree = xBTree_initInline (&mplsInterfaceTable_BTreeNodeCmp);

/* create a new row in the table */
mplsInterfaceEntry_t *
mplsInterfaceTable_createEntry (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsInterfaceTable_BTree);
	return poEntry;
}

mplsInterfaceEntry_t *
mplsInterfaceTable_getByIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInterfaceEntry_t, oBTreeNode);
}

mplsInterfaceEntry_t *
mplsInterfaceTable_getNextIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsInterfaceTable_removeEntry (mplsInterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsInterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInterfaceTable_BTree);
	return mplsInterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsInterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsInterfaceTable_BTree);
	return put_index_data;
}

bool
mplsInterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsInterfaceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsInterfaceTable table mapper */
int
mplsInterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsInterfaceEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINTERFACELABELMININ:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LabelMinIn);
				break;
			case MPLSINTERFACELABELMAXIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LabelMaxIn);
				break;
			case MPLSINTERFACELABELMINOUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LabelMinOut);
				break;
			case MPLSINTERFACELABELMAXOUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LabelMaxOut);
				break;
			case MPLSINTERFACETOTALBANDWIDTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TotalBandwidth);
				break;
			case MPLSINTERFACEAVAILABLEBANDWIDTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32AvailableBandwidth);
				break;
			case MPLSINTERFACELABELPARTICIPATIONTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LabelParticipationType, table_entry->u16LabelParticipationType_len);
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

/** initialize mplsInterfacePerfTable table mapper **/
void
mplsInterfacePerfTable_init (void)
{
	extern oid mplsInterfacePerfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsInterfacePerfTable", &mplsInterfacePerfTable_mapper,
		mplsInterfacePerfTable_oid, OID_LENGTH (mplsInterfacePerfTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: mplsInterfaceIndex */,
		0);
	table_info->min_column = MPLSINTERFACEPERFINLABELSINUSE;
	table_info->max_column = MPLSINTERFACEPERFOUTFRAGMENTEDPKTS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsInterfacePerfTable_getFirst;
	iinfo->get_next_data_point = &mplsInterfacePerfTable_getNext;
	iinfo->get_data_point = &mplsInterfacePerfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsInterfacePerfTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsInterfacePerfEntry_t *pEntry1 = xBTree_entry (pNode1, mplsInterfacePerfEntry_t, oBTreeNode);
	register mplsInterfacePerfEntry_t *pEntry2 = xBTree_entry (pNode2, mplsInterfacePerfEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMplsInterfacePerfTable_BTree = xBTree_initInline (&mplsInterfacePerfTable_BTreeNodeCmp);

/* create a new row in the table */
mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_createEntry (
	uint32_t u32Index)
{
	register mplsInterfacePerfEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree);
	return poEntry;
}

mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_getByIndex (
	uint32_t u32Index)
{
	register mplsInterfacePerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInterfacePerfEntry_t, oBTreeNode);
}

mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_getNextIndex (
	uint32_t u32Index)
{
	register mplsInterfacePerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInterfacePerfEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsInterfacePerfTable_removeEntry (mplsInterfacePerfEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInterfacePerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInterfacePerfTable_BTree);
	return mplsInterfacePerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInterfacePerfTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInterfacePerfEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsInterfacePerfEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsInterfacePerfTable_BTree);
	return put_index_data;
}

bool
mplsInterfacePerfTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInterfacePerfEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsInterfacePerfTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsInterfacePerfTable table mapper */
int
mplsInterfacePerfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsInterfacePerfEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsInterfacePerfEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINTERFACEPERFINLABELSINUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32InLabelsInUse);
				break;
			case MPLSINTERFACEPERFINLABELLOOKUPFAILURES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InLabelLookupFailures);
				break;
			case MPLSINTERFACEPERFOUTLABELSINUSE:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32OutLabelsInUse);
				break;
			case MPLSINTERFACEPERFOUTFRAGMENTEDPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragmentedPkts);
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

/** initialize mplsInSegmentTable table mapper **/
void
mplsInSegmentTable_init (void)
{
	extern oid mplsInSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsInSegmentTable", &mplsInSegmentTable_mapper,
		mplsInSegmentTable_oid, OID_LENGTH (mplsInSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsInSegmentIndex */,
		0);
	table_info->min_column = MPLSINSEGMENTINTERFACE;
	table_info->max_column = MPLSINSEGMENTSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsInSegmentTable_getFirst;
	iinfo->get_next_data_point = &mplsInSegmentTable_getNext;
	iinfo->get_data_point = &mplsInSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsInSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsInSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, mplsInSegmentEntry_t, oBTreeNode);
	register mplsInSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, mplsInSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsInSegmentTable_BTree = xBTree_initInline (&mplsInSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
mplsInSegmentEntry_t *
mplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->aoLabelPtr = zeroDotZero*/;
	poEntry->i32NPop = 1;
	poEntry->i32AddrFamily = mplsInSegmentAddrFamily_other_c;
	/*poEntry->aoTrafficParamPtr = zeroDotZero*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsInSegmentStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsInSegmentTable_BTree);
	return poEntry;
}

mplsInSegmentEntry_t *
mplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInSegmentEntry_t, oBTreeNode);
}

mplsInSegmentEntry_t *
mplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsInSegmentTable_removeEntry (mplsInSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsInSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInSegmentTable_BTree);
	return mplsInSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsInSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsInSegmentTable_BTree);
	return put_index_data;
}

bool
mplsInSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsInSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsInSegmentTable table mapper */
int
mplsInSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsInSegmentEntry_t *table_entry;
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTINTERFACE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32Interface);
				break;
			case MPLSINSEGMENTLABEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Label);
				break;
			case MPLSINSEGMENTLABELPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoLabelPtr, table_entry->u16LabelPtr_len);
				break;
			case MPLSINSEGMENTNPOP:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NPop);
				break;
			case MPLSINSEGMENTADDRFAMILY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddrFamily);
				break;
			case MPLSINSEGMENTXCINDEX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8XCIndex, table_entry->u16XCIndex_len);
				break;
			case MPLSINSEGMENTOWNER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Owner);
				break;
			case MPLSINSEGMENTTRAFFICPARAMPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoTrafficParamPtr, table_entry->u16TrafficParamPtr_len);
				break;
			case MPLSINSEGMENTROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSINSEGMENTSTORAGETYPE:
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTINTERFACE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTLABEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTLABELPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoLabelPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTNPOP:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTADDRFAMILY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTTRAFFICPARAMPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoTrafficParamPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSINSEGMENTSTORAGETYPE:
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsInSegmentTable_createEntry (
						(void*) idx1->val.string, idx1->val_len);
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsInSegmentTable_removeEntry (table_entry);
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTINTERFACE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Interface))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Interface, sizeof (table_entry->u32Interface));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Interface = *request->requestvb->val.integer;
				break;
			case MPLSINSEGMENTLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Label))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Label, sizeof (table_entry->u32Label));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Label = *request->requestvb->val.integer;
				break;
			case MPLSINSEGMENTLABELPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoLabelPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LabelPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoLabelPtr, sizeof (table_entry->aoLabelPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoLabelPtr, 0, sizeof (table_entry->aoLabelPtr));
				memcpy (table_entry->aoLabelPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LabelPtr_len = request->requestvb->val_len;
				break;
			case MPLSINSEGMENTNPOP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32NPop))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32NPop, sizeof (table_entry->i32NPop));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32NPop = *request->requestvb->val.integer;
				break;
			case MPLSINSEGMENTADDRFAMILY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AddrFamily))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AddrFamily, sizeof (table_entry->i32AddrFamily));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AddrFamily = *request->requestvb->val.integer;
				break;
			case MPLSINSEGMENTTRAFFICPARAMPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoTrafficParamPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TrafficParamPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoTrafficParamPtr, sizeof (table_entry->aoTrafficParamPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoTrafficParamPtr, 0, sizeof (table_entry->aoTrafficParamPtr));
				memcpy (table_entry->aoTrafficParamPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TrafficParamPtr_len = request->requestvb->val_len;
				break;
			case MPLSINSEGMENTSTORAGETYPE:
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsInSegmentTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTINTERFACE:
				memcpy (&table_entry->u32Interface, pvOldDdata, sizeof (table_entry->u32Interface));
				break;
			case MPLSINSEGMENTLABEL:
				memcpy (&table_entry->u32Label, pvOldDdata, sizeof (table_entry->u32Label));
				break;
			case MPLSINSEGMENTLABELPTR:
				memcpy (table_entry->aoLabelPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LabelPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSINSEGMENTNPOP:
				memcpy (&table_entry->i32NPop, pvOldDdata, sizeof (table_entry->i32NPop));
				break;
			case MPLSINSEGMENTADDRFAMILY:
				memcpy (&table_entry->i32AddrFamily, pvOldDdata, sizeof (table_entry->i32AddrFamily));
				break;
			case MPLSINSEGMENTTRAFFICPARAMPTR:
				memcpy (table_entry->aoTrafficParamPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TrafficParamPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSINSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsInSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSINSEGMENTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTROWSTATUS:
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
					mplsInSegmentTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsInSegmentPerfTable table mapper **/
void
mplsInSegmentPerfTable_init (void)
{
	extern oid mplsInSegmentPerfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsInSegmentPerfTable", &mplsInSegmentPerfTable_mapper,
		mplsInSegmentPerfTable_oid, OID_LENGTH (mplsInSegmentPerfTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsInSegmentIndex */,
		0);
	table_info->min_column = MPLSINSEGMENTPERFOCTETS;
	table_info->max_column = MPLSINSEGMENTPERFDISCONTINUITYTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsInSegmentPerfTable_getFirst;
	iinfo->get_next_data_point = &mplsInSegmentPerfTable_getNext;
	iinfo->get_data_point = &mplsInSegmentPerfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsInSegmentPerfTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsInSegmentPerfEntry_t *pEntry1 = xBTree_entry (pNode1, mplsInSegmentPerfEntry_t, oBTreeNode);
	register mplsInSegmentPerfEntry_t *pEntry2 = xBTree_entry (pNode2, mplsInSegmentPerfEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsInSegmentPerfTable_BTree = xBTree_initInline (&mplsInSegmentPerfTable_BTreeNodeCmp);

/* create a new row in the table */
mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentPerfEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree);
	return poEntry;
}

mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentPerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInSegmentPerfEntry_t, oBTreeNode);
}

mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentPerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInSegmentPerfEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsInSegmentPerfTable_removeEntry (mplsInSegmentPerfEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInSegmentPerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInSegmentPerfTable_BTree);
	return mplsInSegmentPerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInSegmentPerfTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInSegmentPerfEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsInSegmentPerfEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsInSegmentPerfTable_BTree);
	return put_index_data;
}

bool
mplsInSegmentPerfTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsInSegmentPerfEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsInSegmentPerfTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsInSegmentPerfTable table mapper */
int
mplsInSegmentPerfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsInSegmentPerfEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsInSegmentPerfEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSINSEGMENTPERFOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Octets);
				break;
			case MPLSINSEGMENTPERFPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Packets);
				break;
			case MPLSINSEGMENTPERFERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Errors);
				break;
			case MPLSINSEGMENTPERFDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Discards);
				break;
			case MPLSINSEGMENTPERFHCOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOctets);
				break;
			case MPLSINSEGMENTPERFDISCONTINUITYTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32DiscontinuityTime);
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

/** initialize mplsOutSegmentTable table mapper **/
void
mplsOutSegmentTable_init (void)
{
	extern oid mplsOutSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsOutSegmentTable", &mplsOutSegmentTable_mapper,
		mplsOutSegmentTable_oid, OID_LENGTH (mplsOutSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsOutSegmentIndex */,
		0);
	table_info->min_column = MPLSOUTSEGMENTINTERFACE;
	table_info->max_column = MPLSOUTSEGMENTSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsOutSegmentTable_getFirst;
	iinfo->get_next_data_point = &mplsOutSegmentTable_getNext;
	iinfo->get_data_point = &mplsOutSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsOutSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsOutSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, mplsOutSegmentEntry_t, oBTreeNode);
	register mplsOutSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, mplsOutSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsOutSegmentTable_BTree = xBTree_initInline (&mplsOutSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
mplsOutSegmentEntry_t *
mplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8PushTopLabel = mplsOutSegmentPushTopLabel_true_c;
	poEntry->u32TopLabel = 0;
	/*poEntry->aoTopLabelPtr = zeroDotZero*/;
	/*poEntry->aoTrafficParamPtr = zeroDotZero*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsOutSegmentStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree);
	return poEntry;
}

mplsOutSegmentEntry_t *
mplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsOutSegmentEntry_t, oBTreeNode);
}

mplsOutSegmentEntry_t *
mplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsOutSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsOutSegmentTable_removeEntry (mplsOutSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsOutSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsOutSegmentTable_BTree);
	return mplsOutSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsOutSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsOutSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsOutSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree);
	return put_index_data;
}

bool
mplsOutSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsOutSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsOutSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsOutSegmentTable table mapper */
int
mplsOutSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsOutSegmentEntry_t *table_entry;
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTINTERFACE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32Interface);
				break;
			case MPLSOUTSEGMENTPUSHTOPLABEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8PushTopLabel);
				break;
			case MPLSOUTSEGMENTTOPLABEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TopLabel);
				break;
			case MPLSOUTSEGMENTTOPLABELPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoTopLabelPtr, table_entry->u16TopLabelPtr_len);
				break;
			case MPLSOUTSEGMENTNEXTHOPADDRTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32NextHopAddrType);
				break;
			case MPLSOUTSEGMENTNEXTHOPADDR:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8NextHopAddr, table_entry->u16NextHopAddr_len);
				break;
			case MPLSOUTSEGMENTXCINDEX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8XCIndex, table_entry->u16XCIndex_len);
				break;
			case MPLSOUTSEGMENTOWNER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Owner);
				break;
			case MPLSOUTSEGMENTTRAFFICPARAMPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoTrafficParamPtr, table_entry->u16TrafficParamPtr_len);
				break;
			case MPLSOUTSEGMENTROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSOUTSEGMENTSTORAGETYPE:
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTINTERFACE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTPUSHTOPLABEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTTOPLABEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTTOPLABELPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoTopLabelPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTNEXTHOPADDRTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTNEXTHOPADDR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8NextHopAddr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTTRAFFICPARAMPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoTrafficParamPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSOUTSEGMENTSTORAGETYPE:
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsOutSegmentTable_createEntry (
						(void*) idx1->val.string, idx1->val_len);
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsOutSegmentTable_removeEntry (table_entry);
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTINTERFACE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Interface))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Interface, sizeof (table_entry->u32Interface));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Interface = *request->requestvb->val.integer;
				break;
			case MPLSOUTSEGMENTPUSHTOPLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8PushTopLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8PushTopLabel, sizeof (table_entry->u8PushTopLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8PushTopLabel = *request->requestvb->val.integer;
				break;
			case MPLSOUTSEGMENTTOPLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TopLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TopLabel, sizeof (table_entry->u32TopLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TopLabel = *request->requestvb->val.integer;
				break;
			case MPLSOUTSEGMENTTOPLABELPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoTopLabelPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TopLabelPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoTopLabelPtr, sizeof (table_entry->aoTopLabelPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoTopLabelPtr, 0, sizeof (table_entry->aoTopLabelPtr));
				memcpy (table_entry->aoTopLabelPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TopLabelPtr_len = request->requestvb->val_len;
				break;
			case MPLSOUTSEGMENTNEXTHOPADDRTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32NextHopAddrType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32NextHopAddrType, sizeof (table_entry->i32NextHopAddrType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32NextHopAddrType = *request->requestvb->val.integer;
				break;
			case MPLSOUTSEGMENTNEXTHOPADDR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8NextHopAddr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16NextHopAddr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8NextHopAddr, sizeof (table_entry->au8NextHopAddr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8NextHopAddr, 0, sizeof (table_entry->au8NextHopAddr));
				memcpy (table_entry->au8NextHopAddr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16NextHopAddr_len = request->requestvb->val_len;
				break;
			case MPLSOUTSEGMENTTRAFFICPARAMPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoTrafficParamPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16TrafficParamPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoTrafficParamPtr, sizeof (table_entry->aoTrafficParamPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoTrafficParamPtr, 0, sizeof (table_entry->aoTrafficParamPtr));
				memcpy (table_entry->aoTrafficParamPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16TrafficParamPtr_len = request->requestvb->val_len;
				break;
			case MPLSOUTSEGMENTSTORAGETYPE:
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsOutSegmentTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTINTERFACE:
				memcpy (&table_entry->u32Interface, pvOldDdata, sizeof (table_entry->u32Interface));
				break;
			case MPLSOUTSEGMENTPUSHTOPLABEL:
				memcpy (&table_entry->u8PushTopLabel, pvOldDdata, sizeof (table_entry->u8PushTopLabel));
				break;
			case MPLSOUTSEGMENTTOPLABEL:
				memcpy (&table_entry->u32TopLabel, pvOldDdata, sizeof (table_entry->u32TopLabel));
				break;
			case MPLSOUTSEGMENTTOPLABELPTR:
				memcpy (table_entry->aoTopLabelPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TopLabelPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSOUTSEGMENTNEXTHOPADDRTYPE:
				memcpy (&table_entry->i32NextHopAddrType, pvOldDdata, sizeof (table_entry->i32NextHopAddrType));
				break;
			case MPLSOUTSEGMENTNEXTHOPADDR:
				memcpy (table_entry->au8NextHopAddr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NextHopAddr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSOUTSEGMENTTRAFFICPARAMPTR:
				memcpy (table_entry->aoTrafficParamPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16TrafficParamPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSOUTSEGMENTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSOUTSEGMENTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTROWSTATUS:
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
					mplsOutSegmentTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsOutSegmentPerfTable table mapper **/
void
mplsOutSegmentPerfTable_init (void)
{
	extern oid mplsOutSegmentPerfTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsOutSegmentPerfTable", &mplsOutSegmentPerfTable_mapper,
		mplsOutSegmentPerfTable_oid, OID_LENGTH (mplsOutSegmentPerfTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsOutSegmentIndex */,
		0);
	table_info->min_column = MPLSOUTSEGMENTPERFOCTETS;
	table_info->max_column = MPLSOUTSEGMENTPERFDISCONTINUITYTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsOutSegmentPerfTable_getFirst;
	iinfo->get_next_data_point = &mplsOutSegmentPerfTable_getNext;
	iinfo->get_data_point = &mplsOutSegmentPerfTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsOutSegmentPerfTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsOutSegmentPerfEntry_t *pEntry1 = xBTree_entry (pNode1, mplsOutSegmentPerfEntry_t, oBTreeNode);
	register mplsOutSegmentPerfEntry_t *pEntry2 = xBTree_entry (pNode2, mplsOutSegmentPerfEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsOutSegmentPerfTable_BTree = xBTree_initInline (&mplsOutSegmentPerfTable_BTreeNodeCmp);

/* create a new row in the table */
mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentPerfEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree);
	return poEntry;
}

mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentPerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsOutSegmentPerfEntry_t, oBTreeNode);
}

mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentPerfEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsOutSegmentPerfEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsOutSegmentPerfTable_removeEntry (mplsOutSegmentPerfEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsOutSegmentPerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsOutSegmentPerfTable_BTree);
	return mplsOutSegmentPerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsOutSegmentPerfTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsOutSegmentPerfEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsOutSegmentPerfEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsOutSegmentPerfTable_BTree);
	return put_index_data;
}

bool
mplsOutSegmentPerfTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsOutSegmentPerfEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mplsOutSegmentPerfTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsOutSegmentPerfTable table mapper */
int
mplsOutSegmentPerfTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsOutSegmentPerfEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsOutSegmentPerfEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSOUTSEGMENTPERFOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Octets);
				break;
			case MPLSOUTSEGMENTPERFPACKETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Packets);
				break;
			case MPLSOUTSEGMENTPERFERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Errors);
				break;
			case MPLSOUTSEGMENTPERFDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32Discards);
				break;
			case MPLSOUTSEGMENTPERFHCOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOctets);
				break;
			case MPLSOUTSEGMENTPERFDISCONTINUITYTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32DiscontinuityTime);
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

/** initialize mplsXCTable table mapper **/
void
mplsXCTable_init (void)
{
	extern oid mplsXCTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsXCTable", &mplsXCTable_mapper,
		mplsXCTable_oid, OID_LENGTH (mplsXCTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsXCIndex */,
		ASN_OCTET_STR /* index: mplsXCInSegmentIndex */,
		ASN_OCTET_STR /* index: mplsXCOutSegmentIndex */,
		0);
	table_info->min_column = MPLSXCLSPID;
	table_info->max_column = MPLSXCOPERSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsXCTable_getFirst;
	iinfo->get_next_data_point = &mplsXCTable_getNext;
	iinfo->get_data_point = &mplsXCTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsXCTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsXCEntry_t *pEntry1 = xBTree_entry (pNode1, mplsXCEntry_t, oBTreeNode);
	register mplsXCEntry_t *pEntry2 = xBTree_entry (pNode2, mplsXCEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == 0) ? 0: 1;
}

xBTree_t oMplsXCTable_BTree = xBTree_initInline (&mplsXCTable_BTreeNodeCmp);

/* create a new row in the table */
mplsXCEntry_t *
mplsXCTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register mplsXCEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	memcpy (poEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsXCTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsXCStorageType_volatile_c;
	poEntry->i32AdminStatus = mplsXCAdminStatus_up_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsXCTable_BTree);
	return poEntry;
}

mplsXCEntry_t *
mplsXCTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register mplsXCEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	memcpy (poTmpEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poTmpEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poTmpEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poTmpEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsXCTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsXCEntry_t, oBTreeNode);
}

mplsXCEntry_t *
mplsXCTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len)
{
	register mplsXCEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	memcpy (poTmpEntry->au8InSegmentIndex, pau8InSegmentIndex, u16InSegmentIndex_len);
	poTmpEntry->u16InSegmentIndex_len = u16InSegmentIndex_len;
	memcpy (poTmpEntry->au8OutSegmentIndex, pau8OutSegmentIndex, u16OutSegmentIndex_len);
	poTmpEntry->u16OutSegmentIndex_len = u16OutSegmentIndex_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsXCTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsXCEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsXCTable_removeEntry (mplsXCEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsXCTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsXCTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsXCTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsXCTable_BTree);
	return mplsXCTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsXCTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsXCEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsXCEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8InSegmentIndex, poEntry->u16InSegmentIndex_len);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8OutSegmentIndex, poEntry->u16OutSegmentIndex_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsXCTable_BTree);
	return put_index_data;
}

bool
mplsXCTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsXCEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = mplsXCTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		(void*) idx2->val.string, idx2->val_len,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsXCTable table mapper */
int
mplsXCTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsXCEntry_t *table_entry;
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSXCLSPID:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LspId, table_entry->u16LspId_len);
				break;
			case MPLSXCLABELSTACKINDEX:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LabelStackIndex, table_entry->u16LabelStackIndex_len);
				break;
			case MPLSXCOWNER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Owner);
				break;
			case MPLSXCROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSXCSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case MPLSXCADMINSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminStatus);
				break;
			case MPLSXCOPERSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperStatus);
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSXCLSPID:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LspId));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSXCLABELSTACKINDEX:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LabelStackIndex));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSXCROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSXCSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSXCADMINSTATUS:
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case MPLSXCROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsXCTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
						(void*) idx2->val.string, idx2->val_len,
						(void*) idx3->val.string, idx3->val_len);
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSXCROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsXCTable_removeEntry (table_entry);
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSXCLSPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LspId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LspId_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LspId, sizeof (table_entry->au8LspId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LspId, 0, sizeof (table_entry->au8LspId));
				memcpy (table_entry->au8LspId, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LspId_len = request->requestvb->val_len;
				break;
			case MPLSXCLABELSTACKINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LabelStackIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LabelStackIndex_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LabelStackIndex, sizeof (table_entry->au8LabelStackIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LabelStackIndex, 0, sizeof (table_entry->au8LabelStackIndex));
				memcpy (table_entry->au8LabelStackIndex, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LabelStackIndex_len = request->requestvb->val_len;
				break;
			case MPLSXCSTORAGETYPE:
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
			case MPLSXCADMINSTATUS:
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
				
				table_entry->i32AdminStatus = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSXCROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsXCTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSXCLSPID:
				memcpy (table_entry->au8LspId, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LspId_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSXCLABELSTACKINDEX:
				memcpy (table_entry->au8LabelStackIndex, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LabelStackIndex_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSXCROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsXCTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSXCSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case MPLSXCADMINSTATUS:
				memcpy (&table_entry->i32AdminStatus, pvOldDdata, sizeof (table_entry->i32AdminStatus));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsXCEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSXCROWSTATUS:
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
					mplsXCTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mplsLabelStackTable table mapper **/
void
mplsLabelStackTable_init (void)
{
	extern oid mplsLabelStackTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mplsLabelStackTable", &mplsLabelStackTable_mapper,
		mplsLabelStackTable_oid, OID_LENGTH (mplsLabelStackTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsLabelStackIndex */,
		ASN_UNSIGNED /* index: mplsLabelStackLabelIndex */,
		0);
	table_info->min_column = MPLSLABELSTACKLABEL;
	table_info->max_column = MPLSLABELSTACKSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mplsLabelStackTable_getFirst;
	iinfo->get_next_data_point = &mplsLabelStackTable_getNext;
	iinfo->get_data_point = &mplsLabelStackTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mplsLabelStackTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsLabelStackEntry_t *pEntry1 = xBTree_entry (pNode1, mplsLabelStackEntry_t, oBTreeNode);
	register mplsLabelStackEntry_t *pEntry2 = xBTree_entry (pNode2, mplsLabelStackEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && pEntry1->u32LabelIndex < pEntry2->u32LabelIndex) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && pEntry1->u32LabelIndex == pEntry2->u32LabelIndex) ? 0: 1;
}

xBTree_t oMplsLabelStackTable_BTree = xBTree_initInline (&mplsLabelStackTable_BTreeNodeCmp);

/* create a new row in the table */
mplsLabelStackEntry_t *
mplsLabelStackTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register mplsLabelStackEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	poEntry->u32LabelIndex = u32LabelIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->aoLabelPtr = zeroDotZero*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = mplsLabelStackStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree);
	return poEntry;
}

mplsLabelStackEntry_t *
mplsLabelStackTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register mplsLabelStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	poTmpEntry->u32LabelIndex = u32LabelIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMplsLabelStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsLabelStackEntry_t, oBTreeNode);
}

mplsLabelStackEntry_t *
mplsLabelStackTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex)
{
	register mplsLabelStackEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	poTmpEntry->u32LabelIndex = u32LabelIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMplsLabelStackTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsLabelStackEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mplsLabelStackTable_removeEntry (mplsLabelStackEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsLabelStackTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsLabelStackTable_BTree);
	return mplsLabelStackTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsLabelStackTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsLabelStackEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mplsLabelStackEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32LabelIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsLabelStackTable_BTree);
	return put_index_data;
}

bool
mplsLabelStackTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mplsLabelStackEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mplsLabelStackTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mplsLabelStackTable table mapper */
int
mplsLabelStackTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mplsLabelStackEntry_t *table_entry;
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKLABEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Label);
				break;
			case MPLSLABELSTACKLABELPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoLabelPtr, table_entry->u16LabelPtr_len);
				break;
			case MPLSLABELSTACKROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case MPLSLABELSTACKSTORAGETYPE:
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKLABEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSLABELSTACKLABELPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoLabelPtr));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSLABELSTACKROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MPLSLABELSTACKSTORAGETYPE:
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mplsLabelStackTable_createEntry (
						(void*) idx1->val.string, idx1->val_len,
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsLabelStackTable_removeEntry (table_entry);
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Label))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Label, sizeof (table_entry->u32Label));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Label = *request->requestvb->val.integer;
				break;
			case MPLSLABELSTACKLABELPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoLabelPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LabelPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoLabelPtr, sizeof (table_entry->aoLabelPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoLabelPtr, 0, sizeof (table_entry->aoLabelPtr));
				memcpy (table_entry->aoLabelPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LabelPtr_len = request->requestvb->val_len;
				break;
			case MPLSLABELSTACKSTORAGETYPE:
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mplsLabelStackTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKLABEL:
				memcpy (&table_entry->u32Label, pvOldDdata, sizeof (table_entry->u32Label));
				break;
			case MPLSLABELSTACKLABELPTR:
				memcpy (table_entry->aoLabelPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LabelPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MPLSLABELSTACKROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mplsLabelStackTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case MPLSLABELSTACKSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mplsLabelStackEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MPLSLABELSTACKROWSTATUS:
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
					mplsLabelStackTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize gmplsInterfaceTable table mapper **/
void
gmplsInterfaceTable_init (void)
{
	extern oid gmplsInterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsInterfaceTable", &gmplsInterfaceTable_mapper,
		gmplsInterfaceTable_oid, OID_LENGTH (gmplsInterfaceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: mplsInterfaceIndex */,
		0);
	table_info->min_column = GMPLSINTERFACESIGNALINGCAPS;
	table_info->max_column = GMPLSINTERFACERSVPHELLOPERIOD;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsInterfaceTable_getFirst;
	iinfo->get_next_data_point = &gmplsInterfaceTable_getNext;
	iinfo->get_data_point = &gmplsInterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
gmplsInterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register gmplsInterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, gmplsInterfaceEntry_t, oBTreeNode);
	register gmplsInterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, gmplsInterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oGmplsInterfaceTable_BTree = xBTree_initInline (&gmplsInterfaceTable_BTreeNodeCmp);

/* create a new row in the table */
gmplsInterfaceEntry_t *
gmplsInterfaceTable_createEntry (
	uint32_t u32Index)
{
	register gmplsInterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsInterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBitmap_setBitsRev (poEntry->au8SignalingCaps, 1, 1, gmplsInterfaceSignalingCaps_rsvpGmpls_c);
	poEntry->u32RsvpHelloPeriod = 3000;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oGmplsInterfaceTable_BTree);
	return poEntry;
}

gmplsInterfaceEntry_t *
gmplsInterfaceTable_getByIndex (
	uint32_t u32Index)
{
	register gmplsInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oGmplsInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsInterfaceEntry_t, oBTreeNode);
}

gmplsInterfaceEntry_t *
gmplsInterfaceTable_getNextIndex (
	uint32_t u32Index)
{
	register gmplsInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oGmplsInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsInterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
gmplsInterfaceTable_removeEntry (gmplsInterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsInterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oGmplsInterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsInterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oGmplsInterfaceTable_BTree);
	return gmplsInterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsInterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsInterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, gmplsInterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oGmplsInterfaceTable_BTree);
	return put_index_data;
}

bool
gmplsInterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsInterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = gmplsInterfaceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* gmplsInterfaceTable table mapper */
int
gmplsInterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsInterfaceEntry_t *table_entry;
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
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8SignalingCaps, table_entry->u16SignalingCaps_len);
				break;
			case GMPLSINTERFACERSVPHELLOPERIOD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RsvpHelloPeriod);
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
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8SignalingCaps));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSINTERFACERSVPHELLOPERIOD:
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
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
			case GMPLSINTERFACERSVPHELLOPERIOD:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = gmplsInterfaceTable_createEntry (
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
				}
				break;
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
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
			case GMPLSINTERFACERSVPHELLOPERIOD:
				gmplsInterfaceTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8SignalingCaps))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16SignalingCaps_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8SignalingCaps, sizeof (table_entry->au8SignalingCaps));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8SignalingCaps, 0, sizeof (table_entry->au8SignalingCaps));
				memcpy (table_entry->au8SignalingCaps, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16SignalingCaps_len = request->requestvb->val_len;
				break;
			case GMPLSINTERFACERSVPHELLOPERIOD:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RsvpHelloPeriod))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RsvpHelloPeriod, sizeof (table_entry->u32RsvpHelloPeriod));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RsvpHelloPeriod = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
				if (pvOldDdata == table_entry)
				{
					gmplsInterfaceTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->au8SignalingCaps, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16SignalingCaps_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			case GMPLSINTERFACERSVPHELLOPERIOD:
				if (pvOldDdata == table_entry)
				{
					gmplsInterfaceTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32RsvpHelloPeriod, pvOldDdata, sizeof (table_entry->u32RsvpHelloPeriod));
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize gmplsInSegmentTable table mapper **/
void
gmplsInSegmentTable_init (void)
{
	extern oid gmplsInSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsInSegmentTable", &gmplsInSegmentTable_mapper,
		gmplsInSegmentTable_oid, OID_LENGTH (gmplsInSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsInSegmentIndex */,
		0);
	table_info->min_column = GMPLSINSEGMENTDIRECTION;
	table_info->max_column = GMPLSINSEGMENTEXTRAPARAMSPTR;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsInSegmentTable_getFirst;
	iinfo->get_next_data_point = &gmplsInSegmentTable_getNext;
	iinfo->get_data_point = &gmplsInSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
gmplsInSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register gmplsInSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, gmplsInSegmentEntry_t, oBTreeNode);
	register gmplsInSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, gmplsInSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oGmplsInSegmentTable_BTree = xBTree_initInline (&gmplsInSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
gmplsInSegmentEntry_t *
gmplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsInSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsInSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Direction = gmplsInSegmentDirection_forward_c;
	/*poEntry->aoExtraParamsPtr = zeroDotZero*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oGmplsInSegmentTable_BTree);
	return poEntry;
}

gmplsInSegmentEntry_t *
gmplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oGmplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsInSegmentEntry_t, oBTreeNode);
}

gmplsInSegmentEntry_t *
gmplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oGmplsInSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsInSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
gmplsInSegmentTable_removeEntry (gmplsInSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsInSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oGmplsInSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsInSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oGmplsInSegmentTable_BTree);
	return gmplsInSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsInSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsInSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, gmplsInSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oGmplsInSegmentTable_BTree);
	return put_index_data;
}

bool
gmplsInSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsInSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = gmplsInSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* gmplsInSegmentTable table mapper */
int
gmplsInSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsInSegmentEntry_t *table_entry;
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
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Direction);
				break;
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoExtraParamsPtr, table_entry->u16ExtraParamsPtr_len);
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
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoExtraParamsPtr));
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
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = gmplsInSegmentTable_createEntry (
						(void*) idx1->val.string, idx1->val_len);
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
				}
				break;
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
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				gmplsInSegmentTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
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
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoExtraParamsPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ExtraParamsPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoExtraParamsPtr, sizeof (table_entry->aoExtraParamsPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoExtraParamsPtr, 0, sizeof (table_entry->aoExtraParamsPtr));
				memcpy (table_entry->aoExtraParamsPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ExtraParamsPtr_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
				if (pvOldDdata == table_entry)
				{
					gmplsInSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32Direction, pvOldDdata, sizeof (table_entry->i32Direction));
				}
				break;
			case GMPLSINSEGMENTEXTRAPARAMSPTR:
				if (pvOldDdata == table_entry)
				{
					gmplsInSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->aoExtraParamsPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16ExtraParamsPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize gmplsOutSegmentTable table mapper **/
void
gmplsOutSegmentTable_init (void)
{
	extern oid gmplsOutSegmentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsOutSegmentTable", &gmplsOutSegmentTable_mapper,
		gmplsOutSegmentTable_oid, OID_LENGTH (gmplsOutSegmentTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: mplsOutSegmentIndex */,
		0);
	table_info->min_column = GMPLSOUTSEGMENTDIRECTION;
	table_info->max_column = GMPLSOUTSEGMENTEXTRAPARAMSPTR;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsOutSegmentTable_getFirst;
	iinfo->get_next_data_point = &gmplsOutSegmentTable_getNext;
	iinfo->get_data_point = &gmplsOutSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
gmplsOutSegmentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register gmplsOutSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, gmplsOutSegmentEntry_t, oBTreeNode);
	register gmplsOutSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, gmplsOutSegmentEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oGmplsOutSegmentTable_BTree = xBTree_initInline (&gmplsOutSegmentTable_BTreeNodeCmp);

/* create a new row in the table */
gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsOutSegmentEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Index, pau8Index, u16Index_len);
	poEntry->u16Index_len = u16Index_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Direction = gmplsOutSegmentDirection_forward_c;
	poEntry->u32TTLDecrement = 0;
	/*poEntry->aoExtraParamsPtr = zeroDotZero*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree);
	return poEntry;
}

gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsOutSegmentEntry_t, oBTreeNode);
}

gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsOutSegmentEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
gmplsOutSegmentTable_removeEntry (gmplsOutSegmentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsOutSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oGmplsOutSegmentTable_BTree);
	return gmplsOutSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsOutSegmentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsOutSegmentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, gmplsOutSegmentEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Index, poEntry->u16Index_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oGmplsOutSegmentTable_BTree);
	return put_index_data;
}

bool
gmplsOutSegmentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsOutSegmentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = gmplsOutSegmentTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* gmplsOutSegmentTable table mapper */
int
gmplsOutSegmentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsOutSegmentEntry_t *table_entry;
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
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Direction);
				break;
			case GMPLSOUTSEGMENTTTLDECREMENT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32TTLDecrement);
				break;
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoExtraParamsPtr, table_entry->u16ExtraParamsPtr_len);
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
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSOUTSEGMENTTTLDECREMENT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OBJECT_ID, sizeof (table_entry->aoExtraParamsPtr));
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
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
			case GMPLSOUTSEGMENTTTLDECREMENT:
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = gmplsOutSegmentTable_createEntry (
						(void*) idx1->val.string, idx1->val_len);
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
				}
				break;
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
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
			case GMPLSOUTSEGMENTTTLDECREMENT:
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				gmplsOutSegmentTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
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
			case GMPLSOUTSEGMENTTTLDECREMENT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32TTLDecrement))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32TTLDecrement, sizeof (table_entry->u32TTLDecrement));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32TTLDecrement = *request->requestvb->val.integer;
				break;
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->aoExtraParamsPtr))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ExtraParamsPtr_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->aoExtraParamsPtr, sizeof (table_entry->aoExtraParamsPtr));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->aoExtraParamsPtr, 0, sizeof (table_entry->aoExtraParamsPtr));
				memcpy (table_entry->aoExtraParamsPtr, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ExtraParamsPtr_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (gmplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSOUTSEGMENTDIRECTION:
				if (pvOldDdata == table_entry)
				{
					gmplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32Direction, pvOldDdata, sizeof (table_entry->i32Direction));
				}
				break;
			case GMPLSOUTSEGMENTTTLDECREMENT:
				if (pvOldDdata == table_entry)
				{
					gmplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32TTLDecrement, pvOldDdata, sizeof (table_entry->u32TTLDecrement));
				}
				break;
			case GMPLSOUTSEGMENTEXTRAPARAMSPTR:
				if (pvOldDdata == table_entry)
				{
					gmplsOutSegmentTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (table_entry->aoExtraParamsPtr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
					table_entry->u16ExtraParamsPtr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				}
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize gmplsLabelTable table mapper **/
void
gmplsLabelTable_init (void)
{
	extern oid gmplsLabelTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"gmplsLabelTable", &gmplsLabelTable_mapper,
		gmplsLabelTable_oid, OID_LENGTH (gmplsLabelTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: gmplsLabelInterface */,
		ASN_UNSIGNED /* index: gmplsLabelIndex */,
		ASN_UNSIGNED /* index: gmplsLabelSubindex */,
		0);
	table_info->min_column = GMPLSLABELTYPE;
	table_info->max_column = GMPLSLABELROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsLabelTable_getFirst;
	iinfo->get_next_data_point = &gmplsLabelTable_getNext;
	iinfo->get_data_point = &gmplsLabelTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
gmplsLabelTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register gmplsLabelEntry_t *pEntry1 = xBTree_entry (pNode1, gmplsLabelEntry_t, oBTreeNode);
	register gmplsLabelEntry_t *pEntry2 = xBTree_entry (pNode2, gmplsLabelEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Interface < pEntry2->u32Interface) ||
		(pEntry1->u32Interface == pEntry2->u32Interface && pEntry1->u32Index < pEntry2->u32Index) ||
		(pEntry1->u32Interface == pEntry2->u32Interface && pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Subindex < pEntry2->u32Subindex) ? -1:
		(pEntry1->u32Interface == pEntry2->u32Interface && pEntry1->u32Index == pEntry2->u32Index && pEntry1->u32Subindex == pEntry2->u32Subindex) ? 0: 1;
}

xBTree_t oGmplsLabelTable_BTree = xBTree_initInline (&gmplsLabelTable_BTreeNodeCmp);

/* create a new row in the table */
gmplsLabelEntry_t *
gmplsLabelTable_createEntry (
	uint32_t u32Interface,
	uint32_t u32Index,
	uint32_t u32Subindex)
{
	register gmplsLabelEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Interface = u32Interface;
	poEntry->u32Index = u32Index;
	poEntry->u32Subindex = u32Subindex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsLabelTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32MplsLabel = 0;
	poEntry->u32PortWavelength = 0;
	/*poEntry->au8Freeform = 0*/;
	poEntry->i32SonetSdhSignalIndex = 0;
	poEntry->i32SdhVc = 0;
	poEntry->i32SdhVcBranch = 0;
	poEntry->i32SonetSdhBranch = 0;
	poEntry->i32SonetSdhGroupBranch = 0;
	poEntry->u32WavebandId = 0;
	poEntry->u32WavebandStart = 0;
	poEntry->u32WavebandEnd = 0;
	poEntry->u8StorageType = gmplsLabelStorageType_volatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oGmplsLabelTable_BTree);
	return poEntry;
}

gmplsLabelEntry_t *
gmplsLabelTable_getByIndex (
	uint32_t u32Interface,
	uint32_t u32Index,
	uint32_t u32Subindex)
{
	register gmplsLabelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Interface = u32Interface;
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Subindex = u32Subindex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oGmplsLabelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsLabelEntry_t, oBTreeNode);
}

gmplsLabelEntry_t *
gmplsLabelTable_getNextIndex (
	uint32_t u32Interface,
	uint32_t u32Index,
	uint32_t u32Subindex)
{
	register gmplsLabelEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Interface = u32Interface;
	poTmpEntry->u32Index = u32Index;
	poTmpEntry->u32Subindex = u32Subindex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oGmplsLabelTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, gmplsLabelEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
gmplsLabelTable_removeEntry (gmplsLabelEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oGmplsLabelTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oGmplsLabelTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsLabelTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oGmplsLabelTable_BTree);
	return gmplsLabelTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsLabelTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsLabelEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, gmplsLabelEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32Interface);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Subindex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oGmplsLabelTable_BTree);
	return put_index_data;
}

bool
gmplsLabelTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	gmplsLabelEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = gmplsLabelTable_getByIndex (
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

/* gmplsLabelTable table mapper */
int
gmplsLabelTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	gmplsLabelEntry_t *table_entry;
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSLABELTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case GMPLSLABELMPLSLABEL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MplsLabel);
				break;
			case GMPLSLABELPORTWAVELENGTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PortWavelength);
				break;
			case GMPLSLABELFREEFORM:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Freeform, table_entry->u16Freeform_len);
				break;
			case GMPLSLABELSONETSDHSIGNALINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SonetSdhSignalIndex);
				break;
			case GMPLSLABELSDHVC:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SdhVc);
				break;
			case GMPLSLABELSDHVCBRANCH:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SdhVcBranch);
				break;
			case GMPLSLABELSONETSDHBRANCH:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SonetSdhBranch);
				break;
			case GMPLSLABELSONETSDHGROUPBRANCH:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SonetSdhGroupBranch);
				break;
			case GMPLSLABELWAVEBANDID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WavebandId);
				break;
			case GMPLSLABELWAVEBANDSTART:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WavebandStart);
				break;
			case GMPLSLABELWAVEBANDEND:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32WavebandEnd);
				break;
			case GMPLSLABELSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case GMPLSLABELROWSTATUS:
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSLABELTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELMPLSLABEL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELPORTWAVELENGTH:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELFREEFORM:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Freeform));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSONETSDHSIGNALINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSDHVC:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSDHVCBRANCH:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSONETSDHBRANCH:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSONETSDHGROUPBRANCH:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELWAVEBANDID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELWAVEBANDSTART:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELWAVEBANDEND:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case GMPLSLABELROWSTATUS:
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case GMPLSLABELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = gmplsLabelTable_createEntry (
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSLABELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					gmplsLabelTable_removeEntry (table_entry);
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSLABELTYPE:
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
			case GMPLSLABELMPLSLABEL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MplsLabel))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MplsLabel, sizeof (table_entry->u32MplsLabel));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MplsLabel = *request->requestvb->val.integer;
				break;
			case GMPLSLABELPORTWAVELENGTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PortWavelength))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PortWavelength, sizeof (table_entry->u32PortWavelength));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PortWavelength = *request->requestvb->val.integer;
				break;
			case GMPLSLABELFREEFORM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Freeform))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Freeform_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Freeform, sizeof (table_entry->au8Freeform));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Freeform, 0, sizeof (table_entry->au8Freeform));
				memcpy (table_entry->au8Freeform, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Freeform_len = request->requestvb->val_len;
				break;
			case GMPLSLABELSONETSDHSIGNALINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SonetSdhSignalIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SonetSdhSignalIndex, sizeof (table_entry->i32SonetSdhSignalIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SonetSdhSignalIndex = *request->requestvb->val.integer;
				break;
			case GMPLSLABELSDHVC:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SdhVc))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SdhVc, sizeof (table_entry->i32SdhVc));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SdhVc = *request->requestvb->val.integer;
				break;
			case GMPLSLABELSDHVCBRANCH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SdhVcBranch))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SdhVcBranch, sizeof (table_entry->i32SdhVcBranch));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SdhVcBranch = *request->requestvb->val.integer;
				break;
			case GMPLSLABELSONETSDHBRANCH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SonetSdhBranch))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SonetSdhBranch, sizeof (table_entry->i32SonetSdhBranch));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SonetSdhBranch = *request->requestvb->val.integer;
				break;
			case GMPLSLABELSONETSDHGROUPBRANCH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SonetSdhGroupBranch))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SonetSdhGroupBranch, sizeof (table_entry->i32SonetSdhGroupBranch));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SonetSdhGroupBranch = *request->requestvb->val.integer;
				break;
			case GMPLSLABELWAVEBANDID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WavebandId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WavebandId, sizeof (table_entry->u32WavebandId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WavebandId = *request->requestvb->val.integer;
				break;
			case GMPLSLABELWAVEBANDSTART:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WavebandStart))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WavebandStart, sizeof (table_entry->u32WavebandStart));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WavebandStart = *request->requestvb->val.integer;
				break;
			case GMPLSLABELWAVEBANDEND:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32WavebandEnd))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32WavebandEnd, sizeof (table_entry->u32WavebandEnd));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32WavebandEnd = *request->requestvb->val.integer;
				break;
			case GMPLSLABELSTORAGETYPE:
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSLABELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int gmplsLabelTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case GMPLSLABELTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case GMPLSLABELMPLSLABEL:
				memcpy (&table_entry->u32MplsLabel, pvOldDdata, sizeof (table_entry->u32MplsLabel));
				break;
			case GMPLSLABELPORTWAVELENGTH:
				memcpy (&table_entry->u32PortWavelength, pvOldDdata, sizeof (table_entry->u32PortWavelength));
				break;
			case GMPLSLABELFREEFORM:
				memcpy (table_entry->au8Freeform, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Freeform_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case GMPLSLABELSONETSDHSIGNALINDEX:
				memcpy (&table_entry->i32SonetSdhSignalIndex, pvOldDdata, sizeof (table_entry->i32SonetSdhSignalIndex));
				break;
			case GMPLSLABELSDHVC:
				memcpy (&table_entry->i32SdhVc, pvOldDdata, sizeof (table_entry->i32SdhVc));
				break;
			case GMPLSLABELSDHVCBRANCH:
				memcpy (&table_entry->i32SdhVcBranch, pvOldDdata, sizeof (table_entry->i32SdhVcBranch));
				break;
			case GMPLSLABELSONETSDHBRANCH:
				memcpy (&table_entry->i32SonetSdhBranch, pvOldDdata, sizeof (table_entry->i32SonetSdhBranch));
				break;
			case GMPLSLABELSONETSDHGROUPBRANCH:
				memcpy (&table_entry->i32SonetSdhGroupBranch, pvOldDdata, sizeof (table_entry->i32SonetSdhGroupBranch));
				break;
			case GMPLSLABELWAVEBANDID:
				memcpy (&table_entry->u32WavebandId, pvOldDdata, sizeof (table_entry->u32WavebandId));
				break;
			case GMPLSLABELWAVEBANDSTART:
				memcpy (&table_entry->u32WavebandStart, pvOldDdata, sizeof (table_entry->u32WavebandStart));
				break;
			case GMPLSLABELWAVEBANDEND:
				memcpy (&table_entry->u32WavebandEnd, pvOldDdata, sizeof (table_entry->u32WavebandEnd));
				break;
			case GMPLSLABELSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case GMPLSLABELROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					gmplsLabelTable_removeEntry (table_entry);
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
			table_entry = (gmplsLabelEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case GMPLSLABELROWSTATUS:
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
					gmplsLabelTable_removeEntry (table_entry);
					break;
				}
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
mplsXCUp_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsXCUp_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsXCOperStatus_oid[] = {1,3,6,1,2,1,10,166,2,1,10,1,10, /* insert index here */};
//	oid mplsXCOperStatus_oid[] = {1,3,6,1,2,1,10,166,2,1,10,1,10, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsXCUp_oid, sizeof (mplsXCUp_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsXCOperStatus_oid, OID_LENGTH (mplsXCOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsXCOperStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsXCOperStatus_oid, OID_LENGTH (mplsXCOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsXCOperStatus */
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
mplsXCDown_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mplsXCDown_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mplsXCOperStatus_oid[] = {1,3,6,1,2,1,10,166,2,1,10,1,10, /* insert index here */};
//	oid mplsXCOperStatus_oid[] = {1,3,6,1,2,1,10,166,2,1,10,1,10, /* insert index here */};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mplsXCDown_oid, sizeof (mplsXCDown_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mplsXCOperStatus_oid, OID_LENGTH (mplsXCOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsXCOperStatus */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mplsXCOperStatus_oid, OID_LENGTH (mplsXCOperStatus_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mplsXCOperStatus */
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
