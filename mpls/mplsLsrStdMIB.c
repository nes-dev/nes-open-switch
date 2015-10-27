/*
 *  Copyright (c) 2008-2015
 *      NES Dev <nes.open.switch@gmail.com>
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

static oid mplsLsrObjects_oid[] = {1,3,6,1,2,1,10,166,2,1};

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
	extern oid mplsLsrObjects_oid[];
	
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
	
	/* register mplsLsrStdMIB modules */
	sysORTable_createRegister ("mplsLsrStdMIB", mplsLsrStdMIB_oid, OID_LENGTH (mplsLsrStdMIB_oid));
	sysORTable_createRegister ("gmplsLsrStdMIB", gmplsLsrStdMIB_oid, OID_LENGTH (gmplsLsrStdMIB_oid));
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

mplsInterfaceEntry_t *
mplsInterfaceTable_createExt (
	uint32_t u32Index)
{
	mplsInterfaceEntry_t *poEntry = NULL;
	
	poEntry = mplsInterfaceTable_createEntry (
		u32Index);
	if (poEntry == NULL)
	{
		goto mplsInterfaceTable_createExt_cleanup;
	}
	
	if (!mplsInterfaceTable_createHier (poEntry))
	{
		mplsInterfaceTable_removeEntry (poEntry);
		poEntry = NULL;
		goto mplsInterfaceTable_createExt_cleanup;
	}
	
mplsInterfaceTable_createExt_cleanup:
	
	return poEntry;
}

bool
mplsInterfaceTable_removeExt (mplsInterfaceEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!mplsInterfaceTable_removeHier (poEntry))
	{
		goto mplsInterfaceTable_removeExt_cleanup;
	}
	mplsInterfaceTable_removeEntry (poEntry);
	bRetCode = true;
	
mplsInterfaceTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
mplsInterfaceTable_createHier (
	mplsInterfaceEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (mplsInterfacePerfTable_createEntry (poEntry->u32Index) == NULL)
	{
		goto mplsInterfaceTable_createHier_cleanup;
	}
	
	if (gmplsInterfaceTable_createEntry (poEntry->u32Index) == NULL)
	{
		goto mplsInterfaceTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
mplsInterfaceTable_createHier_cleanup:
	
	!bRetCode ? mplsInterfaceTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
mplsInterfaceTable_removeHier (
	mplsInterfaceEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	mplsInterfacePerfTable_removeEntry (&poEntry->oPerf);
	gmplsInterfaceTable_removeEntry (&poEntry->oG);
	
	bRetCode = true;
	
// mplsInterfaceTable_removeHier_cleanup:
	
	return bRetCode;
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

/* create a new row in the table */
mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_createEntry (
	uint32_t u32Index)
{
	register mplsInterfacePerfEntry_t *poEntry = NULL;
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poInterface->oPerf;
	
	return poEntry;
}

mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_getByIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poInterface->oPerf;
}

mplsInterfacePerfEntry_t *
mplsInterfacePerfTable_getNextIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poInterface->oPerf;
}

/* remove a row from the table */
void
mplsInterfacePerfTable_removeEntry (mplsInterfacePerfEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInterfacePerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInterfaceTable_BTree);
	return mplsInterfacePerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInterfacePerfTable_getNext (
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
mplsInterfacePerfTable_get (
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
	register mplsInterfaceEntry_t *poEntry = NULL;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oPerf;
			
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

static int8_t
mplsInSegmentTable_If_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsInSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, mplsInSegmentEntry_t, oIf_BTreeNode);
	register mplsInSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, mplsInSegmentEntry_t, oIf_BTreeNode);
	
	return
		(pEntry1->oK.u32Interface < pEntry2->oK.u32Interface) ||
		(pEntry1->oK.u32Interface == pEntry2->oK.u32Interface && xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(pEntry1->oK.u32Interface == pEntry2->oK.u32Interface && xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsInSegmentTable_BTree = xBTree_initInline (&mplsInSegmentTable_BTreeNodeCmp);
xBTree_t oMplsInSegmentTable_If_BTree = xBTree_initInline (&mplsInSegmentTable_If_BTreeNodeCmp);

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
	
	poEntry->i32NPop = 1;
	poEntry->i32AddrFamily = mplsInSegmentAddrFamily_other_c;
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

mplsInSegmentEntry_t *
mplsInSegmentTable_If_getNextIndex (
	uint32_t u32Interface,
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->oK.u32Interface = u32Interface;
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oIf_BTreeNode, &oMplsInSegmentTable_If_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsInSegmentEntry_t, oIf_BTreeNode);
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

mplsInSegmentEntry_t *
mplsInSegmentTable_createExt (
	uint8_t *pau8Index, size_t u16Index_len)
{
	mplsInSegmentEntry_t *poEntry = NULL;
	
	if (u16Index_len == 0)
	{
		goto mplsInSegmentTable_createExt_cleanup;
	}
	
	poEntry = mplsInSegmentTable_createEntry (
		pau8Index, u16Index_len);
	if (poEntry == NULL)
	{
		goto mplsInSegmentTable_createExt_cleanup;
	}
	
	if (!mplsInSegmentTable_createHier (poEntry))
	{
		mplsInSegmentTable_removeEntry (poEntry);
		poEntry = NULL;
		goto mplsInSegmentTable_createExt_cleanup;
	}
	
mplsInSegmentTable_createExt_cleanup:
	
	return poEntry;
}

bool
mplsInSegmentTable_removeExt (mplsInSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!mplsInSegmentTable_removeHier (poEntry))
	{
		goto mplsInSegmentTable_removeExt_cleanup;
	}
	mplsInSegmentTable_removeEntry (poEntry);
	bRetCode = true;
	
mplsInSegmentTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
mplsInSegmentTable_createHier (
	mplsInSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (mplsInSegmentPerfTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsInSegmentTable_createHier_cleanup;
	}
	
	if (gmplsInSegmentTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsInSegmentTable_createHier_cleanup;
	}
	
	if (neMplsInSegmentTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsInSegmentTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
mplsInSegmentTable_createHier_cleanup:
	
	!bRetCode ? mplsInSegmentTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
mplsInSegmentTable_removeHier (
	mplsInSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	neMplsInSegmentTable_removeEntry (&poEntry->oNe);
	gmplsInSegmentTable_removeEntry (&poEntry->oG);
	mplsInSegmentPerfTable_removeEntry (&poEntry->oPerf);
	
	bRetCode = true;
	
// mplsInSegmentTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
mplsInSegmentRowStatus_handler (
	mplsInSegmentEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto mplsInSegmentRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto mplsInSegmentRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		
		/*if (!mplsInSegmentRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsInSegmentRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		/*if (!mplsInSegmentRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsInSegmentRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto mplsInSegmentRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
	case xRowStatus_destroy_c:
		/*if (!mplsInSegmentRowStatus_update (poEntry, u8RealStatus))
		{
			goto mplsInSegmentRowStatus_handler_cleanup;
		}*/
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
mplsInSegmentRowStatus_handler_success:
	
	bRetCode = true;
	
mplsInSegmentRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
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
			case MPLSINSEGMENTNPOP:
				memcpy (&table_entry->i32NPop, pvOldDdata, sizeof (table_entry->i32NPop));
				break;
			case MPLSINSEGMENTADDRFAMILY:
				memcpy (&table_entry->i32AddrFamily, pvOldDdata, sizeof (table_entry->i32AddrFamily));
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

/* create a new row in the table */
mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentPerfEntry_t *poEntry = NULL;
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	poEntry = &poInSegment->oPerf;
	
	return poEntry;
}

mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poInSegment->oPerf;
}

mplsInSegmentPerfEntry_t *
mplsInSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getNextIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poInSegment->oPerf;
}

/* remove a row from the table */
void
mplsInSegmentPerfTable_removeEntry (mplsInSegmentPerfEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsInSegmentPerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInSegmentTable_BTree);
	return mplsInSegmentPerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsInSegmentPerfTable_getNext (
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
mplsInSegmentPerfTable_get (
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
	register mplsInSegmentEntry_t *poEntry = NULL;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oPerf;
			
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

static int8_t
mplsOutSegmentTable_If_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsOutSegmentEntry_t *pEntry1 = xBTree_entry (pNode1, mplsOutSegmentEntry_t, oIf_BTreeNode);
	register mplsOutSegmentEntry_t *pEntry2 = xBTree_entry (pNode2, mplsOutSegmentEntry_t, oIf_BTreeNode);
	
	return
		(pEntry1->oK.u32Interface < pEntry2->oK.u32Interface) ||
		(pEntry1->oK.u32Interface == pEntry2->oK.u32Interface && xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ? -1:
		(pEntry1->oK.u32Interface == pEntry2->oK.u32Interface && xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0) ? 0: 1;
}

xBTree_t oMplsOutSegmentTable_BTree = xBTree_initInline (&mplsOutSegmentTable_BTreeNodeCmp);
xBTree_t oMplsOutSegmentTable_If_BTree = xBTree_initInline (&mplsOutSegmentTable_If_BTreeNodeCmp);

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

mplsOutSegmentEntry_t *
mplsOutSegmentTable_If_getNextIndex (
	uint32_t u32Interface,
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->oK.u32Interface = u32Interface;
	memcpy (poTmpEntry->au8Index, pau8Index, u16Index_len);
	poTmpEntry->u16Index_len = u16Index_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oIf_BTreeNode, &oMplsOutSegmentTable_If_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsOutSegmentEntry_t, oIf_BTreeNode);
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

mplsOutSegmentEntry_t *
mplsOutSegmentTable_createExt (
	uint8_t *pau8Index, size_t u16Index_len)
{
	mplsOutSegmentEntry_t *poEntry = NULL;
	
	if (u16Index_len == 0)
	{
		goto mplsOutSegmentTable_createExt_cleanup;
	}
	
	poEntry = mplsOutSegmentTable_createEntry (
		pau8Index, u16Index_len);
	if (poEntry == NULL)
	{
		goto mplsOutSegmentTable_createExt_cleanup;
	}
	
	if (!mplsOutSegmentTable_createHier (poEntry))
	{
		mplsOutSegmentTable_removeEntry (poEntry);
		poEntry = NULL;
		goto mplsOutSegmentTable_createExt_cleanup;
	}
	
mplsOutSegmentTable_createExt_cleanup:
	
	return poEntry;
}

bool
mplsOutSegmentTable_removeExt (mplsOutSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (!mplsOutSegmentTable_removeHier (poEntry))
	{
		goto mplsOutSegmentTable_removeExt_cleanup;
	}
	mplsOutSegmentTable_removeEntry (poEntry);
	
	bRetCode = true;
	
mplsOutSegmentTable_removeExt_cleanup:
	
	return bRetCode;
}

bool
mplsOutSegmentTable_createHier (
	mplsOutSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (mplsOutSegmentPerfTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsOutSegmentTable_createHier_cleanup;
	}
	
	if (gmplsOutSegmentTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsOutSegmentTable_createHier_cleanup;
	}
	
	if (neMplsOutSegmentTable_createEntry (poEntry->au8Index, poEntry->u16Index_len) == NULL)
	{
		goto mplsOutSegmentTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
mplsOutSegmentTable_createHier_cleanup:
	
	!bRetCode ? mplsOutSegmentTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
mplsOutSegmentTable_removeHier (
	mplsOutSegmentEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	neMplsOutSegmentTable_removeEntry (&poEntry->oNe);
	gmplsOutSegmentTable_removeEntry (&poEntry->oG);
	mplsOutSegmentPerfTable_removeEntry (&poEntry->oPerf);
	
	bRetCode = true;
	
// mplsOutSegmentTable_removeHier_cleanup:
	
	return bRetCode;
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
			case MPLSOUTSEGMENTNEXTHOPADDRTYPE:
				memcpy (&table_entry->i32NextHopAddrType, pvOldDdata, sizeof (table_entry->i32NextHopAddrType));
				break;
			case MPLSOUTSEGMENTNEXTHOPADDR:
				memcpy (table_entry->au8NextHopAddr, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16NextHopAddr_len = ((xOctetString_t*) pvOldDdata)->u16Len;
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

/* create a new row in the table */
mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentPerfEntry_t *poEntry = NULL;
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	poEntry = &poOutSegment->oPerf;
	
	return poEntry;
}

mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poOutSegment->oPerf;
}

mplsOutSegmentPerfEntry_t *
mplsOutSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getNextIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poOutSegment->oPerf;
}

/* remove a row from the table */
void
mplsOutSegmentPerfTable_removeEntry (mplsOutSegmentPerfEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mplsOutSegmentPerfTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsOutSegmentTable_BTree);
	return mplsOutSegmentPerfTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mplsOutSegmentPerfTable_getNext (
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
mplsOutSegmentPerfTable_get (
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
	register mplsOutSegmentEntry_t *poEntry = NULL;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (mplsOutSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oPerf;
			
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

static int8_t
mplsXCTable_Out_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mplsXCEntry_t *pEntry1 = xBTree_entry (pNode1, mplsXCEntry_t, oOut_BTreeNode);
	register mplsXCEntry_t *pEntry2 = xBTree_entry (pNode2, mplsXCEntry_t, oOut_BTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == -1) ||
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == -1) ? -1:
		(xBinCmp (pEntry1->au8Index, pEntry2->au8Index, pEntry1->u16Index_len, pEntry2->u16Index_len) == 0 && xBinCmp (pEntry1->au8OutSegmentIndex, pEntry2->au8OutSegmentIndex, pEntry1->u16OutSegmentIndex_len, pEntry2->u16OutSegmentIndex_len) == 0 && xBinCmp (pEntry1->au8InSegmentIndex, pEntry2->au8InSegmentIndex, pEntry1->u16InSegmentIndex_len, pEntry2->u16InSegmentIndex_len) == 0) ? 0: 1;
}

xBTree_t oMplsXCTable_BTree = xBTree_initInline (&mplsXCTable_BTreeNodeCmp);
xBTree_t oMplsXCTable_Out_BTree = xBTree_initInline (&mplsXCTable_Out_BTreeNodeCmp);

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

mplsXCEntry_t *
mplsXCTable_Out_getNextIndex (
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
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oOut_BTreeNode, &oMplsXCTable_Out_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mplsXCEntry_t, oOut_BTreeNode);
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
	xBTree_nodeRemove (&poEntry->oOut_BTreeNode, &oMplsXCTable_Out_BTree);
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
	table_info->min_column = MPLSLABELSTACKROWSTATUS;
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

/* create a new row in the table */
gmplsInterfaceEntry_t *
gmplsInterfaceTable_createEntry (
	uint32_t u32Index)
{
	register gmplsInterfaceEntry_t *poEntry = NULL;
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	poEntry = &poInterface->oG;
	
	xBitmap_setBitsRev (poEntry->au8SignalingCaps, 1, 1, gmplsInterfaceSignalingCaps_rsvpGmpls_c);
	poEntry->u32RsvpHelloPeriod = 3000;
	
	return poEntry;
}

gmplsInterfaceEntry_t *
gmplsInterfaceTable_getByIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getByIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poInterface->oG;
}

gmplsInterfaceEntry_t *
gmplsInterfaceTable_getNextIndex (
	uint32_t u32Index)
{
	register mplsInterfaceEntry_t *poInterface = NULL;
	
	if ((poInterface = mplsInterfaceTable_getNextIndex (u32Index)) == NULL)
	{
		return NULL;
	}
	
	return &poInterface->oG;
}

/* remove a row from the table */
void
gmplsInterfaceTable_removeEntry (gmplsInterfaceEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsInterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInterfaceTable_BTree);
	return gmplsInterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsInterfaceTable_getNext (
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
gmplsInterfaceTable_get (
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
	register mplsInterfaceEntry_t *poEntry = NULL;
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
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oG;
			
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
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oG;
			
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
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSINTERFACESIGNALINGCAPS:
			case GMPLSINTERFACERSVPHELLOPERIOD:
				if (poEntry->u8RowStatus == xRowStatus_active_c || poEntry->u8RowStatus == xRowStatus_notReady_c)
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
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oG;
			
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
			poEntry = (mplsInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oG;
			
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
	table_info->max_column = GMPLSINSEGMENTDIRECTION;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsInSegmentTable_getFirst;
	iinfo->get_next_data_point = &gmplsInSegmentTable_getNext;
	iinfo->get_data_point = &gmplsInSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsInSegmentEntry_t *
gmplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsInSegmentEntry_t *poEntry = NULL;
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	poEntry = &poInSegment->oG;
	
	poEntry->i32Direction = gmplsInSegmentDirection_forward_c;
	
	return poEntry;
}

gmplsInSegmentEntry_t *
gmplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poInSegment->oG;
}

gmplsInSegmentEntry_t *
gmplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsInSegmentEntry_t *poInSegment = NULL;
	
	if ((poInSegment = mplsInSegmentTable_getNextIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poInSegment->oG;
}

/* remove a row from the table */
void
gmplsInSegmentTable_removeEntry (gmplsInSegmentEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsInSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsInSegmentTable_BTree);
	return gmplsInSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsInSegmentTable_getNext (
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
gmplsInSegmentTable_get (
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
	register mplsInSegmentEntry_t *poEntry = NULL;
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
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Direction);
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
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oG;
			
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
				
			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_ERR_NOTWRITABLE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_RESERVE2:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oG;
			
			switch (table_info->colnum)
			{
			case GMPLSINSEGMENTDIRECTION:
				if (poEntry->u8RowStatus == xRowStatus_active_c || poEntry->u8RowStatus == xRowStatus_notReady_c)
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
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oG;
			
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
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (mplsInSegmentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oG;
			
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
	table_info->max_column = GMPLSOUTSEGMENTTTLDECREMENT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &gmplsOutSegmentTable_getFirst;
	iinfo->get_next_data_point = &gmplsOutSegmentTable_getNext;
	iinfo->get_data_point = &gmplsOutSegmentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register gmplsOutSegmentEntry_t *poEntry = NULL;
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	poEntry = &poOutSegment->oG;
	
	poEntry->i32Direction = gmplsOutSegmentDirection_forward_c;
	poEntry->u32TTLDecrement = 0;
	
	return poEntry;
}

gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getByIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poOutSegment->oG;
}

gmplsOutSegmentEntry_t *
gmplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len)
{
	register mplsOutSegmentEntry_t *poOutSegment = NULL;
	
	if ((poOutSegment = mplsOutSegmentTable_getNextIndex (pau8Index, u16Index_len)) == NULL)
	{
		return NULL;
	}
	
	return &poOutSegment->oG;
}

/* remove a row from the table */
void
gmplsOutSegmentTable_removeEntry (gmplsOutSegmentEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
gmplsOutSegmentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMplsOutSegmentTable_BTree);
	return gmplsOutSegmentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
gmplsOutSegmentTable_getNext (
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
	*my_data_context = (void*) &poEntry->oG;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMplsOutSegmentTable_BTree);
	return put_index_data;
}

bool
gmplsOutSegmentTable_get (
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
	
	*my_data_context = (void*) &poEntry->oG;
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
