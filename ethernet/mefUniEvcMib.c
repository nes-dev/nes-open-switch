/*
 *  Copyright (c) 2008-2015
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
#include "mefUniEvcMib.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid mefUniEvcMib_oid[] = {1,3,6,1,4,1,15007,2,2};

static oid mefServiceEvcAttributes_oid[] = {1,3,6,1,4,1,15007,2,2,1,3};
static oid mefServiceBwpAttributes_oid[] = {1,3,6,1,4,1,15007,2,2,1,4};
static oid mefServiceCosAttributes_oid[] = {1,3,6,1,4,1,15007,2,2,1,5};
static oid mefServiceL2cpAttributes_oid[] = {1,3,6,1,4,1,15007,2,2,1,6};
static oid mefServiceNotificationCfg_oid[] = {1,3,6,1,4,1,15007,2,2,1,7};

static oid mefServiceInterfaceCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,1,1};
static oid mefServiceInterfaceStatusTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,1,2};
static oid mefServiceInterfaceStatisticsTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,1,3};
static oid mefServiceUniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,2,1};
static oid mefServiceEvcPerUniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,2,2};
static oid mefServiceEvcCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,3,2};
static oid mefServiceEvcUniCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,3,3};
static oid mefServiceEvcStatusTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,3,4};
static oid mefServiceBwpGrpCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,4,2};
static oid mefServiceBwpCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,4,3};
static oid mefServicePerformanceTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,4,4};
static oid mefServiceCosCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,5,2};
static oid mefServiceL2cpGrpCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,6,2};
static oid mefServiceL2cpCfgTable_oid[] = {1,3,6,1,4,1,15007,2,2,1,6,3};

static oid snmptrap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

static oid mefServiceConfigurationAlarm_oid[] = {1,3,6,1,4,1,15007,2,2,0,1};



/**
 *	initialize mefUniEvcMib group mapper
 */
void
mefUniEvcMib_init (void)
{
	extern oid mefUniEvcMib_oid[];
	extern oid mefServiceEvcAttributes_oid[];
	extern oid mefServiceBwpAttributes_oid[];
	extern oid mefServiceCosAttributes_oid[];
	extern oid mefServiceL2cpAttributes_oid[];
	extern oid mefServiceNotificationCfg_oid[];
	
	DEBUGMSGTL (("mefUniEvcMib", "Initializing\n"));
	
	/* register mefServiceEvcAttributes scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceEvcAttributes_mapper", &mefServiceEvcAttributes_mapper,
			mefServiceEvcAttributes_oid, OID_LENGTH (mefServiceEvcAttributes_oid),
			HANDLER_CAN_RONLY
		),
		MEFSERVICEEVCNEXTINDEX,
		MEFSERVICEEVCNEXTINDEX
	);
	
	/* register mefServiceBwpAttributes scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceBwpAttributes_mapper", &mefServiceBwpAttributes_mapper,
			mefServiceBwpAttributes_oid, OID_LENGTH (mefServiceBwpAttributes_oid),
			HANDLER_CAN_RONLY
		),
		MEFSERVICEBWPGRPNEXTINDEX,
		MEFSERVICEBWPGRPNEXTINDEX
	);
	
	/* register mefServiceCosAttributes scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceCosAttributes_mapper", &mefServiceCosAttributes_mapper,
			mefServiceCosAttributes_oid, OID_LENGTH (mefServiceCosAttributes_oid),
			HANDLER_CAN_RONLY
		),
		MEFSERVICECOSNEXTINDEX,
		MEFSERVICECOSNEXTINDEX
	);
	
	/* register mefServiceL2cpAttributes scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceL2cpAttributes_mapper", &mefServiceL2cpAttributes_mapper,
			mefServiceL2cpAttributes_oid, OID_LENGTH (mefServiceL2cpAttributes_oid),
			HANDLER_CAN_RONLY
		),
		MEFSERVICEL2CPGRPNEXTINDEX,
		MEFSERVICEL2CPGRPNEXTINDEX
	);
	
	/* register mefServiceNotificationCfg scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"mefServiceNotificationCfg_mapper", &mefServiceNotificationCfg_mapper,
			mefServiceNotificationCfg_oid, OID_LENGTH (mefServiceNotificationCfg_oid),
			HANDLER_CAN_RWRITE
		),
		MEFSERVICENOTIFICATIONCFGALARMENABLE,
		MEFSERVICENOTIFICATIONCFGALARMENABLE
	);
	
	
	/* register mefUniEvcMib group table mappers */
	mefServiceInterfaceCfgTable_init ();
	mefServiceInterfaceStatusTable_init ();
	mefServiceInterfaceStatisticsTable_init ();
	mefServiceUniCfgTable_init ();
	mefServiceEvcPerUniCfgTable_init ();
	mefServiceEvcCfgTable_init ();
	mefServiceEvcUniCfgTable_init ();
	mefServiceEvcStatusTable_init ();
	mefServiceBwpGrpCfgTable_init ();
	mefServiceBwpCfgTable_init ();
	mefServicePerformanceTable_init ();
	mefServiceCosCfgTable_init ();
	mefServiceL2cpGrpCfgTable_init ();
	mefServiceL2cpCfgTable_init ();
	
	/* register mefUniEvcMib modules */
	sysORTable_createRegister ("mefUniEvcMib", mefUniEvcMib_oid, OID_LENGTH (mefUniEvcMib_oid));
}


/**
 *	scalar mapper(s)
 */
mefServiceEvcAttributes_t oMefServiceEvcAttributes;

/** mefServiceEvcAttributes scalar mapper **/
int
mefServiceEvcAttributes_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceEvcAttributes_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceEvcAttributes_oid) - 1])
			{
			case MEFSERVICEEVCNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMefServiceEvcAttributes.u32NextIndex);
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

mefServiceBwpAttributes_t oMefServiceBwpAttributes;

/** mefServiceBwpAttributes scalar mapper **/
int
mefServiceBwpAttributes_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceBwpAttributes_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceBwpAttributes_oid) - 1])
			{
			case MEFSERVICEBWPGRPNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMefServiceBwpAttributes.u32GrpNextIndex);
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

mefServiceCosAttributes_t oMefServiceCosAttributes;

/** mefServiceCosAttributes scalar mapper **/
int
mefServiceCosAttributes_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceCosAttributes_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceCosAttributes_oid) - 1])
			{
			case MEFSERVICECOSNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMefServiceCosAttributes.u32NextIndex);
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

mefServiceL2cpAttributes_t oMefServiceL2cpAttributes;

/** mefServiceL2cpAttributes scalar mapper **/
int
mefServiceL2cpAttributes_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceL2cpAttributes_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceL2cpAttributes_oid) - 1])
			{
			case MEFSERVICEL2CPGRPNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oMefServiceL2cpAttributes.u32GrpNextIndex);
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

mefServiceNotificationCfg_t oMefServiceNotificationCfg;

/** mefServiceNotificationCfg scalar mapper **/
int
mefServiceNotificationCfg_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid mefServiceNotificationCfg_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (mefServiceNotificationCfg_oid) - 1])
			{
			case MEFSERVICENOTIFICATIONCFGALARMENABLE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oMefServiceNotificationCfg.au8AlarmEnable, oMefServiceNotificationCfg.u16AlarmEnable_len);
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
			switch (request->requestvb->name[OID_LENGTH (mefServiceNotificationCfg_oid) - 1])
			{
			case MEFSERVICENOTIFICATIONCFGALARMENABLE:
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
			switch (request->requestvb->name[OID_LENGTH (mefServiceNotificationCfg_oid) - 1])
			{
			case MEFSERVICENOTIFICATIONCFGALARMENABLE:
				/* XXX: perform the value change here */
				memset (oMefServiceNotificationCfg.au8AlarmEnable, 0, sizeof (oMefServiceNotificationCfg.au8AlarmEnable));
				memcpy (oMefServiceNotificationCfg.au8AlarmEnable, request->requestvb->val.string, request->requestvb->val_len);
				oMefServiceNotificationCfg.u16AlarmEnable_len = request->requestvb->val_len;
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
			switch (request->requestvb->name[OID_LENGTH (mefServiceNotificationCfg_oid) - 1])
			{
			case MEFSERVICENOTIFICATIONCFGALARMENABLE:
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
/** initialize mefServiceInterfaceCfgTable table mapper **/
void
mefServiceInterfaceCfgTable_init (void)
{
	extern oid mefServiceInterfaceCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceInterfaceCfgTable", &mefServiceInterfaceCfgTable_mapper,
		mefServiceInterfaceCfgTable_oid, OID_LENGTH (mefServiceInterfaceCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEINTERFACECFGTYPE;
	table_info->max_column = MEFSERVICEINTERFACECFGL2CPGRPINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceInterfaceCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceInterfaceCfgTable_getNext;
	iinfo->get_data_point = &mefServiceInterfaceCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceInterfaceCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceInterfaceCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceInterfaceCfgEntry_t, oBTreeNode);
	register mefServiceInterfaceCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceInterfaceCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceInterfaceCfgTable_BTree = xBTree_initInline (&mefServiceInterfaceCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceInterfaceCfgEntry_t *
mefServiceInterfaceCfgTable_createEntry (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBitmap_setBitsRev (poEntry->au8Type, 1, 1, mefServiceInterfaceCfgType_bUni1d1_c);
	/*poEntry->au8Identifier = ""*/;
	poEntry->i32FrameFormat = mefServiceInterfaceCfgFrameFormat_noTag_c;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	poEntry->u32L2cpGrpIndex = 0;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree);
	return poEntry;
}

mefServiceInterfaceCfgEntry_t *
mefServiceInterfaceCfgTable_getByIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceCfgEntry_t, oBTreeNode);
}

mefServiceInterfaceCfgEntry_t *
mefServiceInterfaceCfgTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceInterfaceCfgTable_removeEntry (mefServiceInterfaceCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceInterfaceCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceInterfaceCfgTable_BTree);
	return mefServiceInterfaceCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceInterfaceCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceInterfaceCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceInterfaceCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceInterfaceCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceInterfaceCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceInterfaceCfgTable table mapper */
int
mefServiceInterfaceCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceInterfaceCfgEntry_t *table_entry;
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
			table_entry = (mefServiceInterfaceCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACECFGTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
				break;
			case MEFSERVICEINTERFACECFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEINTERFACECFGFRAMEFORMAT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32FrameFormat);
				break;
			case MEFSERVICEINTERFACECFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEINTERFACECFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
				break;
			case MEFSERVICEINTERFACECFGL2CPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32L2cpGrpIndex);
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
			table_entry = (mefServiceInterfaceCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACECFGTYPE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Type));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEINTERFACECFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEINTERFACECFGFRAMEFORMAT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEINTERFACECFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEINTERFACECFGEGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEINTERFACECFGL2CPGRPINDEX:
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
			table_entry = (mefServiceInterfaceCfgEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (mefServiceInterfaceCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACECFGTYPE:
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
			case MEFSERVICEINTERFACECFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEINTERFACECFGFRAMEFORMAT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32FrameFormat))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32FrameFormat, sizeof (table_entry->i32FrameFormat));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32FrameFormat = *request->requestvb->val.integer;
				break;
			case MEFSERVICEINTERFACECFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEINTERFACECFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEINTERFACECFGL2CPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32L2cpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32L2cpGrpIndex, sizeof (table_entry->u32L2cpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32L2cpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (mefServiceInterfaceCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACECFGTYPE:
				memcpy (table_entry->au8Type, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Type_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEINTERFACECFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEINTERFACECFGFRAMEFORMAT:
				memcpy (&table_entry->i32FrameFormat, pvOldDdata, sizeof (table_entry->i32FrameFormat));
				break;
			case MEFSERVICEINTERFACECFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEINTERFACECFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			case MEFSERVICEINTERFACECFGL2CPGRPINDEX:
				memcpy (&table_entry->u32L2cpGrpIndex, pvOldDdata, sizeof (table_entry->u32L2cpGrpIndex));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceInterfaceStatusTable table mapper **/
void
mefServiceInterfaceStatusTable_init (void)
{
	extern oid mefServiceInterfaceStatusTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceInterfaceStatusTable", &mefServiceInterfaceStatusTable_mapper,
		mefServiceInterfaceStatusTable_oid, OID_LENGTH (mefServiceInterfaceStatusTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEINTERFACESTATUSTYPE;
	table_info->max_column = MEFSERVICEINTERFACESTATUSMAXENDPOINTPERVC;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceInterfaceStatusTable_getFirst;
	iinfo->get_next_data_point = &mefServiceInterfaceStatusTable_getNext;
	iinfo->get_data_point = &mefServiceInterfaceStatusTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceInterfaceStatusTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceInterfaceStatusEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceInterfaceStatusEntry_t, oBTreeNode);
	register mefServiceInterfaceStatusEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceInterfaceStatusEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceInterfaceStatusTable_BTree = xBTree_initInline (&mefServiceInterfaceStatusTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceInterfaceStatusEntry_t *
mefServiceInterfaceStatusTable_createEntry (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatusEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree);
	return poEntry;
}

mefServiceInterfaceStatusEntry_t *
mefServiceInterfaceStatusTable_getByIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceStatusEntry_t, oBTreeNode);
}

mefServiceInterfaceStatusEntry_t *
mefServiceInterfaceStatusTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceStatusEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceInterfaceStatusTable_removeEntry (mefServiceInterfaceStatusEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceInterfaceStatusTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceInterfaceStatusTable_BTree);
	return mefServiceInterfaceStatusTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceInterfaceStatusTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceStatusEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceInterfaceStatusEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceInterfaceStatusTable_BTree);
	return put_index_data;
}

bool
mefServiceInterfaceStatusTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceStatusEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceInterfaceStatusTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceInterfaceStatusTable table mapper */
int
mefServiceInterfaceStatusTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceInterfaceStatusEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceInterfaceStatusEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACESTATUSTYPE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Type, table_entry->u16Type_len);
				break;
			case MEFSERVICEINTERFACESTATUSMAXVC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxVc);
				break;
			case MEFSERVICEINTERFACESTATUSMAXENDPOINTPERVC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxEndPointPerVc);
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

/** initialize mefServiceInterfaceStatisticsTable table mapper **/
void
mefServiceInterfaceStatisticsTable_init (void)
{
	extern oid mefServiceInterfaceStatisticsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceInterfaceStatisticsTable", &mefServiceInterfaceStatisticsTable_mapper,
		mefServiceInterfaceStatisticsTable_oid, OID_LENGTH (mefServiceInterfaceStatisticsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEINTERFACESTATISTICSINGRESSUNDERSIZED;
	table_info->max_column = MEFSERVICEINTERFACESTATISTICSEGRESSBROADCAST;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceInterfaceStatisticsTable_getFirst;
	iinfo->get_next_data_point = &mefServiceInterfaceStatisticsTable_getNext;
	iinfo->get_data_point = &mefServiceInterfaceStatisticsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceInterfaceStatisticsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceInterfaceStatisticsEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceInterfaceStatisticsEntry_t, oBTreeNode);
	register mefServiceInterfaceStatisticsEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceInterfaceStatisticsEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceInterfaceStatisticsTable_BTree = xBTree_initInline (&mefServiceInterfaceStatisticsTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceInterfaceStatisticsEntry_t *
mefServiceInterfaceStatisticsTable_createEntry (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatisticsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree);
	return poEntry;
}

mefServiceInterfaceStatisticsEntry_t *
mefServiceInterfaceStatisticsTable_getByIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatisticsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceStatisticsEntry_t, oBTreeNode);
}

mefServiceInterfaceStatisticsEntry_t *
mefServiceInterfaceStatisticsTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register mefServiceInterfaceStatisticsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceInterfaceStatisticsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceInterfaceStatisticsTable_removeEntry (mefServiceInterfaceStatisticsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceInterfaceStatisticsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceInterfaceStatisticsTable_BTree);
	return mefServiceInterfaceStatisticsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceInterfaceStatisticsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceStatisticsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceInterfaceStatisticsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceInterfaceStatisticsTable_BTree);
	return put_index_data;
}

bool
mefServiceInterfaceStatisticsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceInterfaceStatisticsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceInterfaceStatisticsTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceInterfaceStatisticsTable table mapper */
int
mefServiceInterfaceStatisticsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceInterfaceStatisticsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceInterfaceStatisticsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEINTERFACESTATISTICSINGRESSUNDERSIZED:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IngressUndersized);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSOVERSIZED:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IngressOversized);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSFRAGMENTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IngressFragments);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSCRCALIGNMENT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IngressCrcAlignment);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSINVALIDVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32IngressInvalidVid);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressOctets);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSUNICAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressUnicast);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSMULTICAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressMulticast);
				break;
			case MEFSERVICEINTERFACESTATISTICSINGRESSBROADCAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressBroadcast);
				break;
			case MEFSERVICEINTERFACESTATISTICSEGRESSOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressOctets);
				break;
			case MEFSERVICEINTERFACESTATISTICSEGRESSUNICAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressUnicast);
				break;
			case MEFSERVICEINTERFACESTATISTICSEGRESSMULTICAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressMulticast);
				break;
			case MEFSERVICEINTERFACESTATISTICSEGRESSBROADCAST:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressBroadcast);
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

/** initialize mefServiceUniCfgTable table mapper **/
void
mefServiceUniCfgTable_init (void)
{
	extern oid mefServiceUniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceUniCfgTable", &mefServiceUniCfgTable_mapper,
		mefServiceUniCfgTable_oid, OID_LENGTH (mefServiceUniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEUNICFGIDENTIFIER;
	table_info->max_column = MEFSERVICEUNICFGCEPRIORITYUNTAGGED;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceUniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceUniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceUniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceUniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceUniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceUniCfgEntry_t, oBTreeNode);
	register mefServiceUniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceUniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceUniCfgTable_BTree = xBTree_initInline (&mefServiceUniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceUniCfgEntry_t *
mefServiceUniCfgTable_createEntry (
	uint32_t u32IfIndex)
{
	register mefServiceUniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->i32BundlingMultiplex = mefServiceUniCfgBundlingMultiplex_allToOne_c;
	poEntry->u32CeVidUntagged = 1;
	poEntry->u32CePriorityUntagged = 0;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree);
	return poEntry;
}

mefServiceUniCfgEntry_t *
mefServiceUniCfgTable_getByIndex (
	uint32_t u32IfIndex)
{
	register mefServiceUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceUniCfgEntry_t, oBTreeNode);
}

mefServiceUniCfgEntry_t *
mefServiceUniCfgTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register mefServiceUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceUniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceUniCfgTable_removeEntry (mefServiceUniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceUniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceUniCfgTable_BTree);
	return mefServiceUniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceUniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceUniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceUniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceUniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceUniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceUniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceUniCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceUniCfgTable table mapper */
int
mefServiceUniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceUniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32BundlingMultiplex);
				break;
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CeVidUntagged);
				break;
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CePriorityUntagged);
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
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
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
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
				if (table_entry == NULL)
				{
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceUniCfgTable_createEntry (
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
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
				mefServiceUniCfgTable_removeEntry (table_entry);
				netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32BundlingMultiplex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32BundlingMultiplex, sizeof (table_entry->i32BundlingMultiplex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32BundlingMultiplex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CeVidUntagged))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CeVidUntagged, sizeof (table_entry->u32CeVidUntagged));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CeVidUntagged = *request->requestvb->val.integer;
				break;
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CePriorityUntagged))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CePriorityUntagged, sizeof (table_entry->u32CePriorityUntagged));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CePriorityUntagged = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (mefServiceUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEUNICFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEUNICFGBUNDLINGMULTIPLEX:
				if (pvOldDdata == table_entry)
				{
					mefServiceUniCfgTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->i32BundlingMultiplex, pvOldDdata, sizeof (table_entry->i32BundlingMultiplex));
				}
				break;
			case MEFSERVICEUNICFGCEVIDUNTAGGED:
				if (pvOldDdata == table_entry)
				{
					mefServiceUniCfgTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32CeVidUntagged, pvOldDdata, sizeof (table_entry->u32CeVidUntagged));
				}
				break;
			case MEFSERVICEUNICFGCEPRIORITYUNTAGGED:
				if (pvOldDdata == table_entry)
				{
					mefServiceUniCfgTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
				}
				else
				{
					memcpy (&table_entry->u32CePriorityUntagged, pvOldDdata, sizeof (table_entry->u32CePriorityUntagged));
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

/** initialize mefServiceEvcPerUniCfgTable table mapper **/
void
mefServiceEvcPerUniCfgTable_init (void)
{
	extern oid mefServiceEvcPerUniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceEvcPerUniCfgTable", &mefServiceEvcPerUniCfgTable_mapper,
		mefServiceEvcPerUniCfgTable_oid, OID_LENGTH (mefServiceEvcPerUniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		ASN_UNSIGNED /* index: mefServiceEvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEEVCPERUNICFGSERVICETYPE;
	table_info->max_column = MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceEvcPerUniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceEvcPerUniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceEvcPerUniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceEvcPerUniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceEvcPerUniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceEvcPerUniCfgEntry_t, oBTreeNode);
	register mefServiceEvcPerUniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceEvcPerUniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->u32CfgIndex == pEntry2->u32CfgIndex) ? 0: 1;
}

xBTree_t oMefServiceEvcPerUniCfgTable_BTree = xBTree_initInline (&mefServiceEvcPerUniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceEvcPerUniCfgEntry_t *
mefServiceEvcPerUniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceEvcPerUniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->u32CfgIndex = u32CfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32ServiceType = mefServiceEvcPerUniCfgServiceType_epl_c;
	/*poEntry->au8CeVlanMap = "1:4095"*/;
	poEntry->u32IngressBwpGrpIndex = 0;
	poEntry->u32EgressBwpGrpIndex = 0;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree);
	return poEntry;
}

mefServiceEvcPerUniCfgEntry_t *
mefServiceEvcPerUniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceEvcPerUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcPerUniCfgEntry_t, oBTreeNode);
}

mefServiceEvcPerUniCfgEntry_t *
mefServiceEvcPerUniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex)
{
	register mefServiceEvcPerUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcPerUniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceEvcPerUniCfgTable_removeEntry (mefServiceEvcPerUniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceEvcPerUniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceEvcPerUniCfgTable_BTree);
	return mefServiceEvcPerUniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceEvcPerUniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcPerUniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceEvcPerUniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceEvcPerUniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceEvcPerUniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcPerUniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceEvcPerUniCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceEvcPerUniCfgTable table mapper */
int
mefServiceEvcPerUniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceEvcPerUniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceEvcPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCPERUNICFGSERVICETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ServiceType);
				break;
			case MEFSERVICEEVCPERUNICFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEEVCPERUNICFGCEVLANMAP:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8CeVlanMap, table_entry->u16CeVlanMap_len);
				break;
			case MEFSERVICEEVCPERUNICFGINGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IngressBwpGrpIndex);
				break;
			case MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32EgressBwpGrpIndex);
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
			table_entry = (mefServiceEvcPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCPERUNICFGCEVLANMAP:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8CeVlanMap));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCPERUNICFGINGRESSBWPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX:
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
			table_entry = (mefServiceEvcPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (mefServiceEvcPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCPERUNICFGCEVLANMAP:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8CeVlanMap))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16CeVlanMap_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8CeVlanMap, sizeof (table_entry->au8CeVlanMap));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8CeVlanMap, 0, sizeof (table_entry->au8CeVlanMap));
				memcpy (table_entry->au8CeVlanMap, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16CeVlanMap_len = request->requestvb->val_len;
				break;
			case MEFSERVICEEVCPERUNICFGINGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32IngressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32IngressBwpGrpIndex, sizeof (table_entry->u32IngressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32IngressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32EgressBwpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32EgressBwpGrpIndex, sizeof (table_entry->u32EgressBwpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32EgressBwpGrpIndex = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (mefServiceEvcPerUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCPERUNICFGCEVLANMAP:
				memcpy (table_entry->au8CeVlanMap, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16CeVlanMap_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEEVCPERUNICFGINGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32IngressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32IngressBwpGrpIndex));
				break;
			case MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX:
				memcpy (&table_entry->u32EgressBwpGrpIndex, pvOldDdata, sizeof (table_entry->u32EgressBwpGrpIndex));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceEvcCfgTable table mapper **/
void
mefServiceEvcCfgTable_init (void)
{
	extern oid mefServiceEvcCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceEvcCfgTable", &mefServiceEvcCfgTable_mapper,
		mefServiceEvcCfgTable_oid, OID_LENGTH (mefServiceEvcCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceEvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEEVCCFGIDENTIFIER;
	table_info->max_column = MEFSERVICEEVCCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceEvcCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceEvcCfgTable_getNext;
	iinfo->get_data_point = &mefServiceEvcCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceEvcCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceEvcCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceEvcCfgEntry_t, oBTreeNode);
	register mefServiceEvcCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceEvcCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceEvcCfgTable_BTree = xBTree_initInline (&mefServiceEvcCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceEvcCfgEntry_t *
mefServiceEvcCfgTable_createEntry (
	uint32_t u32Index)
{
	register mefServiceEvcCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->i32ServiceType = mefServiceEvcCfgServiceType_pointToPoint_c;
	poEntry->u32MtuSize = 1522;
	poEntry->i32CeVlanIdPreservation = mefServiceEvcCfgCeVlanIdPreservation_preserve_c;
	poEntry->i32CeVlanCosPreservation = mefServiceEvcCfgCeVlanCosPreservation_preserve_c;
	poEntry->i32UnicastDelivery = mefServiceEvcCfgUnicastDelivery_unconditional_c;
	poEntry->i32MulticastDelivery = mefServiceEvcCfgMulticastDelivery_unconditional_c;
	poEntry->i32BroadcastDelivery = mefServiceEvcCfgBroadcastDelivery_unconditional_c;
	poEntry->u32L2cpGrpIndex = 0;
	poEntry->i32AdminState = mefServiceEvcCfgAdminState_unlocked_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree);
	return poEntry;
}

mefServiceEvcCfgEntry_t *
mefServiceEvcCfgTable_getByIndex (
	uint32_t u32Index)
{
	register mefServiceEvcCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcCfgEntry_t, oBTreeNode);
}

mefServiceEvcCfgEntry_t *
mefServiceEvcCfgTable_getNextIndex (
	uint32_t u32Index)
{
	register mefServiceEvcCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceEvcCfgTable_removeEntry (mefServiceEvcCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceEvcCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceEvcCfgTable_BTree);
	return mefServiceEvcCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceEvcCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceEvcCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceEvcCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceEvcCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceEvcCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceEvcCfgTable table mapper */
int
mefServiceEvcCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceEvcCfgEntry_t *table_entry;
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEEVCCFGSERVICETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ServiceType);
				break;
			case MEFSERVICEEVCCFGMTUSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MtuSize);
				break;
			case MEFSERVICEEVCCFGCEVLANIDPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CeVlanIdPreservation);
				break;
			case MEFSERVICEEVCCFGCEVLANCOSPRESERVATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32CeVlanCosPreservation);
				break;
			case MEFSERVICEEVCCFGUNICASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32UnicastDelivery);
				break;
			case MEFSERVICEEVCCFGMULTICASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MulticastDelivery);
				break;
			case MEFSERVICEEVCCFGBROADCASTDELIVERY:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32BroadcastDelivery);
				break;
			case MEFSERVICEEVCCFGL2CPGRPINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32L2cpGrpIndex);
				break;
			case MEFSERVICEEVCCFGADMINSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AdminState);
				break;
			case MEFSERVICEEVCCFGROWSTATUS:
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGSERVICETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGMTUSIZE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGCEVLANIDPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGCEVLANCOSPRESERVATION:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGUNICASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGMULTICASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGBROADCASTDELIVERY:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGL2CPGRPINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGADMINSTATE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCCFGROWSTATUS:
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceEvcCfgTable_createEntry (
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceEvcCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEEVCCFGSERVICETYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ServiceType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ServiceType, sizeof (table_entry->i32ServiceType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ServiceType = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGMTUSIZE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MtuSize))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MtuSize, sizeof (table_entry->u32MtuSize));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MtuSize = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGCEVLANIDPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CeVlanIdPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CeVlanIdPreservation, sizeof (table_entry->i32CeVlanIdPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CeVlanIdPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGCEVLANCOSPRESERVATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32CeVlanCosPreservation))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32CeVlanCosPreservation, sizeof (table_entry->i32CeVlanCosPreservation));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32CeVlanCosPreservation = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGUNICASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32UnicastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32UnicastDelivery, sizeof (table_entry->i32UnicastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32UnicastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGMULTICASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MulticastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MulticastDelivery, sizeof (table_entry->i32MulticastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MulticastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGBROADCASTDELIVERY:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32BroadcastDelivery))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32BroadcastDelivery, sizeof (table_entry->i32BroadcastDelivery));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32BroadcastDelivery = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGL2CPGRPINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32L2cpGrpIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32L2cpGrpIndex, sizeof (table_entry->u32L2cpGrpIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32L2cpGrpIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEEVCCFGADMINSTATE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AdminState))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AdminState, sizeof (table_entry->i32AdminState));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AdminState = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceEvcCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEEVCCFGSERVICETYPE:
				memcpy (&table_entry->i32ServiceType, pvOldDdata, sizeof (table_entry->i32ServiceType));
				break;
			case MEFSERVICEEVCCFGMTUSIZE:
				memcpy (&table_entry->u32MtuSize, pvOldDdata, sizeof (table_entry->u32MtuSize));
				break;
			case MEFSERVICEEVCCFGCEVLANIDPRESERVATION:
				memcpy (&table_entry->i32CeVlanIdPreservation, pvOldDdata, sizeof (table_entry->i32CeVlanIdPreservation));
				break;
			case MEFSERVICEEVCCFGCEVLANCOSPRESERVATION:
				memcpy (&table_entry->i32CeVlanCosPreservation, pvOldDdata, sizeof (table_entry->i32CeVlanCosPreservation));
				break;
			case MEFSERVICEEVCCFGUNICASTDELIVERY:
				memcpy (&table_entry->i32UnicastDelivery, pvOldDdata, sizeof (table_entry->i32UnicastDelivery));
				break;
			case MEFSERVICEEVCCFGMULTICASTDELIVERY:
				memcpy (&table_entry->i32MulticastDelivery, pvOldDdata, sizeof (table_entry->i32MulticastDelivery));
				break;
			case MEFSERVICEEVCCFGBROADCASTDELIVERY:
				memcpy (&table_entry->i32BroadcastDelivery, pvOldDdata, sizeof (table_entry->i32BroadcastDelivery));
				break;
			case MEFSERVICEEVCCFGL2CPGRPINDEX:
				memcpy (&table_entry->u32L2cpGrpIndex, pvOldDdata, sizeof (table_entry->u32L2cpGrpIndex));
				break;
			case MEFSERVICEEVCCFGADMINSTATE:
				memcpy (&table_entry->i32AdminState, pvOldDdata, sizeof (table_entry->i32AdminState));
				break;
			case MEFSERVICEEVCCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceEvcCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceEvcCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCCFGROWSTATUS:
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
					mefServiceEvcCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceEvcUniCfgTable table mapper **/
void
mefServiceEvcUniCfgTable_init (void)
{
	extern oid mefServiceEvcUniCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceEvcUniCfgTable", &mefServiceEvcUniCfgTable_mapper,
		mefServiceEvcUniCfgTable_oid, OID_LENGTH (mefServiceEvcUniCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceEvcCfgIndex */,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = MEFSERVICEEVCUNICFGTYPE;
	table_info->max_column = MEFSERVICEEVCUNICFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceEvcUniCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceEvcUniCfgTable_getNext;
	iinfo->get_data_point = &mefServiceEvcUniCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceEvcUniCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceEvcUniCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceEvcUniCfgEntry_t, oBTreeNode);
	register mefServiceEvcUniCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceEvcUniCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ||
		(pEntry1->u32CfgIndex == pEntry2->u32CfgIndex && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32CfgIndex == pEntry2->u32CfgIndex && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oMefServiceEvcUniCfgTable_BTree = xBTree_initInline (&mefServiceEvcUniCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceEvcUniCfgEntry_t *
mefServiceEvcUniCfgTable_createEntry (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex)
{
	register mefServiceEvcUniCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CfgIndex = u32CfgIndex;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Type = mefServiceEvcUniCfgType_root_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree);
	return poEntry;
}

mefServiceEvcUniCfgEntry_t *
mefServiceEvcUniCfgTable_getByIndex (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex)
{
	register mefServiceEvcUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcUniCfgEntry_t, oBTreeNode);
}

mefServiceEvcUniCfgEntry_t *
mefServiceEvcUniCfgTable_getNextIndex (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex)
{
	register mefServiceEvcUniCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcUniCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceEvcUniCfgTable_removeEntry (mefServiceEvcUniCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceEvcUniCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceEvcUniCfgTable_BTree);
	return mefServiceEvcUniCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceEvcUniCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcUniCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceEvcUniCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceEvcUniCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceEvcUniCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcUniCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceEvcUniCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceEvcUniCfgTable table mapper */
int
mefServiceEvcUniCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceEvcUniCfgEntry_t *table_entry;
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case MEFSERVICEEVCUNICFGROWSTATUS:
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEEVCUNICFGROWSTATUS:
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceEvcUniCfgTable_createEntry (
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceEvcUniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGTYPE:
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceEvcUniCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case MEFSERVICEEVCUNICFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceEvcUniCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceEvcUniCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCUNICFGROWSTATUS:
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
					mefServiceEvcUniCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceEvcStatusTable table mapper **/
void
mefServiceEvcStatusTable_init (void)
{
	extern oid mefServiceEvcStatusTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceEvcStatusTable", &mefServiceEvcStatusTable_mapper,
		mefServiceEvcStatusTable_oid, OID_LENGTH (mefServiceEvcStatusTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceEvcCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEEVCSTATUSMAXMTUSIZE;
	table_info->max_column = MEFSERVICEEVCSTATUSOPERATIONALSTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceEvcStatusTable_getFirst;
	iinfo->get_next_data_point = &mefServiceEvcStatusTable_getNext;
	iinfo->get_data_point = &mefServiceEvcStatusTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceEvcStatusTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceEvcStatusEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceEvcStatusEntry_t, oBTreeNode);
	register mefServiceEvcStatusEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceEvcStatusEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32CfgIndex < pEntry2->u32CfgIndex) ? -1:
		(pEntry1->u32CfgIndex == pEntry2->u32CfgIndex) ? 0: 1;
}

xBTree_t oMefServiceEvcStatusTable_BTree = xBTree_initInline (&mefServiceEvcStatusTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceEvcStatusEntry_t *
mefServiceEvcStatusTable_createEntry (
	uint32_t u32CfgIndex)
{
	register mefServiceEvcStatusEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32CfgIndex = u32CfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree);
	return poEntry;
}

mefServiceEvcStatusEntry_t *
mefServiceEvcStatusTable_getByIndex (
	uint32_t u32CfgIndex)
{
	register mefServiceEvcStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcStatusEntry_t, oBTreeNode);
}

mefServiceEvcStatusEntry_t *
mefServiceEvcStatusTable_getNextIndex (
	uint32_t u32CfgIndex)
{
	register mefServiceEvcStatusEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32CfgIndex = u32CfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceEvcStatusEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceEvcStatusTable_removeEntry (mefServiceEvcStatusEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceEvcStatusTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceEvcStatusTable_BTree);
	return mefServiceEvcStatusTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceEvcStatusTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcStatusEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceEvcStatusEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32CfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceEvcStatusTable_BTree);
	return put_index_data;
}

bool
mefServiceEvcStatusTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceEvcStatusEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceEvcStatusTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceEvcStatusTable table mapper */
int
mefServiceEvcStatusTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceEvcStatusEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceEvcStatusEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEEVCSTATUSMAXMTUSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxMtuSize);
				break;
			case MEFSERVICEEVCSTATUSMAXNUMUNI:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxNumUni);
				break;
			case MEFSERVICEEVCSTATUSOPERATIONALSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OperationalState);
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

/** initialize mefServiceBwpGrpCfgTable table mapper **/
void
mefServiceBwpGrpCfgTable_init (void)
{
	extern oid mefServiceBwpGrpCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceBwpGrpCfgTable", &mefServiceBwpGrpCfgTable_mapper,
		mefServiceBwpGrpCfgTable_oid, OID_LENGTH (mefServiceBwpGrpCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceBwpGrpCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEBWPCFGNEXTINDEX;
	table_info->max_column = MEFSERVICEBWPGRPCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceBwpGrpCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceBwpGrpCfgTable_getNext;
	iinfo->get_data_point = &mefServiceBwpGrpCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceBwpGrpCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceBwpGrpCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceBwpGrpCfgEntry_t, oBTreeNode);
	register mefServiceBwpGrpCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceBwpGrpCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceBwpGrpCfgTable_BTree = xBTree_initInline (&mefServiceBwpGrpCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceBwpGrpCfgEntry_t *
mefServiceBwpGrpCfgTable_createEntry (
	uint32_t u32Index)
{
	register mefServiceBwpGrpCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32CfgNextIndex = 1;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree);
	return poEntry;
}

mefServiceBwpGrpCfgEntry_t *
mefServiceBwpGrpCfgTable_getByIndex (
	uint32_t u32Index)
{
	register mefServiceBwpGrpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceBwpGrpCfgEntry_t, oBTreeNode);
}

mefServiceBwpGrpCfgEntry_t *
mefServiceBwpGrpCfgTable_getNextIndex (
	uint32_t u32Index)
{
	register mefServiceBwpGrpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceBwpGrpCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceBwpGrpCfgTable_removeEntry (mefServiceBwpGrpCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceBwpGrpCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceBwpGrpCfgTable_BTree);
	return mefServiceBwpGrpCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceBwpGrpCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceBwpGrpCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceBwpGrpCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceBwpGrpCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceBwpGrpCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceBwpGrpCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceBwpGrpCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceBwpGrpCfgTable table mapper */
int
mefServiceBwpGrpCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceBwpGrpCfgEntry_t *table_entry;
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CfgNextIndex);
				break;
			case MEFSERVICEBWPGRPCFGROWSTATUS:
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceBwpGrpCfgTable_createEntry (
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceBwpGrpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceBwpGrpCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceBwpGrpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceBwpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPGRPCFGROWSTATUS:
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
					mefServiceBwpGrpCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceBwpCfgTable table mapper **/
void
mefServiceBwpCfgTable_init (void)
{
	extern oid mefServiceBwpCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceBwpCfgTable", &mefServiceBwpCfgTable_mapper,
		mefServiceBwpCfgTable_oid, OID_LENGTH (mefServiceBwpCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceBwpGrpCfgIndex */,
		ASN_UNSIGNED /* index: mefServiceBwpCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEBWPCFGIDENTIFIER;
	table_info->max_column = MEFSERVICEBWPCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceBwpCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceBwpCfgTable_getNext;
	iinfo->get_data_point = &mefServiceBwpCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceBwpCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceBwpCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceBwpCfgEntry_t, oBTreeNode);
	register mefServiceBwpCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceBwpCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32GrpCfgIndex < pEntry2->u32GrpCfgIndex) ||
		(pEntry1->u32GrpCfgIndex == pEntry2->u32GrpCfgIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32GrpCfgIndex == pEntry2->u32GrpCfgIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceBwpCfgTable_BTree = xBTree_initInline (&mefServiceBwpCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceBwpCfgEntry_t *
mefServiceBwpCfgTable_createEntry (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceBwpCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->u32Cir = 1000000;
	poEntry->u32Cbs = 12;
	poEntry->u32Eir = 0;
	poEntry->u32Ebs = 0;
	poEntry->i32Cm = mefServiceBwpCfgCm_colorBlind_c;
	poEntry->i32Cf = mefServiceBwpCfgCf_couplingYellowEirOnly_c;
	poEntry->u32CosIndex = 0;
	poEntry->i32PerformanceEnable = mefServiceBwpCfgPerformanceEnable_disablePerformanceDataSet_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree);
	return poEntry;
}

mefServiceBwpCfgEntry_t *
mefServiceBwpCfgTable_getByIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceBwpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceBwpCfgEntry_t, oBTreeNode);
}

mefServiceBwpCfgEntry_t *
mefServiceBwpCfgTable_getNextIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceBwpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceBwpCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceBwpCfgTable_removeEntry (mefServiceBwpCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceBwpCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceBwpCfgTable_BTree);
	return mefServiceBwpCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceBwpCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceBwpCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceBwpCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32GrpCfgIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceBwpCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceBwpCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceBwpCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceBwpCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceBwpCfgTable table mapper */
int
mefServiceBwpCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceBwpCfgEntry_t *table_entry;
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICEBWPCFGCIR:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Cir);
				break;
			case MEFSERVICEBWPCFGCBS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Cbs);
				break;
			case MEFSERVICEBWPCFGEIR:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Eir);
				break;
			case MEFSERVICEBWPCFGEBS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Ebs);
				break;
			case MEFSERVICEBWPCFGCM:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Cm);
				break;
			case MEFSERVICEBWPCFGCF:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Cf);
				break;
			case MEFSERVICEBWPCFGCOSINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CosIndex);
				break;
			case MEFSERVICEBWPCFGPERFORMANCEENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32PerformanceEnable);
				break;
			case MEFSERVICEBWPCFGROWSTATUS:
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGCIR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGCBS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGEIR:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGEBS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGCM:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGCF:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGCOSINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGPERFORMANCEENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEBWPCFGROWSTATUS:
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceBwpCfgTable_createEntry (
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceBwpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICEBWPCFGCIR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Cir))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Cir, sizeof (table_entry->u32Cir));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Cir = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGCBS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Cbs))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Cbs, sizeof (table_entry->u32Cbs));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Cbs = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGEIR:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Eir))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Eir, sizeof (table_entry->u32Eir));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Eir = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGEBS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Ebs))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Ebs, sizeof (table_entry->u32Ebs));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Ebs = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGCM:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Cm))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Cm, sizeof (table_entry->i32Cm));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Cm = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGCF:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Cf))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Cf, sizeof (table_entry->i32Cf));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Cf = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGCOSINDEX:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CosIndex))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CosIndex, sizeof (table_entry->u32CosIndex));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CosIndex = *request->requestvb->val.integer;
				break;
			case MEFSERVICEBWPCFGPERFORMANCEENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32PerformanceEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32PerformanceEnable, sizeof (table_entry->i32PerformanceEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32PerformanceEnable = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceBwpCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEBWPCFGCIR:
				memcpy (&table_entry->u32Cir, pvOldDdata, sizeof (table_entry->u32Cir));
				break;
			case MEFSERVICEBWPCFGCBS:
				memcpy (&table_entry->u32Cbs, pvOldDdata, sizeof (table_entry->u32Cbs));
				break;
			case MEFSERVICEBWPCFGEIR:
				memcpy (&table_entry->u32Eir, pvOldDdata, sizeof (table_entry->u32Eir));
				break;
			case MEFSERVICEBWPCFGEBS:
				memcpy (&table_entry->u32Ebs, pvOldDdata, sizeof (table_entry->u32Ebs));
				break;
			case MEFSERVICEBWPCFGCM:
				memcpy (&table_entry->i32Cm, pvOldDdata, sizeof (table_entry->i32Cm));
				break;
			case MEFSERVICEBWPCFGCF:
				memcpy (&table_entry->i32Cf, pvOldDdata, sizeof (table_entry->i32Cf));
				break;
			case MEFSERVICEBWPCFGCOSINDEX:
				memcpy (&table_entry->u32CosIndex, pvOldDdata, sizeof (table_entry->u32CosIndex));
				break;
			case MEFSERVICEBWPCFGPERFORMANCEENABLE:
				memcpy (&table_entry->i32PerformanceEnable, pvOldDdata, sizeof (table_entry->i32PerformanceEnable));
				break;
			case MEFSERVICEBWPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceBwpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceBwpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEBWPCFGROWSTATUS:
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
					mefServiceBwpCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServicePerformanceTable table mapper **/
void
mefServicePerformanceTable_init (void)
{
	extern oid mefServicePerformanceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServicePerformanceTable", &mefServicePerformanceTable_mapper,
		mefServicePerformanceTable_oid, OID_LENGTH (mefServicePerformanceTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceBwpGrpCfgIndex */,
		ASN_UNSIGNED /* index: mefServiceBwpCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEPERFORMANCEINGRESSGREENFRAMECOUNT;
	table_info->max_column = MEFSERVICEPERFORMANCEEGRESSYELLOWOCTETS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServicePerformanceTable_getFirst;
	iinfo->get_next_data_point = &mefServicePerformanceTable_getNext;
	iinfo->get_data_point = &mefServicePerformanceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServicePerformanceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServicePerformanceEntry_t *pEntry1 = xBTree_entry (pNode1, mefServicePerformanceEntry_t, oBTreeNode);
	register mefServicePerformanceEntry_t *pEntry2 = xBTree_entry (pNode2, mefServicePerformanceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BwpGrpCfgIndex < pEntry2->u32BwpGrpCfgIndex) ||
		(pEntry1->u32BwpGrpCfgIndex == pEntry2->u32BwpGrpCfgIndex && pEntry1->u32BwpCfgIndex < pEntry2->u32BwpCfgIndex) ? -1:
		(pEntry1->u32BwpGrpCfgIndex == pEntry2->u32BwpGrpCfgIndex && pEntry1->u32BwpCfgIndex == pEntry2->u32BwpCfgIndex) ? 0: 1;
}

xBTree_t oMefServicePerformanceTable_BTree = xBTree_initInline (&mefServicePerformanceTable_BTreeNodeCmp);

/* create a new row in the table */
mefServicePerformanceEntry_t *
mefServicePerformanceTable_createEntry (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex)
{
	register mefServicePerformanceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BwpGrpCfgIndex = u32BwpGrpCfgIndex;
	poEntry->u32BwpCfgIndex = u32BwpCfgIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServicePerformanceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServicePerformanceTable_BTree);
	return poEntry;
}

mefServicePerformanceEntry_t *
mefServicePerformanceTable_getByIndex (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex)
{
	register mefServicePerformanceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BwpGrpCfgIndex = u32BwpGrpCfgIndex;
	poTmpEntry->u32BwpCfgIndex = u32BwpCfgIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServicePerformanceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServicePerformanceEntry_t, oBTreeNode);
}

mefServicePerformanceEntry_t *
mefServicePerformanceTable_getNextIndex (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex)
{
	register mefServicePerformanceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BwpGrpCfgIndex = u32BwpGrpCfgIndex;
	poTmpEntry->u32BwpCfgIndex = u32BwpCfgIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServicePerformanceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServicePerformanceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServicePerformanceTable_removeEntry (mefServicePerformanceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServicePerformanceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServicePerformanceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServicePerformanceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServicePerformanceTable_BTree);
	return mefServicePerformanceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServicePerformanceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServicePerformanceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServicePerformanceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BwpGrpCfgIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BwpCfgIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServicePerformanceTable_BTree);
	return put_index_data;
}

bool
mefServicePerformanceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServicePerformanceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServicePerformanceTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServicePerformanceTable table mapper */
int
mefServicePerformanceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServicePerformanceEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServicePerformanceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEPERFORMANCEINGRESSGREENFRAMECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressGreenFrameCount);
				break;
			case MEFSERVICEPERFORMANCEINGRESSYELLOWFRAMECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressYellowFrameCount);
				break;
			case MEFSERVICEPERFORMANCEINGRESSREDFRAMECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressRedFrameCount);
				break;
			case MEFSERVICEPERFORMANCEINGRESSGREENOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressGreenOctets);
				break;
			case MEFSERVICEPERFORMANCEINGRESSYELLOWOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressYellowOctets);
				break;
			case MEFSERVICEPERFORMANCEINGRESSREDOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressRedOctets);
				break;
			case MEFSERVICEPERFORMANCEINGRESSGREENFRAMEDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressGreenFrameDiscards);
				break;
			case MEFSERVICEPERFORMANCEINGRESSYELLOWFRAMEDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressYellowFrameDiscards);
				break;
			case MEFSERVICEPERFORMANCEINGRESSGREENOCTETSDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressGreenOctetsDiscards);
				break;
			case MEFSERVICEPERFORMANCEINGRESSYELLOWOCTETSDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64IngressYellowOctetsDiscards);
				break;
			case MEFSERVICEPERFORMANCEEGRESSGREENFRAMECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressGreenFrameCount);
				break;
			case MEFSERVICEPERFORMANCEEGRESSYELLOWFRAMECOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressYellowFrameCount);
				break;
			case MEFSERVICEPERFORMANCEEGRESSGREENOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressGreenOctets);
				break;
			case MEFSERVICEPERFORMANCEEGRESSYELLOWOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64EgressYellowOctets);
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

/** initialize mefServiceCosCfgTable table mapper **/
void
mefServiceCosCfgTable_init (void)
{
	extern oid mefServiceCosCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceCosCfgTable", &mefServiceCosCfgTable_mapper,
		mefServiceCosCfgTable_oid, OID_LENGTH (mefServiceCosCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceCosCfgIndex */,
		0);
	table_info->min_column = MEFSERVICECOSCFGIDENTIFIER;
	table_info->max_column = MEFSERVICECOSCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceCosCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceCosCfgTable_getNext;
	iinfo->get_data_point = &mefServiceCosCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceCosCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceCosCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceCosCfgEntry_t, oBTreeNode);
	register mefServiceCosCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceCosCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceCosCfgTable_BTree = xBTree_initInline (&mefServiceCosCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceCosCfgEntry_t *
mefServiceCosCfgTable_createEntry (
	uint32_t u32Index)
{
	register mefServiceCosCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	/*poEntry->au8Identifier = ""*/;
	poEntry->i32Type = mefServiceCosCfgType_pcp_c;
	/*poEntry->au8IdentifierList = "0:7"*/;
	/*poEntry->au8MacAddress = 0*/;
	poEntry->u32Protocol = 0;
	poEntry->u32SubType = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree);
	return poEntry;
}

mefServiceCosCfgEntry_t *
mefServiceCosCfgTable_getByIndex (
	uint32_t u32Index)
{
	register mefServiceCosCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceCosCfgEntry_t, oBTreeNode);
}

mefServiceCosCfgEntry_t *
mefServiceCosCfgTable_getNextIndex (
	uint32_t u32Index)
{
	register mefServiceCosCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceCosCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceCosCfgTable_removeEntry (mefServiceCosCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceCosCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceCosCfgTable_BTree);
	return mefServiceCosCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceCosCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceCosCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceCosCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceCosCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceCosCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceCosCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceCosCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceCosCfgTable table mapper */
int
mefServiceCosCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceCosCfgEntry_t *table_entry;
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case MEFSERVICECOSCFGTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case MEFSERVICECOSCFGIDENTIFIERLIST:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8IdentifierList, table_entry->u16IdentifierList_len);
				break;
			case MEFSERVICECOSCFGMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MacAddress, table_entry->u16MacAddress_len);
				break;
			case MEFSERVICECOSCFGPROTOCOL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Protocol);
				break;
			case MEFSERVICECOSCFGSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SubType);
				break;
			case MEFSERVICECOSCFGROWSTATUS:
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGIDENTIFIER:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Identifier));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGIDENTIFIERLIST:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8IdentifierList));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGMACADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MacAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGPROTOCOL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGSUBTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICECOSCFGROWSTATUS:
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceCosCfgTable_createEntry (
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceCosCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGIDENTIFIER:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8Identifier))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16Identifier_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8Identifier, sizeof (table_entry->au8Identifier));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8Identifier, 0, sizeof (table_entry->au8Identifier));
				memcpy (table_entry->au8Identifier, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16Identifier_len = request->requestvb->val_len;
				break;
			case MEFSERVICECOSCFGTYPE:
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
			case MEFSERVICECOSCFGIDENTIFIERLIST:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8IdentifierList))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16IdentifierList_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8IdentifierList, sizeof (table_entry->au8IdentifierList));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8IdentifierList, 0, sizeof (table_entry->au8IdentifierList));
				memcpy (table_entry->au8IdentifierList, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16IdentifierList_len = request->requestvb->val_len;
				break;
			case MEFSERVICECOSCFGMACADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MacAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MacAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MacAddress, sizeof (table_entry->au8MacAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MacAddress, 0, sizeof (table_entry->au8MacAddress));
				memcpy (table_entry->au8MacAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MacAddress_len = request->requestvb->val_len;
				break;
			case MEFSERVICECOSCFGPROTOCOL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Protocol))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Protocol, sizeof (table_entry->u32Protocol));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Protocol = *request->requestvb->val.integer;
				break;
			case MEFSERVICECOSCFGSUBTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32SubType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32SubType, sizeof (table_entry->u32SubType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32SubType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceCosCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGIDENTIFIER:
				memcpy (table_entry->au8Identifier, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Identifier_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICECOSCFGTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case MEFSERVICECOSCFGIDENTIFIERLIST:
				memcpy (table_entry->au8IdentifierList, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16IdentifierList_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICECOSCFGMACADDRESS:
				memcpy (table_entry->au8MacAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MacAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICECOSCFGPROTOCOL:
				memcpy (&table_entry->u32Protocol, pvOldDdata, sizeof (table_entry->u32Protocol));
				break;
			case MEFSERVICECOSCFGSUBTYPE:
				memcpy (&table_entry->u32SubType, pvOldDdata, sizeof (table_entry->u32SubType));
				break;
			case MEFSERVICECOSCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceCosCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceCosCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICECOSCFGROWSTATUS:
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
					mefServiceCosCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceL2cpGrpCfgTable table mapper **/
void
mefServiceL2cpGrpCfgTable_init (void)
{
	extern oid mefServiceL2cpGrpCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceL2cpGrpCfgTable", &mefServiceL2cpGrpCfgTable_mapper,
		mefServiceL2cpGrpCfgTable_oid, OID_LENGTH (mefServiceL2cpGrpCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceL2cpGrpCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEL2CPCFGNEXTINDEX;
	table_info->max_column = MEFSERVICEL2CPGRPCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceL2cpGrpCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceL2cpGrpCfgTable_getNext;
	iinfo->get_data_point = &mefServiceL2cpGrpCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceL2cpGrpCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceL2cpGrpCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceL2cpGrpCfgEntry_t, oBTreeNode);
	register mefServiceL2cpGrpCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceL2cpGrpCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceL2cpGrpCfgTable_BTree = xBTree_initInline (&mefServiceL2cpGrpCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceL2cpGrpCfgEntry_t *
mefServiceL2cpGrpCfgTable_createEntry (
	uint32_t u32Index)
{
	register mefServiceL2cpGrpCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32CfgNextIndex = 1;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree);
	return poEntry;
}

mefServiceL2cpGrpCfgEntry_t *
mefServiceL2cpGrpCfgTable_getByIndex (
	uint32_t u32Index)
{
	register mefServiceL2cpGrpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceL2cpGrpCfgEntry_t, oBTreeNode);
}

mefServiceL2cpGrpCfgEntry_t *
mefServiceL2cpGrpCfgTable_getNextIndex (
	uint32_t u32Index)
{
	register mefServiceL2cpGrpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceL2cpGrpCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceL2cpGrpCfgTable_removeEntry (mefServiceL2cpGrpCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceL2cpGrpCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceL2cpGrpCfgTable_BTree);
	return mefServiceL2cpGrpCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceL2cpGrpCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceL2cpGrpCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceL2cpGrpCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceL2cpGrpCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceL2cpGrpCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceL2cpGrpCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = mefServiceL2cpGrpCfgTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceL2cpGrpCfgTable table mapper */
int
mefServiceL2cpGrpCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceL2cpGrpCfgEntry_t *table_entry;
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGNEXTINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CfgNextIndex);
				break;
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceL2cpGrpCfgTable_createEntry (
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceL2cpGrpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceL2cpGrpCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceL2cpGrpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceL2cpGrpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPGRPCFGROWSTATUS:
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
					mefServiceL2cpGrpCfgTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize mefServiceL2cpCfgTable table mapper **/
void
mefServiceL2cpCfgTable_init (void)
{
	extern oid mefServiceL2cpCfgTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"mefServiceL2cpCfgTable", &mefServiceL2cpCfgTable_mapper,
		mefServiceL2cpCfgTable_oid, OID_LENGTH (mefServiceL2cpCfgTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: mefServiceL2cpGrpCfgIndex */,
		ASN_UNSIGNED /* index: mefServiceL2cpCfgIndex */,
		0);
	table_info->min_column = MEFSERVICEL2CPCFGTYPE;
	table_info->max_column = MEFSERVICEL2CPCFGROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &mefServiceL2cpCfgTable_getFirst;
	iinfo->get_next_data_point = &mefServiceL2cpCfgTable_getNext;
	iinfo->get_data_point = &mefServiceL2cpCfgTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
mefServiceL2cpCfgTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register mefServiceL2cpCfgEntry_t *pEntry1 = xBTree_entry (pNode1, mefServiceL2cpCfgEntry_t, oBTreeNode);
	register mefServiceL2cpCfgEntry_t *pEntry2 = xBTree_entry (pNode2, mefServiceL2cpCfgEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32GrpCfgIndex < pEntry2->u32GrpCfgIndex) ||
		(pEntry1->u32GrpCfgIndex == pEntry2->u32GrpCfgIndex && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32GrpCfgIndex == pEntry2->u32GrpCfgIndex && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oMefServiceL2cpCfgTable_BTree = xBTree_initInline (&mefServiceL2cpCfgTable_BTreeNodeCmp);

/* create a new row in the table */
mefServiceL2cpCfgEntry_t *
mefServiceL2cpCfgTable_createEntry (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceL2cpCfgEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Type = mefServiceL2cpCfgType_tunnel_c;
	poEntry->i32MatchScope = mefServiceL2cpCfgMatchScope_destinationAddressOnly_c;
	/*poEntry->au8MacAddress = 1652522221568*/;
	poEntry->u32Protocol = 0;
	poEntry->u32SubType = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree);
	return poEntry;
}

mefServiceL2cpCfgEntry_t *
mefServiceL2cpCfgTable_getByIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceL2cpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceL2cpCfgEntry_t, oBTreeNode);
}

mefServiceL2cpCfgEntry_t *
mefServiceL2cpCfgTable_getNextIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index)
{
	register mefServiceL2cpCfgEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32GrpCfgIndex = u32GrpCfgIndex;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, mefServiceL2cpCfgEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
mefServiceL2cpCfgTable_removeEntry (mefServiceL2cpCfgEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
mefServiceL2cpCfgTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oMefServiceL2cpCfgTable_BTree);
	return mefServiceL2cpCfgTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
mefServiceL2cpCfgTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceL2cpCfgEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, mefServiceL2cpCfgEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32GrpCfgIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oMefServiceL2cpCfgTable_BTree);
	return put_index_data;
}

bool
mefServiceL2cpCfgTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	mefServiceL2cpCfgEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = mefServiceL2cpCfgTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* mefServiceL2cpCfgTable table mapper */
int
mefServiceL2cpCfgTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	mefServiceL2cpCfgEntry_t *table_entry;
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case MEFSERVICEL2CPCFGMATCHSCOPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32MatchScope);
				break;
			case MEFSERVICEL2CPCFGMACADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MacAddress, table_entry->u16MacAddress_len);
				break;
			case MEFSERVICEL2CPCFGPROTOCOL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Protocol);
				break;
			case MEFSERVICEL2CPCFGSUBTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SubType);
				break;
			case MEFSERVICEL2CPCFGROWSTATUS:
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEL2CPCFGMATCHSCOPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEL2CPCFGMACADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8MacAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEL2CPCFGPROTOCOL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEL2CPCFGSUBTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case MEFSERVICEL2CPCFGROWSTATUS:
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = mefServiceL2cpCfgTable_createEntry (
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceL2cpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGTYPE:
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
			case MEFSERVICEL2CPCFGMATCHSCOPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32MatchScope))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32MatchScope, sizeof (table_entry->i32MatchScope));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32MatchScope = *request->requestvb->val.integer;
				break;
			case MEFSERVICEL2CPCFGMACADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8MacAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16MacAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8MacAddress, sizeof (table_entry->au8MacAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8MacAddress, 0, sizeof (table_entry->au8MacAddress));
				memcpy (table_entry->au8MacAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16MacAddress_len = request->requestvb->val_len;
				break;
			case MEFSERVICEL2CPCFGPROTOCOL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32Protocol))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32Protocol, sizeof (table_entry->u32Protocol));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32Protocol = *request->requestvb->val.integer;
				break;
			case MEFSERVICEL2CPCFGSUBTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32SubType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32SubType, sizeof (table_entry->u32SubType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32SubType = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int mefServiceL2cpCfgTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case MEFSERVICEL2CPCFGMATCHSCOPE:
				memcpy (&table_entry->i32MatchScope, pvOldDdata, sizeof (table_entry->i32MatchScope));
				break;
			case MEFSERVICEL2CPCFGMACADDRESS:
				memcpy (table_entry->au8MacAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16MacAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case MEFSERVICEL2CPCFGPROTOCOL:
				memcpy (&table_entry->u32Protocol, pvOldDdata, sizeof (table_entry->u32Protocol));
				break;
			case MEFSERVICEL2CPCFGSUBTYPE:
				memcpy (&table_entry->u32SubType, pvOldDdata, sizeof (table_entry->u32SubType));
				break;
			case MEFSERVICEL2CPCFGROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					mefServiceL2cpCfgTable_removeEntry (table_entry);
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
			table_entry = (mefServiceL2cpCfgEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case MEFSERVICEL2CPCFGROWSTATUS:
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
					mefServiceL2cpCfgTable_removeEntry (table_entry);
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
mefServiceConfigurationAlarm_trap (void)
{
	extern oid snmptrap_oid[];
	extern oid mefServiceConfigurationAlarm_oid[];
	netsnmp_variable_list *var_list = NULL;
	oid mefServiceNotificationObjDateAndTime_oid[] = {1,3,6,1,4,1,15007,2,2,1,8,1, 0};
	oid mefServiceNotificationConfigurationChangeType_oid[] = {1,3,6,1,4,1,15007,2,2,1,8,2, 0};
	
	/*
	 * Set the snmpTrapOid.0 value
	 */
	snmp_varlist_add_variable (&var_list,
		snmptrap_oid, OID_LENGTH (snmptrap_oid),
		ASN_OBJECT_ID,
		(const u_char*) mefServiceConfigurationAlarm_oid, sizeof (mefServiceConfigurationAlarm_oid));
		
	/*
	 * Add any objects from the trap definition
	 */
	snmp_varlist_add_variable (&var_list,
		mefServiceNotificationObjDateAndTime_oid, OID_LENGTH (mefServiceNotificationObjDateAndTime_oid),
		ASN_OCTET_STR,
		/* Set an appropriate value for mefServiceNotificationObjDateAndTime */
		NULL, 0);
	snmp_varlist_add_variable (&var_list,
		mefServiceNotificationConfigurationChangeType_oid, OID_LENGTH (mefServiceNotificationConfigurationChangeType_oid),
		ASN_INTEGER,
		/* Set an appropriate value for mefServiceNotificationConfigurationChangeType */
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
