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
#include "ethernet/ieee8021BridgeMib.h"
#include "if/ifMIB.h"
#include "ipMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ip_oid[] = {1,3,6,1,2,1,4};
static oid ipMIB_oid[] = {1,3,6,1,2,1,48};

static oid ipTrafficStats_oid[] = {1,3,6,1,2,1,4,31};

static oid ipv4InterfaceTable_oid[] = {1,3,6,1,2,1,4,28};
static oid ipv6InterfaceTable_oid[] = {1,3,6,1,2,1,4,30};
static oid ipSystemStatsTable_oid[] = {1,3,6,1,2,1,4,31,1};
static oid ipIfStatsTable_oid[] = {1,3,6,1,2,1,4,31,3};
static oid ipAddressPrefixTable_oid[] = {1,3,6,1,2,1,4,32};
static oid ipAddressTable_oid[] = {1,3,6,1,2,1,4,34};
static oid ipNetToPhysicalTable_oid[] = {1,3,6,1,2,1,4,35};
static oid ipv6ScopeZoneIndexTable_oid[] = {1,3,6,1,2,1,4,36};
static oid ipDefaultRouterTable_oid[] = {1,3,6,1,2,1,4,37};
static oid ipv6RouterAdvertTable_oid[] = {1,3,6,1,2,1,4,39};



/**
 *	initialize ipMIB group mapper
 */
void
ipMIB_init (void)
{
	extern oid ip_oid[];
	extern oid ipMIB_oid[];
	extern oid ipTrafficStats_oid[];
	
	DEBUGMSGTL (("ipMIB", "Initializing\n"));
	
	/* register ip scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ip_mapper", &ip_mapper,
			ip_oid, OID_LENGTH (ip_oid),
			HANDLER_CAN_RWRITE
		),
		IPFORWARDING,
		IPV6ROUTERADVERTSPINLOCK
	);
	
	/* register ipTrafficStats scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ipTrafficStats_mapper", &ipTrafficStats_mapper,
			ipTrafficStats_oid, OID_LENGTH (ipTrafficStats_oid),
			HANDLER_CAN_RONLY
		),
		IPIFSTATSTABLELASTCHANGE,
		IPIFSTATSTABLELASTCHANGE
	);
	
	
	/* register ipMIB group table mappers */
	ipv4InterfaceTable_init ();
	ipv6InterfaceTable_init ();
	ipSystemStatsTable_init ();
	ipIfStatsTable_init ();
	ipAddressPrefixTable_init ();
	ipAddressTable_init ();
	ipNetToPhysicalTable_init ();
	ipv6ScopeZoneIndexTable_init ();
	ipDefaultRouterTable_init ();
	ipv6RouterAdvertTable_init ();
	
	/* register ipMIB modules */
	sysORTable_createRegister ("ip", ip_oid, OID_LENGTH (ip_oid));
	sysORTable_createRegister ("ipMIB", ipMIB_oid, OID_LENGTH (ipMIB_oid));
}


/**
 *	scalar mapper(s)
 */
ip_t oIp;

/** ip scalar mapper **/
int
ip_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ip_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ip_oid) - 1])
			{
			case IPFORWARDING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32Forwarding);
				break;
			case IPDEFAULTTTL:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32DefaultTTL);
				break;
			case IPREASMTIMEOUT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32ReasmTimeout);
				break;
			case IPV6IPFORWARDING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32Ipv6IpForwarding);
				break;
			case IPV6IPDEFAULTHOPLIMIT:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32Ipv6IpDefaultHopLimit);
				break;
			case IPV4INTERFACETABLELASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, oIp.u32Ipv4InterfaceTableLastChange);
				break;
			case IPV6INTERFACETABLELASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, oIp.u32Ipv6InterfaceTableLastChange);
				break;
			case IPADDRESSSPINLOCK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32AddressSpinLock);
				break;
			case IPV6ROUTERADVERTSPINLOCK:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, oIp.i32Ipv6RouterAdvertSpinLock);
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
			switch (request->requestvb->name[OID_LENGTH (ip_oid) - 1])
			{
			case IPFORWARDING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IPDEFAULTTTL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IPV6IPFORWARDING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IPV6IPDEFAULTHOPLIMIT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IPADDRESSSPINLOCK:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case IPV6ROUTERADVERTSPINLOCK:
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
			switch (request->requestvb->name[OID_LENGTH (ip_oid) - 1])
			{
			case IPFORWARDING:
				/* XXX: perform the value change here */
				oIp.i32Forwarding = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IPDEFAULTTTL:
				/* XXX: perform the value change here */
				oIp.i32DefaultTTL = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IPV6IPFORWARDING:
				/* XXX: perform the value change here */
				oIp.i32Ipv6IpForwarding = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IPV6IPDEFAULTHOPLIMIT:
				/* XXX: perform the value change here */
				oIp.i32Ipv6IpDefaultHopLimit = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IPADDRESSSPINLOCK:
				/* XXX: perform the value change here */
				oIp.i32AddressSpinLock = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case IPV6ROUTERADVERTSPINLOCK:
				/* XXX: perform the value change here */
				oIp.i32Ipv6RouterAdvertSpinLock = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (ip_oid) - 1])
			{
			case IPFORWARDING:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IPDEFAULTTTL:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IPV6IPFORWARDING:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IPV6IPDEFAULTHOPLIMIT:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IPADDRESSSPINLOCK:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case IPV6ROUTERADVERTSPINLOCK:
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

ipTrafficStats_t oIpTrafficStats;

/** ipTrafficStats scalar mapper **/
int
ipTrafficStats_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ipTrafficStats_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ipTrafficStats_oid) - 1])
			{
			case IPIFSTATSTABLELASTCHANGE:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, oIpTrafficStats.u32IfStatsTableLastChange);
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
/** initialize ipv4InterfaceTable table mapper **/
void
ipv4InterfaceTable_init (void)
{
	extern oid ipv4InterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipv4InterfaceTable", &ipv4InterfaceTable_mapper,
		ipv4InterfaceTable_oid, OID_LENGTH (ipv4InterfaceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipv4InterfaceIfIndex */,
		0);
	table_info->min_column = IPV4INTERFACEREASMMAXSIZE;
	table_info->max_column = IPV4INTERFACERETRANSMITTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipv4InterfaceTable_getFirst;
	iinfo->get_next_data_point = &ipv4InterfaceTable_getNext;
	iinfo->get_data_point = &ipv4InterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipv4InterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipv4InterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, ipv4InterfaceEntry_t, oBTreeNode);
	register ipv4InterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, ipv4InterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpv4InterfaceTable_BTree = xBTree_initInline (&ipv4InterfaceTable_BTreeNodeCmp);

/* create a new row in the table */
ipv4InterfaceEntry_t *
ipv4InterfaceTable_createEntry (
	uint32_t u32IfIndex)
{
	register ipv4InterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv4InterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32RetransmitTime = 1000;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpv4InterfaceTable_BTree);
	return poEntry;
}

ipv4InterfaceEntry_t *
ipv4InterfaceTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ipv4InterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpv4InterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv4InterfaceEntry_t, oBTreeNode);
}

ipv4InterfaceEntry_t *
ipv4InterfaceTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ipv4InterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpv4InterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv4InterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipv4InterfaceTable_removeEntry (ipv4InterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv4InterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpv4InterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipv4InterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpv4InterfaceTable_BTree);
	return ipv4InterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipv4InterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv4InterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipv4InterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpv4InterfaceTable_BTree);
	return put_index_data;
}

bool
ipv4InterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv4InterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ipv4InterfaceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipv4InterfaceTable table mapper */
int
ipv4InterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipv4InterfaceEntry_t *table_entry;
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
			table_entry = (ipv4InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV4INTERFACEREASMMAXSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ReasmMaxSize);
				break;
			case IPV4INTERFACEENABLESTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableStatus);
				break;
			case IPV4INTERFACERETRANSMITTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RetransmitTime);
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
			table_entry = (ipv4InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV4INTERFACEENABLESTATUS:
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
			table_entry = (ipv4InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ipv4InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV4INTERFACEENABLESTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableStatus, sizeof (table_entry->i32EnableStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableStatus = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ipv4InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV4INTERFACEENABLESTATUS:
				memcpy (&table_entry->i32EnableStatus, pvOldDdata, sizeof (table_entry->i32EnableStatus));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ipv6InterfaceTable table mapper **/
void
ipv6InterfaceTable_init (void)
{
	extern oid ipv6InterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipv6InterfaceTable", &ipv6InterfaceTable_mapper,
		ipv6InterfaceTable_oid, OID_LENGTH (ipv6InterfaceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipv6InterfaceIfIndex */,
		0);
	table_info->min_column = IPV6INTERFACEREASMMAXSIZE;
	table_info->max_column = IPV6INTERFACEFORWARDING;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipv6InterfaceTable_getFirst;
	iinfo->get_next_data_point = &ipv6InterfaceTable_getNext;
	iinfo->get_data_point = &ipv6InterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipv6InterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipv6InterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, ipv6InterfaceEntry_t, oBTreeNode);
	register ipv6InterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, ipv6InterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpv6InterfaceTable_BTree = xBTree_initInline (&ipv6InterfaceTable_BTreeNodeCmp);

/* create a new row in the table */
ipv6InterfaceEntry_t *
ipv6InterfaceTable_createEntry (
	uint32_t u32IfIndex)
{
	register ipv6InterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6InterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpv6InterfaceTable_BTree);
	return poEntry;
}

ipv6InterfaceEntry_t *
ipv6InterfaceTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ipv6InterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpv6InterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6InterfaceEntry_t, oBTreeNode);
}

ipv6InterfaceEntry_t *
ipv6InterfaceTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ipv6InterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpv6InterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6InterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipv6InterfaceTable_removeEntry (ipv6InterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6InterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpv6InterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipv6InterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpv6InterfaceTable_BTree);
	return ipv6InterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipv6InterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6InterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipv6InterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpv6InterfaceTable_BTree);
	return put_index_data;
}

bool
ipv6InterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6InterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ipv6InterfaceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipv6InterfaceTable table mapper */
int
ipv6InterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipv6InterfaceEntry_t *table_entry;
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
			table_entry = (ipv6InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6INTERFACEREASMMAXSIZE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ReasmMaxSize);
				break;
			case IPV6INTERFACEIDENTIFIER:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Identifier, table_entry->u16Identifier_len);
				break;
			case IPV6INTERFACEENABLESTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32EnableStatus);
				break;
			case IPV6INTERFACEREACHABLETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ReachableTime);
				break;
			case IPV6INTERFACERETRANSMITTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RetransmitTime);
				break;
			case IPV6INTERFACEFORWARDING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Forwarding);
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
			table_entry = (ipv6InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6INTERFACEENABLESTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6INTERFACEFORWARDING:
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
			table_entry = (ipv6InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ipv6InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6INTERFACEENABLESTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32EnableStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32EnableStatus, sizeof (table_entry->i32EnableStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32EnableStatus = *request->requestvb->val.integer;
				break;
			case IPV6INTERFACEFORWARDING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Forwarding))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Forwarding, sizeof (table_entry->i32Forwarding));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Forwarding = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ipv6InterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6INTERFACEENABLESTATUS:
				memcpy (&table_entry->i32EnableStatus, pvOldDdata, sizeof (table_entry->i32EnableStatus));
				break;
			case IPV6INTERFACEFORWARDING:
				memcpy (&table_entry->i32Forwarding, pvOldDdata, sizeof (table_entry->i32Forwarding));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ipSystemStatsTable table mapper **/
void
ipSystemStatsTable_init (void)
{
	extern oid ipSystemStatsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipSystemStatsTable", &ipSystemStatsTable_mapper,
		ipSystemStatsTable_oid, OID_LENGTH (ipSystemStatsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipSystemStatsIPVersion */,
		0);
	table_info->min_column = IPSYSTEMSTATSINRECEIVES;
	table_info->max_column = IPSYSTEMSTATSREFRESHRATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipSystemStatsTable_getFirst;
	iinfo->get_next_data_point = &ipSystemStatsTable_getNext;
	iinfo->get_data_point = &ipSystemStatsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipSystemStatsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipSystemStatsEntry_t *pEntry1 = xBTree_entry (pNode1, ipSystemStatsEntry_t, oBTreeNode);
	register ipSystemStatsEntry_t *pEntry2 = xBTree_entry (pNode2, ipSystemStatsEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IPVersion < pEntry2->i32IPVersion) ? -1:
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion) ? 0: 1;
}

xBTree_t oIpSystemStatsTable_BTree = xBTree_initInline (&ipSystemStatsTable_BTreeNodeCmp);

/* create a new row in the table */
ipSystemStatsEntry_t *
ipSystemStatsTable_createEntry (
	int32_t i32IPVersion)
{
	register ipSystemStatsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IPVersion = i32IPVersion;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpSystemStatsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpSystemStatsTable_BTree);
	return poEntry;
}

ipSystemStatsEntry_t *
ipSystemStatsTable_getByIndex (
	int32_t i32IPVersion)
{
	register ipSystemStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpSystemStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipSystemStatsEntry_t, oBTreeNode);
}

ipSystemStatsEntry_t *
ipSystemStatsTable_getNextIndex (
	int32_t i32IPVersion)
{
	register ipSystemStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpSystemStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipSystemStatsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipSystemStatsTable_removeEntry (ipSystemStatsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpSystemStatsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpSystemStatsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipSystemStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpSystemStatsTable_BTree);
	return ipSystemStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipSystemStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipSystemStatsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipSystemStatsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IPVersion);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpSystemStatsTable_BTree);
	return put_index_data;
}

bool
ipSystemStatsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipSystemStatsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ipSystemStatsTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipSystemStatsTable table mapper */
int
ipSystemStatsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipSystemStatsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipSystemStatsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPSYSTEMSTATSINRECEIVES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InReceives);
				break;
			case IPSYSTEMSTATSHCINRECEIVES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInReceives);
				break;
			case IPSYSTEMSTATSINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InOctets);
				break;
			case IPSYSTEMSTATSHCINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInOctets);
				break;
			case IPSYSTEMSTATSINHDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InHdrErrors);
				break;
			case IPSYSTEMSTATSINNOROUTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InNoRoutes);
				break;
			case IPSYSTEMSTATSINADDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InAddrErrors);
				break;
			case IPSYSTEMSTATSINUNKNOWNPROTOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InUnknownProtos);
				break;
			case IPSYSTEMSTATSINTRUNCATEDPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InTruncatedPkts);
				break;
			case IPSYSTEMSTATSINFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InForwDatagrams);
				break;
			case IPSYSTEMSTATSHCINFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInForwDatagrams);
				break;
			case IPSYSTEMSTATSREASMREQDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmReqds);
				break;
			case IPSYSTEMSTATSREASMOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmOKs);
				break;
			case IPSYSTEMSTATSREASMFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmFails);
				break;
			case IPSYSTEMSTATSINDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InDiscards);
				break;
			case IPSYSTEMSTATSINDELIVERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InDelivers);
				break;
			case IPSYSTEMSTATSHCINDELIVERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInDelivers);
				break;
			case IPSYSTEMSTATSOUTREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutRequests);
				break;
			case IPSYSTEMSTATSHCOUTREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutRequests);
				break;
			case IPSYSTEMSTATSOUTNOROUTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutNoRoutes);
				break;
			case IPSYSTEMSTATSOUTFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutForwDatagrams);
				break;
			case IPSYSTEMSTATSHCOUTFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutForwDatagrams);
				break;
			case IPSYSTEMSTATSOUTDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutDiscards);
				break;
			case IPSYSTEMSTATSOUTFRAGREQDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragReqds);
				break;
			case IPSYSTEMSTATSOUTFRAGOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragOKs);
				break;
			case IPSYSTEMSTATSOUTFRAGFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragFails);
				break;
			case IPSYSTEMSTATSOUTFRAGCREATES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragCreates);
				break;
			case IPSYSTEMSTATSOUTTRANSMITS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutTransmits);
				break;
			case IPSYSTEMSTATSHCOUTTRANSMITS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutTransmits);
				break;
			case IPSYSTEMSTATSOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutOctets);
				break;
			case IPSYSTEMSTATSHCOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutOctets);
				break;
			case IPSYSTEMSTATSINMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMcastPkts);
				break;
			case IPSYSTEMSTATSHCINMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInMcastPkts);
				break;
			case IPSYSTEMSTATSINMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMcastOctets);
				break;
			case IPSYSTEMSTATSHCINMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInMcastOctets);
				break;
			case IPSYSTEMSTATSOUTMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMcastPkts);
				break;
			case IPSYSTEMSTATSHCOUTMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutMcastPkts);
				break;
			case IPSYSTEMSTATSOUTMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMcastOctets);
				break;
			case IPSYSTEMSTATSHCOUTMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutMcastOctets);
				break;
			case IPSYSTEMSTATSINBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InBcastPkts);
				break;
			case IPSYSTEMSTATSHCINBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInBcastPkts);
				break;
			case IPSYSTEMSTATSOUTBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutBcastPkts);
				break;
			case IPSYSTEMSTATSHCOUTBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutBcastPkts);
				break;
			case IPSYSTEMSTATSDISCONTINUITYTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32DiscontinuityTime);
				break;
			case IPSYSTEMSTATSREFRESHRATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RefreshRate);
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

/** initialize ipIfStatsTable table mapper **/
void
ipIfStatsTable_init (void)
{
	extern oid ipIfStatsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipIfStatsTable", &ipIfStatsTable_mapper,
		ipIfStatsTable_oid, OID_LENGTH (ipIfStatsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipIfStatsIPVersion */,
		ASN_INTEGER /* index: ipIfStatsIfIndex */,
		0);
	table_info->min_column = IPIFSTATSINRECEIVES;
	table_info->max_column = IPIFSTATSREFRESHRATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipIfStatsTable_getFirst;
	iinfo->get_next_data_point = &ipIfStatsTable_getNext;
	iinfo->get_data_point = &ipIfStatsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipIfStatsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipIfStatsEntry_t *pEntry1 = xBTree_entry (pNode1, ipIfStatsEntry_t, oBTreeNode);
	register ipIfStatsEntry_t *pEntry2 = xBTree_entry (pNode2, ipIfStatsEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32IPVersion < pEntry2->i32IPVersion) ||
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->i32IPVersion == pEntry2->i32IPVersion && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpIfStatsTable_BTree = xBTree_initInline (&ipIfStatsTable_BTreeNodeCmp);

/* create a new row in the table */
ipIfStatsEntry_t *
ipIfStatsTable_createEntry (
	int32_t i32IPVersion,
	uint32_t u32IfIndex)
{
	register ipIfStatsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32IPVersion = i32IPVersion;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpIfStatsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpIfStatsTable_BTree);
	return poEntry;
}

ipIfStatsEntry_t *
ipIfStatsTable_getByIndex (
	int32_t i32IPVersion,
	uint32_t u32IfIndex)
{
	register ipIfStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpIfStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipIfStatsEntry_t, oBTreeNode);
}

ipIfStatsEntry_t *
ipIfStatsTable_getNextIndex (
	int32_t i32IPVersion,
	uint32_t u32IfIndex)
{
	register ipIfStatsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32IPVersion = i32IPVersion;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpIfStatsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipIfStatsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipIfStatsTable_removeEntry (ipIfStatsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpIfStatsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpIfStatsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipIfStatsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpIfStatsTable_BTree);
	return ipIfStatsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipIfStatsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipIfStatsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipIfStatsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32IPVersion);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpIfStatsTable_BTree);
	return put_index_data;
}

bool
ipIfStatsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipIfStatsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ipIfStatsTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipIfStatsTable table mapper */
int
ipIfStatsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipIfStatsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipIfStatsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPIFSTATSINRECEIVES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InReceives);
				break;
			case IPIFSTATSHCINRECEIVES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInReceives);
				break;
			case IPIFSTATSINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InOctets);
				break;
			case IPIFSTATSHCINOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInOctets);
				break;
			case IPIFSTATSINHDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InHdrErrors);
				break;
			case IPIFSTATSINNOROUTES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InNoRoutes);
				break;
			case IPIFSTATSINADDRERRORS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InAddrErrors);
				break;
			case IPIFSTATSINUNKNOWNPROTOS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InUnknownProtos);
				break;
			case IPIFSTATSINTRUNCATEDPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InTruncatedPkts);
				break;
			case IPIFSTATSINFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InForwDatagrams);
				break;
			case IPIFSTATSHCINFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInForwDatagrams);
				break;
			case IPIFSTATSREASMREQDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmReqds);
				break;
			case IPIFSTATSREASMOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmOKs);
				break;
			case IPIFSTATSREASMFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32ReasmFails);
				break;
			case IPIFSTATSINDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InDiscards);
				break;
			case IPIFSTATSINDELIVERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InDelivers);
				break;
			case IPIFSTATSHCINDELIVERS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInDelivers);
				break;
			case IPIFSTATSOUTREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutRequests);
				break;
			case IPIFSTATSHCOUTREQUESTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutRequests);
				break;
			case IPIFSTATSOUTFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutForwDatagrams);
				break;
			case IPIFSTATSHCOUTFORWDATAGRAMS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutForwDatagrams);
				break;
			case IPIFSTATSOUTDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutDiscards);
				break;
			case IPIFSTATSOUTFRAGREQDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragReqds);
				break;
			case IPIFSTATSOUTFRAGOKS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragOKs);
				break;
			case IPIFSTATSOUTFRAGFAILS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragFails);
				break;
			case IPIFSTATSOUTFRAGCREATES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutFragCreates);
				break;
			case IPIFSTATSOUTTRANSMITS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutTransmits);
				break;
			case IPIFSTATSHCOUTTRANSMITS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutTransmits);
				break;
			case IPIFSTATSOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutOctets);
				break;
			case IPIFSTATSHCOUTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutOctets);
				break;
			case IPIFSTATSINMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMcastPkts);
				break;
			case IPIFSTATSHCINMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInMcastPkts);
				break;
			case IPIFSTATSINMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InMcastOctets);
				break;
			case IPIFSTATSHCINMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInMcastOctets);
				break;
			case IPIFSTATSOUTMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMcastPkts);
				break;
			case IPIFSTATSHCOUTMCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutMcastPkts);
				break;
			case IPIFSTATSOUTMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutMcastOctets);
				break;
			case IPIFSTATSHCOUTMCASTOCTETS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutMcastOctets);
				break;
			case IPIFSTATSINBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32InBcastPkts);
				break;
			case IPIFSTATSHCINBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCInBcastPkts);
				break;
			case IPIFSTATSOUTBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER, table_entry->u32OutBcastPkts);
				break;
			case IPIFSTATSHCOUTBCASTPKTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64HCOutBcastPkts);
				break;
			case IPIFSTATSDISCONTINUITYTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32DiscontinuityTime);
				break;
			case IPIFSTATSREFRESHRATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RefreshRate);
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

/** initialize ipAddressPrefixTable table mapper **/
void
ipAddressPrefixTable_init (void)
{
	extern oid ipAddressPrefixTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipAddressPrefixTable", &ipAddressPrefixTable_mapper,
		ipAddressPrefixTable_oid, OID_LENGTH (ipAddressPrefixTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipAddressPrefixIfIndex */,
		ASN_INTEGER /* index: ipAddressPrefixType */,
		ASN_OCTET_STR /* index: ipAddressPrefixPrefix */,
		ASN_UNSIGNED /* index: ipAddressPrefixLength */,
		0);
	table_info->min_column = IPADDRESSPREFIXORIGIN;
	table_info->max_column = IPADDRESSPREFIXADVVALIDLIFETIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipAddressPrefixTable_getFirst;
	iinfo->get_next_data_point = &ipAddressPrefixTable_getNext;
	iinfo->get_data_point = &ipAddressPrefixTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipAddressPrefixTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipAddressPrefixEntry_t *pEntry1 = xBTree_entry (pNode1, ipAddressPrefixEntry_t, oBTreeNode);
	register ipAddressPrefixEntry_t *pEntry2 = xBTree_entry (pNode2, ipAddressPrefixEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Prefix, pEntry2->au8Prefix, pEntry1->u16Prefix_len, pEntry2->u16Prefix_len) == -1) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Prefix, pEntry2->au8Prefix, pEntry1->u16Prefix_len, pEntry2->u16Prefix_len) == 0 && pEntry1->u32Length < pEntry2->u32Length) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Type == pEntry2->i32Type && xBinCmp (pEntry1->au8Prefix, pEntry2->au8Prefix, pEntry1->u16Prefix_len, pEntry2->u16Prefix_len) == 0 && pEntry1->u32Length == pEntry2->u32Length) ? 0: 1;
}

xBTree_t oIpAddressPrefixTable_BTree = xBTree_initInline (&ipAddressPrefixTable_BTreeNodeCmp);

/* create a new row in the table */
ipAddressPrefixEntry_t *
ipAddressPrefixTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length)
{
	register ipAddressPrefixEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->i32Type = i32Type;
	memcpy (poEntry->au8Prefix, pau8Prefix, u16Prefix_len);
	poEntry->u16Prefix_len = u16Prefix_len;
	poEntry->u32Length = u32Length;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpAddressPrefixTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpAddressPrefixTable_BTree);
	return poEntry;
}

ipAddressPrefixEntry_t *
ipAddressPrefixTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length)
{
	register ipAddressPrefixEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Prefix, pau8Prefix, u16Prefix_len);
	poTmpEntry->u16Prefix_len = u16Prefix_len;
	poTmpEntry->u32Length = u32Length;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpAddressPrefixTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressPrefixEntry_t, oBTreeNode);
}

ipAddressPrefixEntry_t *
ipAddressPrefixTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length)
{
	register ipAddressPrefixEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32Type = i32Type;
	memcpy (poTmpEntry->au8Prefix, pau8Prefix, u16Prefix_len);
	poTmpEntry->u16Prefix_len = u16Prefix_len;
	poTmpEntry->u32Length = u32Length;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpAddressPrefixTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressPrefixEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipAddressPrefixTable_removeEntry (ipAddressPrefixEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpAddressPrefixTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpAddressPrefixTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ipAddressPrefixEntry_t *
ipAddressPrefixTable_handler (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32PrefixLength,
	bool bAttach)
{
	register uint8_t u8PrefixSize = 0;
	register uint8_t *pu8Prefix = NULL;
	register ipAddressPrefixEntry_t *poIpAddressPrefixEntry = NULL;
	
	u8PrefixSize =
		i32Type == ipAddressAddrType_ipv4_c ? InetVersion_ipv4_c:
		i32Type == ipAddressAddrType_ipv4z_c ? InetAddressIPv4_size_c:
		i32Type == ipAddressAddrType_ipv6_c ? InetVersion_ipv6_c:
		i32Type == ipAddressAddrType_ipv6z_c ? InetAddressIPv6z_size_c: 0;
		
	if ((pu8Prefix = xBuffer_cAlloc (u8PrefixSize)) == NULL)
	{
		goto ipAddressPrefixTable_handler_cleanup;
	}
	xBitmap_setRev (pu8Prefix, 0, u32PrefixLength - 1, 1);
	xBitmap_and (pu8Prefix, pu8Prefix, pau8Addr, u32PrefixLength);
	if (i32Type == ipAddressAddrType_ipv4z_c || i32Type == ipAddressAddrType_ipv6z_c)
	{
		memcpy (&pu8Prefix [u8PrefixSize - InetZoneIndex_size_c - 1], pau8Addr, InetZoneIndex_size_c);
	}
	
	poIpAddressPrefixEntry = ipAddressPrefixTable_getByIndex (u32IfIndex, i32Type, pu8Prefix, u8PrefixSize, u32PrefixLength);
	
	if (bAttach)
	{
		if (poIpAddressPrefixEntry == NULL &&
			(poIpAddressPrefixEntry = ipAddressPrefixTable_createEntry (u32IfIndex, i32Type, pu8Prefix, u8PrefixSize, u32PrefixLength)) == NULL)
		{
			goto ipAddressPrefixTable_handler_cleanup;
		}
		
		poIpAddressPrefixEntry->u32NumAddresses++;
	}
	else
	{
		if (poIpAddressPrefixEntry == NULL)
		{
			goto ipAddressPrefixTable_handler_cleanup;
		}
		
		poIpAddressPrefixEntry->u32NumAddresses--;
		
		if (poIpAddressPrefixEntry->u32NumAddresses == 0)
		{
			ipAddressPrefixTable_removeEntry (poIpAddressPrefixEntry);
			poIpAddressPrefixEntry = NULL;
		}
	}
	
ipAddressPrefixTable_handler_cleanup:
	
	if (pu8Prefix != NULL)
	{
		xBuffer_free (pu8Prefix);
	}
	return poIpAddressPrefixEntry;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipAddressPrefixTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpAddressPrefixTable_BTree);
	return ipAddressPrefixTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipAddressPrefixTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipAddressPrefixEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipAddressPrefixEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Type);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Prefix, poEntry->u16Prefix_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Length);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpAddressPrefixTable_BTree);
	return put_index_data;
}

bool
ipAddressPrefixTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipAddressPrefixEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = ipAddressPrefixTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		(void*) idx3->val.string, idx3->val_len,
		*idx4->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipAddressPrefixTable table mapper */
int
ipAddressPrefixTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipAddressPrefixEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipAddressPrefixEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPADDRESSPREFIXORIGIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Origin);
				break;
			case IPADDRESSPREFIXONLINKFLAG:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OnLinkFlag);
				break;
			case IPADDRESSPREFIXAUTONOMOUSFLAG:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AutonomousFlag);
				break;
			case IPADDRESSPREFIXADVPREFERREDLIFETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32AdvPreferredLifetime);
				break;
			case IPADDRESSPREFIXADVVALIDLIFETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32AdvValidLifetime);
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

/** initialize ipAddressTable table mapper **/
void
ipAddressTable_init (void)
{
	extern oid ipAddressTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipAddressTable", &ipAddressTable_mapper,
		ipAddressTable_oid, OID_LENGTH (ipAddressTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipAddressAddrType */,
		ASN_OCTET_STR /* index: ipAddressAddr */,
		0);
	table_info->min_column = IPADDRESSIFINDEX;
	table_info->max_column = IPADDRESSSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipAddressTable_getFirst;
	iinfo->get_next_data_point = &ipAddressTable_getNext;
	iinfo->get_data_point = &ipAddressTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipAddressData_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipAddressData_t *pEntry1 = xBTree_entry (pNode1, ipAddressData_t, oBTreeNode);
	register ipAddressData_t *pEntry2 = xBTree_entry (pNode2, ipAddressData_t, oBTreeNode);
	
	return
		(pEntry1->i32AddrType < pEntry2->i32AddrType) ||
		(pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == -1) ? -1:
		(pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0) ? 0: 1;
}

static int8_t
ipAddressData_If_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipAddressData_t *pEntry1 = xBTree_entry (pNode1, ipAddressData_t, oIf_BTreeNode);
	register ipAddressData_t *pEntry2 = xBTree_entry (pNode2, ipAddressData_t, oIf_BTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32AddrType < pEntry2->i32AddrType) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == -1) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0) ? 0: 1;
}

xBTree_t oIpAddressData_BTree = xBTree_initInline (&ipAddressData_BTreeNodeCmp);
static xBTree_t oIpAddressData_If_BTree = xBTree_initInline (&ipAddressData_If_BTreeNodeCmp);

/* create a new row in the table */
ipAddressData_t *
ipAddressData_createEntry (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32AddrType = i32AddrType;
	memcpy (poEntry->au8Addr, pau8Addr, u16Addr_len);
	poEntry->u16Addr_len = u16Addr_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpAddressData_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpAddressData_BTree);
	return poEntry;
}

ipAddressData_t *
ipAddressData_getByIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpAddressData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressData_t, oBTreeNode);
}

ipAddressData_t *
ipAddressData_getNextIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpAddressData_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressData_t, oBTreeNode);
}

ipAddressData_t *
ipAddressData_If_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ipAddressData_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oIf_BTreeNode, &oIpAddressData_If_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressData_t, oIf_BTreeNode);
}

ipAddressData_t *
ipAddressData_If_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ipAddressData_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oIf_BTreeNode, &oIpAddressData_If_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipAddressData_t, oIf_BTreeNode);
}

/* remove a row from the table */
void
ipAddressData_removeEntry (ipAddressData_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpAddressData_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpAddressData_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* create a new row in the table */
ipAddressEntry_t *
ipAddressTable_createEntry (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressEntry_t *poEntry = NULL;
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_createEntry (i32AddrType, pau8Addr, u16Addr_len)) == NULL)
	{
		return NULL;
	}
	poEntry = &poIpAddressData->oIp;
	
	poEntry->i32Type = ipAddressType_unicast_c;
	/*poEntry->aoPrefix = zeroDotZero*/;
	poEntry->i32Status = ipAddressStatus_preferred_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = ipAddressStorageType_volatile_c;
	
	xBitmap_setBit (poIpAddressData->au8Flags, ipAddressFlags_ipCreated_c, 1);
	return poEntry;
}

ipAddressEntry_t *
ipAddressTable_getByIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_getByIndex (i32AddrType, pau8Addr, u16Addr_len)) == NULL ||
		!xBitmap_getBit (poIpAddressData->au8Flags, ipAddressFlags_ipCreated_c))
	{
		return NULL;
	}
	
	return &poIpAddressData->oIp;
}

ipAddressEntry_t *
ipAddressTable_getNextIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_getNextIndex (i32AddrType, pau8Addr, u16Addr_len)) == NULL ||
		!xBitmap_getBit (poIpAddressData->au8Flags, ipAddressFlags_ipCreated_c))
	{
		return NULL;
	}
	
	return &poIpAddressData->oIp;
}

/* remove a row from the table */
void
ipAddressTable_removeEntry (ipAddressEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	ipAddressData_removeEntry (ipAddressData_getByIpEntry (poEntry));
	return;
}

ipAddressEntry_t *
ipAddressTable_createExt (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	ipAddressEntry_t *poEntry = NULL;
	neIpAddressEntry_t *poNeIpAddressEntry = NULL;
	
	poEntry = ipAddressTable_createEntry (
		i32AddrType,
		pau8Addr, u16Addr_len);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	poNeIpAddressEntry = neIpAddressTable_createEntry (
		i32AddrType,
		pau8Addr, u16Addr_len);
	if (poNeIpAddressEntry == NULL)
	{
		ipAddressTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ipAddressTable_removeExt (ipAddressEntry_t *poEntry)
{
	register ipAddressData_t *poIpAddressData = ipAddressData_getByIpEntry (poEntry);
	
	neIpAddressTable_removeEntry (&poIpAddressData->oNe);
	ipAddressTable_removeEntry (poEntry);
	
	return true;
}

bool
ipAddressIfIndex_handler (
	ipAddressEntry_t *poEntry)
{
	register neInetInterfaceEntry_t *poNeInetInterfaceEntry = NULL;
	register ipAddressData_t *poIpAddressData = ipAddressData_getByIpEntry (poEntry);
	
	
	if (poIpAddressData->u32IfIndex == poIpAddressData->oIp.u32IfIndex)
	{
		return true;
	}
	
	if (poIpAddressData->u32IfIndex == 0)
	{
		goto ipAddressIfIndex_handler_newIfIndex;
	}
	
	if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poIpAddressData->u32IfIndex)) == NULL)
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	
	xBTree_nodeRemove (&poIpAddressData->oIf_BTreeNode, &oIpAddressData_If_BTree);
	
	if (poIpAddressData->u32PrefixLength != 0)
	{
		ipAddressPrefixTable_handler (
			poIpAddressData->u32IfIndex, poIpAddressData->i32AddrType, poIpAddressData->au8Addr, poIpAddressData->u16Addr_len, poIpAddressData->u32PrefixLength, false);
			
		poIpAddressData->u32PrefixLength = 0;
	}
	
	if (!neInetInterfaceTable_removeExt (poNeInetInterfaceEntry, poIpAddressData->i32AddrType, poIpAddressData->au8Addr, poIpAddressData->u16Addr_len, false))
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	
	if (!ifData_removeReference (poIpAddressData->u32IfIndex, false, true, false))
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	poIpAddressData->u32IfIndex = 0;
	
	
ipAddressIfIndex_handler_newIfIndex:
	
	if (poIpAddressData->oIp.u32IfIndex == 0)
	{
		goto ipAddressIfIndex_handler_success;
	}
	
	if (!ifData_createReference (poIpAddressData->oIp.u32IfIndex, 0, 0, false, true, false, NULL))
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	
	if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poIpAddressData->oIp.u32IfIndex)) == NULL &&
		(poNeInetInterfaceEntry = neInetInterfaceTable_createExt (
			poIpAddressData->oIp.u32IfIndex, poIpAddressData->i32AddrType, poIpAddressData->au8Addr, poIpAddressData->u16Addr_len, false)) == NULL)
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	
	if (poIpAddressData->oNe.u32PrefixLength != 0 &&
		ipAddressPrefixTable_handler (
			poIpAddressData->oIp.u32IfIndex, poIpAddressData->i32AddrType, poIpAddressData->au8Addr, poIpAddressData->u16Addr_len, poIpAddressData->oNe.u32PrefixLength, true) == NULL)
	{
		goto ipAddressIfIndex_handler_cleanup;
	}
	poIpAddressData->u32PrefixLength = poIpAddressData->oNe.u32PrefixLength;
	
ipAddressIfIndex_handler_success:
	
	poIpAddressData->u32IfIndex = poIpAddressData->oIp.u32IfIndex;
	xBTree_nodeAdd (&poIpAddressData->oIf_BTreeNode, &oIpAddressData_If_BTree);
	
	return true;
	
	
ipAddressIfIndex_handler_cleanup:
	
	return false;
}

bool
ipAddressRowStatus_handler (
	ipAddressEntry_t *poEntry,
	int32_t u8RowStatus)
{
	register neInetInterfaceEntry_t *poNeInetInterfaceEntry = NULL;
	register ipAddressData_t *poIpAddressData = ipAddressData_getByIpEntry (poEntry);
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (poEntry->u8RowStatus == xRowStatus_active_c)
		{
			goto ipAddressRowStatus_handler_success;
		}
		
		if (poIpAddressData->oIp.u32IfIndex == 0 ||
			poIpAddressData->oNe.u32PrefixLength == 0)
		{
			goto ipAddressRowStatus_handler_cleanup;
		}
		
		if (!ipAddressIfIndex_handler (poEntry))
		{
			goto ipAddressRowStatus_handler_cleanup;
		}
		
		if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poIpAddressData->u32IfIndex)) == NULL)
		{
			goto ipAddressRowStatus_handler_cleanup;
		}
		
		/*if (poNeInetInterfaceEntry->i32TrafficEnable == neInetInterfaceTrafficEnable_true_c &&
			!ieee8021BridgeTpPortTable_handler (poIpAddressData->u32IfIndex, false))
		{
			goto ipAddressRowStatus_handler_cleanup;
		}*/
		
		/* TODO */
		poEntry->u8RowStatus = xRowStatus_active_c;
		break;
		
	case xRowStatus_notInService_c:
		if (poEntry->u8RowStatus != xRowStatus_active_c)
		{
			goto ipAddressRowStatus_handler_success;
		}
		
		/*if (((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poIpAddressData->u32IfIndex)) == NULL ||
			 poNeInetInterfaceEntry->i32TrafficEnable == neInetInterfaceTrafficEnable_true_c) &&
			!ieee8021BridgeTpPortTable_handler (poIpAddressData->u32IfIndex, true))
		{
			goto ipAddressRowStatus_handler_cleanup;
		}*/
		
		/* TODO */
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		poEntry->u8RowStatus = xRowStatus_notReady_c;
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (poIpAddressData->u32IfIndex == 0)
		{
			goto ipAddressRowStatus_handler_success;
		}
		
		{
			//uint32_t u32IfIndex = poIpAddressData->u32IfIndex;
			
			if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poIpAddressData->u32IfIndex)) == NULL)
			{
				goto ipAddressRowStatus_handler_cleanup;
			}
			
			poIpAddressData->oIp.u32IfIndex = 0;
			if (!ipAddressIfIndex_handler (poEntry))
			{
				goto ipAddressRowStatus_handler_cleanup;
			}
			
			/*if (((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (u32IfIndex)) == NULL ||
				 poNeInetInterfaceEntry->i32TrafficEnable == neInetInterfaceTrafficEnable_true_c) &&
				!ieee8021BridgeTpPortTable_handler (u32IfIndex, true))
			{
				goto ipAddressRowStatus_handler_cleanup;
			}*/
		}
		
		/* TODO */
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ipAddressRowStatus_handler_success:
	
	return true;
	
	
ipAddressRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipAddressTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpAddressData_BTree);
	return ipAddressTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipAddressTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipAddressData_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipAddressData_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32AddrType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Addr, poEntry->u16Addr_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpAddressData_BTree);
	return put_index_data;
}

bool
ipAddressTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipAddressEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ipAddressTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipAddressTable table mapper */
int
ipAddressTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipAddressEntry_t *table_entry;
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPADDRESSIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32IfIndex);
				break;
			case IPADDRESSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case IPADDRESSPREFIX:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoPrefix, table_entry->u16Prefix_len);
				break;
			case IPADDRESSORIGIN:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Origin);
				break;
			case IPADDRESSSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Status);
				break;
			case IPADDRESSCREATED:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32Created);
				break;
			case IPADDRESSLASTCHANGED:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastChanged);
				break;
			case IPADDRESSROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case IPADDRESSSTORAGETYPE:
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPADDRESSIFINDEX:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPADDRESSTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPADDRESSSTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPADDRESSROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPADDRESSSTORAGETYPE:
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IPADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_WRONGVALUE);
					return SNMP_ERR_NOERROR;
					
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ipAddressTable_createExt (
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
			
			switch (table_info->colnum)
			{
			case IPADDRESSIFINDEX:
			case IPADDRESSTYPE:
			case IPADDRESSSTATUS:
			case IPADDRESSSTORAGETYPE:
				if (table_entry->u8RowStatus == xRowStatus_active_c || table_entry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipAddressTable_removeExt (table_entry);
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPADDRESSIFINDEX:
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
			case IPADDRESSTYPE:
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
			case IPADDRESSSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Status))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Status, sizeof (table_entry->i32Status));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Status = *request->requestvb->val.integer;
				break;
			case IPADDRESSSTORAGETYPE:
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!ipAddressRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPADDRESSIFINDEX:
				memcpy (&table_entry->u32IfIndex, pvOldDdata, sizeof (table_entry->u32IfIndex));
				break;
			case IPADDRESSTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case IPADDRESSSTATUS:
				memcpy (&table_entry->i32Status, pvOldDdata, sizeof (table_entry->i32Status));
				break;
			case IPADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipAddressTable_removeExt (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case IPADDRESSSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPADDRESSROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					ipAddressTable_removeExt (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ipNetToPhysicalTable table mapper **/
void
ipNetToPhysicalTable_init (void)
{
	extern oid ipNetToPhysicalTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipNetToPhysicalTable", &ipNetToPhysicalTable_mapper,
		ipNetToPhysicalTable_oid, OID_LENGTH (ipNetToPhysicalTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipNetToPhysicalIfIndex */,
		ASN_INTEGER /* index: ipNetToPhysicalNetAddressType */,
		ASN_OCTET_STR /* index: ipNetToPhysicalNetAddress */,
		0);
	table_info->min_column = IPNETTOPHYSICALPHYSADDRESS;
	table_info->max_column = IPNETTOPHYSICALROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipNetToPhysicalTable_getFirst;
	iinfo->get_next_data_point = &ipNetToPhysicalTable_getNext;
	iinfo->get_data_point = &ipNetToPhysicalTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipNetToPhysicalTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipNetToPhysicalEntry_t *pEntry1 = xBTree_entry (pNode1, ipNetToPhysicalEntry_t, oBTreeNode);
	register ipNetToPhysicalEntry_t *pEntry2 = xBTree_entry (pNode2, ipNetToPhysicalEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32NetAddressType < pEntry2->i32NetAddressType) ||
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32NetAddressType == pEntry2->i32NetAddressType && xBinCmp (pEntry1->au8NetAddress, pEntry2->au8NetAddress, pEntry1->u16NetAddress_len, pEntry2->u16NetAddress_len) == -1) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32NetAddressType == pEntry2->i32NetAddressType && xBinCmp (pEntry1->au8NetAddress, pEntry2->au8NetAddress, pEntry1->u16NetAddress_len, pEntry2->u16NetAddress_len) == 0) ? 0: 1;
}

xBTree_t oIpNetToPhysicalTable_BTree = xBTree_initInline (&ipNetToPhysicalTable_BTreeNodeCmp);

/* create a new row in the table */
ipNetToPhysicalEntry_t *
ipNetToPhysicalTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	register ipNetToPhysicalEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->i32NetAddressType = i32NetAddressType;
	memcpy (poEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poEntry->u16NetAddress_len = u16NetAddress_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Type = ipNetToPhysicalType_static_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree);
	return poEntry;
}

ipNetToPhysicalEntry_t *
ipNetToPhysicalTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	register ipNetToPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32NetAddressType = i32NetAddressType;
	memcpy (poTmpEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poTmpEntry->u16NetAddress_len = u16NetAddress_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipNetToPhysicalEntry_t, oBTreeNode);
}

ipNetToPhysicalEntry_t *
ipNetToPhysicalTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len)
{
	register ipNetToPhysicalEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32NetAddressType = i32NetAddressType;
	memcpy (poTmpEntry->au8NetAddress, pau8NetAddress, u16NetAddress_len);
	poTmpEntry->u16NetAddress_len = u16NetAddress_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipNetToPhysicalEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipNetToPhysicalTable_removeEntry (ipNetToPhysicalEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipNetToPhysicalTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpNetToPhysicalTable_BTree);
	return ipNetToPhysicalTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipNetToPhysicalTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipNetToPhysicalEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipNetToPhysicalEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32NetAddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8NetAddress, poEntry->u16NetAddress_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpNetToPhysicalTable_BTree);
	return put_index_data;
}

bool
ipNetToPhysicalTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipNetToPhysicalEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ipNetToPhysicalTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer,
		(void*) idx3->val.string, idx3->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipNetToPhysicalTable table mapper */
int
ipNetToPhysicalTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipNetToPhysicalEntry_t *table_entry;
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8PhysAddress, table_entry->u16PhysAddress_len);
				break;
			case IPNETTOPHYSICALLASTUPDATED:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32LastUpdated);
				break;
			case IPNETTOPHYSICALTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case IPNETTOPHYSICALSTATE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32State);
				break;
			case IPNETTOPHYSICALROWSTATUS:
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8PhysAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPNETTOPHYSICALTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPNETTOPHYSICALROWSTATUS:
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ipNetToPhysicalTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipNetToPhysicalTable_removeEntry (table_entry);
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8PhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16PhysAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8PhysAddress, sizeof (table_entry->au8PhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8PhysAddress, 0, sizeof (table_entry->au8PhysAddress));
				memcpy (table_entry->au8PhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16PhysAddress_len = request->requestvb->val_len;
				break;
			case IPNETTOPHYSICALTYPE:
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ipNetToPhysicalTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALPHYSADDRESS:
				memcpy (table_entry->au8PhysAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16PhysAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IPNETTOPHYSICALTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case IPNETTOPHYSICALROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipNetToPhysicalTable_removeEntry (table_entry);
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
			table_entry = (ipNetToPhysicalEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPNETTOPHYSICALROWSTATUS:
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
					ipNetToPhysicalTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ipv6ScopeZoneIndexTable table mapper **/
void
ipv6ScopeZoneIndexTable_init (void)
{
	extern oid ipv6ScopeZoneIndexTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipv6ScopeZoneIndexTable", &ipv6ScopeZoneIndexTable_mapper,
		ipv6ScopeZoneIndexTable_oid, OID_LENGTH (ipv6ScopeZoneIndexTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipv6ScopeZoneIndexIfIndex */,
		0);
	table_info->min_column = IPV6SCOPEZONEINDEXLINKLOCAL;
	table_info->max_column = IPV6SCOPEZONEINDEXD;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipv6ScopeZoneIndexTable_getFirst;
	iinfo->get_next_data_point = &ipv6ScopeZoneIndexTable_getNext;
	iinfo->get_data_point = &ipv6ScopeZoneIndexTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipv6ScopeZoneIndexTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipv6ScopeZoneIndexEntry_t *pEntry1 = xBTree_entry (pNode1, ipv6ScopeZoneIndexEntry_t, oBTreeNode);
	register ipv6ScopeZoneIndexEntry_t *pEntry2 = xBTree_entry (pNode2, ipv6ScopeZoneIndexEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpv6ScopeZoneIndexTable_BTree = xBTree_initInline (&ipv6ScopeZoneIndexTable_BTreeNodeCmp);

/* create a new row in the table */
ipv6ScopeZoneIndexEntry_t *
ipv6ScopeZoneIndexTable_createEntry (
	uint32_t u32IfIndex)
{
	register ipv6ScopeZoneIndexEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree);
	return poEntry;
}

ipv6ScopeZoneIndexEntry_t *
ipv6ScopeZoneIndexTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ipv6ScopeZoneIndexEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6ScopeZoneIndexEntry_t, oBTreeNode);
}

ipv6ScopeZoneIndexEntry_t *
ipv6ScopeZoneIndexTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ipv6ScopeZoneIndexEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6ScopeZoneIndexEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipv6ScopeZoneIndexTable_removeEntry (ipv6ScopeZoneIndexEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipv6ScopeZoneIndexTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpv6ScopeZoneIndexTable_BTree);
	return ipv6ScopeZoneIndexTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipv6ScopeZoneIndexTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6ScopeZoneIndexEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipv6ScopeZoneIndexEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpv6ScopeZoneIndexTable_BTree);
	return put_index_data;
}

bool
ipv6ScopeZoneIndexTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6ScopeZoneIndexEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ipv6ScopeZoneIndexTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipv6ScopeZoneIndexTable table mapper */
int
ipv6ScopeZoneIndexTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipv6ScopeZoneIndexEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipv6ScopeZoneIndexEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6SCOPEZONEINDEXLINKLOCAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LinkLocal);
				break;
			case IPV6SCOPEZONEINDEX3:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Index3);
				break;
			case IPV6SCOPEZONEINDEXADMINLOCAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32AdminLocal);
				break;
			case IPV6SCOPEZONEINDEXSITELOCAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32SiteLocal);
				break;
			case IPV6SCOPEZONEINDEX6:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Index6);
				break;
			case IPV6SCOPEZONEINDEX7:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Index7);
				break;
			case IPV6SCOPEZONEINDEXORGANIZATIONLOCAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32OrganizationLocal);
				break;
			case IPV6SCOPEZONEINDEX9:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Index9);
				break;
			case IPV6SCOPEZONEINDEXA:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IndexA);
				break;
			case IPV6SCOPEZONEINDEXB:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IndexB);
				break;
			case IPV6SCOPEZONEINDEXC:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IndexC);
				break;
			case IPV6SCOPEZONEINDEXD:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32IndexD);
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

/** initialize ipDefaultRouterTable table mapper **/
void
ipDefaultRouterTable_init (void)
{
	extern oid ipDefaultRouterTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipDefaultRouterTable", &ipDefaultRouterTable_mapper,
		ipDefaultRouterTable_oid, OID_LENGTH (ipDefaultRouterTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipDefaultRouterAddressType */,
		ASN_OCTET_STR /* index: ipDefaultRouterAddress */,
		ASN_INTEGER /* index: ipDefaultRouterIfIndex */,
		0);
	table_info->min_column = IPDEFAULTROUTERLIFETIME;
	table_info->max_column = IPDEFAULTROUTERPREFERENCE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipDefaultRouterTable_getFirst;
	iinfo->get_next_data_point = &ipDefaultRouterTable_getNext;
	iinfo->get_data_point = &ipDefaultRouterTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipDefaultRouterTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipDefaultRouterEntry_t *pEntry1 = xBTree_entry (pNode1, ipDefaultRouterEntry_t, oBTreeNode);
	register ipDefaultRouterEntry_t *pEntry2 = xBTree_entry (pNode2, ipDefaultRouterEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32AddressType < pEntry2->i32AddressType) ||
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpDefaultRouterTable_BTree = xBTree_initInline (&ipDefaultRouterTable_BTreeNodeCmp);

/* create a new row in the table */
ipDefaultRouterEntry_t *
ipDefaultRouterTable_createEntry (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex)
{
	register ipDefaultRouterEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32AddressType = i32AddressType;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpDefaultRouterTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpDefaultRouterTable_BTree);
	return poEntry;
}

ipDefaultRouterEntry_t *
ipDefaultRouterTable_getByIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex)
{
	register ipDefaultRouterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpDefaultRouterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipDefaultRouterEntry_t, oBTreeNode);
}

ipDefaultRouterEntry_t *
ipDefaultRouterTable_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex)
{
	register ipDefaultRouterEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpDefaultRouterTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipDefaultRouterEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipDefaultRouterTable_removeEntry (ipDefaultRouterEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpDefaultRouterTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpDefaultRouterTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipDefaultRouterTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpDefaultRouterTable_BTree);
	return ipDefaultRouterTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipDefaultRouterTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipDefaultRouterEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipDefaultRouterEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32AddressType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpDefaultRouterTable_BTree);
	return put_index_data;
}

bool
ipDefaultRouterTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipDefaultRouterEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ipDefaultRouterTable_getByIndex (
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

/* ipDefaultRouterTable table mapper */
int
ipDefaultRouterTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipDefaultRouterEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipDefaultRouterEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPDEFAULTROUTERLIFETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Lifetime);
				break;
			case IPDEFAULTROUTERPREFERENCE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Preference);
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

/** initialize ipv6RouterAdvertTable table mapper **/
void
ipv6RouterAdvertTable_init (void)
{
	extern oid ipv6RouterAdvertTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ipv6RouterAdvertTable", &ipv6RouterAdvertTable_mapper,
		ipv6RouterAdvertTable_oid, OID_LENGTH (ipv6RouterAdvertTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipv6RouterAdvertIfIndex */,
		0);
	table_info->min_column = IPV6ROUTERADVERTSENDADVERTS;
	table_info->max_column = IPV6ROUTERADVERTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ipv6RouterAdvertTable_getFirst;
	iinfo->get_next_data_point = &ipv6RouterAdvertTable_getNext;
	iinfo->get_data_point = &ipv6RouterAdvertTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ipv6RouterAdvertTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ipv6RouterAdvertEntry_t *pEntry1 = xBTree_entry (pNode1, ipv6RouterAdvertEntry_t, oBTreeNode);
	register ipv6RouterAdvertEntry_t *pEntry2 = xBTree_entry (pNode2, ipv6RouterAdvertEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oIpv6RouterAdvertTable_BTree = xBTree_initInline (&ipv6RouterAdvertTable_BTreeNodeCmp);

/* create a new row in the table */
ipv6RouterAdvertEntry_t *
ipv6RouterAdvertTable_createEntry (
	uint32_t u32IfIndex)
{
	register ipv6RouterAdvertEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32SendAdverts = ipv6RouterAdvertSendAdverts_false_c;
	poEntry->u32MaxInterval = 600;
	poEntry->i32ManagedFlag = ipv6RouterAdvertManagedFlag_false_c;
	poEntry->i32OtherConfigFlag = ipv6RouterAdvertOtherConfigFlag_false_c;
	poEntry->u32LinkMTU = 0;
	poEntry->u32ReachableTime = 0;
	poEntry->u32RetransmitTime = 0;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree);
	return poEntry;
}

ipv6RouterAdvertEntry_t *
ipv6RouterAdvertTable_getByIndex (
	uint32_t u32IfIndex)
{
	register ipv6RouterAdvertEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6RouterAdvertEntry_t, oBTreeNode);
}

ipv6RouterAdvertEntry_t *
ipv6RouterAdvertTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register ipv6RouterAdvertEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ipv6RouterAdvertEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ipv6RouterAdvertTable_removeEntry (ipv6RouterAdvertEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ipv6RouterAdvertTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpv6RouterAdvertTable_BTree);
	return ipv6RouterAdvertTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ipv6RouterAdvertTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6RouterAdvertEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ipv6RouterAdvertEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIpv6RouterAdvertTable_BTree);
	return put_index_data;
}

bool
ipv6RouterAdvertTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ipv6RouterAdvertEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ipv6RouterAdvertTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ipv6RouterAdvertTable table mapper */
int
ipv6RouterAdvertTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ipv6RouterAdvertEntry_t *table_entry;
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTSENDADVERTS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32SendAdverts);
				break;
			case IPV6ROUTERADVERTMAXINTERVAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxInterval);
				break;
			case IPV6ROUTERADVERTMININTERVAL:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MinInterval);
				break;
			case IPV6ROUTERADVERTMANAGEDFLAG:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32ManagedFlag);
				break;
			case IPV6ROUTERADVERTOTHERCONFIGFLAG:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32OtherConfigFlag);
				break;
			case IPV6ROUTERADVERTLINKMTU:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32LinkMTU);
				break;
			case IPV6ROUTERADVERTREACHABLETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32ReachableTime);
				break;
			case IPV6ROUTERADVERTRETRANSMITTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RetransmitTime);
				break;
			case IPV6ROUTERADVERTCURHOPLIMIT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32CurHopLimit);
				break;
			case IPV6ROUTERADVERTDEFAULTLIFETIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32DefaultLifetime);
				break;
			case IPV6ROUTERADVERTROWSTATUS:
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTSENDADVERTS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTMAXINTERVAL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTMININTERVAL:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTMANAGEDFLAG:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTOTHERCONFIGFLAG:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTLINKMTU:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTREACHABLETIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTRETRANSMITTIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTCURHOPLIMIT:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTDEFAULTLIFETIME:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IPV6ROUTERADVERTROWSTATUS:
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ipv6RouterAdvertTable_createEntry (
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipv6RouterAdvertTable_removeEntry (table_entry);
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTSENDADVERTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32SendAdverts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32SendAdverts, sizeof (table_entry->i32SendAdverts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32SendAdverts = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTMAXINTERVAL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MaxInterval))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MaxInterval, sizeof (table_entry->u32MaxInterval));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MaxInterval = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTMININTERVAL:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32MinInterval))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32MinInterval, sizeof (table_entry->u32MinInterval));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32MinInterval = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTMANAGEDFLAG:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32ManagedFlag))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32ManagedFlag, sizeof (table_entry->i32ManagedFlag));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32ManagedFlag = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTOTHERCONFIGFLAG:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32OtherConfigFlag))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32OtherConfigFlag, sizeof (table_entry->i32OtherConfigFlag));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32OtherConfigFlag = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTLINKMTU:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LinkMTU))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LinkMTU, sizeof (table_entry->u32LinkMTU));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LinkMTU = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTREACHABLETIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32ReachableTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32ReachableTime, sizeof (table_entry->u32ReachableTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32ReachableTime = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTRETRANSMITTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RetransmitTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RetransmitTime, sizeof (table_entry->u32RetransmitTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RetransmitTime = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTCURHOPLIMIT:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32CurHopLimit))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32CurHopLimit, sizeof (table_entry->u32CurHopLimit));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32CurHopLimit = *request->requestvb->val.integer;
				break;
			case IPV6ROUTERADVERTDEFAULTLIFETIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32DefaultLifetime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32DefaultLifetime, sizeof (table_entry->u32DefaultLifetime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32DefaultLifetime = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ipv6RouterAdvertTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTSENDADVERTS:
				memcpy (&table_entry->i32SendAdverts, pvOldDdata, sizeof (table_entry->i32SendAdverts));
				break;
			case IPV6ROUTERADVERTMAXINTERVAL:
				memcpy (&table_entry->u32MaxInterval, pvOldDdata, sizeof (table_entry->u32MaxInterval));
				break;
			case IPV6ROUTERADVERTMININTERVAL:
				memcpy (&table_entry->u32MinInterval, pvOldDdata, sizeof (table_entry->u32MinInterval));
				break;
			case IPV6ROUTERADVERTMANAGEDFLAG:
				memcpy (&table_entry->i32ManagedFlag, pvOldDdata, sizeof (table_entry->i32ManagedFlag));
				break;
			case IPV6ROUTERADVERTOTHERCONFIGFLAG:
				memcpy (&table_entry->i32OtherConfigFlag, pvOldDdata, sizeof (table_entry->i32OtherConfigFlag));
				break;
			case IPV6ROUTERADVERTLINKMTU:
				memcpy (&table_entry->u32LinkMTU, pvOldDdata, sizeof (table_entry->u32LinkMTU));
				break;
			case IPV6ROUTERADVERTREACHABLETIME:
				memcpy (&table_entry->u32ReachableTime, pvOldDdata, sizeof (table_entry->u32ReachableTime));
				break;
			case IPV6ROUTERADVERTRETRANSMITTIME:
				memcpy (&table_entry->u32RetransmitTime, pvOldDdata, sizeof (table_entry->u32RetransmitTime));
				break;
			case IPV6ROUTERADVERTCURHOPLIMIT:
				memcpy (&table_entry->u32CurHopLimit, pvOldDdata, sizeof (table_entry->u32CurHopLimit));
				break;
			case IPV6ROUTERADVERTDEFAULTLIFETIME:
				memcpy (&table_entry->u32DefaultLifetime, pvOldDdata, sizeof (table_entry->u32DefaultLifetime));
				break;
			case IPV6ROUTERADVERTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ipv6RouterAdvertTable_removeEntry (table_entry);
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
			table_entry = (ipv6RouterAdvertEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IPV6ROUTERADVERTROWSTATUS:
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
					ipv6RouterAdvertTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
