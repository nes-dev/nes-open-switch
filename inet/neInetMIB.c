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
#include "if/ifMIB.h"
#include "ipMIB.h"
#include "neInetMIB.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid neInetMIB_oid[] = {1,3,6,1,4,1,36969,53};

static oid neInetScalars_oid[] = {1,3,6,1,4,1,36969,53,1,1};
static oid neIpScalars_oid[] = {1,3,6,1,4,1,36969,53,3,1};

static oid neInetInterfaceTable_oid[] = {1,3,6,1,4,1,36969,53,1,2};
static oid neInetIntRouteTable_oid[] = {1,3,6,1,4,1,36969,53,1,3};
static oid neInetRouteTable_oid[] = {1,3,6,1,4,1,36969,53,1,4};
static oid neIpAddressTable_oid[] = {1,3,6,1,4,1,36969,53,3,2};
static oid neIpUnNumTable_oid[] = {1,3,6,1,4,1,36969,53,3,3};
static oid neIpAsNodeTable_oid[] = {1,3,6,1,4,1,36969,53,3,4};



/**
 *	initialize neInetMIB group mapper
 */
void
neInetMIB_init (void)
{
	extern oid neInetMIB_oid[];
	extern oid neInetScalars_oid[];
	extern oid neIpScalars_oid[];
	
	DEBUGMSGTL (("neInetMIB", "Initializing\n"));
	
	/* register neInetScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"neInetScalars_mapper", &neInetScalars_mapper,
			neInetScalars_oid, OID_LENGTH (neInetScalars_oid),
			HANDLER_CAN_RWRITE
		),
		NEINETFORWARDINGENABLE,
		NEINETFORWARDINGENABLE
	);
	
	/* register neIpScalars scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"neIpScalars_mapper", &neIpScalars_mapper,
			neIpScalars_oid, OID_LENGTH (neIpScalars_oid),
			HANDLER_CAN_RWRITE
		),
		NEIPASN,
		NEIPROUTERID
	);
	
	
	/* register neInetMIB group table mappers */
	neInetInterfaceTable_init ();
	neInetIntRouteTable_init ();
	neInetRouteTable_init ();
	neIpAddressTable_init ();
	neIpUnNumTable_init ();
	neIpAsNodeTable_init ();
	
	/* register neInetMIB modules */
	sysORTable_createRegister ("neInetMIB", neInetMIB_oid, OID_LENGTH (neInetMIB_oid));
}


/**
 *	scalar mapper(s)
 */
neInetScalars_t oNeInetScalars;

/** neInetScalars scalar mapper **/
int
neInetScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid neInetScalars_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (neInetScalars_oid)])
			{
			case NEINETFORWARDINGENABLE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) oNeInetScalars.au8ForwardingEnable, oNeInetScalars.u16ForwardingEnable_len);
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
			switch (request->requestvb->name[OID_LENGTH (neInetScalars_oid)])
			{
			case NEINETFORWARDINGENABLE:
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
			switch (request->requestvb->name[OID_LENGTH (neInetScalars_oid)])
			{
			case NEINETFORWARDINGENABLE:
				/* XXX: perform the value change here */
				memset (oNeInetScalars.au8ForwardingEnable, 0, sizeof (oNeInetScalars.au8ForwardingEnable));
				memcpy (oNeInetScalars.au8ForwardingEnable, request->requestvb->val.string, request->requestvb->val_len);
				oNeInetScalars.u16ForwardingEnable_len = request->requestvb->val_len;
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
			switch (request->requestvb->name[OID_LENGTH (neInetScalars_oid)])
			{
			case NEINETFORWARDINGENABLE:
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

neIpScalars_t oNeIpScalars;

/** neIpScalars scalar mapper **/
int
neIpScalars_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	extern oid neIpScalars_oid[];
	netsnmp_request_info *request;
	int ret;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (neIpScalars_oid)])
			{
			case NEIPASN:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeIpScalars.u32Asn);
				break;
			case NEIPROUTERID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, oNeIpScalars.u32RouterId);
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
			switch (request->requestvb->name[OID_LENGTH (neIpScalars_oid)])
			{
			case NEIPASN:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, requests, ret);
				}
				break;
			case NEIPROUTERID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
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
			switch (request->requestvb->name[OID_LENGTH (neIpScalars_oid)])
			{
			case NEIPASN:
				/* XXX: perform the value change here */
				oNeIpScalars.u32Asn = *request->requestvb->val.integer;
				if (/* TODO: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					netsnmp_set_request_error (reqinfo, requests, /* some error */ TOBE_REPLACED);
				}
				break;
			case NEIPROUTERID:
				/* XXX: perform the value change here */
				oNeIpScalars.u32RouterId = *request->requestvb->val.integer;
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
			switch (request->requestvb->name[OID_LENGTH (neIpScalars_oid)])
			{
			case NEIPASN:
				/* XXX: UNDO and return to previous value for the object */
				if (/* XXX: error? */ TOBE_REPLACED != TOBE_REPLACED)
				{
					/* try _really_really_ hard to never get to this point */
					netsnmp_set_request_error (reqinfo, requests, SNMP_ERR_UNDOFAILED);
				}
				break;
			case NEIPROUTERID:
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
/** initialize neInetInterfaceTable table mapper **/
void
neInetInterfaceTable_init (void)
{
	extern oid neInetInterfaceTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neInetInterfaceTable", &neInetInterfaceTable_mapper,
		neInetInterfaceTable_oid, OID_LENGTH (neInetInterfaceTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = NEINETINTERFACETRAFFICENABLE;
	table_info->max_column = NEINETINTERFACEFORWARDINGENABLE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neInetInterfaceTable_getFirst;
	iinfo->get_next_data_point = &neInetInterfaceTable_getNext;
	iinfo->get_data_point = &neInetInterfaceTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neInetInterfaceTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neInetInterfaceEntry_t *pEntry1 = xBTree_entry (pNode1, neInetInterfaceEntry_t, oBTreeNode);
	register neInetInterfaceEntry_t *pEntry2 = xBTree_entry (pNode2, neInetInterfaceEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oNeInetInterfaceTable_BTree = xBTree_initInline (&neInetInterfaceTable_BTreeNodeCmp);

/* create a new row in the table */
neInetInterfaceEntry_t *
neInetInterfaceTable_createEntry (
	uint32_t u32IfIndex)
{
	register neInetInterfaceEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetInterfaceTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32TrafficEnable = neInetInterfaceTrafficEnable_true_c;
	/*poEntry->au8ForwardingEnable = neInetInterfaceForwardingEnable_{ ipv4 , ipv6 , clnp }_c*/;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeInetInterfaceTable_BTree);
	return poEntry;
}

neInetInterfaceEntry_t *
neInetInterfaceTable_getByIndex (
	uint32_t u32IfIndex)
{
	register neInetInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeInetInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetInterfaceEntry_t, oBTreeNode);
}

neInetInterfaceEntry_t *
neInetInterfaceTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register neInetInterfaceEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeInetInterfaceTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetInterfaceEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neInetInterfaceTable_removeEntry (neInetInterfaceEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetInterfaceTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeInetInterfaceTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

neInetInterfaceEntry_t *
neInetInterfaceTable_createExt (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	bool bUnNumAddr)
{
	neInetInterfaceEntry_t *poEntry = NULL;
	
	if (!ifData_getByIndexExt (u32IfIndex, false, NULL))
	{
		return NULL;
	}
	
	if ((poEntry = neInetInterfaceTable_getByIndex (u32IfIndex)) == NULL &&
		(poEntry = neInetInterfaceTable_createEntry (u32IfIndex)) == NULL)
	{
		return NULL;
	}
	
	if (!neInetInterfaceTable_createHier (poEntry, i32AddrType, pau8Addr, u16Addr_len))
	{
		neInetInterfaceTable_removeEntry (poEntry);
		return NULL;
	}
	
	if (bUnNumAddr)
	{
		switch (i32AddrType)
		{
		case ipAddressAddrType_ipv4_c:
			poEntry->u32NumIpv4UnNumAddresses++;
			oIp.u32NumIpv4UnNumAddresses++;
			break;
		case ipAddressAddrType_ipv6_c:
			poEntry->u32NumIpv6UnNumAddresses++;
			oIp.u32NumIpv6UnNumAddresses++;
			break;
		case ipAddressAddrType_ipv4z_c:
			poEntry->u32NumIpv4zUnNumAddresses++;
			oIp.u32NumIpv4zUnNumAddresses++;
			break;
		case ipAddressAddrType_ipv6z_c:
			poEntry->u32NumIpv6zUnNumAddresses++;
			oIp.u32NumIpv6zUnNumAddresses++;
			break;
		}
	}
	else
	{
		switch (i32AddrType)
		{
		case ipAddressAddrType_ipv4_c:
			poEntry->u32NumIpv4Addresses++;
			oIp.u32NumIpv4Addresses++;
			break;
		case ipAddressAddrType_ipv6_c:
			poEntry->u32NumIpv6Addresses++;
			oIp.u32NumIpv6Addresses++;
			break;
		case ipAddressAddrType_ipv4z_c:
			poEntry->u32NumIpv4zAddresses++;
			oIp.u32NumIpv4zAddresses++;
			break;
		case ipAddressAddrType_ipv6z_c:
			poEntry->u32NumIpv6zAddresses++;
			oIp.u32NumIpv6zAddresses++;
			break;
		}
	}
	
	return poEntry;
}

bool
neInetInterfaceTable_removeExt (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	bool bUnNumAddr)
{
	if (bUnNumAddr)
	{
		switch (i32AddrType)
		{
		case ipAddressAddrType_ipv4_c:
			poEntry->u32NumIpv4UnNumAddresses--;
			oIp.u32NumIpv4UnNumAddresses--;
			break;
		case ipAddressAddrType_ipv6_c:
			poEntry->u32NumIpv6UnNumAddresses--;
			oIp.u32NumIpv6UnNumAddresses--;
			break;
		case ipAddressAddrType_ipv4z_c:
			poEntry->u32NumIpv4zUnNumAddresses--;
			oIp.u32NumIpv4zUnNumAddresses--;
			break;
		case ipAddressAddrType_ipv6z_c:
			poEntry->u32NumIpv6zUnNumAddresses--;
			oIp.u32NumIpv6zUnNumAddresses--;
			break;
		}
	}
	else
	{
		switch (i32AddrType)
		{
		case ipAddressAddrType_ipv4_c:
			poEntry->u32NumIpv4Addresses--;
			oIp.u32NumIpv4Addresses--;
			break;
		case ipAddressAddrType_ipv4z_c:
			poEntry->u32NumIpv4zAddresses--;
			oIp.u32NumIpv4zAddresses--;
			break;
		case ipAddressAddrType_ipv6_c:
			poEntry->u32NumIpv6Addresses--;
			oIp.u32NumIpv6Addresses--;
			break;
		case ipAddressAddrType_ipv6z_c:
			poEntry->u32NumIpv6zAddresses--;
			oIp.u32NumIpv6zAddresses--;
			break;
		}
	}
	
	if (!neInetInterfaceTable_removeHier (poEntry, i32AddrType, pau8Addr, u16Addr_len))
	{
		return false;
	}
	
	if (poEntry->u32NumIpv4Addresses == 0 && poEntry->u32NumIpv4zAddresses == 0 && poEntry->u32NumIpv4UnNumAddresses == 0 && poEntry->u32NumIpv4zUnNumAddresses == 0 &&
		poEntry->u32NumIpv6Addresses == 0 && poEntry->u32NumIpv6zAddresses == 0 && poEntry->u32NumIpv6UnNumAddresses == 0 && poEntry->u32NumIpv6zUnNumAddresses == 0)
	{
		neInetInterfaceTable_removeEntry (poEntry);
	}
	
	return true;
}

bool
neInetInterfaceTable_createHier (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register uint8_t u8InetVersion = 0;
	register ipv4InterfaceEntry_t *poIpv4InterfaceEntry = NULL;
	register ipv6InterfaceEntry_t *poIpv6InterfaceEntry = NULL;
	register ipSystemStatsEntry_t *poIpSystemStatsEntry = NULL;
	register ipIfStatsEntry_t *poIpIfStatsEntry = NULL;
	register ipv6ScopeZoneIndexEntry_t *poIpv6ScopeZoneIndexEntry = NULL;
	
	
	u8InetVersion =
		i32AddrType == ipAddressAddrType_ipv4_c || i32AddrType == ipAddressAddrType_ipv4z_c ? InetVersion_ipv4_c:
		i32AddrType == ipAddressAddrType_ipv6_c || i32AddrType == ipAddressAddrType_ipv6z_c ? InetVersion_ipv6_c: InetVersion_unknown_c;
		
	if (u8InetVersion == InetVersion_ipv4_c)
	{
		if ((poIpv4InterfaceEntry = ipv4InterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL &&
			(poIpv4InterfaceEntry = ipv4InterfaceTable_createEntry (poEntry->u32IfIndex)) == NULL)
		{
			goto neInetInterfaceTable_createHier_cleanup;
		}
	}
	else if (u8InetVersion == InetVersion_ipv6_c)
	{
		if ((poIpv6InterfaceEntry = ipv6InterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL &&
			(poIpv6InterfaceEntry = ipv6InterfaceTable_createEntry (poEntry->u32IfIndex)) == NULL)
		{
			goto neInetInterfaceTable_createHier_cleanup;
		}
	}
	
	
	if ((poIpSystemStatsEntry = ipSystemStatsTable_getByIndex (u8InetVersion)) == NULL &&
		(poIpSystemStatsEntry = ipSystemStatsTable_createEntry (u8InetVersion)) == NULL)
	{
		goto neInetInterfaceTable_createHier_cleanup;
	}
	
	if ((poIpIfStatsEntry = ipIfStatsTable_getByIndex (u8InetVersion, poEntry->u32IfIndex)) == NULL &&
		(poIpIfStatsEntry = ipIfStatsTable_createEntry (u8InetVersion, poEntry->u32IfIndex)) == NULL)
	{
		goto neInetInterfaceTable_createHier_cleanup;
	}
	
	if (u8InetVersion == InetVersion_ipv6_c)
	{
		if ((poIpv6ScopeZoneIndexEntry = ipv6ScopeZoneIndexTable_getByIndex (poEntry->u32IfIndex)) == NULL &&
			(poIpv6ScopeZoneIndexEntry = ipv6ScopeZoneIndexTable_createEntry (poEntry->u32IfIndex)) == NULL)
		{
			goto neInetInterfaceTable_createHier_cleanup;
		}
	}
	
	return true;
	
	
neInetInterfaceTable_createHier_cleanup:
	
	neInetInterfaceTable_removeHier (poEntry, i32AddrType, pau8Addr, u16Addr_len);
	return false;
}

bool
neInetInterfaceTable_removeHier (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len)
{
	register uint8_t u8InetVersion = 0;
	register ipv4InterfaceEntry_t *poIpv4InterfaceEntry = NULL;
	register ipv6InterfaceEntry_t *poIpv6InterfaceEntry = NULL;
	register ipSystemStatsEntry_t *poIpSystemStatsEntry = NULL;
	register ipIfStatsEntry_t *poIpIfStatsEntry = NULL;
	register ipv6ScopeZoneIndexEntry_t *poIpv6ScopeZoneIndexEntry = NULL;
	
	
	u8InetVersion =
		i32AddrType == ipAddressAddrType_ipv4_c || i32AddrType == ipAddressAddrType_ipv4z_c ? InetVersion_ipv4_c:
		i32AddrType == ipAddressAddrType_ipv6_c || i32AddrType == ipAddressAddrType_ipv6z_c ? InetVersion_ipv6_c: InetVersion_unknown_c;
		
	if (u8InetVersion == InetVersion_ipv4_c)
	{
		if ((poIpv4InterfaceEntry = ipv4InterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL)
		{
			return false;
		}
	}
	else if (u8InetVersion == InetVersion_ipv6_c)
	{
		if ((poIpv6InterfaceEntry = ipv6InterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL)
		{
			return false;
		}
	}
	
	
	if (u8InetVersion == InetVersion_ipv6_c &&
		poEntry->u32NumIpv6Addresses == 0 && poEntry->u32NumIpv6zAddresses == 0 && poEntry->u32NumIpv6UnNumAddresses == 0 && poEntry->u32NumIpv6zUnNumAddresses == 0)
	{
		if ((poIpv6ScopeZoneIndexEntry = ipv6ScopeZoneIndexTable_getByIndex (poEntry->u32IfIndex)) != NULL)
		{
			ipv6ScopeZoneIndexTable_removeEntry (poIpv6ScopeZoneIndexEntry);
		}
	}
	
	if ((u8InetVersion == InetVersion_ipv4_c &&
		 poEntry->u32NumIpv4Addresses == 0 && poEntry->u32NumIpv4zAddresses == 0 && poEntry->u32NumIpv4UnNumAddresses == 0 && poEntry->u32NumIpv4zUnNumAddresses == 0) ||
		(u8InetVersion == InetVersion_ipv6_c &&
		 poEntry->u32NumIpv6Addresses == 0 && poEntry->u32NumIpv6zAddresses == 0 && poEntry->u32NumIpv6UnNumAddresses == 0 && poEntry->u32NumIpv6zUnNumAddresses == 0))
	{
		if ((poIpIfStatsEntry = ipIfStatsTable_getByIndex (u8InetVersion, poEntry->u32IfIndex)) == NULL)
		{
			ipIfStatsTable_removeEntry (poIpIfStatsEntry);
		}
	}
	
	if ((u8InetVersion == InetVersion_ipv4_c &&
		 oIp.u32NumIpv4Addresses == 0 && oIp.u32NumIpv4zAddresses == 0 && oIp.u32NumIpv4UnNumAddresses == 0 && oIp.u32NumIpv4zUnNumAddresses == 0) ||
		(u8InetVersion == InetVersion_ipv6_c &&
		 oIp.u32NumIpv6Addresses == 0 && oIp.u32NumIpv6zAddresses == 0 && oIp.u32NumIpv6UnNumAddresses == 0 && oIp.u32NumIpv6zUnNumAddresses == 0))
	{
		if ((poIpSystemStatsEntry = ipSystemStatsTable_getByIndex (u8InetVersion)) != NULL)
		{
			ipSystemStatsTable_removeEntry (poIpSystemStatsEntry);
		}
	}
	
	if (u8InetVersion == InetVersion_ipv4_c &&
		poEntry->u32NumIpv4Addresses == 0 && poEntry->u32NumIpv4zAddresses == 0 && poEntry->u32NumIpv4UnNumAddresses == 0 && poEntry->u32NumIpv4zUnNumAddresses == 0)
	{
		ipv4InterfaceTable_removeEntry (poIpv4InterfaceEntry);
	}
	else if (
		u8InetVersion == InetVersion_ipv6_c &&
		poEntry->u32NumIpv6Addresses == 0 && poEntry->u32NumIpv6zAddresses == 0 && poEntry->u32NumIpv6UnNumAddresses == 0 && poEntry->u32NumIpv6zUnNumAddresses == 0)
	{
		ipv6InterfaceTable_removeEntry (poIpv6InterfaceEntry);
	}
	
	return true;
}

bool
neInetInterfaceTrafficEnable_handler (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32TrafficEnable)
{
	if (i32TrafficEnable != neInetInterfaceTrafficEnable_true_c &&
		i32TrafficEnable != neInetInterfaceTrafficEnable_false_c)
	{
		goto neInetInterfaceTrafficEnable_handler_cleanup;
	}
	
	if (poEntry->i32TrafficEnable == i32TrafficEnable)
	{
		goto neInetInterfaceTrafficEnable_handler_success;
	}
	
	/*if (!ieee8021BridgeTpPortTable_handler (poEntry->u32IfIndex, i32TrafficEnable != neInetInterfaceTrafficEnable_true_c))
	{
		goto neInetInterfaceTrafficEnable_handler_cleanup;
	}*/
	
neInetInterfaceTrafficEnable_handler_success:
	
	poEntry->i32TrafficEnable = i32TrafficEnable;
	return true;
	
	
neInetInterfaceTrafficEnable_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neInetInterfaceTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeInetInterfaceTable_BTree);
	return neInetInterfaceTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neInetInterfaceTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetInterfaceEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neInetInterfaceEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeInetInterfaceTable_BTree);
	return put_index_data;
}

bool
neInetInterfaceTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetInterfaceEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neInetInterfaceTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neInetInterfaceTable table mapper */
int
neInetInterfaceTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neInetInterfaceEntry_t *table_entry;
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
			table_entry = (neInetInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEINETINTERFACETRAFFICENABLE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32TrafficEnable);
				break;
			case NEINETINTERFACEFORWARDINGENABLE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForwardingEnable, table_entry->u16ForwardingEnable_len);
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
			table_entry = (neInetInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEINETINTERFACETRAFFICENABLE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEINETINTERFACEFORWARDINGENABLE:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ForwardingEnable));
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
			table_entry = (neInetInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				return SNMP_ERR_NOERROR;
			}
		}
		break;
		
	case MODE_SET_FREE:
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neInetInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEINETINTERFACETRAFFICENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32TrafficEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32TrafficEnable, sizeof (table_entry->i32TrafficEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32TrafficEnable = *request->requestvb->val.integer;
				break;
			case NEINETINTERFACEFORWARDINGENABLE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ForwardingEnable))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForwardingEnable_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ForwardingEnable, sizeof (table_entry->au8ForwardingEnable));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ForwardingEnable, 0, sizeof (table_entry->au8ForwardingEnable));
				memcpy (table_entry->au8ForwardingEnable, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForwardingEnable_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neInetInterfaceEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEINETINTERFACETRAFFICENABLE:
				memcpy (&table_entry->i32TrafficEnable, pvOldDdata, sizeof (table_entry->i32TrafficEnable));
				break;
			case NEINETINTERFACEFORWARDINGENABLE:
				memcpy (table_entry->au8ForwardingEnable, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForwardingEnable_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neInetIntRouteTable table mapper **/
void
neInetIntRouteTable_init (void)
{
	extern oid neInetIntRouteTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neInetIntRouteTable", &neInetIntRouteTable_mapper,
		neInetIntRouteTable_oid, OID_LENGTH (neInetIntRouteTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: neInetIntRouteDest */,
		ASN_UNSIGNED /* index: neInetIntRouteDestPrefixLen */,
		ASN_UNSIGNED /* index: neInetIntRouteIndex */,
		ASN_OCTET_STR /* index: neInetIntRouteNextHop */,
		ASN_INTEGER /* index: neInetIntRouteIfIndex */,
		ASN_INTEGER /* index: neInetIntRouteProto */,
		0);
	table_info->min_column = NEINETINTROUTEPOLICY;
	table_info->max_column = NEINETINTROUTESTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neInetIntRouteTable_getFirst;
	iinfo->get_next_data_point = &neInetIntRouteTable_getNext;
	iinfo->get_data_point = &neInetIntRouteTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neInetIntRouteTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neInetIntRouteEntry_t *pEntry1 = xBTree_entry (pNode1, neInetIntRouteEntry_t, oBTreeNode);
	register neInetIntRouteEntry_t *pEntry2 = xBTree_entry (pNode2, neInetIntRouteEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == -1) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen < pEntry2->u32DestPrefixLen) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index < pEntry2->u32Index) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == -1) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0 && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0 && pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Proto < pEntry2->i32Proto) ? -1:
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0 && pEntry1->u32IfIndex == pEntry2->u32IfIndex && pEntry1->i32Proto == pEntry2->i32Proto) ? 0: 1;
}

xBTree_t oNeInetIntRouteTable_BTree = xBTree_initInline (&neInetIntRouteTable_BTreeNodeCmp);

/* create a new row in the table */
neInetIntRouteEntry_t *
neInetIntRouteTable_createEntry (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto)
{
	register neInetIntRouteEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Dest, pau8Dest, u16Dest_len);
	poEntry->u16Dest_len = u16Dest_len;
	poEntry->u32DestPrefixLen = u32DestPrefixLen;
	poEntry->u32Index = u32Index;
	memcpy (poEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poEntry->u16NextHop_len = u16NextHop_len;
	poEntry->u32IfIndex = u32IfIndex;
	poEntry->i32Proto = i32Proto;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetIntRouteTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeInetIntRouteTable_BTree);
	return poEntry;
}

neInetIntRouteEntry_t *
neInetIntRouteTable_getByIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto)
{
	register neInetIntRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32Proto = i32Proto;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeInetIntRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetIntRouteEntry_t, oBTreeNode);
}

neInetIntRouteEntry_t *
neInetIntRouteTable_getNextIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto)
{
	register neInetIntRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	poTmpEntry->i32Proto = i32Proto;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeInetIntRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetIntRouteEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neInetIntRouteTable_removeEntry (neInetIntRouteEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetIntRouteTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeInetIntRouteTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neInetIntRouteTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeInetIntRouteTable_BTree);
	return neInetIntRouteTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neInetIntRouteTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetIntRouteEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neInetIntRouteEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Dest, poEntry->u16Dest_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32DestPrefixLen);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8NextHop, poEntry->u16NextHop_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Proto);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeInetIntRouteTable_BTree);
	return put_index_data;
}

bool
neInetIntRouteTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetIntRouteEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	register netsnmp_variable_list *idx6 = idx5->next_variable;
	
	poEntry = neInetIntRouteTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		*idx2->val.integer,
		*idx3->val.integer,
		(void*) idx4->val.string, idx4->val_len,
		*idx5->val.integer,
		*idx6->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neInetIntRouteTable table mapper */
int
neInetIntRouteTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neInetIntRouteEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neInetIntRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEINETINTROUTEPOLICY:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoPolicy, table_entry->u16Policy_len);
				break;
			case NEINETINTROUTESTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8State, table_entry->u16State_len);
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

/** initialize neInetRouteTable table mapper **/
void
neInetRouteTable_init (void)
{
	extern oid neInetRouteTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neInetRouteTable", &neInetRouteTable_mapper,
		neInetRouteTable_oid, OID_LENGTH (neInetRouteTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_OCTET_STR /* index: neInetRouteDest */,
		ASN_UNSIGNED /* index: neInetRouteDestPrefixLen */,
		ASN_UNSIGNED /* index: neInetRouteIndex */,
		ASN_OCTET_STR /* index: neInetRouteNextHop */,
		ASN_INTEGER /* index: neInetRouteIfIndex */,
		0);
	table_info->min_column = NEINETROUTEPOLICY;
	table_info->max_column = NEINETROUTESTATE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neInetRouteTable_getFirst;
	iinfo->get_next_data_point = &neInetRouteTable_getNext;
	iinfo->get_data_point = &neInetRouteTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neInetRouteTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neInetRouteEntry_t *pEntry1 = xBTree_entry (pNode1, neInetRouteEntry_t, oBTreeNode);
	register neInetRouteEntry_t *pEntry2 = xBTree_entry (pNode2, neInetRouteEntry_t, oBTreeNode);
	
	return
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == -1) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen < pEntry2->u32DestPrefixLen) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index < pEntry2->u32Index) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == -1) ||
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0 && pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(xBinCmp (pEntry1->au8Dest, pEntry2->au8Dest, pEntry1->u16Dest_len, pEntry2->u16Dest_len) == 0 && pEntry1->u32DestPrefixLen == pEntry2->u32DestPrefixLen && pEntry1->u32Index == pEntry2->u32Index && xBinCmp (pEntry1->au8NextHop, pEntry2->au8NextHop, pEntry1->u16NextHop_len, pEntry2->u16NextHop_len) == 0 && pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

xBTree_t oNeInetRouteTable_BTree = xBTree_initInline (&neInetRouteTable_BTreeNodeCmp);

/* create a new row in the table */
neInetRouteEntry_t *
neInetRouteTable_createEntry (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex)
{
	register neInetRouteEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poEntry->au8Dest, pau8Dest, u16Dest_len);
	poEntry->u16Dest_len = u16Dest_len;
	poEntry->u32DestPrefixLen = u32DestPrefixLen;
	poEntry->u32Index = u32Index;
	memcpy (poEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poEntry->u16NextHop_len = u16NextHop_len;
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetRouteTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeInetRouteTable_BTree);
	return poEntry;
}

neInetRouteEntry_t *
neInetRouteTable_getByIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex)
{
	register neInetRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeInetRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetRouteEntry_t, oBTreeNode);
}

neInetRouteEntry_t *
neInetRouteTable_getNextIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex)
{
	register neInetRouteEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	memcpy (poTmpEntry->au8Dest, pau8Dest, u16Dest_len);
	poTmpEntry->u16Dest_len = u16Dest_len;
	poTmpEntry->u32DestPrefixLen = u32DestPrefixLen;
	poTmpEntry->u32Index = u32Index;
	memcpy (poTmpEntry->au8NextHop, pau8NextHop, u16NextHop_len);
	poTmpEntry->u16NextHop_len = u16NextHop_len;
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeInetRouteTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neInetRouteEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neInetRouteTable_removeEntry (neInetRouteEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeInetRouteTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeInetRouteTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neInetRouteTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeInetRouteTable_BTree);
	return neInetRouteTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neInetRouteTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetRouteEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neInetRouteEntry_t, oBTreeNode);
	
	snmp_set_var_value (idx, poEntry->au8Dest, poEntry->u16Dest_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32DestPrefixLen);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8NextHop, poEntry->u16NextHop_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeInetRouteTable_BTree);
	return put_index_data;
}

bool
neInetRouteTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neInetRouteEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	register netsnmp_variable_list *idx5 = idx4->next_variable;
	
	poEntry = neInetRouteTable_getByIndex (
		(void*) idx1->val.string, idx1->val_len,
		*idx2->val.integer,
		*idx3->val.integer,
		(void*) idx4->val.string, idx4->val_len,
		*idx5->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neInetRouteTable table mapper */
int
neInetRouteTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neInetRouteEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neInetRouteEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEINETROUTEPOLICY:
				snmp_set_var_typed_value (request->requestvb, ASN_OBJECT_ID, (u_char*) table_entry->aoPolicy, table_entry->u16Policy_len);
				break;
			case NEINETROUTESTATE:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8State, table_entry->u16State_len);
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

/** initialize neIpAddressTable table mapper **/
void
neIpAddressTable_init (void)
{
	extern oid neIpAddressTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIpAddressTable", &neIpAddressTable_mapper,
		neIpAddressTable_oid, OID_LENGTH (neIpAddressTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ipAddressAddrType */,
		ASN_OCTET_STR /* index: ipAddressAddr */,
		0);
	table_info->min_column = NEIPADDRESSPREFIXLENGTH;
	table_info->max_column = NEIPADDRESSPREFIXLENGTH;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIpAddressTable_getFirst;
	iinfo->get_next_data_point = &neIpAddressTable_getNext;
	iinfo->get_data_point = &neIpAddressTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
neIpAddressEntry_t *
neIpAddressTable_createEntry (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len)
{
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_getByIndex (i32IpAddressAddrType, pau8IpAddressAddr, u16IpAddressAddr_len)) == NULL ||
		xBitmap_getBit (poIpAddressData->au8Flags, ipAddressFlags_neCreated_c))
	{
		return NULL;
	}
	
	xBitmap_setBit (poIpAddressData->au8Flags, ipAddressFlags_neCreated_c, 1);
	return &poIpAddressData->oNe;
}

neIpAddressEntry_t *
neIpAddressTable_getByIndex (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len)
{
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_getByIndex (i32IpAddressAddrType, pau8IpAddressAddr, u16IpAddressAddr_len)) == NULL ||
		!xBitmap_getBit (poIpAddressData->au8Flags, ipAddressFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poIpAddressData->oNe;
}

neIpAddressEntry_t *
neIpAddressTable_getNextIndex (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len)
{
	register ipAddressData_t *poIpAddressData = NULL;
	
	if ((poIpAddressData = ipAddressData_getNextIndex (i32IpAddressAddrType, pau8IpAddressAddr, u16IpAddressAddr_len)) == NULL ||
		!xBitmap_getBit (poIpAddressData->au8Flags, ipAddressFlags_neCreated_c))
	{
		return NULL;
	}
	
	return &poIpAddressData->oNe;
}

/* remove a row from the table */
void
neIpAddressTable_removeEntry (neIpAddressEntry_t *poEntry)
{
	if (poEntry == NULL)
	{
		return;
	}
	
	register ipAddressData_t *poIpAddressData = ipAddressData_getByNeEntry (poEntry);
	
	xBitmap_setBit (poIpAddressData->au8Flags, ipAddressFlags_neCreated_c, 0);
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIpAddressTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIpAddressData_BTree);
	return neIpAddressTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIpAddressTable_getNext (
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
neIpAddressTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIpAddressEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = neIpAddressTable_getByIndex (
		*idx1->val.integer,
		(void*) idx2->val.string, idx2->val_len);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIpAddressTable table mapper */
int
neIpAddressTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIpAddressEntry_t *table_entry;
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
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PrefixLength);
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
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
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
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			default:
				if (table_entry == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
			
			register ipAddressData_t *poIpAddressData = ipAddressData_getByNeEntry (table_entry);
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
				if (poIpAddressData->oIp.u8RowStatus == xRowStatus_active_c || poIpAddressData->oIp.u8RowStatus == xRowStatus_notReady_c)
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
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
				break;
			}
		}
		break;
		
	case MODE_SET_ACTION:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PrefixLength))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PrefixLength, sizeof (table_entry->u32PrefixLength));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PrefixLength = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (neIpAddressEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPADDRESSPREFIXLENGTH:
				if (pvOldDdata == table_entry)
				{
				}
				else
				{
					memcpy (&table_entry->u32PrefixLength, pvOldDdata, sizeof (table_entry->u32PrefixLength));
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

/** initialize neIpUnNumTable table mapper **/
void
neIpUnNumTable_init (void)
{
	extern oid neIpUnNumTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIpUnNumTable", &neIpUnNumTable_mapper,
		neIpUnNumTable_oid, OID_LENGTH (neIpUnNumTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_INTEGER /* index: ifIndex */,
		0);
	table_info->min_column = NEIPUNNUMADDRESSTYPE;
	table_info->max_column = NEIPUNNUMSTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIpUnNumTable_getFirst;
	iinfo->get_next_data_point = &neIpUnNumTable_getNext;
	iinfo->get_data_point = &neIpUnNumTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIpUnNumTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIpUnNumEntry_t *pEntry1 = xBTree_entry (pNode1, neIpUnNumEntry_t, oBTreeNode);
	register neIpUnNumEntry_t *pEntry2 = xBTree_entry (pNode2, neIpUnNumEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32IfIndex < pEntry2->u32IfIndex) ? -1:
		(pEntry1->u32IfIndex == pEntry2->u32IfIndex) ? 0: 1;
}

static int8_t
neIpUnNumTable_LocalId_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIpUnNumEntry_t *pEntry1 = xBTree_entry (pNode1, neIpUnNumEntry_t, oLocalId_BTreeNode);
	register neIpUnNumEntry_t *pEntry2 = xBTree_entry (pNode2, neIpUnNumEntry_t, oLocalId_BTreeNode);
	
	return
		(pEntry1->u32LocalId < pEntry2->u32LocalId) ? -1:
		(pEntry1->u32LocalId == pEntry2->u32LocalId) ? 0: 1;
}

static int8_t
neIpUnNumTable_RemoteId_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIpUnNumEntry_t *pEntry1 = xBTree_entry (pNode1, neIpUnNumEntry_t, oRemoteId_BTreeNode);
	register neIpUnNumEntry_t *pEntry2 = xBTree_entry (pNode2, neIpUnNumEntry_t, oRemoteId_BTreeNode);
	
	return
		(pEntry1->u32RemoteId < pEntry2->u32RemoteId) ||
		(pEntry1->u32RemoteId == pEntry2->u32RemoteId && pEntry1->i32AddressType < pEntry2->i32AddressType) ||
		(pEntry1->u32RemoteId == pEntry2->u32RemoteId && pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == -1) ? -1:
		(pEntry1->u32RemoteId == pEntry2->u32RemoteId && pEntry1->i32AddressType == pEntry2->i32AddressType && xBinCmp (pEntry1->au8RemoteAddress, pEntry2->au8RemoteAddress, pEntry1->u16RemoteAddress_len, pEntry2->u16RemoteAddress_len) == 0) ? 0: 1;
}

xBTree_t oNeIpUnNumTable_BTree = xBTree_initInline (&neIpUnNumTable_BTreeNodeCmp);
xBTree_t oNeIpUnNumTable_LocalId_BTree = xBTree_initInline (&neIpUnNumTable_LocalId_BTreeNodeCmp);
xBTree_t oNeIpUnNumTable_RemoteId_BTree = xBTree_initInline (&neIpUnNumTable_RemoteId_BTreeNodeCmp);

/* create a new row in the table */
neIpUnNumEntry_t *
neIpUnNumTable_createEntry (
	uint32_t u32IfIndex)
{
	register neIpUnNumEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32IfIndex = u32IfIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIpUnNumTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AddressType = neIpUnNumAddressType_ipv4_c;
	poEntry->u32NumberedIfIndex = 0;
	poEntry->u32RemoteId = 0;
	/*poEntry->au8DestPhysAddress = 0*/;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neIpUnNumStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIpUnNumTable_BTree);
	return poEntry;
}

neIpUnNumEntry_t *
neIpUnNumTable_getByIndex (
	uint32_t u32IfIndex)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIpUnNumTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oBTreeNode);
}

neIpUnNumEntry_t *
neIpUnNumTable_getNextIndex (
	uint32_t u32IfIndex)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32IfIndex = u32IfIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIpUnNumTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oBTreeNode);
}

neIpUnNumEntry_t *
neIpUnNumTable_LocalId_getByIndex (
	uint32_t u32LocalId)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (neIpUnNumEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LocalId = u32LocalId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIpUnNumTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oBTreeNode);
}

neIpUnNumEntry_t *
neIpUnNumTable_LocalId_getNextIndex (
	uint32_t u32LocalId)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (neIpUnNumEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32LocalId = u32LocalId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIpUnNumTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oBTreeNode);
}

neIpUnNumEntry_t *
neIpUnNumTable_RemoteId_getByIndex (
	uint32_t u32RemoteId,
	int32_t i32AddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (neIpUnNumEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32RemoteId = u32RemoteId;
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8RemoteAddress, pau8RemoteAddress, u16RemoteAddress_len);
	poTmpEntry->u16RemoteAddress_len = u16RemoteAddress_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oRemoteId_BTreeNode, &oNeIpUnNumTable_RemoteId_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oRemoteId_BTreeNode);
}

neIpUnNumEntry_t *
neIpUnNumTable_RemoteId_getNextIndex (
	uint32_t u32RemoteId,
	int32_t i32AddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len)
{
	register neIpUnNumEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (neIpUnNumEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32RemoteId = u32RemoteId;
	poTmpEntry->i32AddressType = i32AddressType;
	memcpy (poTmpEntry->au8RemoteAddress, pau8RemoteAddress, u16RemoteAddress_len);
	poTmpEntry->u16RemoteAddress_len = u16RemoteAddress_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oRemoteId_BTreeNode, &oNeIpUnNumTable_RemoteId_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpUnNumEntry_t, oRemoteId_BTreeNode);
}

/* remove a row from the table */
void
neIpUnNumTable_removeEntry (neIpUnNumEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIpUnNumTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIpUnNumTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

neIpUnNumEntry_t *
neIpUnNumTable_createExt (
	uint32_t u32IfIndex)
{
	neIpUnNumEntry_t *poEntry = NULL;
	
	if (!ifData_getByIndexExt (u32IfIndex, false, NULL))
	{
		goto neIpUnNumTable_createExt_cleanup;
	}
	
	poEntry = neIpUnNumTable_createEntry (
		u32IfIndex);
	if (poEntry == NULL)
	{
		goto neIpUnNumTable_createExt_cleanup;
	}
	
neIpUnNumTable_createExt_cleanup:
	
	return poEntry;
}

bool
neIpUnNumTable_removeExt (neIpUnNumEntry_t *poEntry)
{
	neIpUnNumTable_removeEntry (poEntry);
	
	return true;
}

bool
neIpUnNumTable_createHier (
	neIpUnNumEntry_t *poEntry)
{
	register ipAddressData_t *poIpAddressData = NULL;
	register neInetInterfaceEntry_t *poNeInetInterfaceEntry = NULL;
	
	if (poEntry->u32LocalId == 0)
	{
		goto neIpUnNumTable_createHier_cleanup;
	}
	
	if ((poIpAddressData = ipAddressData_getByIndex (poEntry->i32AddressType, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len)) == NULL)
	{
		goto neIpUnNumTable_createHier_cleanup;
	}
	
	if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL &&
		(poNeInetInterfaceEntry = neInetInterfaceTable_createExt (poEntry->u32IfIndex, poEntry->i32AddressType, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len, true)) == NULL)
	{
		goto neIpUnNumTable_createHier_cleanup;
	}
	
	poEntry->u32NumberedIfIndex = poIpAddressData->u32IfIndex;
	poIpAddressData->u32NumUnNumAddresses++;
	
	xBTree_nodeAdd (&poEntry->oLocalId_BTreeNode, &oNeIpUnNumTable_LocalId_BTree);
	return true;
	
	
neIpUnNumTable_createHier_cleanup:
	
	neIpUnNumTable_removeHier (poEntry);
	return false;
}

bool
neIpUnNumTable_removeHier (
	neIpUnNumEntry_t *poEntry)
{
	register ipAddressData_t *poIpAddressData = NULL;
	register neInetInterfaceEntry_t *poNeInetInterfaceEntry = NULL;
	
	if ((poNeInetInterfaceEntry = neInetInterfaceTable_getByIndex (poEntry->u32IfIndex)) == NULL)
	{
		goto neIpUnNumTable_removeHier_cleanup;
	}
	
	neInetInterfaceTable_removeExt (poNeInetInterfaceEntry, poEntry->i32AddressType, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len, true);
	
	if ((poIpAddressData = ipAddressData_getByIndex (poEntry->i32AddressType, poEntry->au8LocalAddress, poEntry->u16LocalAddress_len)) == NULL)
	{
		goto neIpUnNumTable_removeHier_cleanup;
	}
	
	poEntry->u32NumberedIfIndex = 0;
	poIpAddressData->u32NumUnNumAddresses--;
	
	xBTree_nodeRemove (&poEntry->oLocalId_BTreeNode, &oNeIpUnNumTable_LocalId_BTree);
	return true;
	
	
neIpUnNumTable_removeHier_cleanup:
	
	return false;
}

bool
neIpUnNumRowStatus_handler (
	neIpUnNumEntry_t *poEntry,
	int32_t u8RowStatus)
{
	if (!ifData_getByIndexExt (poEntry->u32IfIndex, false, NULL))
	{
		goto neIpUnNumRowStatus_handler_cleanup;
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (poEntry->u8RowStatus == xRowStatus_active_c)
		{
			goto neIpUnNumRowStatus_handler_success;
		}
		
		if (!neIpUnNumTable_createHier (poEntry))
		{
			goto neIpUnNumRowStatus_handler_cleanup;
		}
		
		/* TODO */
		poEntry->u8RowStatus = xRowStatus_active_c;
		break;
		
	case xRowStatus_notInService_c:
		if (poEntry->u8RowStatus != xRowStatus_active_c)
		{
			goto neIpUnNumRowStatus_handler_success;
		}
		
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
		if (!neIpUnNumTable_removeHier (poEntry))
		{
			goto neIpUnNumRowStatus_handler_cleanup;
		}
		
		/* TODO */
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
neIpUnNumRowStatus_handler_success:
	
	return true;
	
	
neIpUnNumRowStatus_handler_cleanup:
	
	return false;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIpUnNumTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIpUnNumTable_BTree);
	return neIpUnNumTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIpUnNumTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIpUnNumEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIpUnNumEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32IfIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIpUnNumTable_BTree);
	return put_index_data;
}

bool
neIpUnNumTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIpUnNumEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = neIpUnNumTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* neIpUnNumTable table mapper */
int
neIpUnNumTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIpUnNumEntry_t *table_entry;
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMADDRESSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AddressType);
				break;
			case NEIPUNNUMNUMBEREDIFINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32NumberedIfIndex);
				break;
			case NEIPUNNUMLOCALADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8LocalAddress, table_entry->u16LocalAddress_len);
				break;
			case NEIPUNNUMREMOTEADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8RemoteAddress, table_entry->u16RemoteAddress_len);
				break;
			case NEIPUNNUMLOCALID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32LocalId);
				break;
			case NEIPUNNUMREMOTEID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32RemoteId);
				break;
			case NEIPUNNUMDESTPHYSADDRESS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8DestPhysAddress, table_entry->u16DestPhysAddress_len);
				break;
			case NEIPUNNUMROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEIPUNNUMSTORAGETYPE:
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMADDRESSTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMLOCALADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8LocalAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMREMOTEADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8RemoteAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMLOCALID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMREMOTEID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMDESTPHYSADDRESS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8DestPhysAddress));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPUNNUMSTORAGETYPE:
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_WRONGVALUE);
					return SNMP_ERR_NOERROR;
					
				case RS_CREATEANDWAIT:
					table_entry = neIpUnNumTable_createExt (
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
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMADDRESSTYPE:
			case NEIPUNNUMLOCALADDRESS:
			case NEIPUNNUMREMOTEADDRESS:
			case NEIPUNNUMLOCALID:
			case NEIPUNNUMREMOTEID:
			case NEIPUNNUMDESTPHYSADDRESS:
			case NEIPUNNUMSTORAGETYPE:
				if (table_entry->u8RowStatus == xRowStatus_active_c || table_entry->u8RowStatus == xRowStatus_notReady_c)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIpUnNumTable_removeExt (table_entry);
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMADDRESSTYPE:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AddressType))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AddressType, sizeof (table_entry->i32AddressType));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AddressType = *request->requestvb->val.integer;
				break;
			case NEIPUNNUMLOCALADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8LocalAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16LocalAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8LocalAddress, sizeof (table_entry->au8LocalAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8LocalAddress, 0, sizeof (table_entry->au8LocalAddress));
				memcpy (table_entry->au8LocalAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16LocalAddress_len = request->requestvb->val_len;
				break;
			case NEIPUNNUMREMOTEADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8RemoteAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16RemoteAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8RemoteAddress, sizeof (table_entry->au8RemoteAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8RemoteAddress, 0, sizeof (table_entry->au8RemoteAddress));
				memcpy (table_entry->au8RemoteAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16RemoteAddress_len = request->requestvb->val_len;
				break;
			case NEIPUNNUMLOCALID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LocalId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LocalId, sizeof (table_entry->u32LocalId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LocalId = *request->requestvb->val.integer;
				break;
			case NEIPUNNUMREMOTEID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RemoteId))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RemoteId, sizeof (table_entry->u32RemoteId));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RemoteId = *request->requestvb->val.integer;
				break;
			case NEIPUNNUMDESTPHYSADDRESS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8DestPhysAddress))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16DestPhysAddress_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8DestPhysAddress, sizeof (table_entry->au8DestPhysAddress));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8DestPhysAddress, 0, sizeof (table_entry->au8DestPhysAddress));
				memcpy (table_entry->au8DestPhysAddress, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16DestPhysAddress_len = request->requestvb->val_len;
				break;
			case NEIPUNNUMSTORAGETYPE:
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!neIpUnNumRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMADDRESSTYPE:
				memcpy (&table_entry->i32AddressType, pvOldDdata, sizeof (table_entry->i32AddressType));
				break;
			case NEIPUNNUMLOCALADDRESS:
				memcpy (table_entry->au8LocalAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16LocalAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEIPUNNUMREMOTEADDRESS:
				memcpy (table_entry->au8RemoteAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16RemoteAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEIPUNNUMLOCALID:
				memcpy (&table_entry->u32LocalId, pvOldDdata, sizeof (table_entry->u32LocalId));
				break;
			case NEIPUNNUMREMOTEID:
				memcpy (&table_entry->u32RemoteId, pvOldDdata, sizeof (table_entry->u32RemoteId));
				break;
			case NEIPUNNUMDESTPHYSADDRESS:
				memcpy (table_entry->au8DestPhysAddress, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16DestPhysAddress_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case NEIPUNNUMROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIpUnNumTable_removeExt (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEIPUNNUMSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neIpUnNumEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPUNNUMROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					neIpUnNumTable_removeExt (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize neIpAsNodeTable table mapper **/
void
neIpAsNodeTable_init (void)
{
	extern oid neIpAsNodeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"neIpAsNodeTable", &neIpAsNodeTable_mapper,
		neIpAsNodeTable_oid, OID_LENGTH (neIpAsNodeTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: neIpAsNodeAsn */,
		ASN_INTEGER /* index: neIpAsNodeAddrType */,
		ASN_OCTET_STR /* index: neIpAsNodeAddr */,
		ASN_UNSIGNED /* index: neIpAsNodeAddrPrefixLen */,
		0);
	table_info->min_column = NEIPASNODEROUTERID;
	table_info->max_column = NEIPASNODESTORAGETYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &neIpAsNodeTable_getFirst;
	iinfo->get_next_data_point = &neIpAsNodeTable_getNext;
	iinfo->get_data_point = &neIpAsNodeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
neIpAsNodeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIpAsNodeEntry_t *pEntry1 = xBTree_entry (pNode1, neIpAsNodeEntry_t, oBTreeNode);
	register neIpAsNodeEntry_t *pEntry2 = xBTree_entry (pNode2, neIpAsNodeEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32Asn < pEntry2->u32Asn) ||
		(pEntry1->u32Asn == pEntry2->u32Asn && pEntry1->i32AddrType < pEntry2->i32AddrType) ||
		(pEntry1->u32Asn == pEntry2->u32Asn && pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == -1) ||
		(pEntry1->u32Asn == pEntry2->u32Asn && pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0 && pEntry1->u32AddrPrefixLen < pEntry2->u32AddrPrefixLen) ? -1:
		(pEntry1->u32Asn == pEntry2->u32Asn && pEntry1->i32AddrType == pEntry2->i32AddrType && xBinCmp (pEntry1->au8Addr, pEntry2->au8Addr, pEntry1->u16Addr_len, pEntry2->u16Addr_len) == 0 && pEntry1->u32AddrPrefixLen == pEntry2->u32AddrPrefixLen) ? 0: 1;
}

xBTree_t oNeIpAsNodeTable_BTree = xBTree_initInline (&neIpAsNodeTable_BTreeNodeCmp);

/* create a new row in the table */
neIpAsNodeEntry_t *
neIpAsNodeTable_createEntry (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen)
{
	register neIpAsNodeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32Asn = u32Asn;
	poEntry->i32AddrType = i32AddrType;
	memcpy (poEntry->au8Addr, pau8Addr, u16Addr_len);
	poEntry->u16Addr_len = u16Addr_len;
	poEntry->u32AddrPrefixLen = u32AddrPrefixLen;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIpAsNodeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u8StorageType = neIpAsNodeStorageType_volatile_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIpAsNodeTable_BTree);
	return poEntry;
}

neIpAsNodeEntry_t *
neIpAsNodeTable_getByIndex (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen)
{
	register neIpAsNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Asn = u32Asn;
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	poTmpEntry->u32AddrPrefixLen = u32AddrPrefixLen;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIpAsNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpAsNodeEntry_t, oBTreeNode);
}

neIpAsNodeEntry_t *
neIpAsNodeTable_getNextIndex (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen)
{
	register neIpAsNodeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Asn = u32Asn;
	poTmpEntry->i32AddrType = i32AddrType;
	memcpy (poTmpEntry->au8Addr, pau8Addr, u16Addr_len);
	poTmpEntry->u16Addr_len = u16Addr_len;
	poTmpEntry->u32AddrPrefixLen = u32AddrPrefixLen;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oNeIpAsNodeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIpAsNodeEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
neIpAsNodeTable_removeEntry (neIpAsNodeEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIpAsNodeTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIpAsNodeTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
neIpAsNodeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oNeIpAsNodeTable_BTree);
	return neIpAsNodeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
neIpAsNodeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIpAsNodeEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, neIpAsNodeEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Asn);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32AddrType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Addr, poEntry->u16Addr_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32AddrPrefixLen);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oNeIpAsNodeTable_BTree);
	return put_index_data;
}

bool
neIpAsNodeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	neIpAsNodeEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = neIpAsNodeTable_getByIndex (
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

/* neIpAsNodeTable table mapper */
int
neIpAsNodeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	neIpAsNodeEntry_t *table_entry;
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROUTERID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32RouterId);
				break;
			case NEIPASNODEINFO:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Info, table_entry->u16Info_len);
				break;
			case NEIPASNODEROWSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RowStatus);
				break;
			case NEIPASNODESTORAGETYPE:
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
				ret = netsnmp_check_vb_rowstatus (request->requestvb, (table_entry ? RS_ACTIVE : RS_NONEXISTENT));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case NEIPASNODESTORAGETYPE:
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = neIpAsNodeTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						(void*) idx3->val.string, idx3->val_len,
						*idx4->val.integer);
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIpAsNodeTable_removeEntry (table_entry);
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPASNODESTORAGETYPE:
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int neIpAsNodeTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					neIpAsNodeTable_removeEntry (table_entry);
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
				}
				break;
			case NEIPASNODESTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (neIpAsNodeEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case NEIPASNODEROWSTATUS:
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
					neIpAsNodeTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
