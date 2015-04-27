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
#include "ethernetUtils.h"
#include "ieee8021BridgeMib.h"
#include "ieee8021QBridgeMib.h"

#include "system_ext.h"

#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define ROLLBACK_BUFFER "ROLLBACK_BUFFER"



static oid ieee8021QBridgeMib_oid[] = {1,3,111,2,802,1,1,4};

static oid ieee8021QBridgeVlan_oid[] = {1,3,111,2,802,1,1,4,1,4};

static oid ieee8021QBridgeTable_oid[] = {1,3,111,2,802,1,1,4,1,1,1};
static oid ieee8021QBridgeCVlanPortTable_oid[] = {1,3,111,2,802,1,1,4,1,1,2};
static oid ieee8021QBridgeFdbTable_oid[] = {1,3,111,2,802,1,1,4,1,2,1};
static oid ieee8021QBridgeTpFdbTable_oid[] = {1,3,111,2,802,1,1,4,1,2,2};
static oid ieee8021QBridgeTpGroupTable_oid[] = {1,3,111,2,802,1,1,4,1,2,3};
static oid ieee8021QBridgeForwardAllTable_oid[] = {1,3,111,2,802,1,1,4,1,2,4};
static oid ieee8021QBridgeForwardUnregisteredTable_oid[] = {1,3,111,2,802,1,1,4,1,2,5};
static oid ieee8021QBridgeStaticUnicastTable_oid[] = {1,3,111,2,802,1,1,4,1,3,1};
static oid ieee8021QBridgeStaticMulticastTable_oid[] = {1,3,111,2,802,1,1,4,1,3,2};
static oid ieee8021QBridgeVlanCurrentTable_oid[] = {1,3,111,2,802,1,1,4,1,4,2};
static oid ieee8021QBridgeVlanStaticTable_oid[] = {1,3,111,2,802,1,1,4,1,4,3};
static oid ieee8021QBridgeNextFreeLocalVlanTable_oid[] = {1,3,111,2,802,1,1,4,1,4,4};
static oid ieee8021QBridgePortTable_oid[] = {1,3,111,2,802,1,1,4,1,4,5};
static oid ieee8021QBridgePortVlanStatisticsTable_oid[] = {1,3,111,2,802,1,1,4,1,4,6};
static oid ieee8021QBridgeLearningConstraintsTable_oid[] = {1,3,111,2,802,1,1,4,1,4,8};
static oid ieee8021QBridgeLearningConstraintDefaultsTable_oid[] = {1,3,111,2,802,1,1,4,1,4,9};
static oid ieee8021QBridgeProtocolGroupTable_oid[] = {1,3,111,2,802,1,1,4,1,5,1};
static oid ieee8021QBridgeProtocolPortTable_oid[] = {1,3,111,2,802,1,1,4,1,5,2};
static oid ieee8021QBridgeIngressVidXTable_oid[] = {1,3,111,2,802,1,1,4,1,6,1};
static oid ieee8021QBridgeEgressVidXTable_oid[] = {1,3,111,2,802,1,1,4,1,6,2};



/**
 *	initialize ieee8021QBridgeMib group mapper
 */
void
ieee8021QBridgeMib_init (void)
{
	extern oid ieee8021QBridgeMib_oid[];
	extern oid ieee8021QBridgeVlan_oid[];
	
	DEBUGMSGTL (("ieee8021QBridgeMib", "Initializing\n"));
	
	/* register ieee8021QBridgeVlan scalar mapper */
	netsnmp_register_scalar_group (
		netsnmp_create_handler_registration (
			"ieee8021QBridgeVlan_mapper", &ieee8021QBridgeVlan_mapper,
			ieee8021QBridgeVlan_oid, OID_LENGTH (ieee8021QBridgeVlan_oid),
			HANDLER_CAN_RONLY
		),
		IEEE8021QBRIDGEVLANNUMDELETES,
		IEEE8021QBRIDGEVLANNUMDELETES
	);
	
	
	/* register ieee8021QBridgeMib group table mappers */
	ieee8021QBridgeTable_init ();
	ieee8021QBridgeCVlanPortTable_init ();
	ieee8021QBridgeFdbTable_init ();
	ieee8021QBridgeTpFdbTable_init ();
	ieee8021QBridgeTpGroupTable_init ();
	ieee8021QBridgeForwardAllTable_init ();
	ieee8021QBridgeForwardUnregisteredTable_init ();
	ieee8021QBridgeStaticUnicastTable_init ();
	ieee8021QBridgeStaticMulticastTable_init ();
	ieee8021QBridgeVlanCurrentTable_init ();
	ieee8021QBridgeVlanStaticTable_init ();
	ieee8021QBridgeNextFreeLocalVlanTable_init ();
	ieee8021QBridgePortTable_init ();
	ieee8021QBridgePortVlanStatisticsTable_init ();
	ieee8021QBridgeLearningConstraintsTable_init ();
	ieee8021QBridgeLearningConstraintDefaultsTable_init ();
	ieee8021QBridgeProtocolGroupTable_init ();
	ieee8021QBridgeProtocolPortTable_init ();
	ieee8021QBridgeIngressVidXTable_init ();
	ieee8021QBridgeEgressVidXTable_init ();
	
	/* register ieee8021QBridgeMib modules */
	sysORTable_createRegister ("ieee8021QBridgeMib", ieee8021QBridgeMib_oid, OID_LENGTH (ieee8021QBridgeMib_oid));
}


/**
 *	scalar mapper(s)
 */
ieee8021QBridgeVlan_t oIeee8021QBridgeVlan;

/** ieee8021QBridgeVlan scalar mapper **/
int
ieee8021QBridgeVlan_mapper (netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info   *reqinfo,
	netsnmp_request_info         *requests)
{
	extern oid ieee8021QBridgeVlan_oid[];
	netsnmp_request_info *request;
	/* We are never called for a GETNEXT if it's registered as a
	   "group instance", as it's "magically" handled for us. */
	
	switch (reqinfo->mode)
	{
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			switch (request->requestvb->name[OID_LENGTH (ieee8021QBridgeVlan_oid) - 1])
			{
			case IEEE8021QBRIDGEVLANNUMDELETES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, oIeee8021QBridgeVlan.u64NumDeletes);
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
/** initialize ieee8021QBridgeTable table mapper **/
void
ieee8021QBridgeTable_init (void)
{
	extern oid ieee8021QBridgeTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeTable", &ieee8021QBridgeTable_mapper,
		ieee8021QBridgeTable_oid, OID_LENGTH (ieee8021QBridgeTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeComponentId */,
		0);
	table_info->min_column = IEEE8021QBRIDGEVLANVERSIONNUMBER;
	table_info->max_column = IEEE8021QBRIDGEMVRPENABLEDSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
ieee8021QBridgeEntry_t *
ieee8021QBridgeTable_createEntry (
	uint32_t u32ComponentId)
{
	register ieee8021QBridgeEntry_t *poEntry = NULL;
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poComponent->oQ;
	
	poEntry->i32VlanVersionNumber = ieee8021QBridgeVlanVersionNumber_version2_c;
	poEntry->u32MaxVlanId = 4095;
	poEntry->u32MaxSupportedVlans = 4095;
	poEntry->u8MvrpEnabledStatus = ieee8021QBridgeMvrpEnabledStatus_true_c;
	
	return poEntry;
}

ieee8021QBridgeEntry_t *
ieee8021QBridgeTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oQ;
}

ieee8021QBridgeEntry_t *
ieee8021QBridgeTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getNextIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oQ;
}

/* remove a row from the table */
void
ieee8021QBridgeTable_removeEntry (ieee8021QBridgeEntry_t *poEntry)
{
	return;
}

ieee8021QBridgeEntry_t *
ieee8021QBridgeTable_createExt (
	uint32_t u32ComponentId)
{
	ieee8021QBridgeEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgeTable_createEntry (
		u32ComponentId);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021QBridgeTable_createHier (poEntry))
	{
		ieee8021QBridgeTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021QBridgeTable_removeExt (ieee8021QBridgeEntry_t *poEntry)
{
	if (!ieee8021QBridgeTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeTable_createHier (
	ieee8021QBridgeEntry_t *poEntry)
{
	register ieee8021BridgeBaseEntry_t *poComponent = ieee8021BridgeBaseTable_getByQEntry (poEntry);
	register ieee8021QBridgeNextFreeLocalVlanEntry_t *poIeee8021QBridgeNextFreeLocalVlanEntry = NULL;
	register ieee8021QBridgeLearningConstraintDefaultsEntry_t *poIeee8021QBridgeLearningConstraintDefaultsEntry = NULL;
	
	if ((poIeee8021QBridgeNextFreeLocalVlanEntry = ieee8021QBridgeNextFreeLocalVlanTable_getByIndex (poComponent->u32ComponentId)) == NULL &&
		(poIeee8021QBridgeNextFreeLocalVlanEntry = ieee8021QBridgeNextFreeLocalVlanTable_createEntry (poComponent->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeTable_createHier_cleanup;
	}
	
	if ((poIeee8021QBridgeLearningConstraintDefaultsEntry = ieee8021QBridgeLearningConstraintDefaultsTable_getByIndex (poComponent->u32ComponentId)) == NULL &&
		(poIeee8021QBridgeLearningConstraintDefaultsEntry = ieee8021QBridgeLearningConstraintDefaultsTable_createEntry (poComponent->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeTable_createHier_cleanup;
	}
	
	return true;
	
	
ieee8021QBridgeTable_createHier_cleanup:
	
	ieee8021QBridgeTable_removeHier (poEntry);
	return false;
}

bool
ieee8021QBridgeTable_removeHier (
	ieee8021QBridgeEntry_t *poEntry)
{
	register ieee8021BridgeBaseEntry_t *poComponent = ieee8021BridgeBaseTable_getByQEntry (poEntry);
	
	{
		uint32_t u32FdbId = 0;
		uint8_t au8Address[6] = {0};
		size_t u16Address_len = 0;
		register ieee8021QBridgeTpFdbEntry_t *poIeee8021QBridgeTpFdbEntry = NULL;
		
		while ((poIeee8021QBridgeTpFdbEntry = ieee8021QBridgeTpFdbTable_getNextIndex (poComponent->u32ComponentId, u32FdbId, au8Address, u16Address_len)) != NULL &&
			poIeee8021QBridgeTpFdbEntry->u32FdbComponentId == poComponent->u32ComponentId)
		{
			u32FdbId = poIeee8021QBridgeTpFdbEntry->u32FdbId;
			memcpy (au8Address, poIeee8021QBridgeTpFdbEntry->au8Address, sizeof (au8Address));
			u16Address_len = poIeee8021QBridgeTpFdbEntry->u16Address_len;
			ieee8021QBridgeTpFdbTable_removeEntry (poIeee8021QBridgeTpFdbEntry);
		}
	}
	
	{
		uint32_t u32Id = 0;
		register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
		
		while ((poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getNextIndex (poComponent->u32ComponentId, u32Id)) != NULL &&
			poIeee8021QBridgeFdbEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32Id = poIeee8021QBridgeFdbEntry->u32Id;
			ieee8021QBridgeFdbTable_removeEntry (poIeee8021QBridgeFdbEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		uint8_t au8Address[6] = {0};
		size_t u16Address_len = 0;
		register ieee8021QBridgeTpGroupEntry_t *poIeee8021QBridgeTpGroupEntry = NULL;
		
		while ((poIeee8021QBridgeTpGroupEntry = ieee8021QBridgeTpGroupTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex, au8Address, u16Address_len)) != NULL &&
			poIeee8021QBridgeTpGroupEntry->u32VlanCurrentComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeTpGroupEntry->u32VlanIndex;
			memcpy (au8Address, poIeee8021QBridgeTpGroupEntry->au8Address, sizeof (au8Address));
			u16Address_len = poIeee8021QBridgeTpGroupEntry->u16Address_len;
			ieee8021QBridgeTpGroupTable_removeEntry (poIeee8021QBridgeTpGroupEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		register ieee8021QBridgeForwardAllEntry_t *poIeee8021QBridgeForwardAllEntry = NULL;
		
		while ((poIeee8021QBridgeForwardAllEntry = ieee8021QBridgeForwardAllTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex)) != NULL &&
			poIeee8021QBridgeForwardAllEntry->u32VlanCurrentComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeForwardAllEntry->u32VlanIndex;
			ieee8021QBridgeForwardAllTable_removeEntry (poIeee8021QBridgeForwardAllEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		register ieee8021QBridgeForwardUnregisteredEntry_t *poIeee8021QBridgeForwardUnregisteredEntry = NULL;
		
		while ((poIeee8021QBridgeForwardUnregisteredEntry = ieee8021QBridgeForwardUnregisteredTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex)) != NULL &&
			poIeee8021QBridgeForwardUnregisteredEntry->u32VlanCurrentComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeForwardUnregisteredEntry->u32VlanIndex;
			ieee8021QBridgeForwardUnregisteredTable_removeEntry (poIeee8021QBridgeForwardUnregisteredEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		uint8_t au8Address[6] = {0};
		size_t u16Address_len = 0;
		uint32_t u32ReceivePort = 0;
		register ieee8021QBridgeStaticUnicastEntry_t *poIeee8021QBridgeStaticUnicastEntry = NULL;
		
		while ((poIeee8021QBridgeStaticUnicastEntry = ieee8021QBridgeStaticUnicastTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex, au8Address, u16Address_len, u32ReceivePort)) != NULL &&
			poIeee8021QBridgeStaticUnicastEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeStaticUnicastEntry->u32VlanIndex;
			memcpy (au8Address, poIeee8021QBridgeStaticUnicastEntry->au8Address, sizeof (au8Address));
			u16Address_len = poIeee8021QBridgeStaticUnicastEntry->u16Address_len;
			u32ReceivePort = poIeee8021QBridgeStaticUnicastEntry->u32ReceivePort;
			ieee8021QBridgeStaticUnicastTable_removeEntry (poIeee8021QBridgeStaticUnicastEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		uint8_t au8Address[6] = {0};
		size_t u16Address_len = 0;
		uint32_t u32ReceivePort = 0;
		register ieee8021QBridgeStaticMulticastEntry_t *poIeee8021QBridgeStaticMulticastEntry = NULL;
		
		while ((poIeee8021QBridgeStaticMulticastEntry = ieee8021QBridgeStaticMulticastTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex, au8Address, u16Address_len, u32ReceivePort)) != NULL &&
			poIeee8021QBridgeStaticMulticastEntry->u32VlanCurrentComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeStaticMulticastEntry->u32VlanIndex;
			memcpy (au8Address, poIeee8021QBridgeStaticMulticastEntry->au8Address, sizeof (au8Address));
			u16Address_len = poIeee8021QBridgeStaticMulticastEntry->u16Address_len;
			u32ReceivePort = poIeee8021QBridgeStaticMulticastEntry->u32ReceivePort;
			ieee8021QBridgeStaticMulticastTable_removeEntry (poIeee8021QBridgeStaticMulticastEntry);
		}
	}
	
	{
		uint32_t u32BridgeBasePort = 0;
		int32_t i32GroupId = 0;
		register ieee8021QBridgeProtocolPortEntry_t *poIeee8021QBridgeProtocolPortEntry = NULL;
		
		while ((poIeee8021QBridgeProtocolPortEntry = ieee8021QBridgeProtocolPortTable_getNextIndex (poComponent->u32ComponentId, u32BridgeBasePort, i32GroupId)) != NULL &&
			poIeee8021QBridgeProtocolPortEntry->u32BridgeBasePortComponentId == poComponent->u32ComponentId)
		{
			u32BridgeBasePort = poIeee8021QBridgeProtocolPortEntry->u32BridgeBasePort;
			i32GroupId = poIeee8021QBridgeProtocolPortEntry->i32GroupId;
			ieee8021QBridgeProtocolPortTable_removeEntry (poIeee8021QBridgeProtocolPortEntry);
		}
	}
	
	{
		int32_t i32TemplateFrameType = 0;
		uint8_t au8TemplateProtocolValue[5] = {0};
		size_t u16TemplateProtocolValue_len = 0;
		register ieee8021QBridgeProtocolGroupEntry_t *poIeee8021QBridgeProtocolGroupEntry = NULL;
		
		while ((poIeee8021QBridgeProtocolGroupEntry = ieee8021QBridgeProtocolGroupTable_getNextIndex (poComponent->u32ComponentId, i32TemplateFrameType, au8TemplateProtocolValue, u16TemplateProtocolValue_len)) != NULL &&
			poIeee8021QBridgeProtocolGroupEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			i32TemplateFrameType = poIeee8021QBridgeProtocolGroupEntry->i32TemplateFrameType;
			memcpy (au8TemplateProtocolValue, poIeee8021QBridgeProtocolGroupEntry->au8TemplateProtocolValue, sizeof (au8TemplateProtocolValue));
			u16TemplateProtocolValue_len = poIeee8021QBridgeProtocolGroupEntry->u16TemplateProtocolValue_len;
			ieee8021QBridgeProtocolGroupTable_removeEntry (poIeee8021QBridgeProtocolGroupEntry);
		}
	}
	
	{
		uint32_t u32BridgeBasePort = 0;
		uint32_t u32LocalVid = 0;
		register ieee8021QBridgeIngressVidXEntry_t *poIeee8021QBridgeIngressVidXEntry = NULL;
		
		while ((poIeee8021QBridgeIngressVidXEntry = ieee8021QBridgeIngressVidXTable_getNextIndex (poComponent->u32ComponentId, u32BridgeBasePort, u32LocalVid)) != NULL &&
			poIeee8021QBridgeIngressVidXEntry->u32BridgeBasePortComponentId == poComponent->u32ComponentId)
		{
			u32BridgeBasePort = poIeee8021QBridgeIngressVidXEntry->u32BridgeBasePort;
			u32LocalVid = poIeee8021QBridgeIngressVidXEntry->u32LocalVid;
			ieee8021QBridgeIngressVidXTable_removeEntry (poIeee8021QBridgeIngressVidXEntry);
		}
	}
	
	{
		uint32_t u32BridgeBasePort = 0;
		uint32_t u32RelayVid = 0;
		register ieee8021QBridgeEgressVidXEntry_t *poIeee8021QBridgeEgressVidXEntry = NULL;
		
		while ((poIeee8021QBridgeEgressVidXEntry = ieee8021QBridgeEgressVidXTable_getNextIndex (poComponent->u32ComponentId, u32BridgeBasePort, u32RelayVid)) != NULL &&
			poIeee8021QBridgeEgressVidXEntry->u32BridgeBaseComponentId == poComponent->u32ComponentId)
		{
			u32BridgeBasePort = poIeee8021QBridgeEgressVidXEntry->u32BridgeBasePort;
			u32RelayVid = poIeee8021QBridgeEgressVidXEntry->u32RelayVid;
			ieee8021QBridgeEgressVidXTable_removeEntry (poIeee8021QBridgeEgressVidXEntry);
		}
	}
	
	{
		uint32_t u32Number = 0;
		register ieee8021QBridgeCVlanPortEntry_t *poIeee8021QBridgeCVlanPortEntry = NULL;
		
		while ((poIeee8021QBridgeCVlanPortEntry = ieee8021QBridgeCVlanPortTable_getNextIndex (poComponent->u32ComponentId, u32Number)) != NULL &&
			poIeee8021QBridgeCVlanPortEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32Number = poIeee8021QBridgeCVlanPortEntry->u32Number;
			ieee8021QBridgeCVlanPortTable_removeEntry (poIeee8021QBridgeCVlanPortEntry);
		}
	}
	
	{
		uint32_t u32Vlan = 0;
		int32_t i32Set = 0;
		register ieee8021QBridgeLearningConstraintsEntry_t *poIeee8021QBridgeLearningConstraintsEntry = NULL;
		
		while ((poIeee8021QBridgeLearningConstraintsEntry = ieee8021QBridgeLearningConstraintsTable_getNextIndex (poComponent->u32ComponentId, u32Vlan, i32Set)) != NULL &&
			poIeee8021QBridgeLearningConstraintsEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32Vlan = poIeee8021QBridgeLearningConstraintsEntry->u32Vlan;
			i32Set = poIeee8021QBridgeLearningConstraintsEntry->i32Set;
			ieee8021QBridgeLearningConstraintsTable_removeEntry (poIeee8021QBridgeLearningConstraintsEntry);
		}
	}
	
	{
		register ieee8021QBridgeLearningConstraintDefaultsEntry_t *poIeee8021QBridgeLearningConstraintDefaultsEntry = NULL;
		
		if ((poIeee8021QBridgeLearningConstraintDefaultsEntry = ieee8021QBridgeLearningConstraintDefaultsTable_getNextIndex (poComponent->u32ComponentId)) != NULL)
		{
			ieee8021QBridgeLearningConstraintDefaultsTable_removeEntry (poIeee8021QBridgeLearningConstraintDefaultsEntry);
		}
	}
	
	{
		uint32_t u32BridgeBasePort = 0;
		uint32_t u32VlanIndex = 0;
		register ieee8021QBridgePortVlanStatisticsEntry_t *poIeee8021QBridgePortVlanStatisticsEntry = NULL;
		
		while ((poIeee8021QBridgePortVlanStatisticsEntry = ieee8021QBridgePortVlanStatisticsTable_getNextIndex (poComponent->u32ComponentId, u32BridgeBasePort, u32VlanIndex)) != NULL &&
			poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePortComponentId == poComponent->u32ComponentId)
		{
			u32BridgeBasePort = poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePort;
			u32VlanIndex = poIeee8021QBridgePortVlanStatisticsEntry->u32VlanIndex;
			ieee8021QBridgePortVlanStatisticsTable_removeEntry (poIeee8021QBridgePortVlanStatisticsEntry);
		}
	}
	
	{
		uint32_t u32BridgeBasePort = 0;
		register ieee8021QBridgePortEntry_t *poIeee8021QBridgePortEntry = NULL;
		
		while ((poIeee8021QBridgePortEntry = ieee8021QBridgePortTable_getNextIndex (poComponent->u32ComponentId, u32BridgeBasePort)) != NULL &&
			poIeee8021QBridgePortEntry->u32BridgeBasePortComponentId == poComponent->u32ComponentId)
		{
			u32BridgeBasePort = poIeee8021QBridgePortEntry->u32BridgeBasePort;
			ieee8021QBridgePortTable_removeEntry (poIeee8021QBridgePortEntry);
		}
	}
	
	{
		uint32_t u32Index = 0;
		register ieee8021QBridgeVlanCurrentEntry_t *poIeee8021QBridgeVlanCurrentEntry = NULL;
		
		while ((poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_Vlan_getNextIndex (poComponent->u32ComponentId, u32Index)) != NULL &&
			poIeee8021QBridgeVlanCurrentEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32Index = poIeee8021QBridgeVlanCurrentEntry->u32Index;
			ieee8021QBridgeVlanCurrentTable_removeEntry (poIeee8021QBridgeVlanCurrentEntry);
		}
	}
	
	{
		uint32_t u32VlanIndex = 0;
		register ieee8021QBridgeVlanStaticEntry_t *poIeee8021QBridgeVlanStaticEntry = NULL;
		
		while ((poIeee8021QBridgeVlanStaticEntry = ieee8021QBridgeVlanStaticTable_getNextIndex (poComponent->u32ComponentId, u32VlanIndex)) != NULL &&
			poIeee8021QBridgeVlanStaticEntry->u32ComponentId == poComponent->u32ComponentId)
		{
			u32VlanIndex = poIeee8021QBridgeVlanStaticEntry->u32VlanIndex;
			ieee8021QBridgeVlanStaticTable_removeEntry (poIeee8021QBridgeVlanStaticEntry);
		}
	}
	
	{
		register ieee8021QBridgeNextFreeLocalVlanEntry_t *poIeee8021QBridgeNextFreeLocalVlanEntry = NULL;
		
		if ((poIeee8021QBridgeNextFreeLocalVlanEntry = ieee8021QBridgeNextFreeLocalVlanTable_getByIndex (poComponent->u32ComponentId)) != NULL)
		{
			ieee8021QBridgeNextFreeLocalVlanTable_removeEntry (poIeee8021QBridgeNextFreeLocalVlanEntry);
		}
	}
	
	return true;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBaseTable_BTree);
	return ieee8021QBridgeTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021BridgeBaseEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBaseTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021BridgeBaseTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeTable table mapper */
int
ieee8021QBridgeTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeEntry_t *table_entry;
	register ieee8021BridgeBaseEntry_t *poEntry = NULL;
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oQ;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANVERSIONNUMBER:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32VlanVersionNumber);
				break;
			case IEEE8021QBRIDGEMAXVLANID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32MaxVlanId);
				break;
			case IEEE8021QBRIDGEMAXSUPPORTEDVLANS:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32MaxSupportedVlans);
				break;
			case IEEE8021QBRIDGENUMVLANS:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32NumVlans);
				break;
			case IEEE8021QBRIDGEMVRPENABLEDSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8MvrpEnabledStatus);
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oQ;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEMVRPENABLEDSTATUS:
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			if (poEntry == NULL)
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oQ;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEMVRPENABLEDSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8MvrpEnabledStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8MvrpEnabledStatus, sizeof (table_entry->u8MvrpEnabledStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8MvrpEnabledStatus = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oQ;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEMVRPENABLEDSTATUS:
				memcpy (&table_entry->u8MvrpEnabledStatus, pvOldDdata, sizeof (table_entry->u8MvrpEnabledStatus));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeCVlanPortTable table mapper **/
void
ieee8021QBridgeCVlanPortTable_init (void)
{
	extern oid ieee8021QBridgeCVlanPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeCVlanPortTable", &ieee8021QBridgeCVlanPortTable_mapper,
		ieee8021QBridgeCVlanPortTable_oid, OID_LENGTH (ieee8021QBridgeCVlanPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeCVlanPortComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeCVlanPortNumber */,
		0);
	table_info->min_column = IEEE8021QBRIDGECVLANPORTROWSTATUS;
	table_info->max_column = IEEE8021QBRIDGECVLANPORTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeCVlanPortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeCVlanPortTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeCVlanPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeCVlanPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeCVlanPortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeCVlanPortEntry_t, oBTreeNode);
	register ieee8021QBridgeCVlanPortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeCVlanPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Number < pEntry2->u32Number) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Number == pEntry2->u32Number) ? 0: 1;
}

xBTree_t oIeee8021QBridgeCVlanPortTable_BTree = xBTree_initInline (&ieee8021QBridgeCVlanPortTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeCVlanPortEntry_t *
ieee8021QBridgeCVlanPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Number)
{
	register ieee8021QBridgeCVlanPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Number = u32Number;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree);
	return poEntry;
}

ieee8021QBridgeCVlanPortEntry_t *
ieee8021QBridgeCVlanPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Number)
{
	register ieee8021QBridgeCVlanPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Number = u32Number;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeCVlanPortEntry_t, oBTreeNode);
}

ieee8021QBridgeCVlanPortEntry_t *
ieee8021QBridgeCVlanPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Number)
{
	register ieee8021QBridgeCVlanPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Number = u32Number;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeCVlanPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeCVlanPortTable_removeEntry (ieee8021QBridgeCVlanPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgeCVlanPortEntry_t *
ieee8021QBridgeCVlanPortTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Number)
{
	ieee8021QBridgeCVlanPortEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgeCVlanPortTable_createEntry (
		u32ComponentId,
		u32Number);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021QBridgeCVlanPortTable_createHier (poEntry))
	{
		ieee8021QBridgeCVlanPortTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021QBridgeCVlanPortTable_removeExt (ieee8021QBridgeCVlanPortEntry_t *poEntry)
{
	if (!ieee8021QBridgeCVlanPortTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeCVlanPortTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeCVlanPortTable_createHier (
	ieee8021QBridgeCVlanPortEntry_t *poEntry)
{
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32ComponentId)) == NULL ||
		(poIeee8021BridgeBaseEntry->u8RowStatus == xRowStatus_active_c && poIeee8021BridgeBaseEntry->i32ComponentType != ieee8021BridgeBaseComponentType_cVlanComponent_c))
	{
		goto ieee8021QBridgeCVlanPortTable_createHier_cleanup;
	}
	
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Number)) == NULL &&
		(poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_createExt (poIeee8021BridgeBaseEntry, poEntry->u32Number)) == NULL)
	{
		goto ieee8021QBridgeCVlanPortTable_createHier_cleanup;
	}
	
	poIeee8021BridgeBasePortEntry->i32Type = ieee8021BridgeBasePortType_customerVlanPort_c;
	
	return true;
	
	
ieee8021QBridgeCVlanPortTable_createHier_cleanup:
	
	ieee8021QBridgeCVlanPortTable_removeHier (poEntry);
	return false;
}

bool
ieee8021QBridgeCVlanPortTable_removeHier (
	ieee8021QBridgeCVlanPortEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021BridgeBasePortEntry_t *poIeee8021BridgeBasePortEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeCVlanPortTable_removeHier_success;
	}
	
	if ((poIeee8021BridgeBasePortEntry = ieee8021BridgeBasePortTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Number)) != NULL &&
		!ieee8021BridgeBasePortTable_removeExt (poIeee8021BridgeBaseEntry, poIeee8021BridgeBasePortEntry))
	{
		goto ieee8021QBridgeCVlanPortTable_removeHier_cleanup;
	}
	
ieee8021QBridgeCVlanPortTable_removeHier_success:
	
	bRetCode = true;
	
ieee8021QBridgeCVlanPortTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeCVlanPortRowStatus_handler (
	ieee8021QBridgeCVlanPortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeCVlanPortRowStatus_handler_cleanup;
	}
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgeCVlanPortRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021QBridgeCVlanPortRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poIeee8021BridgeBaseEntry->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021QBridgeCVlanPortRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeCVlanPortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeCVlanPortRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeCVlanPortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021QBridgeCVlanPortRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeCVlanPortRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeCVlanPortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeCVlanPortRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeCVlanPortRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeCVlanPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeCVlanPortTable_BTree);
	return ieee8021QBridgeCVlanPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeCVlanPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeCVlanPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeCVlanPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Number);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeCVlanPortTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeCVlanPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeCVlanPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgeCVlanPortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeCVlanPortTable table mapper */
int
ieee8021QBridgeCVlanPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeCVlanPortEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
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
					
					table_entry = ieee8021QBridgeCVlanPortTable_createEntry (
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeCVlanPortTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!ieee8021QBridgeCVlanPortRowStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeCVlanPortTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeCVlanPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGECVLANPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					ieee8021QBridgeCVlanPortTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeFdbTable table mapper **/
void
ieee8021QBridgeFdbTable_init (void)
{
	extern oid ieee8021QBridgeFdbTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeFdbTable", &ieee8021QBridgeFdbTable_mapper,
		ieee8021QBridgeFdbTable_oid, OID_LENGTH (ieee8021QBridgeFdbTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeFdbComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeFdbId */,
		0);
	table_info->min_column = IEEE8021QBRIDGEFDBDYNAMICCOUNT;
	table_info->max_column = IEEE8021QBRIDGEFDBAGINGTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeFdbTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeFdbTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeFdbTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeFdbTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeFdbEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeFdbEntry_t, oBTreeNode);
	register ieee8021QBridgeFdbEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeFdbEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id < pEntry2->u32Id) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Id == pEntry2->u32Id) ? 0: 1;
}

xBTree_t oIeee8021QBridgeFdbTable_BTree = xBTree_initInline (&ieee8021QBridgeFdbTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeFdbEntry_t *
ieee8021QBridgeFdbTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021QBridgeFdbEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Id = u32Id;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32AgingTime = 300;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree);
	return poEntry;
}

ieee8021QBridgeFdbEntry_t *
ieee8021QBridgeFdbTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021QBridgeFdbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeFdbEntry_t, oBTreeNode);
}

ieee8021QBridgeFdbEntry_t *
ieee8021QBridgeFdbTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	register ieee8021QBridgeFdbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Id = u32Id;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeFdbEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeFdbTable_removeEntry (ieee8021QBridgeFdbEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgeFdbEntry_t *
ieee8021QBridgeFdbTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Id)
{
	ieee8021QBridgeFdbEntry_t *poEntry = NULL;
	
	if (u32Id < ieee8021QBridgeFdbId_start_c || u32Id > ieee8021QBridgeFdbId_end_c)
	{
		goto ieee8021QBridgeFdbTable_createExt_cleanup;
	}
	
	poEntry = ieee8021QBridgeFdbTable_createEntry (
		u32ComponentId,
		u32Id);
	if (poEntry == NULL)
	{
		goto ieee8021QBridgeFdbTable_createExt_cleanup;
	}
	
ieee8021QBridgeFdbTable_createExt_cleanup:
	
	return poEntry;
}

bool
ieee8021QBridgeFdbTable_removeExt (ieee8021QBridgeFdbEntry_t *poEntry)
{
	ieee8021QBridgeFdbTable_removeEntry (poEntry);
	
	return true;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeFdbTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeFdbTable_BTree);
	return ieee8021QBridgeFdbTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeFdbTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeFdbEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeFdbEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Id);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeFdbTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeFdbTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeFdbEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgeFdbTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeFdbTable table mapper */
int
ieee8021QBridgeFdbTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeFdbEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeFdbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFDBDYNAMICCOUNT:
				snmp_set_var_typed_integer (request->requestvb, ASN_GAUGE, table_entry->u32DynamicCount);
				break;
			case IEEE8021QBRIDGEFDBLEARNEDENTRYDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64LearnedEntryDiscards);
				break;
			case IEEE8021QBRIDGEFDBAGINGTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AgingTime);
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
			table_entry = (ieee8021QBridgeFdbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFDBAGINGTIME:
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
			table_entry = (ieee8021QBridgeFdbEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021QBridgeFdbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFDBAGINGTIME:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AgingTime))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AgingTime, sizeof (table_entry->i32AgingTime));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AgingTime = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021QBridgeFdbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFDBAGINGTIME:
				memcpy (&table_entry->i32AgingTime, pvOldDdata, sizeof (table_entry->i32AgingTime));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeTpFdbTable table mapper **/
void
ieee8021QBridgeTpFdbTable_init (void)
{
	extern oid ieee8021QBridgeTpFdbTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeTpFdbTable", &ieee8021QBridgeTpFdbTable_mapper,
		ieee8021QBridgeTpFdbTable_oid, OID_LENGTH (ieee8021QBridgeTpFdbTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeFdbComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeFdbId */,
		ASN_OCTET_STR /* index: ieee8021QBridgeTpFdbAddress */,
		0);
	table_info->min_column = IEEE8021QBRIDGETPFDBPORT;
	table_info->max_column = IEEE8021QBRIDGETPFDBSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeTpFdbTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeTpFdbTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeTpFdbTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeTpFdbTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeTpFdbEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeTpFdbEntry_t, oBTreeNode);
	register ieee8021QBridgeTpFdbEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeTpFdbEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32FdbComponentId < pEntry2->u32FdbComponentId) ||
		(pEntry1->u32FdbComponentId == pEntry2->u32FdbComponentId && pEntry1->u32FdbId < pEntry2->u32FdbId) ||
		(pEntry1->u32FdbComponentId == pEntry2->u32FdbComponentId && pEntry1->u32FdbId == pEntry2->u32FdbId && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ? -1:
		(pEntry1->u32FdbComponentId == pEntry2->u32FdbComponentId && pEntry1->u32FdbId == pEntry2->u32FdbId && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021QBridgeTpFdbTable_BTree = xBTree_initInline (&ieee8021QBridgeTpFdbTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeTpFdbEntry_t *
ieee8021QBridgeTpFdbTable_createEntry (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ieee8021QBridgeTpFdbEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32FdbComponentId = u32FdbComponentId;
	poEntry->u32FdbId = u32FdbId;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree);
	return poEntry;
}

ieee8021QBridgeTpFdbEntry_t *
ieee8021QBridgeTpFdbTable_getByIndex (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ieee8021QBridgeTpFdbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32FdbComponentId = u32FdbComponentId;
	poTmpEntry->u32FdbId = u32FdbId;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeTpFdbEntry_t, oBTreeNode);
}

ieee8021QBridgeTpFdbEntry_t *
ieee8021QBridgeTpFdbTable_getNextIndex (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ieee8021QBridgeTpFdbEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32FdbComponentId = u32FdbComponentId;
	poTmpEntry->u32FdbId = u32FdbId;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeTpFdbEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeTpFdbTable_removeEntry (ieee8021QBridgeTpFdbEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeTpFdbTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeTpFdbTable_BTree);
	return ieee8021QBridgeTpFdbTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeTpFdbTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeTpFdbEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeTpFdbEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32FdbComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32FdbId);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeTpFdbTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeTpFdbTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeTpFdbEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeTpFdbTable_getByIndex (
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

/* ieee8021QBridgeTpFdbTable table mapper */
int
ieee8021QBridgeTpFdbTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeTpFdbEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeTpFdbEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGETPFDBPORT:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Port);
				break;
			case IEEE8021QBRIDGETPFDBSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Status);
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

/** initialize ieee8021QBridgeTpGroupTable table mapper **/
void
ieee8021QBridgeTpGroupTable_init (void)
{
	extern oid ieee8021QBridgeTpGroupTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeTpGroupTable", &ieee8021QBridgeTpGroupTable_mapper,
		ieee8021QBridgeTpGroupTable_oid, OID_LENGTH (ieee8021QBridgeTpGroupTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanIndex */,
		ASN_OCTET_STR /* index: ieee8021QBridgeTpGroupAddress */,
		0);
	table_info->min_column = IEEE8021QBRIDGETPGROUPEGRESSPORTS;
	table_info->max_column = IEEE8021QBRIDGETPGROUPLEARNT;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeTpGroupTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeTpGroupTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeTpGroupTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeTpGroupTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeTpGroupEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeTpGroupEntry_t, oBTreeNode);
	register ieee8021QBridgeTpGroupEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeTpGroupEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32VlanCurrentComponentId < pEntry2->u32VlanCurrentComponentId) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ? -1:
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021QBridgeTpGroupTable_BTree = xBTree_initInline (&ieee8021QBridgeTpGroupTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeTpGroupEntry_t *
ieee8021QBridgeTpGroupTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeTpGroupEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 2 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8EgressPorts = (void *) (poEntry + 1);
	poEntry->pu8Learnt = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->u16EgressPorts_len = u16Ports_len;
	poEntry->u16Learnt_len = u16Ports_len;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree);
	return poEntry;
}

ieee8021QBridgeTpGroupEntry_t *
ieee8021QBridgeTpGroupTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ieee8021QBridgeTpGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeTpGroupEntry_t, oBTreeNode);
}

ieee8021QBridgeTpGroupEntry_t *
ieee8021QBridgeTpGroupTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len)
{
	register ieee8021QBridgeTpGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeTpGroupEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeTpGroupTable_removeEntry (ieee8021QBridgeTpGroupEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeTpGroupTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeTpGroupTable_BTree);
	return ieee8021QBridgeTpGroupTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeTpGroupTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeTpGroupEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeTpGroupEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanCurrentComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeTpGroupTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeTpGroupTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeTpGroupEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeTpGroupTable_getByIndex (
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

/* ieee8021QBridgeTpGroupTable table mapper */
int
ieee8021QBridgeTpGroupTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeTpGroupEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeTpGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGETPGROUPEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8EgressPorts, table_entry->u16EgressPorts_len);
				break;
			case IEEE8021QBRIDGETPGROUPLEARNT:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8Learnt, table_entry->u16Learnt_len);
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

/** initialize ieee8021QBridgeForwardAllTable table mapper **/
void
ieee8021QBridgeForwardAllTable_init (void)
{
	extern oid ieee8021QBridgeForwardAllTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeForwardAllTable", &ieee8021QBridgeForwardAllTable_mapper,
		ieee8021QBridgeForwardAllTable_oid, OID_LENGTH (ieee8021QBridgeForwardAllTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeForwardAllVlanIndex */,
		0);
	table_info->min_column = IEEE8021QBRIDGEFORWARDALLPORTS;
	table_info->max_column = IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeForwardAllTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeForwardAllTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeForwardAllTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeForwardAllTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeForwardAllEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeForwardAllEntry_t, oBTreeNode);
	register ieee8021QBridgeForwardAllEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeForwardAllEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32VlanCurrentComponentId < pEntry2->u32VlanCurrentComponentId) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ? -1:
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex) ? 0: 1;
}

xBTree_t oIeee8021QBridgeForwardAllTable_BTree = xBTree_initInline (&ieee8021QBridgeForwardAllTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeForwardAllEntry_t *
ieee8021QBridgeForwardAllTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeForwardAllEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 3 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8Ports = (void *) (poEntry + 1);
	poEntry->pu8StaticPorts = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->pu8ForbiddenPorts = ((void *) (poEntry + 1)) + 2 * u16Ports_len;
	poEntry->u16Ports_len = u16Ports_len;
	poEntry->u16StaticPorts_len = u16Ports_len;
	poEntry->u16ForbiddenPorts_len = u16Ports_len;
	xBitmap_setAll (poEntry->pu8Ports, xBitmap_bitLength (poEntry->u16Ports_len));
	xBitmap_setAll (poEntry->pu8StaticPorts, xBitmap_bitLength (poEntry->u16StaticPorts_len));
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree);
	return poEntry;
}

ieee8021QBridgeForwardAllEntry_t *
ieee8021QBridgeForwardAllTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeForwardAllEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeForwardAllEntry_t, oBTreeNode);
}

ieee8021QBridgeForwardAllEntry_t *
ieee8021QBridgeForwardAllTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeForwardAllEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeForwardAllEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeForwardAllTable_removeEntry (ieee8021QBridgeForwardAllEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeForwardAllTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeForwardAllTable_BTree);
	return ieee8021QBridgeForwardAllTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeForwardAllTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeForwardAllEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeForwardAllEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanCurrentComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardAllTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeForwardAllTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeForwardAllEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgeForwardAllTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeForwardAllTable table mapper */
int
ieee8021QBridgeForwardAllTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeForwardAllEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeForwardAllEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDALLPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8Ports, table_entry->u16Ports_len);
				break;
			case IEEE8021QBRIDGEFORWARDALLSTATICPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8StaticPorts, table_entry->u16StaticPorts_len);
				break;
			case IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8ForbiddenPorts, table_entry->u16ForbiddenPorts_len);
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
			table_entry = (ieee8021QBridgeForwardAllEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDALLSTATICPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16StaticPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16ForbiddenPorts_len);
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
			table_entry = (ieee8021QBridgeForwardAllEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021QBridgeForwardAllEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDALLSTATICPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16StaticPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16StaticPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8StaticPorts, table_entry->u16StaticPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8StaticPorts, 0, table_entry->u16StaticPorts_len);
				memcpy (table_entry->pu8StaticPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16StaticPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16ForbiddenPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8ForbiddenPorts, table_entry->u16ForbiddenPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8ForbiddenPorts, 0, table_entry->u16ForbiddenPorts_len);
				memcpy (table_entry->pu8ForbiddenPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenPorts_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021QBridgeForwardAllEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDALLSTATICPORTS:
				memcpy (table_entry->pu8StaticPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16StaticPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS:
				memcpy (table_entry->pu8ForbiddenPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeForwardUnregisteredTable table mapper **/
void
ieee8021QBridgeForwardUnregisteredTable_init (void)
{
	extern oid ieee8021QBridgeForwardUnregisteredTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeForwardUnregisteredTable", &ieee8021QBridgeForwardUnregisteredTable_mapper,
		ieee8021QBridgeForwardUnregisteredTable_oid, OID_LENGTH (ieee8021QBridgeForwardUnregisteredTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeForwardUnregisteredVlanIndex */,
		0);
	table_info->min_column = IEEE8021QBRIDGEFORWARDUNREGISTEREDPORTS;
	table_info->max_column = IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeForwardUnregisteredTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeForwardUnregisteredTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeForwardUnregisteredTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeForwardUnregisteredTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeForwardUnregisteredEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeForwardUnregisteredEntry_t, oBTreeNode);
	register ieee8021QBridgeForwardUnregisteredEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeForwardUnregisteredEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32VlanCurrentComponentId < pEntry2->u32VlanCurrentComponentId) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ? -1:
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex) ? 0: 1;
}

xBTree_t oIeee8021QBridgeForwardUnregisteredTable_BTree = xBTree_initInline (&ieee8021QBridgeForwardUnregisteredTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeForwardUnregisteredEntry_t *
ieee8021QBridgeForwardUnregisteredTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeForwardUnregisteredEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 3 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8Ports = (void *) (poEntry + 1);
	poEntry->pu8StaticPorts = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->pu8ForbiddenPorts = ((void *) (poEntry + 1)) + 2 * u16Ports_len;
	poEntry->u16Ports_len = u16Ports_len;
	poEntry->u16StaticPorts_len = u16Ports_len;
	poEntry->u16ForbiddenPorts_len = u16Ports_len;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree);
	return poEntry;
}

ieee8021QBridgeForwardUnregisteredEntry_t *
ieee8021QBridgeForwardUnregisteredTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeForwardUnregisteredEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeForwardUnregisteredEntry_t, oBTreeNode);
}

ieee8021QBridgeForwardUnregisteredEntry_t *
ieee8021QBridgeForwardUnregisteredTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeForwardUnregisteredEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeForwardUnregisteredEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeForwardUnregisteredTable_removeEntry (ieee8021QBridgeForwardUnregisteredEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeForwardUnregisteredTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeForwardUnregisteredTable_BTree);
	return ieee8021QBridgeForwardUnregisteredTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeForwardUnregisteredTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeForwardUnregisteredEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeForwardUnregisteredEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanCurrentComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeForwardUnregisteredTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeForwardUnregisteredTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeForwardUnregisteredEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgeForwardUnregisteredTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeForwardUnregisteredTable table mapper */
int
ieee8021QBridgeForwardUnregisteredTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeForwardUnregisteredEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeForwardUnregisteredEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8Ports, table_entry->u16Ports_len);
				break;
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDSTATICPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8StaticPorts, table_entry->u16StaticPorts_len);
				break;
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8ForbiddenPorts, table_entry->u16ForbiddenPorts_len);
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
			table_entry = (ieee8021QBridgeForwardUnregisteredEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDSTATICPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16StaticPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16ForbiddenPorts_len);
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
			table_entry = (ieee8021QBridgeForwardUnregisteredEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021QBridgeForwardUnregisteredEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDSTATICPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16StaticPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16StaticPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8StaticPorts, table_entry->u16StaticPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8StaticPorts, 0, table_entry->u16StaticPorts_len);
				memcpy (table_entry->pu8StaticPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16StaticPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16ForbiddenPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8ForbiddenPorts, table_entry->u16ForbiddenPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8ForbiddenPorts, 0, table_entry->u16ForbiddenPorts_len);
				memcpy (table_entry->pu8ForbiddenPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenPorts_len = request->requestvb->val_len;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021QBridgeForwardUnregisteredEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDSTATICPORTS:
				memcpy (table_entry->pu8StaticPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16StaticPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS:
				memcpy (table_entry->pu8ForbiddenPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeStaticUnicastTable table mapper **/
void
ieee8021QBridgeStaticUnicastTable_init (void)
{
	extern oid ieee8021QBridgeStaticUnicastTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeStaticUnicastTable", &ieee8021QBridgeStaticUnicastTable_mapper,
		ieee8021QBridgeStaticUnicastTable_oid, OID_LENGTH (ieee8021QBridgeStaticUnicastTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeStaticUnicastComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeStaticUnicastVlanIndex */,
		ASN_OCTET_STR /* index: ieee8021QBridgeStaticUnicastAddress */,
		ASN_UNSIGNED /* index: ieee8021QBridgeStaticUnicastReceivePort */,
		0);
	table_info->min_column = IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS;
	table_info->max_column = IEEE8021QBRIDGESTATICUNICASTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeStaticUnicastTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeStaticUnicastTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeStaticUnicastTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeStaticUnicastTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeStaticUnicastEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeStaticUnicastEntry_t, oBTreeNode);
	register ieee8021QBridgeStaticUnicastEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeStaticUnicastEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32ReceivePort < pEntry2->u32ReceivePort) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32ReceivePort == pEntry2->u32ReceivePort) ? 0: 1;
}

xBTree_t oIeee8021QBridgeStaticUnicastTable_BTree = xBTree_initInline (&ieee8021QBridgeStaticUnicastTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeStaticUnicastEntry_t *
ieee8021QBridgeStaticUnicastTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeStaticUnicastEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 2 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32ReceivePort = u32ReceivePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8StaticEgressPorts = (void *) (poEntry + 1);
	poEntry->pu8ForbiddenEgressPorts = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->u16StaticEgressPorts_len = u16Ports_len;
	poEntry->u16ForbiddenEgressPorts_len = u16Ports_len;
	poEntry->u8StorageType = ieee8021QBridgeStaticUnicastStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree);
	return poEntry;
}

ieee8021QBridgeStaticUnicastEntry_t *
ieee8021QBridgeStaticUnicastTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort)
{
	register ieee8021QBridgeStaticUnicastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32ReceivePort = u32ReceivePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeStaticUnicastEntry_t, oBTreeNode);
}

ieee8021QBridgeStaticUnicastEntry_t *
ieee8021QBridgeStaticUnicastTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort)
{
	register ieee8021QBridgeStaticUnicastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32ReceivePort = u32ReceivePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeStaticUnicastEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeStaticUnicastTable_removeEntry (ieee8021QBridgeStaticUnicastEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeStaticUnicastTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeStaticUnicastTable_BTree);
	return ieee8021QBridgeStaticUnicastTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeStaticUnicastTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeStaticUnicastEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeStaticUnicastEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ReceivePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticUnicastTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeStaticUnicastTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeStaticUnicastEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = ieee8021QBridgeStaticUnicastTable_getByIndex (
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

/* ieee8021QBridgeStaticUnicastTable table mapper */
int
ieee8021QBridgeStaticUnicastTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeStaticUnicastEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8StaticEgressPorts, table_entry->u16StaticEgressPorts_len);
				break;
			case IEEE8021QBRIDGESTATICUNICASTFORBIDDENEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8ForbiddenEgressPorts, table_entry->u16ForbiddenEgressPorts_len);
				break;
			case IEEE8021QBRIDGESTATICUNICASTSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16StaticEgressPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICUNICASTFORBIDDENEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16ForbiddenEgressPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICUNICASTSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
					
					if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (*idx1->val.integer)) == NULL)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeStaticUnicastTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						(void*) idx3->val.string, idx3->val_len,
						*idx4->val.integer,
						poIeee8021BridgeBaseEntry->oNe.u16Ports_len);
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeStaticUnicastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16StaticEgressPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16StaticEgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8StaticEgressPorts, table_entry->u16StaticEgressPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8StaticEgressPorts, 0, table_entry->u16StaticEgressPorts_len);
				memcpy (table_entry->pu8StaticEgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16StaticEgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGESTATICUNICASTFORBIDDENEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16ForbiddenEgressPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenEgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8ForbiddenEgressPorts, table_entry->u16ForbiddenEgressPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8ForbiddenEgressPorts, 0, table_entry->u16ForbiddenEgressPorts_len);
				memcpy (table_entry->pu8ForbiddenEgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenEgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGESTATICUNICASTSTORAGETYPE:
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeStaticUnicastTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS:
				memcpy (table_entry->pu8StaticEgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16StaticEgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGESTATICUNICASTFORBIDDENEGRESSPORTS:
				memcpy (table_entry->pu8ForbiddenEgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenEgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGESTATICUNICASTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeStaticUnicastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeStaticUnicastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICUNICASTROWSTATUS:
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
					ieee8021QBridgeStaticUnicastTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeStaticMulticastTable table mapper **/
void
ieee8021QBridgeStaticMulticastTable_init (void)
{
	extern oid ieee8021QBridgeStaticMulticastTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeStaticMulticastTable", &ieee8021QBridgeStaticMulticastTable_mapper,
		ieee8021QBridgeStaticMulticastTable_oid, OID_LENGTH (ieee8021QBridgeStaticMulticastTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanIndex */,
		ASN_OCTET_STR /* index: ieee8021QBridgeStaticMulticastAddress */,
		ASN_UNSIGNED /* index: ieee8021QBridgeStaticMulticastReceivePort */,
		0);
	table_info->min_column = IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS;
	table_info->max_column = IEEE8021QBRIDGESTATICMULTICASTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeStaticMulticastTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeStaticMulticastTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeStaticMulticastTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeStaticMulticastTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeStaticMulticastEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeStaticMulticastEntry_t, oBTreeNode);
	register ieee8021QBridgeStaticMulticastEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeStaticMulticastEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32VlanCurrentComponentId < pEntry2->u32VlanCurrentComponentId) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == -1) ||
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32ReceivePort < pEntry2->u32ReceivePort) ? -1:
		(pEntry1->u32VlanCurrentComponentId == pEntry2->u32VlanCurrentComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex && xBinCmp (pEntry1->au8Address, pEntry2->au8Address, pEntry1->u16Address_len, pEntry2->u16Address_len) == 0 && pEntry1->u32ReceivePort == pEntry2->u32ReceivePort) ? 0: 1;
}

xBTree_t oIeee8021QBridgeStaticMulticastTable_BTree = xBTree_initInline (&ieee8021QBridgeStaticMulticastTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeStaticMulticastEntry_t *
ieee8021QBridgeStaticMulticastTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeStaticMulticastEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 2 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poEntry->au8Address, pau8Address, u16Address_len);
	poEntry->u16Address_len = u16Address_len;
	poEntry->u32ReceivePort = u32ReceivePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8StaticEgressPorts = (void *) (poEntry + 1);
	poEntry->pu8ForbiddenEgressPorts = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->u16StaticEgressPorts_len = u16Ports_len;
	poEntry->u16ForbiddenEgressPorts_len = u16Ports_len;
	poEntry->u8StorageType = ieee8021QBridgeStaticMulticastStorageType_nonVolatile_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree);
	return poEntry;
}

ieee8021QBridgeStaticMulticastEntry_t *
ieee8021QBridgeStaticMulticastTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort)
{
	register ieee8021QBridgeStaticMulticastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32ReceivePort = u32ReceivePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeStaticMulticastEntry_t, oBTreeNode);
}

ieee8021QBridgeStaticMulticastEntry_t *
ieee8021QBridgeStaticMulticastTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort)
{
	register ieee8021QBridgeStaticMulticastEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32VlanCurrentComponentId = u32VlanCurrentComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	memcpy (poTmpEntry->au8Address, pau8Address, u16Address_len);
	poTmpEntry->u16Address_len = u16Address_len;
	poTmpEntry->u32ReceivePort = u32ReceivePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeStaticMulticastEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeStaticMulticastTable_removeEntry (ieee8021QBridgeStaticMulticastEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeStaticMulticastTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeStaticMulticastTable_BTree);
	return ieee8021QBridgeStaticMulticastTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeStaticMulticastTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeStaticMulticastEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeStaticMulticastEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanCurrentComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8Address, poEntry->u16Address_len);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ReceivePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeStaticMulticastTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeStaticMulticastTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeStaticMulticastEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	register netsnmp_variable_list *idx4 = idx3->next_variable;
	
	poEntry = ieee8021QBridgeStaticMulticastTable_getByIndex (
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

/* ieee8021QBridgeStaticMulticastTable table mapper */
int
ieee8021QBridgeStaticMulticastTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeStaticMulticastEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8StaticEgressPorts, table_entry->u16StaticEgressPorts_len);
				break;
			case IEEE8021QBRIDGESTATICMULTICASTFORBIDDENEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8ForbiddenEgressPorts, table_entry->u16ForbiddenEgressPorts_len);
				break;
			case IEEE8021QBRIDGESTATICMULTICASTSTORAGETYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8StorageType);
				break;
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16StaticEgressPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICMULTICASTFORBIDDENEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, table_entry->u16ForbiddenEgressPorts_len);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICMULTICASTSTORAGETYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			register netsnmp_variable_list *idx4 = idx3->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
					
					if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (*idx1->val.integer)) == NULL)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeStaticMulticastTable_createEntry (
						*idx1->val.integer,
						*idx2->val.integer,
						(void*) idx3->val.string, idx3->val_len,
						*idx4->val.integer,
						poIeee8021BridgeBaseEntry->oNe.u16Ports_len);
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeStaticMulticastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16StaticEgressPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16StaticEgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8StaticEgressPorts, table_entry->u16StaticEgressPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8StaticEgressPorts, 0, table_entry->u16StaticEgressPorts_len);
				memcpy (table_entry->pu8StaticEgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16StaticEgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGESTATICMULTICASTFORBIDDENEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + table_entry->u16ForbiddenEgressPorts_len)) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenEgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->pu8ForbiddenEgressPorts, table_entry->u16ForbiddenEgressPorts_len);
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->pu8ForbiddenEgressPorts, 0, table_entry->u16ForbiddenEgressPorts_len);
				memcpy (table_entry->pu8ForbiddenEgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenEgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGESTATICMULTICASTSTORAGETYPE:
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeStaticMulticastTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS:
				memcpy (table_entry->pu8StaticEgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16StaticEgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGESTATICMULTICASTFORBIDDENEGRESSPORTS:
				memcpy (table_entry->pu8ForbiddenEgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenEgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGESTATICMULTICASTSTORAGETYPE:
				memcpy (&table_entry->u8StorageType, pvOldDdata, sizeof (table_entry->u8StorageType));
				break;
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeStaticMulticastTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeStaticMulticastEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGESTATICMULTICASTROWSTATUS:
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
					ieee8021QBridgeStaticMulticastTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeVlanCurrentTable table mapper **/
void
ieee8021QBridgeVlanCurrentTable_init (void)
{
	extern oid ieee8021QBridgeVlanCurrentTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeVlanCurrentTable", &ieee8021QBridgeVlanCurrentTable_mapper,
		ieee8021QBridgeVlanCurrentTable_oid, OID_LENGTH (ieee8021QBridgeVlanCurrentTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_TIMETICKS /* index: ieee8021QBridgeVlanTimeMark */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanCurrentComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanIndex */,
		0);
	table_info->min_column = IEEE8021QBRIDGEVLANFDBID;
	table_info->max_column = IEEE8021QBRIDGEVLANCREATIONTIME;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeVlanCurrentTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeVlanCurrentTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeVlanCurrentTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeVlanCurrentTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeVlanCurrentEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
	register ieee8021QBridgeVlanCurrentEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32TimeMark < pEntry2->u32TimeMark) ||
		(pEntry1->u32TimeMark == pEntry2->u32TimeMark && pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32TimeMark == pEntry2->u32TimeMark && pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32TimeMark == pEntry2->u32TimeMark && pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

static int8_t
ieee8021QBridgeVlanCurrentTable_Vlan_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeVlanCurrentEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeVlanCurrentEntry_t, oVlan_BTreeNode);
	register ieee8021QBridgeVlanCurrentEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeVlanCurrentEntry_t, oVlan_BTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

xBTree_t oIeee8021QBridgeVlanCurrentTable_BTree = xBTree_initInline (&ieee8021QBridgeVlanCurrentTable_BTreeNodeCmp);
xBTree_t oIeee8021QBridgeVlanCurrentTable_Vlan_BTree = xBTree_initInline (&ieee8021QBridgeVlanCurrentTable_Vlan_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_createEntry (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index,
	uint16_t u16Ports_len)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	
	if (u16Ports_len == 0 || (poEntry = xBuffer_cAlloc (sizeof (*poEntry) + 2 * u16Ports_len)) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32TimeMark = u32TimeMark;
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->pu8EgressPorts = (void *) (poEntry + 1);
	poEntry->pu8UntaggedPorts = ((void *) (poEntry + 1)) + u16Ports_len;
	poEntry->oNe.pu8Learnt = ((void *) (poEntry + 1)) + 2 * u16Ports_len;
	poEntry->u16EgressPorts_len = u16Ports_len;
	poEntry->u16UntaggedPorts_len = u16Ports_len;
	poEntry->oNe.u16Learnt_len = u16Ports_len;
	poEntry->i32Status = ieee8021QBridgeVlanStatus_dynamicMvrp_c;
	poEntry->u32CreationTime++;	/* TODO */
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree);
	xBTree_nodeAdd (&poEntry->oVlan_BTreeNode, &oIeee8021QBridgeVlanCurrentTable_Vlan_BTree);
	return poEntry;
}

ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_getByIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32TimeMark = u32TimeMark;
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
}

ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_getNextIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32TimeMark = u32TimeMark;
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
}

ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_Vlan_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021QBridgeVlanCurrentEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oVlan_BTreeNode, &oIeee8021QBridgeVlanCurrentTable_Vlan_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanCurrentEntry_t, oVlan_BTreeNode);
}

ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_Vlan_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Index)
{
	register ieee8021QBridgeVlanCurrentEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (ieee8021QBridgeVlanCurrentEntry_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oVlan_BTreeNode, &oIeee8021QBridgeVlanCurrentTable_Vlan_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanCurrentEntry_t, oVlan_BTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeVlanCurrentTable_removeEntry (ieee8021QBridgeVlanCurrentEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree);
	xBTree_nodeRemove (&poEntry->oVlan_BTreeNode, &oIeee8021QBridgeVlanCurrentTable_Vlan_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgeVlanCurrentEntry_t *
ieee8021QBridgeVlanCurrentTable_createExt (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index,
	uint16_t u16Ports_len)
{
	ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgeVlanCurrentTable_createEntry (
		u32TimeMark,
		u32ComponentId,
		u32Index,
		u16Ports_len);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021QBridgeVlanCurrentTable_createHier (poEntry))
	{
		ieee8021QBridgeVlanCurrentTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021QBridgeVlanCurrentTable_removeExt (ieee8021QBridgeVlanCurrentEntry_t *poEntry)
{
	if (!ieee8021QBridgeVlanCurrentTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeVlanCurrentTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeVlanCurrentTable_createHier (
	ieee8021QBridgeVlanCurrentEntry_t *poEntry)
{
	register uint16_t u16PortIndex = 0;
	register uint32_t u32VlanIndex = 0;
	register ieee8021QBridgeEntry_t *poIeee8021QBridgeEntry = NULL;
	register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
	register ieee8021QBridgeForwardAllEntry_t *poIeee8021QBridgeForwardAllEntry = NULL;
	register ieee8021QBridgeForwardUnregisteredEntry_t *poIeee8021QBridgeForwardUnregisteredEntry = NULL;
	register ieee8021QBridgePortVlanStatisticsEntry_t *poIeee8021QBridgePortVlanStatisticsEntry = NULL;
	
	if ((poIeee8021QBridgeEntry = ieee8021QBridgeTable_getByIndex (poEntry->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentTable_createHier_cleanup;
	}
	
	
	if (poEntry->u32FdbId != 0 &&
		(poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, poEntry->u32FdbId)) == NULL &&
		(poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_createEntry (poEntry->u32ComponentId, poEntry->u32FdbId)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentTable_createHier_cleanup;
	}
	
	if ((poIeee8021QBridgeForwardAllEntry = ieee8021QBridgeForwardAllTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Index)) == NULL &&
		(poIeee8021QBridgeForwardAllEntry = ieee8021QBridgeForwardAllTable_createEntry (poEntry->u32ComponentId, poEntry->u32Index, poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentTable_createHier_cleanup;
	}
	
	if ((poIeee8021QBridgeForwardUnregisteredEntry = ieee8021QBridgeForwardUnregisteredTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Index)) == NULL &&
		(poIeee8021QBridgeForwardUnregisteredEntry = ieee8021QBridgeForwardUnregisteredTable_createEntry (poEntry->u32ComponentId, poEntry->u32Index, poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanCurrentTable_createHier_cleanup;
	}
	
	u32VlanIndex = poEntry->u32Index;
	while (
		(poIeee8021QBridgePortVlanStatisticsEntry = ieee8021QBridgePortVlanStatisticsTable_getNextIndex (poEntry->u32ComponentId, (uint32_t) u16PortIndex, u32VlanIndex)) != NULL &&
		poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePortComponentId == poEntry->u32ComponentId)
	{
		u16PortIndex = poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePort;
		u32VlanIndex = poIeee8021QBridgePortVlanStatisticsEntry->u32VlanIndex;
		
		if (poIeee8021QBridgePortVlanStatisticsEntry->u32VlanIndex != poEntry->u32Index)
		{
			continue;
		}
		if (xBitmap_getBitRev (poEntry->pu8EgressPorts, (uint16_t) (poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePort - 1)))
		{
			continue;
		}
		
		ieee8021QBridgePortVlanStatisticsTable_removeEntry (poIeee8021QBridgePortVlanStatisticsEntry);
	}
	
	xBitmap_scanBitRangeRev (
		poEntry->pu8EgressPorts, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 1, u16PortIndex)
	{
		if (ieee8021QBridgePortVlanStatisticsTable_getByIndex (poEntry->u32ComponentId, u16PortIndex + 1, poEntry->u32Index) != NULL)
		{
			continue;
		}
		
		if (ieee8021QBridgePortVlanStatisticsTable_createEntry (poEntry->u32ComponentId, u16PortIndex + 1, poEntry->u32Index) == NULL)
		{
			goto ieee8021QBridgeVlanCurrentTable_createHier_cleanup;
		}
		/* TODO */
	}
	
	poIeee8021QBridgeEntry->u32NumVlans++;
	return true;
	
	
ieee8021QBridgeVlanCurrentTable_createHier_cleanup:
	
	ieee8021QBridgeVlanCurrentTable_removeHier (poEntry);
	return false;
}

bool
ieee8021QBridgeVlanCurrentTable_removeHier (
	ieee8021QBridgeVlanCurrentEntry_t *poEntry)
{
	register uint16_t u16PortIndex = 0;
	register uint32_t u32VlanIndex = 0;
	register ieee8021QBridgeEntry_t *poIeee8021QBridgeEntry = NULL;
	register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
	register ieee8021QBridgeForwardAllEntry_t *poIeee8021QBridgeForwardAllEntry = NULL;
	register ieee8021QBridgeForwardUnregisteredEntry_t *poIeee8021QBridgeForwardUnregisteredEntry = NULL;
	register ieee8021QBridgePortVlanStatisticsEntry_t *poIeee8021QBridgePortVlanStatisticsEntry = NULL;
	
	if ((poIeee8021QBridgeEntry = ieee8021QBridgeTable_getByIndex (poEntry->u32ComponentId)) == NULL)
	{
		return false;
	}
	
	
	u32VlanIndex = poEntry->u32Index;
	while (
		(poIeee8021QBridgePortVlanStatisticsEntry = ieee8021QBridgePortVlanStatisticsTable_getNextIndex (poEntry->u32ComponentId, (uint32_t) u16PortIndex, u32VlanIndex)) != NULL &&
		poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePortComponentId == poEntry->u32ComponentId)
	{
		u16PortIndex = poIeee8021QBridgePortVlanStatisticsEntry->u32BridgeBasePort;
		u32VlanIndex = poIeee8021QBridgePortVlanStatisticsEntry->u32VlanIndex;
		
		if (poIeee8021QBridgePortVlanStatisticsEntry->u32VlanIndex != poEntry->u32Index)
		{
			continue;
		}
		
		ieee8021QBridgePortVlanStatisticsTable_removeEntry (poIeee8021QBridgePortVlanStatisticsEntry);
	}
	
	if ((poIeee8021QBridgeForwardUnregisteredEntry = ieee8021QBridgeForwardUnregisteredTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Index)) != NULL)
	{
		ieee8021QBridgeForwardUnregisteredTable_removeEntry (poIeee8021QBridgeForwardUnregisteredEntry);
	}
	
	if ((poIeee8021QBridgeForwardAllEntry = ieee8021QBridgeForwardAllTable_getByIndex (poEntry->u32ComponentId, poEntry->u32Index)) != NULL)
	{
		ieee8021QBridgeForwardAllTable_removeEntry (poIeee8021QBridgeForwardAllEntry);
	}
	
	if (poEntry->u32FdbId != 0 && (poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, poEntry->u32FdbId)) != NULL)
	{
		ieee8021QBridgeFdbTable_removeEntry (poIeee8021QBridgeFdbEntry);
	}
	
	poIeee8021QBridgeEntry->u32NumVlans--;
	return true;
}

bool
ieee8021QBridgeVlanCurrentTable_vlanHandler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	
	if (!ieee8021QBridgeVlanCurrentTable_vlanUpdate (poComponent, poEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
	{
		goto ieee8021QBridgeVlanCurrentTable_vlanHandler_cleanup;
	}
	
	xBitmap_or (poEntry->pu8EgressPorts, poEntry->pu8EgressPorts, pu8EnabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_sub (poEntry->pu8EgressPorts, poEntry->pu8EgressPorts, pu8DisabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_or (poEntry->pu8UntaggedPorts, poEntry->pu8UntaggedPorts, pu8UntaggedPorts, xBitmap_bitLength (poEntry->u16UntaggedPorts_len));
	xBitmap_sub (poEntry->pu8UntaggedPorts, poEntry->pu8UntaggedPorts, pu8DisabledPorts, xBitmap_bitLength (poEntry->u16UntaggedPorts_len));
	
	poEntry->u32TimeMark++;	/* TODO */
	bRetCode = true;
	
ieee8021QBridgeVlanCurrentTable_vlanHandler_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanCurrentRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021QBridgeVlanCurrentRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poComponent->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021QBridgeVlanCurrentRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanCurrentRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeVlanCurrentRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanCurrentRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_createAndGo_c:
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeVlanCurrentRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanCurrentRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeVlanCurrentRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeVlanCurrentRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeVlanCurrentTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeVlanCurrentTable_BTree);
	return ieee8021QBridgeVlanCurrentTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeVlanCurrentTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeVlanCurrentEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_TIMETICKS, poEntry->u32TimeMark);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Index);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanCurrentTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeVlanCurrentTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanCurrentEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeVlanCurrentTable_getByIndex (
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

/* ieee8021QBridgeVlanCurrentTable table mapper */
int
ieee8021QBridgeVlanCurrentTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeVlanCurrentEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeVlanCurrentEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANFDBID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32FdbId);
				break;
			case IEEE8021QBRIDGEVLANCURRENTEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8EgressPorts, table_entry->u16EgressPorts_len);
				break;
			case IEEE8021QBRIDGEVLANCURRENTUNTAGGEDPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->pu8UntaggedPorts, table_entry->u16UntaggedPorts_len);
				break;
			case IEEE8021QBRIDGEVLANSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Status);
				break;
			case IEEE8021QBRIDGEVLANCREATIONTIME:
				snmp_set_var_typed_integer (request->requestvb, ASN_TIMETICKS, table_entry->u32CreationTime);
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

/** initialize ieee8021QBridgeVlanStaticTable table mapper **/
void
ieee8021QBridgeVlanStaticTable_init (void)
{
	extern oid ieee8021QBridgeVlanStaticTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeVlanStaticTable", &ieee8021QBridgeVlanStaticTable_mapper,
		ieee8021QBridgeVlanStaticTable_oid, OID_LENGTH (ieee8021QBridgeVlanStaticTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanStaticComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanStaticVlanIndex */,
		0);
	table_info->min_column = IEEE8021QBRIDGEVLANSTATICNAME;
	table_info->max_column = IEEE8021QBRIDGEVLANSTATICROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeVlanStaticTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeVlanStaticTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeVlanStaticTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeVlanStaticTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeVlanStaticEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeVlanStaticEntry_t, oBTreeNode);
	register ieee8021QBridgeVlanStaticEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeVlanStaticEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex) ? 0: 1;
}

xBTree_t oIeee8021QBridgeVlanStaticTable_BTree = xBTree_initInline (&ieee8021QBridgeVlanStaticTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeVlanStaticEntry_t *
ieee8021QBridgeVlanStaticTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeVlanStaticEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32VlanIndex = u32VlanIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	poEntry->u16EgressPorts_len = ETHERNET_PORT_MAP_SIZE;
	poEntry->u16ForbiddenEgressPorts_len = ETHERNET_PORT_MAP_SIZE;
	poEntry->u16UntaggedPorts_len = ETHERNET_PORT_MAP_SIZE;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree);
	return poEntry;
}

ieee8021QBridgeVlanStaticEntry_t *
ieee8021QBridgeVlanStaticTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeVlanStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanStaticEntry_t, oBTreeNode);
}

ieee8021QBridgeVlanStaticEntry_t *
ieee8021QBridgeVlanStaticTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgeVlanStaticEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeVlanStaticEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeVlanStaticTable_removeEntry (ieee8021QBridgeVlanStaticEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgeVlanStaticEntry_t *
ieee8021QBridgeVlanStaticTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex)
{
	ieee8021QBridgeVlanStaticEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgeVlanStaticTable_createEntry (
		u32ComponentId,
		u32VlanIndex);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	if (!ieee8021QBridgeVlanStaticTable_createHier (poEntry))
	{
		ieee8021QBridgeVlanStaticTable_removeEntry (poEntry);
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021QBridgeVlanStaticTable_removeExt (ieee8021QBridgeVlanStaticEntry_t *poEntry)
{
	if (!ieee8021QBridgeVlanStaticTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeVlanStaticTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeVlanStaticTable_createHier (
	ieee8021QBridgeVlanStaticEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021QBridgeVlanCurrentEntry_t *poIeee8021QBridgeVlanCurrentEntry = NULL;
	
	if ((poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_Vlan_getByIndex (poEntry->u32ComponentId, poEntry->u32VlanIndex)) == NULL &&
		(poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_createExt (0, poEntry->u32ComponentId, poEntry->u32VlanIndex, poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_createHier_cleanup;
	}
	
	poIeee8021QBridgeVlanCurrentEntry->i32Status = ieee8021QBridgeVlanStatus_permanent_c;
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_createHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticTable_removeHier (
	ieee8021QBridgeVlanStaticEntry_t *poEntry)
{
	register bool bRetCode = false;
	register uint8_t *pu8EnabledPorts = NULL;
	register uint8_t *pu8DisabledPorts = NULL;
	register uint8_t *pu8UntaggedPorts = NULL;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	register ieee8021QBridgeVlanCurrentEntry_t *poIeee8021QBridgeVlanCurrentEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32ComponentId)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_removeHier_cleanup;
	}
	
	if ((poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_Vlan_getByIndex (poEntry->u32ComponentId, poEntry->u32VlanIndex)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_removeHier_success;
	}
	
	if ((pu8EnabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8DisabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8UntaggedPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_removeHier_cleanup;
	}
	
	xBitmap_and (pu8DisabledPorts, poEntry->au8EgressPorts, poIeee8021QBridgeVlanCurrentEntry->pu8EgressPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_sub (pu8DisabledPorts, pu8DisabledPorts, poIeee8021QBridgeVlanCurrentEntry->oNe.pu8Learnt, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	
	if (xBitmap_checkBitRange (pu8DisabledPorts, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 1) == xBitmap_index_invalid_c)
	{
		if (!ieee8021QBridgeVlanCurrentTable_removeExt (poIeee8021QBridgeVlanCurrentEntry))
		{
			goto ieee8021QBridgeVlanStaticTable_removeHier_cleanup;
		}
	}
	else
	{
		if (!ieee8021QBridgeVlanCurrentTable_vlanHandler (poIeee8021BridgeBaseEntry, poIeee8021QBridgeVlanCurrentEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
		{
			goto ieee8021QBridgeVlanStaticTable_removeHier_cleanup;
		}
		poIeee8021QBridgeVlanCurrentEntry->i32Status = ieee8021QBridgeVlanStatus_dynamicMvrp_c;
	}
	
ieee8021QBridgeVlanStaticTable_removeHier_success:
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_removeHier_cleanup:
	
	if (pu8DisabledPorts != NULL)
	{
		xBuffer_free (pu8EnabledPorts);
		xBuffer_free (pu8DisabledPorts);
		xBuffer_free (pu8UntaggedPorts);
	}
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticTable_vlanUpdater (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	register ieee8021QBridgeVlanCurrentEntry_t *poIeee8021QBridgeVlanCurrentEntry = NULL;
	
	if ((poIeee8021QBridgeVlanCurrentEntry = ieee8021QBridgeVlanCurrentTable_Vlan_getByIndex (poEntry->u32ComponentId, poEntry->u32VlanIndex)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_vlanUpdater_cleanup;
	}
	
	if (!ieee8021QBridgeVlanCurrentTable_vlanHandler (poComponent, poIeee8021QBridgeVlanCurrentEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
	{
		goto ieee8021QBridgeVlanStaticTable_vlanUpdater_cleanup;
	}
	
	if (!ieee8021QBridgeVlanStaticTable_vlanUpdate (poComponent, poEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts))
	{
		goto ieee8021QBridgeVlanStaticTable_vlanUpdater_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_vlanUpdater_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticTable_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EgressPorts, uint8_t *pu8ForbiddenEgressPorts, uint8_t *pu8UntaggedPorts)
{
	register bool bRetCode = false;
	register uint8_t *pu8EnabledPorts = NULL;
	register uint8_t *pu8DisabledPorts = NULL;
	register uint8_t *pu8UntaggedPorts2 = NULL;
	register uint8_t *pu8TmpPorts = NULL;
	
	if (pu8EgressPorts == NULL && pu8ForbiddenEgressPorts == NULL && pu8UntaggedPorts == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_handler_success;
	}
	
	pu8EgressPorts == NULL ? pu8EgressPorts = poEntry->au8EgressPorts: false;
	pu8ForbiddenEgressPorts == NULL ? pu8ForbiddenEgressPorts = poEntry->au8ForbiddenEgressPorts: false;
	pu8UntaggedPorts == NULL ? pu8UntaggedPorts = poEntry->au8UntaggedPorts: false;
	
	xBitmap_sub (pu8EgressPorts, pu8EgressPorts, pu8ForbiddenEgressPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_and (pu8UntaggedPorts, pu8EgressPorts, pu8UntaggedPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	
	if ((pu8EnabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8DisabledPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8UntaggedPorts2 = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL ||
		(pu8TmpPorts = xBuffer_cAlloc (poEntry->u16EgressPorts_len)) == NULL)
	{
		goto ieee8021QBridgeVlanStaticTable_handler_cleanup;
	}
	
	xBitmap_xor (pu8EnabledPorts, poEntry->au8EgressPorts, pu8EgressPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_xor (pu8TmpPorts, poEntry->au8UntaggedPorts, pu8UntaggedPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_and (pu8TmpPorts, pu8EgressPorts, pu8TmpPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	
	xBitmap_and (pu8DisabledPorts, poEntry->au8EgressPorts, pu8EnabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_and (pu8EnabledPorts, pu8EgressPorts, pu8EnabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	xBitmap_or (pu8EnabledPorts, pu8EnabledPorts, pu8TmpPorts, xBitmap_bitLength (poEntry->u16UntaggedPorts_len));
	xBitmap_and (pu8UntaggedPorts2, pu8UntaggedPorts, pu8EnabledPorts, xBitmap_bitLength (poEntry->u16EgressPorts_len));
	
	xBuffer_free (pu8TmpPorts);
	
	if ((xBitmap_checkBitRange (pu8EnabledPorts, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 1) != xBitmap_index_invalid_c ||
		 xBitmap_checkBitRange (pu8DisabledPorts, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 1) != xBitmap_index_invalid_c ||
		 xBitmap_checkBitRange (pu8UntaggedPorts2, 0, xBitmap_bitLength (poEntry->u16EgressPorts_len) - 1, 1) != xBitmap_index_invalid_c) &&
		!ieee8021QBridgeVlanStaticTable_vlanUpdater (poComponent, poEntry, pu8EnabledPorts, pu8DisabledPorts, pu8UntaggedPorts2))
	{
		goto ieee8021QBridgeVlanStaticTable_handler_cleanup;
	}
	
ieee8021QBridgeVlanStaticTable_handler_success:
	
	memcpy (poEntry->au8EgressPorts, pu8EgressPorts, poEntry->u16EgressPorts_len);
	memcpy (poEntry->au8ForbiddenEgressPorts, pu8ForbiddenEgressPorts, poEntry->u16ForbiddenEgressPorts_len);
	memcpy (poEntry->au8UntaggedPorts, pu8UntaggedPorts, poEntry->u16UntaggedPorts_len);
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticTable_handler_cleanup:
	
	if (pu8EnabledPorts != NULL)
	{
		xBuffer_free (pu8EnabledPorts);
		xBuffer_free (pu8DisabledPorts);
		xBuffer_free (pu8UntaggedPorts2);
	}
	
	return bRetCode;
}

bool
ieee8021QBridgeVlanStaticRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgeVlanStaticRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021QBridgeVlanStaticRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poComponent->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		/* TODO */
		
		if (!ieee8021QBridgeVlanStaticRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanStaticRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeVlanStaticRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanStaticRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_createAndGo_c:
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeVlanStaticRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeVlanStaticRowStatus_handler_cleanup;
		}
		
		/* TODO */
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeVlanStaticRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeVlanStaticRowStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeVlanStaticTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeVlanStaticTable_BTree);
	return ieee8021QBridgeVlanStaticTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeVlanStaticTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanStaticEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeVlanStaticEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeVlanStaticTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeVlanStaticTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeVlanStaticEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgeVlanStaticTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeVlanStaticTable table mapper */
int
ieee8021QBridgeVlanStaticTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeVlanStaticEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICNAME:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8Name, table_entry->u16Name_len);
				break;
			case IEEE8021QBRIDGEVLANSTATICEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8EgressPorts, table_entry->u16EgressPorts_len);
				break;
			case IEEE8021QBRIDGEVLANFORBIDDENEGRESSPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8ForbiddenEgressPorts, table_entry->u16ForbiddenEgressPorts_len);
				break;
			case IEEE8021QBRIDGEVLANSTATICUNTAGGEDPORTS:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8UntaggedPorts, table_entry->u16UntaggedPorts_len);
				break;
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICNAME:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8Name));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEVLANSTATICEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8EgressPorts));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEVLANFORBIDDENEGRESSPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8ForbiddenEgressPorts));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEVLANSTATICUNTAGGEDPORTS:
				ret = netsnmp_check_vb_type_and_max_size (request->requestvb, ASN_OCTET_STR, sizeof (table_entry->au8UntaggedPorts));
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeVlanStaticTable_createEntry (
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeVlanStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICNAME:
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
			case IEEE8021QBRIDGEVLANSTATICEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8EgressPorts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16EgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8EgressPorts, sizeof (table_entry->au8EgressPorts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8EgressPorts, 0, sizeof (table_entry->au8EgressPorts));
				memcpy (table_entry->au8EgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16EgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGEVLANFORBIDDENEGRESSPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8ForbiddenEgressPorts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16ForbiddenEgressPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8ForbiddenEgressPorts, sizeof (table_entry->au8ForbiddenEgressPorts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8ForbiddenEgressPorts, 0, sizeof (table_entry->au8ForbiddenEgressPorts));
				memcpy (table_entry->au8ForbiddenEgressPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16ForbiddenEgressPorts_len = request->requestvb->val_len;
				break;
			case IEEE8021QBRIDGEVLANSTATICUNTAGGEDPORTS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (xOctetString_t) + sizeof (table_entry->au8UntaggedPorts))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					((xOctetString_t*) pvOldDdata)->pData = pvOldDdata + sizeof (xOctetString_t);
					((xOctetString_t*) pvOldDdata)->u16Len = table_entry->u16UntaggedPorts_len;
					memcpy (((xOctetString_t*) pvOldDdata)->pData, table_entry->au8UntaggedPorts, sizeof (table_entry->au8UntaggedPorts));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				memset (table_entry->au8UntaggedPorts, 0, sizeof (table_entry->au8UntaggedPorts));
				memcpy (table_entry->au8UntaggedPorts, request->requestvb->val.string, request->requestvb->val_len);
				table_entry->u16UntaggedPorts_len = request->requestvb->val_len;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeVlanStaticTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICNAME:
				memcpy (table_entry->au8Name, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16Name_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEVLANSTATICEGRESSPORTS:
				memcpy (table_entry->au8EgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16EgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEVLANFORBIDDENEGRESSPORTS:
				memcpy (table_entry->au8ForbiddenEgressPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16ForbiddenEgressPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEVLANSTATICUNTAGGEDPORTS:
				memcpy (table_entry->au8UntaggedPorts, ((xOctetString_t*) pvOldDdata)->pData, ((xOctetString_t*) pvOldDdata)->u16Len);
				table_entry->u16UntaggedPorts_len = ((xOctetString_t*) pvOldDdata)->u16Len;
				break;
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeVlanStaticTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeVlanStaticEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEVLANSTATICROWSTATUS:
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
					ieee8021QBridgeVlanStaticTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeNextFreeLocalVlanTable table mapper **/
void
ieee8021QBridgeNextFreeLocalVlanTable_init (void)
{
	extern oid ieee8021QBridgeNextFreeLocalVlanTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeNextFreeLocalVlanTable", &ieee8021QBridgeNextFreeLocalVlanTable_mapper,
		ieee8021QBridgeNextFreeLocalVlanTable_oid, OID_LENGTH (ieee8021QBridgeNextFreeLocalVlanTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeNextFreeLocalVlanComponentId */,
		0);
	table_info->min_column = IEEE8021QBRIDGENEXTFREELOCALVLANINDEX;
	table_info->max_column = IEEE8021QBRIDGENEXTFREELOCALVLANINDEX;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeNextFreeLocalVlanTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeNextFreeLocalVlanTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeNextFreeLocalVlanTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
ieee8021QBridgeNextFreeLocalVlanEntry_t *
ieee8021QBridgeNextFreeLocalVlanTable_createEntry (
	uint32_t u32ComponentId)
{
	register ieee8021QBridgeNextFreeLocalVlanEntry_t *poEntry = NULL;
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poComponent->oNextFreeLocalVlan;
	
	return poEntry;
}

ieee8021QBridgeNextFreeLocalVlanEntry_t *
ieee8021QBridgeNextFreeLocalVlanTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oNextFreeLocalVlan;
}

ieee8021QBridgeNextFreeLocalVlanEntry_t *
ieee8021QBridgeNextFreeLocalVlanTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getNextIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oNextFreeLocalVlan;
}

/* remove a row from the table */
void
ieee8021QBridgeNextFreeLocalVlanTable_removeEntry (ieee8021QBridgeNextFreeLocalVlanEntry_t *poEntry)
{
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeNextFreeLocalVlanTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBaseTable_BTree);
	return ieee8021QBridgeNextFreeLocalVlanTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeNextFreeLocalVlanTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021BridgeBaseEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBaseTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeNextFreeLocalVlanTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021BridgeBaseTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeNextFreeLocalVlanTable table mapper */
int
ieee8021QBridgeNextFreeLocalVlanTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeNextFreeLocalVlanEntry_t *table_entry;
	register ieee8021BridgeBaseEntry_t *poEntry = NULL;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oNextFreeLocalVlan;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGENEXTFREELOCALVLANINDEX:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32Index);
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

/** initialize ieee8021QBridgePortTable table mapper **/
void
ieee8021QBridgePortTable_init (void)
{
	extern oid ieee8021QBridgePortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgePortTable", &ieee8021QBridgePortTable_mapper,
		ieee8021QBridgePortTable_oid, OID_LENGTH (ieee8021QBridgePortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		0);
	table_info->min_column = IEEE8021QBRIDGEPORTPVID;
	table_info->max_column = IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgePortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgePortTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgePortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgePortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgePortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgePortEntry_t, oBTreeNode);
	register ieee8021QBridgePortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgePortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort) ? 0: 1;
}

xBTree_t oIeee8021QBridgePortTable_BTree = xBTree_initInline (&ieee8021QBridgePortTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgePortEntry_t *
ieee8021QBridgePortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021QBridgePortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u32PVid = 1;
	poEntry->i32AcceptableFrameTypes = ieee8021QBridgePortAcceptableFrameTypes_admitAll_c;
	poEntry->u8IngressFiltering = ieee8021QBridgePortIngressFiltering_false_c;
	poEntry->u8MvrpEnabledStatus = ieee8021QBridgePortMvrpEnabledStatus_true_c;
	poEntry->u8RestrictedVlanRegistration = ieee8021QBridgePortRestrictedVlanRegistration_false_c;
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree);
	return poEntry;
}

ieee8021QBridgePortEntry_t *
ieee8021QBridgePortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021QBridgePortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgePortEntry_t, oBTreeNode);
}

ieee8021QBridgePortEntry_t *
ieee8021QBridgePortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	register ieee8021QBridgePortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgePortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgePortTable_removeEntry (ieee8021QBridgePortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgePortEntry_t *
ieee8021QBridgePortTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort)
{
	ieee8021QBridgePortEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgePortTable_createEntry (
		u32BridgeBasePortComponentId,
		u32BridgeBasePort);
	if (poEntry == NULL)
	{
		return NULL;
	}
	
	return poEntry;
}

bool
ieee8021QBridgePortTable_removeExt (ieee8021QBridgePortEntry_t *poEntry)
{
	ieee8021QBridgePortTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgePortRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgePortRowStatus_handler_success;
	}
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
	case xRowStatus_notReady_c:
		if (poEntry->u32PVid == 0)
		{
			goto ieee8021QBridgePortRowStatus_handler_cleanup;
		}
		
		if (!ieee8021QBridgePortRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgePortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgePortRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgePortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021QBridgePortRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgePortRowStatus_update (poComponent, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgePortRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgePortRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgePortRowStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgePortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgePortTable_BTree);
	return ieee8021QBridgePortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgePortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgePortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgePortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgePortTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgePortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgePortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	
	poEntry = ieee8021QBridgePortTable_getByIndex (
		*idx1->val.integer,
		*idx2->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgePortTable table mapper */
int
ieee8021QBridgePortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgePortEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPORTPVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_UNSIGNED, table_entry->u32PVid);
				break;
			case IEEE8021QBRIDGEPORTACCEPTABLEFRAMETYPES:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32AcceptableFrameTypes);
				break;
			case IEEE8021QBRIDGEPORTINGRESSFILTERING:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8IngressFiltering);
				break;
			case IEEE8021QBRIDGEPORTMVRPENABLEDSTATUS:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8MvrpEnabledStatus);
				break;
			case IEEE8021QBRIDGEPORTMVRPFAILEDREGISTRATIONS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64MvrpFailedRegistrations);
				break;
			case IEEE8021QBRIDGEPORTMVRPLASTPDUORIGIN:
				snmp_set_var_typed_value (request->requestvb, ASN_OCTET_STR, (u_char*) table_entry->au8MvrpLastPduOrigin, table_entry->u16MvrpLastPduOrigin_len);
				break;
			case IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u8RestrictedVlanRegistration);
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
			table_entry = (ieee8021QBridgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPORTPVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_UNSIGNED);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPORTACCEPTABLEFRAMETYPES:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPORTINGRESSFILTERING:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPORTMVRPENABLEDSTATUS:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION:
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
			table_entry = (ieee8021QBridgePortEntry_t*) netsnmp_extract_iterator_context (request);
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
			table_entry = (ieee8021QBridgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPORTPVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32PVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32PVid, sizeof (table_entry->u32PVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32PVid = *request->requestvb->val.integer;
				break;
			case IEEE8021QBRIDGEPORTACCEPTABLEFRAMETYPES:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32AcceptableFrameTypes))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32AcceptableFrameTypes, sizeof (table_entry->i32AcceptableFrameTypes));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32AcceptableFrameTypes = *request->requestvb->val.integer;
				break;
			case IEEE8021QBRIDGEPORTINGRESSFILTERING:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8IngressFiltering))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8IngressFiltering, sizeof (table_entry->u8IngressFiltering));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8IngressFiltering = *request->requestvb->val.integer;
				break;
			case IEEE8021QBRIDGEPORTMVRPENABLEDSTATUS:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8MvrpEnabledStatus))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8MvrpEnabledStatus, sizeof (table_entry->u8MvrpEnabledStatus));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8MvrpEnabledStatus = *request->requestvb->val.integer;
				break;
			case IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u8RestrictedVlanRegistration))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u8RestrictedVlanRegistration, sizeof (table_entry->u8RestrictedVlanRegistration));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u8RestrictedVlanRegistration = *request->requestvb->val.integer;
				break;
			}
		}
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			table_entry = (ieee8021QBridgePortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPORTPVID:
				memcpy (&table_entry->u32PVid, pvOldDdata, sizeof (table_entry->u32PVid));
				break;
			case IEEE8021QBRIDGEPORTACCEPTABLEFRAMETYPES:
				memcpy (&table_entry->i32AcceptableFrameTypes, pvOldDdata, sizeof (table_entry->i32AcceptableFrameTypes));
				break;
			case IEEE8021QBRIDGEPORTINGRESSFILTERING:
				memcpy (&table_entry->u8IngressFiltering, pvOldDdata, sizeof (table_entry->u8IngressFiltering));
				break;
			case IEEE8021QBRIDGEPORTMVRPENABLEDSTATUS:
				memcpy (&table_entry->u8MvrpEnabledStatus, pvOldDdata, sizeof (table_entry->u8MvrpEnabledStatus));
				break;
			case IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION:
				memcpy (&table_entry->u8RestrictedVlanRegistration, pvOldDdata, sizeof (table_entry->u8RestrictedVlanRegistration));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgePortVlanStatisticsTable table mapper **/
void
ieee8021QBridgePortVlanStatisticsTable_init (void)
{
	extern oid ieee8021QBridgePortVlanStatisticsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgePortVlanStatisticsTable", &ieee8021QBridgePortVlanStatisticsTable_mapper,
		ieee8021QBridgePortVlanStatisticsTable_oid, OID_LENGTH (ieee8021QBridgePortVlanStatisticsTable_oid),
		HANDLER_CAN_RONLY
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_UNSIGNED /* index: ieee8021QBridgeVlanIndex */,
		0);
	table_info->min_column = IEEE8021QBRIDGETPVLANPORTINFRAMES;
	table_info->max_column = IEEE8021QBRIDGETPVLANPORTINDISCARDS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgePortVlanStatisticsTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgePortVlanStatisticsTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgePortVlanStatisticsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgePortVlanStatisticsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgePortVlanStatisticsEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgePortVlanStatisticsEntry_t, oBTreeNode);
	register ieee8021QBridgePortVlanStatisticsEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgePortVlanStatisticsEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32VlanIndex < pEntry2->u32VlanIndex) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32VlanIndex == pEntry2->u32VlanIndex) ? 0: 1;
}

xBTree_t oIeee8021QBridgePortVlanStatisticsTable_BTree = xBTree_initInline (&ieee8021QBridgePortVlanStatisticsTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgePortVlanStatisticsEntry_t *
ieee8021QBridgePortVlanStatisticsTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgePortVlanStatisticsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32VlanIndex = u32VlanIndex;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree);
	return poEntry;
}

ieee8021QBridgePortVlanStatisticsEntry_t *
ieee8021QBridgePortVlanStatisticsTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgePortVlanStatisticsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgePortVlanStatisticsEntry_t, oBTreeNode);
}

ieee8021QBridgePortVlanStatisticsEntry_t *
ieee8021QBridgePortVlanStatisticsTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex)
{
	register ieee8021QBridgePortVlanStatisticsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32VlanIndex = u32VlanIndex;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgePortVlanStatisticsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgePortVlanStatisticsTable_removeEntry (ieee8021QBridgePortVlanStatisticsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgePortVlanStatisticsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgePortVlanStatisticsTable_BTree);
	return ieee8021QBridgePortVlanStatisticsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgePortVlanStatisticsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgePortVlanStatisticsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgePortVlanStatisticsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32VlanIndex);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgePortVlanStatisticsTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgePortVlanStatisticsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgePortVlanStatisticsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgePortVlanStatisticsTable_getByIndex (
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

/* ieee8021QBridgePortVlanStatisticsTable table mapper */
int
ieee8021QBridgePortVlanStatisticsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgePortVlanStatisticsEntry_t *table_entry;
	
	switch (reqinfo->mode)
	{
	/*
	 * Read-support (also covers GetNext requests)
	 */
	case MODE_GET:
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgePortVlanStatisticsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGETPVLANPORTINFRAMES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64InFrames);
				break;
			case IEEE8021QBRIDGETPVLANPORTOUTFRAMES:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64OutFrames);
				break;
			case IEEE8021QBRIDGETPVLANPORTINDISCARDS:
				snmp_set_var_typed_integer (request->requestvb, ASN_COUNTER64, table_entry->u64InDiscards);
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

/** initialize ieee8021QBridgeLearningConstraintsTable table mapper **/
void
ieee8021QBridgeLearningConstraintsTable_init (void)
{
	extern oid ieee8021QBridgeLearningConstraintsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeLearningConstraintsTable", &ieee8021QBridgeLearningConstraintsTable_mapper,
		ieee8021QBridgeLearningConstraintsTable_oid, OID_LENGTH (ieee8021QBridgeLearningConstraintsTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeLearningConstraintsComponentId */,
		ASN_UNSIGNED /* index: ieee8021QBridgeLearningConstraintsVlan */,
		ASN_INTEGER /* index: ieee8021QBridgeLearningConstraintsSet */,
		0);
	table_info->min_column = IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE;
	table_info->max_column = IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeLearningConstraintsTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeLearningConstraintsTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeLearningConstraintsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeLearningConstraintsTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeLearningConstraintsEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeLearningConstraintsEntry_t, oBTreeNode);
	register ieee8021QBridgeLearningConstraintsEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeLearningConstraintsEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Vlan < pEntry2->u32Vlan) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Vlan == pEntry2->u32Vlan && pEntry1->i32Set < pEntry2->i32Set) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->u32Vlan == pEntry2->u32Vlan && pEntry1->i32Set == pEntry2->i32Set) ? 0: 1;
}

xBTree_t oIeee8021QBridgeLearningConstraintsTable_BTree = xBTree_initInline (&ieee8021QBridgeLearningConstraintsTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeLearningConstraintsEntry_t *
ieee8021QBridgeLearningConstraintsTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set)
{
	register ieee8021QBridgeLearningConstraintsEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->u32Vlan = u32Vlan;
	poEntry->i32Set = i32Set;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->i32Type = ieee8021QBridgeLearningConstraintsType_shared_c;
	poEntry->u8Status = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree);
	return poEntry;
}

ieee8021QBridgeLearningConstraintsEntry_t *
ieee8021QBridgeLearningConstraintsTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set)
{
	register ieee8021QBridgeLearningConstraintsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Vlan = u32Vlan;
	poTmpEntry->i32Set = i32Set;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeLearningConstraintsEntry_t, oBTreeNode);
}

ieee8021QBridgeLearningConstraintsEntry_t *
ieee8021QBridgeLearningConstraintsTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set)
{
	register ieee8021QBridgeLearningConstraintsEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->u32Vlan = u32Vlan;
	poTmpEntry->i32Set = i32Set;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeLearningConstraintsEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeLearningConstraintsTable_removeEntry (ieee8021QBridgeLearningConstraintsEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

ieee8021QBridgeLearningConstraintsEntry_t *
ieee8021QBridgeLearningConstraintsTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set)
{
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry = NULL;
	
	if (i32Set < ieee8021QBridgeFdbId_start_c || i32Set > ieee8021QBridgeFdbId_end_c)
	{
		goto ieee8021QBridgeLearningConstraintsTable_createExt_cleanup;
	}
	
	poEntry = ieee8021QBridgeLearningConstraintsTable_createEntry (
		u32ComponentId,
		u32Vlan,
		i32Set);
	if (poEntry == NULL)
	{
		goto ieee8021QBridgeLearningConstraintsTable_createExt_cleanup;
	}
	
	if (!ieee8021QBridgeLearningConstraintsTable_createHier (poEntry))
	{
		ieee8021QBridgeLearningConstraintsTable_removeEntry (poEntry);
		poEntry = NULL;
		goto ieee8021QBridgeLearningConstraintsTable_createExt_cleanup;
	}
	
ieee8021QBridgeLearningConstraintsTable_createExt_cleanup:
	
	return poEntry;
}

bool
ieee8021QBridgeLearningConstraintsTable_removeExt (ieee8021QBridgeLearningConstraintsEntry_t *poEntry)
{
	if (!ieee8021QBridgeLearningConstraintsTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeLearningConstraintsTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeLearningConstraintsTable_createHier (ieee8021QBridgeLearningConstraintsEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
	
	if ((poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, poEntry->i32Set)) == NULL &&
		(poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_createExt (poEntry->u32ComponentId, poEntry->i32Set)) == NULL)
	{
		goto ieee8021QBridgeLearningConstraintsTable_createHier_cleanup;
	}
	poEntry->u32Vlan != ieee8021QBridgeVlanIndex_all_c ? poIeee8021QBridgeFdbEntry->u32NumVlans++: false;
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintsTable_createHier_cleanup:
	
	!bRetCode ? ieee8021QBridgeLearningConstraintsTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintsTable_removeHier (ieee8021QBridgeLearningConstraintsEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021QBridgeFdbEntry_t *poIeee8021QBridgeFdbEntry = NULL;
	
	if ((poIeee8021QBridgeFdbEntry = ieee8021QBridgeFdbTable_getByIndex (poEntry->u32ComponentId, poEntry->i32Set)) != NULL)
	{
		poEntry->u32Vlan != ieee8021QBridgeVlanIndex_all_c && poIeee8021QBridgeFdbEntry->u32NumVlans > 0 ? poIeee8021QBridgeFdbEntry->u32NumVlans--: false;
		if (poIeee8021QBridgeFdbEntry->u32NumVlans == 0 && !ieee8021QBridgeFdbTable_removeExt (poIeee8021QBridgeFdbEntry))
		{
			goto ieee8021QBridgeLearningConstraintsTable_removeHier_cleanup;
		}
	}
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintsTable_removeHier_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintsType_handler (
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry, int32_t i32Type, bool bForce)
{
	register bool bRetCode = false;
	
	if (poEntry->i32Type == i32Type && !bForce)
	{
		goto ieee8021QBridgeLearningConstraintsType_handler_success;
	}
	
	switch (i32Type)
	{
	default:
		goto ieee8021QBridgeLearningConstraintsType_handler_cleanup;
		
	case ieee8021QBridgeLearningConstraintsType_independent_c:
	case ieee8021QBridgeLearningConstraintsType_shared_c:
		if (!ieee8021QBridgeLearningConstraintsType_update (poEntry, i32Type))
		{
			goto ieee8021QBridgeLearningConstraintsType_handler_cleanup;
		}
		break;
	}
	
	!bForce ? (poEntry->i32Type = i32Type): false;
	
ieee8021QBridgeLearningConstraintsType_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintsType_handler_cleanup:
	
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintsStatus_handler (
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	if (poEntry->u8Status == u8RowStatus)
	{
		goto ieee8021QBridgeLearningConstraintsStatus_handler_success;
	}
	
	switch (u8RowStatus)
	{
	case xRowStatus_createAndGo_c:
		u8RowStatus = xRowStatus_active_c;
		
	case xRowStatus_active_c:
		if (!ieee8021QBridgeLearningConstraintsStatus_update (poEntry, u8RowStatus))
		{
			goto ieee8021QBridgeLearningConstraintsStatus_handler_cleanup;
		}
		
		poEntry->u8Status = u8RowStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeLearningConstraintsStatus_update (poEntry, u8RowStatus))
		{
			goto ieee8021QBridgeLearningConstraintsStatus_handler_cleanup;
		}
		
		poEntry->u8Status = u8RowStatus;
		break;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8Status = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeLearningConstraintsStatus_update (poEntry, u8RowStatus))
		{
			goto ieee8021QBridgeLearningConstraintsStatus_handler_cleanup;
		}
		
		poEntry->u8Status = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeLearningConstraintsStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintsStatus_handler_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeLearningConstraintsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeLearningConstraintsTable_BTree);
	return ieee8021QBridgeLearningConstraintsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeLearningConstraintsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeLearningConstraintsEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32Vlan);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32Set);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeLearningConstraintsTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeLearningConstraintsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeLearningConstraintsEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeLearningConstraintsTable_getByIndex (
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

/* ieee8021QBridgeLearningConstraintsTable table mapper */
int
ieee8021QBridgeLearningConstraintsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeLearningConstraintsEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeLearningConstraintsTable_createEntry (
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeLearningConstraintsTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE:
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
				
				if (!ieee8021QBridgeLearningConstraintsType_handler (table_entry, *request->requestvb->val.integer, false))
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
					return SNMP_ERR_NOERROR;
				}
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_NOTINSERVICE:
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
				case RS_DESTROY:
					if (!ieee8021QBridgeLearningConstraintsStatus_handler (table_entry, *request->requestvb->val.integer))
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeLearningConstraintsTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeLearningConstraintsEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					netsnmp_request_remove_list_entry (request, ROLLBACK_BUFFER);
					break;
					
				case RS_DESTROY:
					ieee8021QBridgeLearningConstraintsTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeLearningConstraintDefaultsTable table mapper **/
void
ieee8021QBridgeLearningConstraintDefaultsTable_init (void)
{
	extern oid ieee8021QBridgeLearningConstraintDefaultsTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeLearningConstraintDefaultsTable", &ieee8021QBridgeLearningConstraintDefaultsTable_mapper,
		ieee8021QBridgeLearningConstraintDefaultsTable_oid, OID_LENGTH (ieee8021QBridgeLearningConstraintDefaultsTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeLearningConstraintDefaultsComponentId */,
		0);
	table_info->min_column = IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET;
	table_info->max_column = IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeLearningConstraintDefaultsTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeLearningConstraintDefaultsTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeLearningConstraintDefaultsTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

/* create a new row in the table */
ieee8021QBridgeLearningConstraintDefaultsEntry_t *
ieee8021QBridgeLearningConstraintDefaultsTable_createEntry (
	uint32_t u32ComponentId)
{
	register ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry = NULL;
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	poEntry = &poComponent->oLearningConstraintDefaults;
	
	poEntry->i32Type = ieee8021QBridgeLearningConstraintDefaultsType_shared_c;
	
	return poEntry;
}

ieee8021QBridgeLearningConstraintDefaultsEntry_t *
ieee8021QBridgeLearningConstraintDefaultsTable_getByIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getByIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oLearningConstraintDefaults;
}

ieee8021QBridgeLearningConstraintDefaultsEntry_t *
ieee8021QBridgeLearningConstraintDefaultsTable_getNextIndex (
	uint32_t u32ComponentId)
{
	register ieee8021BridgeBaseEntry_t *poComponent = NULL;
	
	if ((poComponent = ieee8021BridgeBaseTable_getNextIndex (u32ComponentId)) == NULL)
	{
		return NULL;
	}
	
	return &poComponent->oLearningConstraintDefaults;
}

/* remove a row from the table */
void
ieee8021QBridgeLearningConstraintDefaultsTable_removeEntry (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry)
{
	return;
}

ieee8021QBridgeLearningConstraintDefaultsEntry_t *
ieee8021QBridgeLearningConstraintDefaultsTable_createExt (
	uint32_t u32ComponentId)
{
	ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry = NULL;
	
	poEntry = ieee8021QBridgeLearningConstraintDefaultsTable_createEntry (
		u32ComponentId);
	if (poEntry == NULL)
	{
		goto ieee8021QBridgeLearningConstraintDefaultsTable_createExt_cleanup;
	}
	
	if (!ieee8021QBridgeLearningConstraintDefaultsTable_createHier (poEntry))
	{
		ieee8021QBridgeLearningConstraintDefaultsTable_removeEntry (poEntry);
		poEntry = NULL;
		goto ieee8021QBridgeLearningConstraintDefaultsTable_createExt_cleanup;
	}
	
ieee8021QBridgeLearningConstraintDefaultsTable_createExt_cleanup:
	
	return poEntry;
}

bool
ieee8021QBridgeLearningConstraintDefaultsTable_removeExt (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry)
{
	if (!ieee8021QBridgeLearningConstraintDefaultsTable_removeHier (poEntry))
	{
		return false;
	}
	ieee8021QBridgeLearningConstraintDefaultsTable_removeEntry (poEntry);
	
	return true;
}

bool
ieee8021QBridgeLearningConstraintDefaultsTable_createHier (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *poComponent = ieee8021BridgeBaseTable_getByLearningConstraintDefaultsEntry (poEntry);
	
	if (ieee8021QBridgeLearningConstraintsTable_getByIndex (poComponent->u32ComponentId, ieee8021QBridgeVlanIndex_all_c, poEntry->i32Set) == NULL &&
		ieee8021QBridgeLearningConstraintsTable_createExt (poComponent->u32ComponentId, ieee8021QBridgeVlanIndex_all_c, poEntry->i32Set) == NULL)
	{
		goto ieee8021QBridgeLearningConstraintDefaultsTable_createHier_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintDefaultsTable_createHier_cleanup:
	
	!bRetCode ? ieee8021QBridgeLearningConstraintDefaultsTable_removeHier (poEntry): false;
	return bRetCode;
}

bool
ieee8021QBridgeLearningConstraintDefaultsTable_removeHier (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry)
{
	register bool bRetCode = false;
	register ieee8021BridgeBaseEntry_t *poComponent = ieee8021BridgeBaseTable_getByLearningConstraintDefaultsEntry (poEntry);
	register ieee8021QBridgeLearningConstraintsEntry_t *poIeee8021QBridgeLearningConstraintsEntry = NULL;
	
	if ((poIeee8021QBridgeLearningConstraintsEntry = ieee8021QBridgeLearningConstraintsTable_getByIndex (poComponent->u32ComponentId, ieee8021QBridgeVlanIndex_all_c, poEntry->i32Set)) != NULL &&
		!ieee8021QBridgeLearningConstraintsTable_removeExt (poIeee8021QBridgeLearningConstraintsEntry))
	{
		goto ieee8021QBridgeLearningConstraintDefaultsTable_removeHier_cleanup;
	}
	
	bRetCode = true;
	
ieee8021QBridgeLearningConstraintDefaultsTable_removeHier_cleanup:
	
	return bRetCode;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeLearningConstraintDefaultsTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021BridgeBaseTable_BTree);
	return ieee8021QBridgeLearningConstraintDefaultsTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeLearningConstraintDefaultsTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021BridgeBaseEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021BridgeBaseTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeLearningConstraintDefaultsTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021BridgeBaseEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	
	poEntry = ieee8021BridgeBaseTable_getByIndex (
		*idx1->val.integer);
	if (poEntry == NULL)
	{
		return false;
	}
	
	*my_data_context = (void*) poEntry;
	return true;
}

/* ieee8021QBridgeLearningConstraintDefaultsTable table mapper */
int
ieee8021QBridgeLearningConstraintDefaultsTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeLearningConstraintDefaultsEntry_t *table_entry;
	register ieee8021BridgeBaseEntry_t *poEntry = NULL;
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			table_entry = &poEntry->oLearningConstraintDefaults;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Set);
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Type);
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oLearningConstraintDefaults;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE:
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			if (poEntry == NULL)
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
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			table_entry = &poEntry->oLearningConstraintDefaults;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Set))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Set, sizeof (table_entry->i32Set));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Set = *request->requestvb->val.integer;
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE:
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
		break;
		
	case MODE_SET_UNDO:
		for (request = requests; request != NULL; request = request->next)
		{
			pvOldDdata = netsnmp_request_get_list_data (request, ROLLBACK_BUFFER);
			poEntry = (ieee8021BridgeBaseEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (poEntry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			table_entry = &poEntry->oLearningConstraintDefaults;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET:
				memcpy (&table_entry->i32Set, pvOldDdata, sizeof (table_entry->i32Set));
				break;
			case IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE:
				memcpy (&table_entry->i32Type, pvOldDdata, sizeof (table_entry->i32Type));
				break;
			}
		}
		break;
		
	case MODE_SET_COMMIT:
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeProtocolGroupTable table mapper **/
void
ieee8021QBridgeProtocolGroupTable_init (void)
{
	extern oid ieee8021QBridgeProtocolGroupTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeProtocolGroupTable", &ieee8021QBridgeProtocolGroupTable_mapper,
		ieee8021QBridgeProtocolGroupTable_oid, OID_LENGTH (ieee8021QBridgeProtocolGroupTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021QBridgeProtocolGroupComponentId */,
		ASN_INTEGER /* index: ieee8021QBridgeProtocolTemplateFrameType */,
		ASN_OCTET_STR /* index: ieee8021QBridgeProtocolTemplateProtocolValue */,
		0);
	table_info->min_column = IEEE8021QBRIDGEPROTOCOLGROUPID;
	table_info->max_column = IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeProtocolGroupTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeProtocolGroupTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeProtocolGroupTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeProtocolGroupTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeProtocolGroupEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeProtocolGroupEntry_t, oBTreeNode);
	register ieee8021QBridgeProtocolGroupEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeProtocolGroupEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32ComponentId < pEntry2->u32ComponentId) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32TemplateFrameType < pEntry2->i32TemplateFrameType) ||
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32TemplateFrameType == pEntry2->i32TemplateFrameType && xBinCmp (pEntry1->au8TemplateProtocolValue, pEntry2->au8TemplateProtocolValue, pEntry1->u16TemplateProtocolValue_len, pEntry2->u16TemplateProtocolValue_len) == -1) ? -1:
		(pEntry1->u32ComponentId == pEntry2->u32ComponentId && pEntry1->i32TemplateFrameType == pEntry2->i32TemplateFrameType && xBinCmp (pEntry1->au8TemplateProtocolValue, pEntry2->au8TemplateProtocolValue, pEntry1->u16TemplateProtocolValue_len, pEntry2->u16TemplateProtocolValue_len) == 0) ? 0: 1;
}

xBTree_t oIeee8021QBridgeProtocolGroupTable_BTree = xBTree_initInline (&ieee8021QBridgeProtocolGroupTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeProtocolGroupEntry_t *
ieee8021QBridgeProtocolGroupTable_createEntry (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len)
{
	register ieee8021QBridgeProtocolGroupEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32ComponentId = u32ComponentId;
	poEntry->i32TemplateFrameType = i32TemplateFrameType;
	memcpy (poEntry->au8TemplateProtocolValue, pau8TemplateProtocolValue, u16TemplateProtocolValue_len);
	poEntry->u16TemplateProtocolValue_len = u16TemplateProtocolValue_len;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree);
	return poEntry;
}

ieee8021QBridgeProtocolGroupEntry_t *
ieee8021QBridgeProtocolGroupTable_getByIndex (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len)
{
	register ieee8021QBridgeProtocolGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->i32TemplateFrameType = i32TemplateFrameType;
	memcpy (poTmpEntry->au8TemplateProtocolValue, pau8TemplateProtocolValue, u16TemplateProtocolValue_len);
	poTmpEntry->u16TemplateProtocolValue_len = u16TemplateProtocolValue_len;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeProtocolGroupEntry_t, oBTreeNode);
}

ieee8021QBridgeProtocolGroupEntry_t *
ieee8021QBridgeProtocolGroupTable_getNextIndex (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len)
{
	register ieee8021QBridgeProtocolGroupEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32ComponentId = u32ComponentId;
	poTmpEntry->i32TemplateFrameType = i32TemplateFrameType;
	memcpy (poTmpEntry->au8TemplateProtocolValue, pau8TemplateProtocolValue, u16TemplateProtocolValue_len);
	poTmpEntry->u16TemplateProtocolValue_len = u16TemplateProtocolValue_len;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeProtocolGroupEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeProtocolGroupTable_removeEntry (ieee8021QBridgeProtocolGroupEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeProtocolGroupTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeProtocolGroupTable_BTree);
	return ieee8021QBridgeProtocolGroupTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeProtocolGroupTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeProtocolGroupEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeProtocolGroupEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32ComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32TemplateFrameType);
	idx = idx->next_variable;
	snmp_set_var_value (idx, poEntry->au8TemplateProtocolValue, poEntry->u16TemplateProtocolValue_len);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolGroupTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeProtocolGroupTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeProtocolGroupEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeProtocolGroupTable_getByIndex (
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

/* ieee8021QBridgeProtocolGroupTable table mapper */
int
ieee8021QBridgeProtocolGroupTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeProtocolGroupEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->i32Id);
				break;
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeProtocolGroupTable_createEntry (
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeProtocolGroupTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->i32Id))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->i32Id, sizeof (table_entry->i32Id));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->i32Id = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeProtocolGroupTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPID:
				memcpy (&table_entry->i32Id, pvOldDdata, sizeof (table_entry->i32Id));
				break;
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeProtocolGroupTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeProtocolGroupEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS:
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
					ieee8021QBridgeProtocolGroupTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeProtocolPortTable table mapper **/
void
ieee8021QBridgeProtocolPortTable_init (void)
{
	extern oid ieee8021QBridgeProtocolPortTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeProtocolPortTable", &ieee8021QBridgeProtocolPortTable_mapper,
		ieee8021QBridgeProtocolPortTable_oid, OID_LENGTH (ieee8021QBridgeProtocolPortTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021QBridgeProtocolPortGroupId */,
		0);
	table_info->min_column = IEEE8021QBRIDGEPROTOCOLPORTGROUPVID;
	table_info->max_column = IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeProtocolPortTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeProtocolPortTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeProtocolPortTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeProtocolPortTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeProtocolPortEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeProtocolPortEntry_t, oBTreeNode);
	register ieee8021QBridgeProtocolPortEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeProtocolPortEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->i32GroupId < pEntry2->i32GroupId) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->i32GroupId == pEntry2->i32GroupId) ? 0: 1;
}

xBTree_t oIeee8021QBridgeProtocolPortTable_BTree = xBTree_initInline (&ieee8021QBridgeProtocolPortTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeProtocolPortEntry_t *
ieee8021QBridgeProtocolPortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId)
{
	register ieee8021QBridgeProtocolPortEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->i32GroupId = i32GroupId;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree);
	return poEntry;
}

ieee8021QBridgeProtocolPortEntry_t *
ieee8021QBridgeProtocolPortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId)
{
	register ieee8021QBridgeProtocolPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->i32GroupId = i32GroupId;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeProtocolPortEntry_t, oBTreeNode);
}

ieee8021QBridgeProtocolPortEntry_t *
ieee8021QBridgeProtocolPortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId)
{
	register ieee8021QBridgeProtocolPortEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->i32GroupId = i32GroupId;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeProtocolPortEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeProtocolPortTable_removeEntry (ieee8021QBridgeProtocolPortEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeProtocolPortTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeProtocolPortTable_BTree);
	return ieee8021QBridgeProtocolPortTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeProtocolPortTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeProtocolPortEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeProtocolPortEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->i32GroupId);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeProtocolPortTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeProtocolPortTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeProtocolPortEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeProtocolPortTable_getByIndex (
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

/* ieee8021QBridgeProtocolPortTable table mapper */
int
ieee8021QBridgeProtocolPortTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeProtocolPortEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTGROUPVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32GroupVid);
				break;
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTGROUPVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeProtocolPortTable_createEntry (
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeProtocolPortTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTGROUPVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32GroupVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32GroupVid, sizeof (table_entry->u32GroupVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32GroupVid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeProtocolPortTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTGROUPVID:
				memcpy (&table_entry->u32GroupVid, pvOldDdata, sizeof (table_entry->u32GroupVid));
				break;
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeProtocolPortTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeProtocolPortEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS:
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
					ieee8021QBridgeProtocolPortTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeIngressVidXTable table mapper **/
void
ieee8021QBridgeIngressVidXTable_init (void)
{
	extern oid ieee8021QBridgeIngressVidXTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeIngressVidXTable", &ieee8021QBridgeIngressVidXTable_mapper,
		ieee8021QBridgeIngressVidXTable_oid, OID_LENGTH (ieee8021QBridgeIngressVidXTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePortComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021QBridgeIngressVidXLocalVid */,
		0);
	table_info->min_column = IEEE8021QBRIDGEINGRESSVIDXRELAYVID;
	table_info->max_column = IEEE8021QBRIDGEINGRESSVIDXROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeIngressVidXTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeIngressVidXTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeIngressVidXTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeIngressVidXTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeIngressVidXEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeIngressVidXEntry_t, oBTreeNode);
	register ieee8021QBridgeIngressVidXEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeIngressVidXEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBasePortComponentId < pEntry2->u32BridgeBasePortComponentId) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32LocalVid < pEntry2->u32LocalVid) ? -1:
		(pEntry1->u32BridgeBasePortComponentId == pEntry2->u32BridgeBasePortComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32LocalVid == pEntry2->u32LocalVid) ? 0: 1;
}

xBTree_t oIeee8021QBridgeIngressVidXTable_BTree = xBTree_initInline (&ieee8021QBridgeIngressVidXTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeIngressVidXEntry_t *
ieee8021QBridgeIngressVidXTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid)
{
	register ieee8021QBridgeIngressVidXEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32LocalVid = u32LocalVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree);
	return poEntry;
}

ieee8021QBridgeIngressVidXEntry_t *
ieee8021QBridgeIngressVidXTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid)
{
	register ieee8021QBridgeIngressVidXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32LocalVid = u32LocalVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeIngressVidXEntry_t, oBTreeNode);
}

ieee8021QBridgeIngressVidXEntry_t *
ieee8021QBridgeIngressVidXTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid)
{
	register ieee8021QBridgeIngressVidXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBasePortComponentId = u32BridgeBasePortComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32LocalVid = u32LocalVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeIngressVidXEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeIngressVidXTable_removeEntry (ieee8021QBridgeIngressVidXEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

bool
ieee8021QBridgeIngressVidXRowStatus_handler (
	ieee8021QBridgeIngressVidXEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBasePortComponentId)) == NULL)
	{
		goto ieee8021QBridgeIngressVidXRowStatus_handler_cleanup;
	}
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgeIngressVidXRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021QBridgeIngressVidXRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poIeee8021BridgeBaseEntry->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021QBridgeIngressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeIngressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeIngressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeIngressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021QBridgeIngressVidXRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeIngressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeIngressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeIngressVidXRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeIngressVidXRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeIngressVidXTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeIngressVidXTable_BTree);
	return ieee8021QBridgeIngressVidXTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeIngressVidXTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeIngressVidXEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeIngressVidXEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePortComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32LocalVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeIngressVidXTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeIngressVidXTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeIngressVidXEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeIngressVidXTable_getByIndex (
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

/* ieee8021QBridgeIngressVidXTable table mapper */
int
ieee8021QBridgeIngressVidXTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeIngressVidXEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXRELAYVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32RelayVid);
				break;
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXRELAYVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeIngressVidXTable_createEntry (
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeIngressVidXTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXRELAYVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32RelayVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32RelayVid, sizeof (table_entry->u32RelayVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32RelayVid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeIngressVidXTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXRELAYVID:
				memcpy (&table_entry->u32RelayVid, pvOldDdata, sizeof (table_entry->u32RelayVid));
				break;
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeIngressVidXTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeIngressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEINGRESSVIDXROWSTATUS:
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
					ieee8021QBridgeIngressVidXTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}

/** initialize ieee8021QBridgeEgressVidXTable table mapper **/
void
ieee8021QBridgeEgressVidXTable_init (void)
{
	extern oid ieee8021QBridgeEgressVidXTable_oid[];
	netsnmp_handler_registration *reg;
	netsnmp_iterator_info *iinfo;
	netsnmp_table_registration_info *table_info;
	
	reg = netsnmp_create_handler_registration (
		"ieee8021QBridgeEgressVidXTable", &ieee8021QBridgeEgressVidXTable_mapper,
		ieee8021QBridgeEgressVidXTable_oid, OID_LENGTH (ieee8021QBridgeEgressVidXTable_oid),
		HANDLER_CAN_RWRITE
		);
		
	table_info = xBuffer_cAlloc (sizeof (netsnmp_table_registration_info));
	netsnmp_table_helper_add_indexes (table_info,
		ASN_UNSIGNED /* index: ieee8021BridgeBaseComponentId */,
		ASN_UNSIGNED /* index: ieee8021BridgeBasePort */,
		ASN_INTEGER /* index: ieee8021QBridgeEgressVidXRelayVid */,
		0);
	table_info->min_column = IEEE8021QBRIDGEEGRESSVIDXLOCALVID;
	table_info->max_column = IEEE8021QBRIDGEEGRESSVIDXROWSTATUS;
	
	iinfo = xBuffer_cAlloc (sizeof (netsnmp_iterator_info));
	iinfo->get_first_data_point = &ieee8021QBridgeEgressVidXTable_getFirst;
	iinfo->get_next_data_point = &ieee8021QBridgeEgressVidXTable_getNext;
	iinfo->get_data_point = &ieee8021QBridgeEgressVidXTable_get;
	iinfo->table_reginfo = table_info;
	iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
	
	netsnmp_register_table_iterator (reg, iinfo);
	
	/* Initialise the contents of the table here */
}

static int8_t
ieee8021QBridgeEgressVidXTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ieee8021QBridgeEgressVidXEntry_t *pEntry1 = xBTree_entry (pNode1, ieee8021QBridgeEgressVidXEntry_t, oBTreeNode);
	register ieee8021QBridgeEgressVidXEntry_t *pEntry2 = xBTree_entry (pNode2, ieee8021QBridgeEgressVidXEntry_t, oBTreeNode);
	
	return
		(pEntry1->u32BridgeBaseComponentId < pEntry2->u32BridgeBaseComponentId) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32BridgeBasePort < pEntry2->u32BridgeBasePort) ||
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32RelayVid < pEntry2->u32RelayVid) ? -1:
		(pEntry1->u32BridgeBaseComponentId == pEntry2->u32BridgeBaseComponentId && pEntry1->u32BridgeBasePort == pEntry2->u32BridgeBasePort && pEntry1->u32RelayVid == pEntry2->u32RelayVid) ? 0: 1;
}

xBTree_t oIeee8021QBridgeEgressVidXTable_BTree = xBTree_initInline (&ieee8021QBridgeEgressVidXTable_BTreeNodeCmp);

/* create a new row in the table */
ieee8021QBridgeEgressVidXEntry_t *
ieee8021QBridgeEgressVidXTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid)
{
	register ieee8021QBridgeEgressVidXEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poEntry->u32BridgeBasePort = u32BridgeBasePort;
	poEntry->u32RelayVid = u32RelayVid;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	poEntry->u8RowStatus = xRowStatus_notInService_c;
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree);
	return poEntry;
}

ieee8021QBridgeEgressVidXEntry_t *
ieee8021QBridgeEgressVidXTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid)
{
	register ieee8021QBridgeEgressVidXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32RelayVid = u32RelayVid;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeEgressVidXEntry_t, oBTreeNode);
}

ieee8021QBridgeEgressVidXEntry_t *
ieee8021QBridgeEgressVidXTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid)
{
	register ieee8021QBridgeEgressVidXEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32BridgeBaseComponentId = u32BridgeBaseComponentId;
	poTmpEntry->u32BridgeBasePort = u32BridgeBasePort;
	poTmpEntry->u32RelayVid = u32RelayVid;
	if ((poNode = xBTree_nodeFindNext (&poTmpEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ieee8021QBridgeEgressVidXEntry_t, oBTreeNode);
}

/* remove a row from the table */
void
ieee8021QBridgeEgressVidXTable_removeEntry (ieee8021QBridgeEgressVidXEntry_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}

bool
ieee8021QBridgeEgressVidXRowStatus_handler (
	ieee8021QBridgeEgressVidXEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register uint8_t u8RealStatus = u8RowStatus & xRowStatus_mask_c;
	register ieee8021BridgeBaseEntry_t *poIeee8021BridgeBaseEntry = NULL;
	
	if ((poIeee8021BridgeBaseEntry = ieee8021BridgeBaseTable_getByIndex (poEntry->u32BridgeBaseComponentId)) == NULL)
	{
		goto ieee8021QBridgeEgressVidXRowStatus_handler_cleanup;
	}
	
	if (poEntry->u8RowStatus == u8RealStatus)
	{
		goto ieee8021QBridgeEgressVidXRowStatus_handler_success;
	}
	if (u8RowStatus & xRowStatus_fromParent_c &&
		((u8RealStatus == xRowStatus_active_c && poEntry->u8RowStatus != xRowStatus_notReady_c) ||
		 (u8RealStatus == xRowStatus_notInService_c && poEntry->u8RowStatus != xRowStatus_active_c)))
	{
		goto ieee8021QBridgeEgressVidXRowStatus_handler_success;
	}
	
	
	switch (u8RealStatus)
	{
	case xRowStatus_active_c:
		if (!(u8RowStatus & xRowStatus_fromParent_c) && poIeee8021BridgeBaseEntry->u8RowStatus != xRowStatus_active_c)
		{
			u8RealStatus = xRowStatus_notReady_c;
		}
		
		if (!ieee8021QBridgeEgressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeEgressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = u8RealStatus;
		break;
		
	case xRowStatus_notInService_c:
		if (!ieee8021QBridgeEgressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeEgressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus =
			poEntry->u8RowStatus == xRowStatus_active_c && (u8RowStatus & xRowStatus_fromParent_c) ? xRowStatus_notReady_c: xRowStatus_notInService_c;
		break;
		
	case xRowStatus_createAndGo_c:
		goto ieee8021QBridgeEgressVidXRowStatus_handler_cleanup;
		
	case xRowStatus_createAndWait_c:
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
		
	case xRowStatus_destroy_c:
		if (!ieee8021QBridgeEgressVidXRowStatus_update (poIeee8021BridgeBaseEntry, poEntry, u8RealStatus))
		{
			goto ieee8021QBridgeEgressVidXRowStatus_handler_cleanup;
		}
		
		poEntry->u8RowStatus = xRowStatus_notInService_c;
		break;
	}
	
ieee8021QBridgeEgressVidXRowStatus_handler_success:
	
	bRetCode = true;
	
ieee8021QBridgeEgressVidXRowStatus_handler_cleanup:
	
	return bRetCode || (u8RowStatus & xRowStatus_fromParent_c);
}

/* example iterator hook routines - using 'getNext' to do most of the work */
netsnmp_variable_list *
ieee8021QBridgeEgressVidXTable_getFirst (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	*my_loop_context = xBTree_nodeGetFirst (&oIeee8021QBridgeEgressVidXTable_BTree);
	return ieee8021QBridgeEgressVidXTable_getNext (my_loop_context, my_data_context, put_index_data, mydata);
}

netsnmp_variable_list *
ieee8021QBridgeEgressVidXTable_getNext (
	void **my_loop_context, void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeEgressVidXEntry_t *poEntry = NULL;
	netsnmp_variable_list *idx = put_index_data;
	
	if (*my_loop_context == NULL)
	{
		return NULL;
	}
	poEntry = xBTree_entry (*my_loop_context, ieee8021QBridgeEgressVidXEntry_t, oBTreeNode);
	
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBaseComponentId);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_UNSIGNED, poEntry->u32BridgeBasePort);
	idx = idx->next_variable;
	snmp_set_var_typed_integer (idx, ASN_INTEGER, poEntry->u32RelayVid);
	*my_data_context = (void*) poEntry;
	*my_loop_context = (void*) xBTree_nodeGetNext (&poEntry->oBTreeNode, &oIeee8021QBridgeEgressVidXTable_BTree);
	return put_index_data;
}

bool
ieee8021QBridgeEgressVidXTable_get (
	void **my_data_context,
	netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	ieee8021QBridgeEgressVidXEntry_t *poEntry = NULL;
	register netsnmp_variable_list *idx1 = put_index_data;
	register netsnmp_variable_list *idx2 = idx1->next_variable;
	register netsnmp_variable_list *idx3 = idx2->next_variable;
	
	poEntry = ieee8021QBridgeEgressVidXTable_getByIndex (
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

/* ieee8021QBridgeEgressVidXTable table mapper */
int
ieee8021QBridgeEgressVidXTable_mapper (
	netsnmp_mib_handler *handler,
	netsnmp_handler_registration *reginfo,
	netsnmp_agent_request_info *reqinfo,
	netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *table_info;
	ieee8021QBridgeEgressVidXEntry_t *table_entry;
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL)
			{
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXLOCALVID:
				snmp_set_var_typed_integer (request->requestvb, ASN_INTEGER, table_entry->u32LocalVid);
				break;
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXLOCALVID:
				ret = netsnmp_check_vb_type (requests->requestvb, ASN_INTEGER);
				if (ret != SNMP_ERR_NOERROR)
				{
					netsnmp_set_request_error (reqinfo, request, ret);
					return SNMP_ERR_NOERROR;
				}
				break;
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			register netsnmp_variable_list *idx1 = table_info->indexes;
			register netsnmp_variable_list *idx2 = idx1->next_variable;
			register netsnmp_variable_list *idx3 = idx2->next_variable;
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					if (/* TODO */ TOBE_REPLACED != TOBE_REPLACED)
					{
						netsnmp_set_request_error (reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
						return SNMP_ERR_NOERROR;
					}
					
					table_entry = ieee8021QBridgeEgressVidXTable_createEntry (
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeEgressVidXTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXLOCALVID:
				if (pvOldDdata == NULL && (pvOldDdata = xBuffer_cAlloc (sizeof (table_entry->u32LocalVid))) == NULL)
				{
					netsnmp_set_request_error (reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);
					return SNMP_ERR_NOERROR;
				}
				else if (pvOldDdata != table_entry)
				{
					memcpy (pvOldDdata, &table_entry->u32LocalVid, sizeof (table_entry->u32LocalVid));
					netsnmp_request_add_list_data (request, netsnmp_create_data_list (ROLLBACK_BUFFER, pvOldDdata, &xBuffer_free));
				}
				
				table_entry->u32LocalVid = *request->requestvb->val.integer;
				break;
			}
		}
		/* Check the internal consistency of an active row */
		for (request = requests; request != NULL; request = request->next)
		{
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_ACTIVE:
				case RS_CREATEANDGO:
					if (/* TODO : int ieee8021QBridgeEgressVidXTable_dep (...) */ TOBE_REPLACED != TOBE_REPLACED)
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			if (table_entry == NULL || pvOldDdata == NULL)
			{
				continue;
			}
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXLOCALVID:
				memcpy (&table_entry->u32LocalVid, pvOldDdata, sizeof (table_entry->u32LocalVid));
				break;
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
				switch (*request->requestvb->val.integer)
				{
				case RS_CREATEANDGO:
				case RS_CREATEANDWAIT:
					ieee8021QBridgeEgressVidXTable_removeEntry (table_entry);
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
			table_entry = (ieee8021QBridgeEgressVidXEntry_t*) netsnmp_extract_iterator_context (request);
			table_info = netsnmp_extract_table_info (request);
			
			switch (table_info->colnum)
			{
			case IEEE8021QBRIDGEEGRESSVIDXROWSTATUS:
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
					ieee8021QBridgeEgressVidXTable_removeEntry (table_entry);
					break;
				}
			}
		}
		break;
	}
	
	return SNMP_ERR_NOERROR;
}
