#*
#*  Copyright (c) 2008-2016
#*      NES Repo <nes.repo@gmail.com>
#*
#*  All rights reserved. This source file is the sole property of NES, and
#*  contain proprietary and confidential information related to NES.
#*
#*  Licensed under the NES RED License, Version 1.0 (the "License"); you may
#*  not use this file except in compliance with the License. You may obtain a
#*  copy of the License bundled along with this file. Any kind of reproduction
#*  or duplication of any part of this file which conflicts with the License
#*  without prior written consent from NES is strictly prohibited.
#*
#*  Unless required by applicable law and agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#*  License for the specific language governing permissions and limitations
#*  under the License.
#*

MODULE := snmp
MODULE_BIN = ${MODULE}${OBJ_EXT}
MODULE_TREE :=
NET_SNMP_CONFIG := net-snmp-config


ifneq (${PROJECT_NAME},)
SNMP_CFLAGS := $(shell ${NET_SNMP_CONFIG} --cflags)
SNMP_LDFLAGS := $(shell ${NET_SNMP_CONFIG} --libdir)
SNMP_LDLIBS := $(shell ${NET_SNMP_CONFIG} --base-agent-libs) $(shell ${NET_SNMP_CONFIG} --external-agent-libs)
$(eval $(call MODULE_INC,${MODULE},${MODULE_TREE}))
else

include ${MK_COMMON}

CFLAGS +=

SNMP_SRC := snmp_main.c snmpMIB.c
MODULE_SRC := ${SNMP_SRC}

$(call MODULE_DEP,${MODULE_SRC},${CFLAGS},${INCLUDES})

$(SNMP_SRC:%.c=%.o): CFLAGS += ${SNMP_CFLAGS}

all: ${MODULE_BIN}

${MODULE_BIN}: $(MODULE_SRC:%.c=%.o)

include make.dep

endif
