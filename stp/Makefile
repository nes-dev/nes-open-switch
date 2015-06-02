#*
#*  Copyright (c) 2008-2015
#*      NES Dev <nes.open.switch@gmail.com>
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

MODULE := stp
MODULE_BIN = ${MODULE}${OBJ_EXT}
MODULE_TREE :=


ifneq (${PROJECT_NAME},)
$(eval $(call MODULE_INC,${MODULE},${MODULE_TREE}))
else

include ${MK_COMMON}

CFLAGS +=

SNMP_SRC := ieee8021SpanningTreeMib.c ieee8021MstpMib.c neIeee8021StpMIB.c
MODULE_SRC := stp_main.c stpUtils.c ${SNMP_SRC}

$(call MODULE_DEP,${MODULE_SRC},${CFLAGS},${INCLUDES})

$(SNMP_SRC:%.c=%.o): CFLAGS += ${SNMP_CFLAGS}

all: ${MODULE_BIN}

${MODULE_BIN}: $(MODULE_SRC:%.c=%.o)

include make.dep

endif
