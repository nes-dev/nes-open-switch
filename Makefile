#*
#*  Copyright (c) 2008-2015
#*      NES <nes.open.switch@gmail.com>
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

PROJECT_NAME	:= switch
PROJECT_BIN	:= ${PROJECT_NAME}
PROJECT_DIR	:= ${CURDIR}
MK_COMMON	:= $(abspath ${PROJECT_DIR}/Makefile.common)


INCLUDES	:= -I${PROJECT_DIR} -I${PROJECT_DIR}/include
DEFINES		:= -D_POSIX_C_SOURCE=200112 -D_POSIX_SOURCE=200112 -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -D_REENTRANT
CFLAGS		+= -std=gnu99 -Wall -g -O3
#CFLAGS		+= -std=gnu99 -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -D_REENTRANT -Wall -g
LDFLAGS		+= -lrt -lpthread
LDLIBS		:=

SNMP_CFLAGS	:=
SNMP_LDFLAGS	:=
SNMP_LDLIBS	:=


include ${MK_COMMON}

PROJECT_OBJS	:=

MODULE_TREE	:= lib snmp system if hal ethernet lag bridge cfm stp inet tcpUdp
MODULE_PATH	:= .

include $(addsuffix /Makefile,${MODULE_TREE})


export DEFINES
export CFLAGS
export SNMP_CFLAGS
export LDFLAGS
export SNMP_LDFLAGS
export INCLUDES
export MK_COMMON



MODULE		:= ${PROJECT_NAME}
MODULE_BIN	:= ${MODULE}${OBJ_EXT}
MODULE_SRC	:= switch_main.c


$(call MODULE_DEP,${MODULE_SRC},${CFLAGS},${INCLUDES})

$(call CHK_MODULE_TREE,${PROJECT_OBJS})

all: check_module_tree ${PROJECT_BIN}

${PROJECT_BIN}: LDFLAGS += ${SNMP_LDFLAGS}
${PROJECT_BIN}: LDLIBS += ${SNMP_LDLIBS}
${PROJECT_BIN}: ${PROJECT_OBJS} ${MODULE_BIN}

${MODULE_BIN}: $(MODULE_SRC:%.c=%.o)

$(call MK_MODULE_TREE,${PROJECT_OBJS})

include make.dep
