/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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

#ifndef __ENTITYMIB_AGENT_H__
#	define __ENTITYMIB_AGENT_H__

#	ifdef __cplusplus
extern "C" {
#	endif



/**
 *	agent MIB function
 */
void entityMIB_init (void);


/**
 *	notification mapper(s)
 */
int entConfigChange_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __ENTITYMIB_AGENT_H__ */
