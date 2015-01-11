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
//set ts=4 sw=4

#ifndef __NUMBER_C__
#	define __NUMBER_C__



#include "number.h"

#include <stdbool.h>
#include <stdint.h>


bool
xNumber_toUint32 (
	void *pvNumber, uint16_t u16NumberSize,
	uint16_t u16StartByte, uint16_t u16StopByte,
	uint32_t *pu32Number)
{
	if (u16StopByte - u16StartByte >= 4 ||
		u16StartByte > u16StopByte ||
		u16StartByte >= u16NumberSize ||
		u16StopByte >= u16NumberSize)
	{
		return false;
	}
	
	for (register uint16_t u16Index = u16StopByte, u16Offset = 0; u16StopByte >= u16Index && u16Index >= u16StartByte; u16Index--, u16Offset++)
	{
		*pu32Number += (((uint8_t*) pvNumber)[u16Index] << (u16Offset << 3));
	}
	
	return true;
}

bool
xNumber_toUint64 (
	void *pvNumber, uint16_t u16NumberSize,
	uint16_t u16StartByte, uint16_t u16StopByte,
	uint64_t *pu64Number)
{
	if (u16StopByte - u16StartByte >= 8 ||
		u16StartByte > u16StopByte ||
		u16StartByte >= u16NumberSize ||
		u16StopByte >= u16NumberSize)
	{
		return false;
	}
	
	for (register uint16_t u16Index = u16StopByte, u16Offset = 0; u16StopByte >= u16Index && u16Index >= u16StartByte; u16Index--, u16Offset++)
	{
		*pu64Number += (((uint8_t*) pvNumber)[u16Index] << (u16Offset << 3));
	}
	
	return true;
}

bool
xNumber_checkUint32 (
	void *pvNumber, uint16_t u16NumberSize)
{
	register uint16_t u16Index = 0;
	
	if (u16NumberSize <= 4)
	{
		return true;
	}
	
	for (u16Index = u16NumberSize - 5; u16NumberSize > u16Index && u16Index >= 0 && ((uint8_t *) pvNumber)[u16Index] == 0; u16Index--);
	
	return u16Index == 0xFFFF && ((uint8_t *) pvNumber)[0] == 0;
}

bool
xNumber_checkUint64 (
	void *pvNumber, uint16_t u16NumberSize)
{
	register uint16_t u16Index = 0;
	
	if (u16NumberSize <= 8)
	{
		return true;
	}
	
	for (u16Index = u16NumberSize - 9; u16NumberSize > u16Index && u16Index >= 0 && ((uint8_t *) pvNumber)[u16Index] == 0; u16Index--);
	
	return u16Index == 0xFFFF && ((uint8_t *) pvNumber)[0] == 0;
}



#endif	// __NUMBER_C__
