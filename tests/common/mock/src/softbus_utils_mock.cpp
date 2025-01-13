/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_utils_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_utilsInterface;

UtilsInterfaceMock::UtilsInterfaceMock()
{
    g_utilsInterface = reinterpret_cast<void *>(this);
}

UtilsInterfaceMock::~UtilsInterfaceMock()
{
    g_utilsInterface = nullptr;
}

static UtilsInterface *GetUtilsInterface()
{
    return reinterpret_cast<UtilsInterfaceMock *>(g_utilsInterface);
}

extern "C" {
int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback)
{
    return GetUtilsInterface()->RegisterTimeoutCallback(timerFunId, callback);
}

int32_t SoftBusTimerInit(void)
{
    return GetUtilsInterface()->SoftBusTimerInit();
}

void SoftBusTimerDeInit(void)
{
    GetUtilsInterface()->SoftBusTimerDeInit();
}

SoftBusList *CreateSoftBusList(void)
{
    return GetUtilsInterface()->CreateSoftBusList();
}

void DestroySoftBusList(SoftBusList *list)
{
    GetUtilsInterface()->DestroySoftBusList(list);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetUtilsInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t ConvertBtMacToStrNoColon(char *strMac, uint32_t strMacLen, const uint8_t *binMac,
    uint32_t binMacLen)
{
    return GetUtilsInterface()->ConvertBtMacToStrNoColon(strMac, strMacLen, binMac, binMacLen);
}

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, uint32_t inLen)
{
    return GetUtilsInterface()->ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
}

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetUtilsInterface()->ConvertBytesToUpperCaseHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t GenerateRandomStr(char *str, uint32_t size)
{
    return GetUtilsInterface()->GenerateRandomStr(str, size);
}

bool IsValidString(const char *input, uint32_t maxLen)
{
    return GetUtilsInterface()->IsValidString(input, maxLen);
}

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen)
{
    return GetUtilsInterface()->ConvertBtMacToBinary(strMac, strMacLen, binMac, binMacLen);
}

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return GetUtilsInterface()->ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
}

int32_t ConvertReverseBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return GetUtilsInterface()->ConvertReverseBtMacToStr(strMac, strMacLen, binMac, binMacLen);
}

int32_t ConvertBtMacToU64(const char *strMac, uint32_t strMacLen, uint64_t *u64Mac)
{
    return GetUtilsInterface()->ConvertBtMacToU64(strMac, strMacLen, u64Mac);
}

int32_t ConvertU64MacToStr(uint64_t u64Mac, char *strMac, uint32_t strMacLen)
{
    return GetUtilsInterface()->ConvertU64MacToStr(u64Mac, strMac, strMacLen);
}

bool Int64ToString(int64_t src, char *buf, uint32_t bufLen)
{
    return GetUtilsInterface()->Int64ToString(src, buf, bufLen);
}

int32_t StrCmpIgnoreCase(const char *str1, const char *str2)
{
    return GetUtilsInterface()->StrCmpIgnoreCase(str1, str2);
}

int32_t StringToUpperCase(const char *str, char *buf, int32_t size)
{
    return GetUtilsInterface()->StringToUpperCase(str, buf, size);
}

int32_t StringToLowerCase(const char *str, char *buf, int32_t size)
{
    return GetUtilsInterface()->StringToLowerCase(str, buf, size);
}

int32_t WriteInt32ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t data)
{
    return GetUtilsInterface()->WriteInt32ToBuf(buf, dataLen, offSet, data);
}

int32_t WriteUint8ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t data)
{
    return GetUtilsInterface()->WriteUint8ToBuf(buf, dataLen, offSet, data);
}

int32_t ReadInt32FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t *data)
{
    return GetUtilsInterface()->ReadInt32FromBuf(buf, dataLen, offSet, data);
}


int32_t ReadUint8FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t *data)
{
    return GetUtilsInterface()->ReadUint8FromBuf(buf, dataLen, offSet, data);
}

void SetSignalingMsgSwitchOn(void)
{
    GetUtilsInterface()->SetSignalingMsgSwitchOn();
}

void SetSignalingMsgSwitchOff(void)
{
    GetUtilsInterface()->SetSignalingMsgSwitchOff();
}

bool GetSignalingMsgSwitch(void)
{
    return GetUtilsInterface()->GetSignalingMsgSwitch();
}
}
} // namespace OHOS