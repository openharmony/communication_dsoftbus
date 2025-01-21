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

#ifndef SOFTBUS_UTILS_MOCK_H
#define SOFTBUS_UTILS_MOCK_H

#include "softbus_utils.h"

#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class UtilsInterface {
public:
    UtilsInterface() {};
    virtual ~UtilsInterface() {};

    virtual int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback) = 0;
    virtual int32_t SoftBusTimerInit(void) = 0;
    virtual void SoftBusTimerDeInit(void) = 0;
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual void DestroySoftBusList(SoftBusList *list) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t ConvertBtMacToStrNoColon(
        char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t ConvertHexStringToBytes(
        unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, uint32_t inLen) = 0;
    virtual int32_t ConvertBytesToUpperCaseHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t GenerateRandomStr(char *str, uint32_t size) = 0;
    virtual bool IsValidString(const char *input, uint32_t maxLen) = 0;
    virtual int32_t ConvertBtMacToBinary(
        const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t ConvertReverseBtMacToStr(
        char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t ConvertBtMacToU64(const char *strMac, uint32_t strMacLen, uint64_t *u64Mac) = 0;
    virtual int32_t ConvertU64MacToStr(uint64_t u64Mac, char *strMac, uint32_t strMacLen) = 0;
    virtual bool Int64ToString(int64_t src, char *buf, uint32_t bufLen) = 0;
    virtual int32_t StrCmpIgnoreCase(const char *str1, const char *str2) = 0;
    virtual int32_t StringToUpperCase(const char *str, char *buf, int32_t size) = 0;
    virtual int32_t StringToLowerCase(const char *str, char *buf, int32_t size) = 0;
    virtual int32_t WriteInt32ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t data) = 0;
    virtual int32_t WriteUint8ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t data) = 0;
    virtual int32_t ReadInt32FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t *data) = 0;
    virtual int32_t ReadUint8FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t *data) = 0;
    virtual void SetSignalingMsgSwitchOn(void) = 0;
    virtual void SetSignalingMsgSwitchOff(void) = 0;
    virtual bool GetSignalingMsgSwitch(void) = 0;
};
class UtilsInterfaceMock : public UtilsInterface {
public:
    UtilsInterfaceMock();
    ~UtilsInterfaceMock() override;

    MOCK_METHOD2(RegisterTimeoutCallback, int32_t(int32_t, TimerFunCallback));
    MOCK_METHOD0(SoftBusTimerInit, int32_t());
    MOCK_METHOD0(SoftBusTimerDeInit, void(void));
    MOCK_METHOD0(CreateSoftBusList, SoftBusList *(void));
    MOCK_METHOD1(DestroySoftBusList, void(SoftBusList *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD4(ConvertBtMacToStrNoColon, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertHexStringToBytes, int32_t(unsigned char *, uint32_t, const char *, uint32_t));
    MOCK_METHOD4(ConvertBytesToUpperCaseHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD2(GenerateRandomStr, int32_t(char *, uint32_t));
    MOCK_METHOD2(IsValidString, bool(const char *, uint32_t));
    MOCK_METHOD4(ConvertBtMacToBinary, int32_t(const char *, uint32_t, uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertBtMacToStr, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertReverseBtMacToStr, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD3(ConvertBtMacToU64, int32_t(const char *, uint32_t, uint64_t *));
    MOCK_METHOD3(ConvertU64MacToStr, int32_t(uint64_t, char *, uint32_t));
    MOCK_METHOD3(Int64ToString, bool(int64_t, char *, uint32_t));
    MOCK_METHOD2(StrCmpIgnoreCase, int32_t(const char *, const char *));
    MOCK_METHOD3(StringToUpperCase, int32_t(const char *, char *, int32_t));
    MOCK_METHOD3(StringToLowerCase, int32_t(const char *, char *, int32_t));
    MOCK_METHOD4(WriteInt32ToBuf, int32_t(uint8_t *, uint32_t, int32_t *, int32_t));
    MOCK_METHOD4(WriteUint8ToBuf, int32_t(uint8_t *, uint32_t, int32_t *, uint8_t));
    MOCK_METHOD4(ReadInt32FromBuf, int32_t(uint8_t *, uint32_t, int32_t *, int32_t *));
    MOCK_METHOD4(ReadUint8FromBuf, int32_t(uint8_t *, uint32_t, int32_t *, uint8_t *));
    MOCK_METHOD0(SetSignalingMsgSwitchOn, void(void));
    MOCK_METHOD0(SetSignalingMsgSwitchOff, void(void));
    MOCK_METHOD0(GetSignalingMsgSwitch, bool(void));
};
} // namespace OHOS
#endif // SOFTBUS_UTILS_MOCK_H