/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "softbus_error_code.h"
#include "softbus_utils.h"

using namespace testing::ext;

namespace OHOS {
constexpr uint32_t ERROR_CODE_SUB_SYSTEM_INDEX = 21;
constexpr uint32_t ERROR_CODE_MODULE_INDEX = 16;
constexpr uint32_t ERROR_CODE_SUB_SYSTEM_AND = 0x1FE00000;
constexpr uint32_t ERROR_CODE_MODULE_AND = 0x1F0000;
constexpr uint32_t TEST_MAX_LEN = 256;
constexpr uint32_t TEST_LEN = 8;

class SoftBusUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) { }
    static void TearDownTestCase(void) { }
};

void MockSoftBusTimer(void) { }

/**
 * @tc.name: SoftBusUtilsTest_CreateSoftBusList_001
 * @tc.desc: Normal destroy softbus list test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_DestroySoftBusList_001, TestSize.Level1)
{
    SoftBusList *list = CreateSoftBusList();
    EXPECT_TRUE(list != nullptr);
    DestroySoftBusList(list);
}

/**
 * @tc.name: SoftBusUtilsTest_CreateSoftBusList_001
 * @tc.desc: Error register timeout callback test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_RegisterTimeoutCallback_001, TestSize.Level1)
{
    int32_t timerFunId = SOFTBUS_CONN_TIMER_FUN;
    TimerFunCallback callbac = nullptr;
    int32_t ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    callbac = MockSoftBusTimer;
    timerFunId = SOFTBUS_CONN_TIMER_FUN - 1;
    ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    timerFunId = SOFTBUS_MAX_TIMER_FUN_NUM;
    ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_RegisterTimeoutCallback_002
 * @tc.desc: Normal register timeout callback test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_RegisterTimeoutCallback_002, TestSize.Level1)
{
    int32_t timerFunId = SOFTBUS_CONN_TIMER_FUN;
    TimerFunCallback callbac = MockSoftBusTimer;
    int32_t ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_OK, ret);

    timerFunId = SOFTBUS_CONN_TIMER_FUN + 1;
    ret = RegisterTimeoutCallback(timerFunId, callbac);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_UnRegisterTimeoutCallback
 * @tc.desc: Normal unregister timeout callback test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_UnRegisterTimeoutCallback, TestSize.Level1)
{
    int32_t timerFunId = SOFTBUS_CONN_TIMER_FUN - 1;
    int32_t ret = UnRegisterTimeoutCallback(timerFunId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    timerFunId = SOFTBUS_MAX_TIMER_FUN_NUM;
    ret = UnRegisterTimeoutCallback(timerFunId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    timerFunId = SOFTBUS_CONN_TIMER_FUN;
    ret = UnRegisterTimeoutCallback(timerFunId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftBusTimerInit_001
 * @tc.desc: Normal timer init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftBusTimerInit_001, TestSize.Level1)
{
    int32_t ret = SoftBusTimerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusTimerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftBusTimerDeInit_001
 * @tc.desc: Normal timer deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftBusTimerDeInit_001, TestSize.Level1)
{
    int32_t ret = SoftBusTimerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusTimerDeInit();
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertHexStringToBytes_001
 * @tc.desc: Parameter error when convert hex string to bytes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertHexStringToBytes_001, TestSize.Level1)
{
    unsigned char *outBuf = nullptr;
    uint32_t outBufLen = 0;
    const char *inBuf = "41424344";
    uint32_t inLen = 8;
    int32_t ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    unsigned char outBufArray[5] = "\0";
    outBuf = outBufArray;
    outBufLen = 5;
    inBuf = nullptr;
    inLen = 0;
    ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    outBuf = outBufArray;
    outBufLen = 5;
    inBuf = "414243444";
    inLen = 9;
    ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    outBuf = outBufArray;
    outBufLen = 5;
    inBuf = "414243FG";
    inLen = 8;
    ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    outBuf = outBufArray;
    outBufLen = 5;
    inBuf = "414243GF";
    inLen = 8;
    ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertHexStringToBytes_002
 * @tc.desc: Normal convert hex string to bytes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertHexStringToBytes_002, TestSize.Level1)
{
    unsigned char outBuf[5] = "\0";
    uint32_t outBufLen = 5;
    const char *inBuf = "41424344";
    uint32_t inLen = 8;
    int32_t ret = ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const unsigned char expect[5] = "ABCD";
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expect[i], outBuf[i]);
    }
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertBytesToHexString_001
 * @tc.desc: Parameter error when convert bytes to hex string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBytesToHexString_001, TestSize.Level1)
{
    char *outBuf = nullptr;
    uint32_t outBufLen = 0;
    const unsigned char inBuf[5] = "ABCD";
    uint32_t inLen = 4;
    int32_t ret = ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    char outBufArray[5] = "\0";
    outBuf = outBufArray;
    outBufLen = 4;
    inLen = 8;
    ret = ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    outBufLen = 9;
    const unsigned char *inBuf2 = nullptr;
    inLen = 0;
    ret = ConvertBytesToHexString(outBuf, outBufLen, inBuf2, inLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertBytesToHexString_002
 * @tc.desc: Normal convert bytes to hex string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBytesToHexString_002, TestSize.Level1)
{
    char outBuf[9] = "\0";
    uint32_t outBufLen = 9;
    unsigned char inBuf[5] = "abcd";
    uint32_t inLen = 4;
    int32_t ret = ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *expect = "61626364";
    EXPECT_STREQ(expect, outBuf);
}

/**
 * @tc.name: SoftBusUtilsTest_GenerateRandomStr_001
 * @tc.desc: Parameter error when generate random string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_GenerateRandomStr_001, TestSize.Level1)
{
    char *str = nullptr;
    uint32_t len = 4;
    int32_t ret = GenerateRandomStr(str, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    char str2[5] = "\0";
    len = 1;
    ret = GenerateRandomStr(str2, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_IsValidString_001
 * @tc.desc: Check string valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_IsValidString_001, TestSize.Level1)
{
    const char *input = nullptr;
    uint32_t maxLen = 4;
    EXPECT_FALSE(IsValidString(input, maxLen));

    input = "";
    maxLen = 4;
    EXPECT_FALSE(IsValidString(input, maxLen));

    input = "ABCDE";
    maxLen = 4;
    EXPECT_FALSE(IsValidString(input, maxLen));

    input = "ABCDE";
    maxLen = 5;
    EXPECT_TRUE(IsValidString(input, maxLen));
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToBinary_001
 * @tc.desc: Parameter error when convert bt mac to binary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToBinary_001, TestSize.Level1)
{
    const char *strMac = nullptr;
    uint32_t strMacLen = 0;
    uint8_t *binMac = nullptr;
    uint32_t binMacLen = 0;
    int32_t ret = ConvertBtMacToBinary(strMac, strMacLen, binMac, binMacLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStr_001
 * @tc.desc: Parameter error when convert binary to bt mac.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToStr_001, TestSize.Level1)
{
    char *strMac = nullptr;
    uint32_t strMacLen = 0;
    const uint8_t *binMac = nullptr;
    uint32_t binMacLen = 0;
    int32_t ret = ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStr_002
 * @tc.desc: Normal convert binary to bt mac.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToStr_002, TestSize.Level1)
{
    char strMac[19] = "\0";
    uint32_t strMacLen = 18;
    const uint8_t binMac[6] = { 101, 102, 103, 104, 105, 106 };
    uint32_t binMacLen = 6;
    int32_t ret = ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *expect = "65:66:67:68:69:6a";
    EXPECT_STREQ(expect, strMac);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_001
 * @tc.desc: Test softbus event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_001, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_PUBLIC_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), PUBLIC_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_002
 * @tc.desc: Test disc event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_002, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_DISCOVER_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), DISC_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_003
 * @tc.desc: Test conn event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_003, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_CONN_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), CONN_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_004
 * @tc.desc: Test auth event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_004, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_AUTH_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), AUTH_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_005
 * @tc.desc: Test lnn event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_005, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_NETWORK_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), LNN_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_006
 * @tc.desc: Test trans event error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_006, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_TRANS_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), TRANS_SUB_MODULE_CODE);
}

/**
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize001
 * @tc.desc: Test CalculateMbsTruncateSize with null str.
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SoftBusUtilsTest, CalculateMbsTruncateSize001, TestSize.Level1)
{
    uint32_t maxCapacity = 15;
    char multiByteStr[] = "";
    uint32_t exceptSize = 0;
    uint32_t truncatedSize = 0;

    for (uint32_t capacity = 0; capacity < maxCapacity; ++capacity) {
        int32_t ret = CalculateMbsTruncateSize(multiByteStr, capacity, &truncatedSize);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_EQ(truncatedSize, exceptSize);
    }
}

/**
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize002
 * @tc.desc: Test CalculateMbsTruncateSize with ascii str.
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SoftBusUtilsTest, CalculateMbsTruncateSize002, TestSize.Level1)
{
    uint32_t maxCapacity = 25;
    char multiByteStr[] = "ABCDEF Ghig 12 Klm";
    uint32_t exceptSize[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 18, 18, 18, 18, 18, 18
    };
    uint32_t truncatedSize = 0;

    for (uint32_t capacity = 0; capacity < maxCapacity; ++capacity) {
        int32_t ret = CalculateMbsTruncateSize(multiByteStr, capacity, &truncatedSize);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_EQ(truncatedSize, exceptSize[capacity]);
    }
}

/**
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize003
 * @tc.desc: Test CalculateMbsTruncateSize with utf-8 str.
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SoftBusUtilsTest, CalculateMbsTruncateSize003, TestSize.Level1)
{
    uint32_t maxCapacity = 40;
    char multiByteStr[] = "床前明月,光疑是地上霜。";
    uint32_t exceptSize[] = {
        0, 0, 0, 3, 3, 3, 6, 6, 6, 9, 9, 9, 12, 13, 13, 13, 16, 16, 16, 19, 19, 19, 22, 22, 22, 25, 25, 25, 28, 28, 28,
        31, 31, 31, 34, 34, 34, 34, 34, 34
    };
    uint32_t truncatedSize = 0;

    for (uint32_t capacity = 0; capacity < maxCapacity; ++capacity) {
        int32_t ret = CalculateMbsTruncateSize(multiByteStr, capacity, &truncatedSize);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_EQ(truncatedSize, exceptSize[capacity]);
    }
}

/**
 * @tc.name: AddNumberToSocketName001
 * @tc.desc: Test Add Number To Socket Name
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SoftBusUtilsTest, AddNumberToSocketName001, TestSize.Level1)
{
    uint32_t num = 1;
    uint32_t preLen = TEST_MAX_LEN;
    const char *testName = "socket_";
    char socketName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = AddNumberToSocketName(num, testName, preLen, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddNumberToSocketName(num, nullptr, preLen, socketName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddNumberToSocketName(num, testName, preLen, socketName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    preLen = 1;
    ret = AddNumberToSocketName(num, testName, preLen, socketName);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    preLen = TEST_LEN;
    ret = AddNumberToSocketName(num, testName, preLen, socketName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS