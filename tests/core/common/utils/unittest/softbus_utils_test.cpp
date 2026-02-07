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

/*
 * @tc.name: SoftBusUtilsTest_CreateSoftBusList_001
 * @tc.desc: Verify CreateSoftBusList returns non-nullptr and DestroySoftBusList
 *           executes successfully for normal softbus list destruction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_DestroySoftBusList_001, TestSize.Level1)
{
    SoftBusList *list = CreateSoftBusList();
    EXPECT_TRUE(list != nullptr);
    DestroySoftBusList(list);
}

/*
 * @tc.name: SoftBusUtilsTest_CreateSoftBusList_001
 * @tc.desc: Verify RegisterTimeoutCallback returns SOFTBUS_INVALID_PARAM when callback is nullptr
 *           or timerFunId is out of valid range
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

/*
 * @tc.name: SoftBusUtilsTest_RegisterTimeoutCallback_002
 * @tc.desc: Verify RegisterTimeoutCallback works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_UnRegisterTimeoutCallback
 * @tc.desc: Verify UnRegisterTimeoutCallback works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_SoftBusTimerInit_001
 * @tc.desc: Verify SoftBusTimerInit works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_SoftBusTimerDeInit_001
 * @tc.desc: Verify SoftBusTimerDeInit works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftBusTimerDeInit_001, TestSize.Level1)
{
    int32_t ret = SoftBusTimerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusTimerDeInit();
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertHexStringToBytes_001
 * @tc.desc: Verify ConvertHexStringToBytes returns SOFTBUS_INVALID_PARAM when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertHexStringToBytes_002
 * @tc.desc: Verify ConvertHexStringToBytes works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBytesToHexString_001
 * @tc.desc: Verify ConvertBytesToHexString returns SOFTBUS_INVALID_PARAM when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBytesToHexString_002
 * @tc.desc: Verify ConvertBytesToHexString works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_GenerateRandomStr_001
 * @tc.desc: Verify GenerateRandomStr returns SOFTBUS_INVALID_PARAM when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_IsValidString_001
 * @tc.desc: Verify IsValidString returns false when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToBinary_001
 * @tc.desc: Verify ConvertBtMacToBinary returns SOFTBUS_INVALID_PARAM when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStr_001
 * @tc.desc: Verify ConvertBtMacToStr returns SOFTBUS_INVALID_PARAM when input parameters are invalid
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStr_002
 * @tc.desc: Verify ConvertBtMacToStr works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_001
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_001, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_PUBLIC_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), PUBLIC_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_002
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_002, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_DISCOVER_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), DISC_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_003
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_003, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_CONN_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), CONN_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_004
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_004, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_AUTH_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), AUTH_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_005
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_005, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_NETWORK_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), LNN_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusErrorCodeStandard_006
 * @tc.desc: Verify SoftbusErrorCodeStandard works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusErrorCodeStandard_006, TestSize.Level1)
{
    uint32_t errorCode = -SOFTBUS_TRANS_ERR_BASE;
    EXPECT_EQ(((errorCode & ERROR_CODE_SUB_SYSTEM_AND) >> ERROR_CODE_SUB_SYSTEM_INDEX), SOFTBUS_SUB_SYSTEM);
    EXPECT_EQ(((errorCode & ERROR_CODE_MODULE_AND) >> ERROR_CODE_MODULE_INDEX), TRANS_SUB_MODULE_CODE);
}

/*
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize001
 * @tc.desc: Verify CalculateMbsTruncateSize works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize002
 * @tc.desc: Verify CalculateMbsTruncateSize works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_CalculateMbsTruncateSize003
 * @tc.desc: Verify CalculateMbsTruncateSize works correctly with valid input parameters
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

/*
 * @tc.name: AddNumberToSocketName001
 * @tc.desc: Verify AddNumberToSocketName works correctly with valid input parameters
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

/*
 * @tc.name: SoftBusUtilsTest_ConvertBytesToUpperCaseHexString_001
 * @tc.desc: Verify ConvertBytesToUpperCaseHexString works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBytesToUpperCaseHexString_001, TestSize.Level1)
{
    unsigned char inBuf[] = {0x61, 0x62, 0x63, 0x64};
    char outBuf[9] = {0};
    int32_t ret = ConvertBytesToUpperCaseHexString(outBuf, 9, inBuf, 4);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ("61626364", outBuf);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertBytesToUpperCaseHexString_002
 * @tc.desc: Verify ConvertBytesToUpperCaseHexString returns SOFTBUS_ERR when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBytesToUpperCaseHexString_002, TestSize.Level1)
{
    unsigned char inBuf[] = {0x61, 0x62};
    char outBuf[5] = {0};
    int32_t ret = ConvertBytesToUpperCaseHexString(nullptr, 5, inBuf, 2);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ConvertBytesToUpperCaseHexString(outBuf, 5, nullptr, 2);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ConvertBytesToUpperCaseHexString(outBuf, 3, inBuf, 2);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStrNoColon_001
 * @tc.desc: Verify ConvertBtMacToStrNoColon works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToStrNoColon_001, TestSize.Level1)
{
    uint8_t binMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    char strMac[13] = {0};
    int32_t ret = ConvertBtMacToStrNoColon(strMac, 13, binMac, 6);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ("aabbccddeeff", strMac);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToStrNoColon_002
 * @tc.desc: Verify ConvertBtMacToStrNoColon returns SOFTBUS_INVALID_PARAM when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToStrNoColon_002, TestSize.Level1)
{
    uint8_t binMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    char strMac[13] = {0};
    int32_t ret = ConvertBtMacToStrNoColon(nullptr, 13, binMac, 6);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertBtMacToStrNoColon(strMac, 12, binMac, 6);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertBtMacToStrNoColon(strMac, 13, nullptr, 6);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertBtMacToStrNoColon(strMac, 13, binMac, 5);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToU64_001
 * @tc.desc: Verify ConvertBtMacToU64 works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToU64_001, TestSize.Level1)
{
    const char *strMac = "AA:BB:CC:DD:EE:FF";
    uint64_t u64Mac = 0;
    int32_t ret = ConvertBtMacToU64(strMac, 18, &u64Mac);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(u64Mac, 0);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertBtMacToU64_002
 * @tc.desc: Verify ConvertBtMacToU64 returns SOFTBUS_INVALID_PARAM when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertBtMacToU64_002, TestSize.Level1)
{
    uint64_t u64Mac = 0;
    int32_t ret = ConvertBtMacToU64(nullptr, 17, &u64Mac);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertBtMacToU64("AA:BB", 5, &u64Mac);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertBtMacToU64("AA:BB:CC:DD:EE:FF", 17, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertU64MacToStr_001
 * @tc.desc: Verify ConvertU64MacToStr works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertU64MacToStr_001, TestSize.Level1)
{
    uint64_t u64Mac = 0xAABBCCDDEEFF;
    char strMac[18] = {0};
    int32_t ret = ConvertU64MacToStr(u64Mac, strMac, 18);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusUtilsTest_ConvertU64MacToStr_002
 * @tc.desc: Verify ConvertU64MacToStr returns SOFTBUS_INVALID_PARAM when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ConvertU64MacToStr_002, TestSize.Level1)
{
    uint64_t u64Mac = 0xAABBCCDDEEFF;
    char strMac[18] = {0};
    int32_t ret = ConvertU64MacToStr(u64Mac, nullptr, 18);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertU64MacToStr(u64Mac, strMac, 17);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertU64MacToStr(0, strMac, 18);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusUtilsTest_StringToUpperCase_001
 * @tc.desc: Verify StringToUpperCase works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StringToUpperCase_001, TestSize.Level1)
{
    const char *str = "hello";
    char buf[10] = {0};
    int32_t ret = StringToUpperCase(str, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ("HELLO", buf);
}

/*
 * @tc.name: SoftBusUtilsTest_StringToUpperCase_002
 * @tc.desc: Verify StringToUpperCase returns SOFTBUS_ERR when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StringToUpperCase_002, TestSize.Level1)
{
    char buf[10] = {0};
    int32_t ret = StringToUpperCase(nullptr, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = StringToUpperCase("hello", nullptr, 10);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusUtilsTest_StringToLowerCase_001
 * @tc.desc: Verify StringToLowerCase works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StringToLowerCase_001, TestSize.Level1)
{
    const char *str = "HELLO";
    char buf[10] = {0};
    int32_t ret = StringToLowerCase(str, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ("hello", buf);
}

/*
 * @tc.name: SoftBusUtilsTest_StringToLowerCase_002
 * @tc.desc: Verify StringToLowerCase returns SOFTBUS_ERR when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StringToLowerCase_002, TestSize.Level1)
{
    char buf[10] = {0};
    int32_t ret = StringToLowerCase(nullptr, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = StringToLowerCase("HELLO", nullptr, 10);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusUtilsTest_Int64ToString_001
 * @tc.desc: Verify Int64ToString works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_Int64ToString_001, TestSize.Level1)
{
    int64_t src = -1234567890;
    char buf[21] = {0};
    bool ret = Int64ToString(src, buf, 21);
    EXPECT_TRUE(ret);
    EXPECT_STREQ("-1234567890", buf);
}

/*
 * @tc.name: SoftBusUtilsTest_Int64ToString_002
 * @tc.desc: Verify Int64ToString returns false when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_Int64ToString_002, TestSize.Level1)
{
    int64_t src = 12345;
    bool ret = Int64ToString(src, nullptr, 10);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: SoftBusUtilsTest_StrCmpIgnoreCase_001
 * @tc.desc: Verify StrCmpIgnoreCase works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StrCmpIgnoreCase_001, TestSize.Level1)
{
    const char *str1 = "Hello";
    const char *str2 = "HELLO";
    int32_t ret = StrCmpIgnoreCase(str1, str2);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusUtilsTest_StrCmpIgnoreCase_002
 * @tc.desc: Verify StrCmpIgnoreCase returns SOFTBUS_ERR when input parameters are invalid or strings don't match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_StrCmpIgnoreCase_002, TestSize.Level1)
{
    const char *str1 = "Hello";
    int32_t ret = StrCmpIgnoreCase(nullptr, str1);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = StrCmpIgnoreCase(str1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = StrCmpIgnoreCase("Hello", "World");
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusUtilsTest_SignalingMsgSwitch_001
 * @tc.desc: Verify signaling message switch functions work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SignalingMsgSwitch_001, TestSize.Level1)
{
    SetSignalingMsgSwitchOn();
    EXPECT_TRUE(GetSignalingMsgSwitch());
    SetSignalingMsgSwitchOff();
    EXPECT_FALSE(GetSignalingMsgSwitch());
}

/*
 * @tc.name: SoftBusUtilsTest_DataMasking_001
 * @tc.desc: Verify DataMasking function masks MAC address correctly using MacInstead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_DataMasking_001, TestSize.Level1)
{
    const char *data = "AA:BB:CC:DD:EE:FF";
    char container[20] = {0};
    EXPECT_NO_FATAL_FAILURE(DataMasking(data, 18, ':', container));
    // First two segments should remain unchanged
    EXPECT_EQ(container[0], 'A');
    EXPECT_EQ(container[1], 'A');
    EXPECT_EQ(container[2], ':');
    EXPECT_EQ(container[3], 'B');
    EXPECT_EQ(container[4], 'B');
    // After second delimiter, characters should be masked to '*'
    EXPECT_EQ(container[6], '*');
    EXPECT_EQ(container[7], '*');
}

/*
 * @tc.name: SoftBusUtilsTest_DataMasking_002
 * @tc.desc: Verify DataMasking function masks IP address correctly using IpInstead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_DataMasking_002, TestSize.Level1)
{
    const char *data = "192.168.1.1";
    char container[12] = {0};
    EXPECT_NO_FATAL_FAILURE(DataMasking(data, 11, '.', container));
    // First segment should remain unchanged
    EXPECT_EQ(container[0], '1');
    EXPECT_EQ(container[1], '9');
    EXPECT_EQ(container[2], '2');
    // After first delimiter, characters should be masked to '*'
    EXPECT_EQ(container[4], '*');
    EXPECT_EQ(container[5], '*');
}

/*
 * @tc.name: SoftBusUtilsTest_WriteInt32ToBuf_001
 * @tc.desc: Verify WriteInt32ToBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteInt32ToBuf_001, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    int32_t data = 0x12345678;
    int32_t ret = WriteInt32ToBuf(buf, 32, &offset, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(offset, 4);
}

/*
 * @tc.name: SoftBusUtilsTest_WriteInt32ToBuf_002
 * @tc.desc: Verify WriteInt32ToBuf returns SOFTBUS_INVALID_PARAM when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteInt32ToBuf_002, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    int32_t data = 0x12345678;
    int32_t ret = WriteInt32ToBuf(nullptr, 32, &offset, data);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = WriteInt32ToBuf(buf, 32, nullptr, data);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = WriteInt32ToBuf(buf, 2, &offset, data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: SoftBusUtilsTest_WriteUint64ToBuf_001
 * @tc.desc: Verify WriteUint64ToBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteUint64ToBuf_001, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    uint64_t data = 0x123456789ABCDEF0;
    int32_t ret = WriteUint64ToBuf(buf, 32, &offset, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(offset, 8);
}

/*
 * @tc.name: SoftBusUtilsTest_WriteUint8ToBuf_001
 * @tc.desc: Verify WriteUint8ToBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteUint8ToBuf_001, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    uint8_t data = 0xAB;
    int32_t ret = WriteUint8ToBuf(buf, 32, &offset, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(offset, 1);
}

/*
 * @tc.name: SoftBusUtilsTest_WriteStringToBuf_001
 * @tc.desc: Verify WriteStringToBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteStringToBuf_001, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    char data[] = "test";
    int32_t ret = WriteStringToBuf(buf, 32, &offset, data, 4);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusUtilsTest_WriteStringToBuf_002
 * @tc.desc: Verify WriteStringToBuf returns SOFTBUS_INVALID_PARAM when input parameters are invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_WriteStringToBuf_002, TestSize.Level1)
{
    uint8_t buf[32] = {0};
    int32_t offset = 0;
    int32_t ret = WriteStringToBuf(buf, 32, &offset, nullptr, 4);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusUtilsTest_ReadInt32FromBuf_001
 * @tc.desc: Verify ReadInt32FromBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ReadInt32FromBuf_001, TestSize.Level1)
{
    uint8_t buf[] = {0x78, 0x56, 0x34, 0x12};
    int32_t offset = 0;
    int32_t data;
    int32_t ret = ReadInt32FromBuf(buf, 4, &offset, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(offset, 4);
}

/*
 * @tc.name: SoftBusUtilsTest_ReadUint64FromBuf_001
 * @tc.desc: Verify ReadUint64FromBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ReadUint64FromBuf_001, TestSize.Level1)
{
    uint8_t buf[] = {0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12};
    int32_t offset = 0;
    uint64_t data;
    int32_t ret = ReadUint64FromBuf(buf, 8, &offset, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusUtilsTest_ReadUint8FromBuf_001
 * @tc.desc: Verify ReadUint8FromBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ReadUint8FromBuf_001, TestSize.Level1)
{
    uint8_t buf[] = {0xAB};
    int32_t offset = 0;
    uint8_t data;
    int32_t ret = ReadUint8FromBuf(buf, 1, &offset, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(data, 0xAB);
}

/*
 * @tc.name: SoftBusUtilsTest_ReadStringLenFormBuf_001
 * @tc.desc: Verify ReadStringLenFormBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ReadStringLenFormBuf_001, TestSize.Level1)
{
    uint8_t buf[] = {0x04, 0x00, 0x00, 0x00};
    int32_t offset = 0;
    uint32_t len;
    int32_t ret = ReadStringLenFormBuf(buf, 4, &offset, &len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(len, 4);
}

/*
 * @tc.name: SoftBusUtilsTest_ReadStringFromBuf_001
 * @tc.desc: Verify ReadStringFromBuf works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_ReadStringFromBuf_001, TestSize.Level1)
{
    uint8_t buf[] = {0x04, 0x00, 0x00, 0x00, 't', 'e', 's', 't'};
    int32_t offset = 0;
    char data[10] = {0};
    int32_t ret = ReadStringFromBuf(buf, 8, &offset, data, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(data, "test");
}

/*
 * @tc.name: SoftBusUtilsTest_EnableCapabilityBit_001
 * @tc.desc: Verify EnableCapabilityBit and GetCapabilityBit work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_EnableCapabilityBit_001, TestSize.Level1)
{
    uint32_t value = 0x00;
    EnableCapabilityBit(&value, 2);
    EXPECT_TRUE(GetCapabilityBit(value, 2));
    EXPECT_FALSE(GetCapabilityBit(value, 1));
}

/*
 * @tc.name: SoftBusUtilsTest_DisableCapabilityBit_001
 * @tc.desc: Verify DisableCapabilityBit works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_DisableCapabilityBit_001, TestSize.Level1)
{
    uint32_t value = 0xFF;
    DisableCapabilityBit(&value, 2);
    EXPECT_FALSE(GetCapabilityBit(value, 2));
    EXPECT_TRUE(GetCapabilityBit(value, 1));
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusDumpBytes_001
 * @tc.desc: Verify SoftbusDumpBytes executes without crash for normal input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusDumpBytes_001, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpBytes("TestMessage", data, 4));
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusDumpBytes_002
 * @tc.desc: Verify SoftbusDumpBytes handles nullptr message gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusDumpBytes_002, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpBytes(nullptr, data, 4));
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusDumpBytes_003
 * @tc.desc: Verify SoftbusDumpBytes handles nullptr data gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusDumpBytes_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpBytes("TestMessage", nullptr, 4));
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusDumpBytes_004
 * @tc.desc: Verify SoftbusDumpBytes handles zero length gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusDumpBytes_004, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpBytes("TestMessage", data, 0));
}

/*
 * @tc.name: SoftBusUtilsTest_SoftbusDumpBytes_005
 * @tc.desc: Verify SoftbusDumpBytes handles large data within max limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusUtilsTest, SoftBusUtilsTest_SoftbusDumpBytes_005, TestSize.Level1)
{
    uint8_t data[100] = {0};
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpBytes("LargeData", data, 100));
}
} // namespace OHOS