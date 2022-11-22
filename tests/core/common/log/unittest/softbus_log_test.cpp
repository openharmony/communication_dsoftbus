/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <gtest/gtest.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "softbus_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class SoftBusLogTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SoftBusLogTest::SetUpTestCase(void)
{
}

void SoftBusLogTest::TearDownTestCase(void)
{
}

void SoftBusLogTest::SetUp(void)
{
}

void SoftBusLogTest::TearDown(void)
{
}

/**
 * @tc.name: NstackxLogTest001
 * @tc.desc: Verify nstackx log.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, NstackxLogTest001, TestSize.Level1)
{
    const char *moduleName = nullptr;
    uint32_t nstackLevel = SOFTBUS_LOG_LEVEL_MAX;
    NstackxLog(moduleName, nstackLevel, "nstackx log error.");

    const char *moduleName2 = "nstackx";
    uint32_t nstackLevel2 = SOFTBUS_LOG_LEVEL_MAX;
    NstackxLog(moduleName2, nstackLevel2, "nstackx log error.");
}

/**
 * @tc.name: SoftBusLogTest001
 * @tc.desc: Verify softbus log.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, SoftBusLogTest001, TestSize.Level1)
{
    SoftBusLogModule module = SOFTBUS_LOG_MODULE_MAX;
    SoftBusLogLevel level = SOFTBUS_LOG_LEVEL_MAX;
    SoftBusLog(module, level, "softbus log error.");

    SoftBusLogModule module2 = SOFTBUS_LOG_COMM;
    SoftBusLogLevel level2 = SOFTBUS_LOG_LEVEL_MAX;
    SoftBusLog(module2, level2, "softbus log error.");
}

/**
 * @tc.name: AnonymizesTest001
 * @tc.desc: Anonymize.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonymizesTest001, TestSize.Level1)
{
    const char *target = nullptr;
    uint8_t expectAnonymizedLength = 0;
    const char *expected = "NULL";
    const char *actual = Anonymizes(target, expectAnonymizedLength);
    EXPECT_STREQ(expected, actual);

    const char *target1 = "target";
    uint8_t expectAnonymizedLength1 = 0;
    const char *expected1 = "BADLENGTH";
    const char *actual1 = Anonymizes(target1, expectAnonymizedLength1);
    EXPECT_STREQ(expected1, actual1);

    const char *target2 = "target";
    uint8_t expectAnonymizedLength2 = 6;
    const char *expected2 = "TOOSHORT";
    const char *actual2 = Anonymizes(target2, expectAnonymizedLength2);
    EXPECT_STREQ(expected2, actual2);
}

/**
 * @tc.name: AnonyPacketPrintoutTest001
 * @tc.desc: Anonymize packet print out.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonyPacketPrintoutTest001, TestSize.Level1)
{
    SetSignalingMsgSwitchOff();

    SoftBusLogModule module = SOFTBUS_LOG_COMM;
    const char *msg = nullptr;
    const char *packet = nullptr;
    size_t packetLen = 0;
    AnonyPacketPrintout(module, msg, packet, packetLen);

    const char *msg2 = "message";
    const char *packet2 = nullptr;
    size_t packetLen2 = 0;
    AnonyPacketPrintout(module, msg2, packet2, packetLen2);

    const char *msg3 = "message";
    const char *packet3 = "packet";
    size_t packetLen3 = 0;
    AnonyPacketPrintout(module, msg3, packet3, packetLen3);

    const char *msg4 = "message";
    const char *packet4 = "packet";
    size_t packetLen4 = SIZE_MAX;
    AnonyPacketPrintout(module, msg4, packet4, packetLen4);

    const char *msg5 = "message";
    const char *packet5 = "packet";
    size_t packetLen5 = 6;
    AnonyPacketPrintout(module, msg5, packet5, packetLen5);
}

/**
 * @tc.name: AnonyPacketPrintoutTest002
 * @tc.desc: Anonymize packet print out.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonyPacketPrintoutTest002, TestSize.Level1)
{
    SetSignalingMsgSwitchOn();

    SoftBusLogModule module = SOFTBUS_LOG_COMM;
    const char *msg = nullptr;
    const char *packet = nullptr;
    size_t packetLen = 0;
    AnonyPacketPrintout(module, msg, packet, packetLen);

    const char *msg2 = "message";
    const char *packet2 = nullptr;
    size_t packetLen2 = 0;
    AnonyPacketPrintout(module, msg2, packet2, packetLen2);

    const char *msg3 = "message";
    const char *packet3 = "packet";
    size_t packetLen3 = 0;
    AnonyPacketPrintout(module, msg3, packet3, packetLen3);

    const char *msg4 = "message";
    const char *packet4 = "packet";
    size_t packetLen4 = SIZE_MAX;
    AnonyPacketPrintout(module, msg4, packet4, packetLen4);

    const char *msg5 = "message";
    const char *packet5 = "packet";
    size_t packetLen5 = 6;
    AnonyPacketPrintout(module, msg5, packet5, packetLen5);
}

/**
 * @tc.name: AnonyDevIdTest001
 * @tc.desc: Anonymize devid.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonyDevIdTest001, TestSize.Level1)
{
    char *outName = nullptr;
    const char *inName = nullptr;
    const char *expected = "null";
    const char *actual = AnonyDevId(&outName, inName);
    EXPECT_STREQ(expected, actual);

    char *outName2 = nullptr;
    const char *inName2 = "abcdeg";
    const char *expected2 = "abcdeg";
    const char *actual2 = AnonyDevId(&outName2, inName2);
    EXPECT_STREQ(expected2, actual2);
}

} // namespace OHOS