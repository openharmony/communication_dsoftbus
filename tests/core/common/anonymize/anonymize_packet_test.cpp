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
#include "softbus_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_originPacket = "\"DEVICE_ID\":\"18f3b221c8661b51eaf6520c223f48afe211111113ab9c6a4f03b7c719eb60d1\"";
const char *g_anonymizedPacket = "\"DEVICE_ID\":\"18f3******60d1\"";
const char *g_shortPacket = "\"DEVICE_ID\":\"18f3b221c8661b5111111111111111b7c719eb60d1\"";
const char *g_testSessionName = "test.ohos.abc60272D6C226F0E08021F07AAAAAAAAAABBBBBBBB9A0111111111169A5342784D2EB\
123456789ABCCCCCCCCCCCCCD57A4Cam_Cam123";
const char *g_testAnonySessionName = "test.ohos.abc6027******57A4Cam_Cam123";

class AnonymizePacketTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AnonymizePacketTest::SetUpTestCase(void) {}

void AnonymizePacketTest::TearDownTestCase(void) {}

void AnonymizePacketTest::SetUp(void) {}

void AnonymizePacketTest::TearDown(void) {}

/**
 * @tc.name: AnonymizePacketNormalTest001
 * @tc.desc: Verify AnonymizePacket function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizePacketTest, AnonymizePacketNormalTest001, TestSize.Level0)
{
    AnonyPacketPrintout(SOFTBUS_LOG_COMM, "AnonymizePacketNormalTest001: ", g_originPacket, strlen(g_originPacket));
}

/**
 * @tc.name: AnonymizePacketNormalTest002
 * @tc.desc: Verify AnonymizePacket function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizePacketTest, AnonymizePacketNormalTest002, TestSize.Level0)
{
    AnonyPacketPrintout(SOFTBUS_LOG_COMM, "AnonymizePacketNormalTest002: ", g_shortPacket, strlen(g_shortPacket));
}

/**
 * @tc.name: AnonymizePacketWrongTest001
 * @tc.desc: Verify AnonymizePacket function, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizePacketTest, AnonymizePacketWrongTest001, TestSize.Level0)
{
    AnonyPacketPrintout(SOFTBUS_LOG_COMM, "AnonymizePacketWrongTest001: ", NULL, strlen(g_originPacket));
}

/**
 * @tc.name: AnonySessionNameNormalTest001
 * @tc.desc: Verify AnonyDevId function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizePacketTest, AnonySessionNameNormalTest001, TestSize.Level0)
{
    char *anonymizedOut = nullptr;
    const char *res = AnonyDevId(&anonymizedOut, g_testSessionName);
    EXPECT_STREQ(g_testAnonySessionName, res);

    SoftBusFree(anonymizedOut);
}
}; // namespace OHOS
