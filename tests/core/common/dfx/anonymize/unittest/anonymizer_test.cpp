/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>
#include <string>

#include "anonymizer.h"

using namespace std;
using namespace testing::ext;

namespace {
static const char *TEST_PLAIN_PACKET_ID = "start.sjgDTUJlzPAvUJWsugNt6bOUT6IJsE9zz2xWrj34kUhwZLoF9L5t7WNolk2jKmIP.end";
static const char *TEST_ANONYMIZED_PACKET_ID = "start.*z2xWrj34kUhwZLoF9L5t7WNolk2jKmIP.end";
static const char *TEST_PLAIN_PACKET_IDT = "start.\"uz8jUyq9enjB488uUyiqwutwfGiXbK0j\".end";
static const char *TEST_ANONYMIZED_PACKET_IDT = "start.*UyiqwutwfGiXbK0j\".end";
static const char *TEST_PLAIN_PACKET_IP = "start.10.11.12.13.end";
static const char *TEST_ANONYMIZED_PACKET_IP = "start.*12.13.end";
static const char *TEST_PLAIN_PACKET_MAC = "start.dd-15-bc-b9-f2-04.end";
static const char *TEST_ANONYMIZED_PACKET_MAC = "start.*b9-f2-04.end";
static const char *TEST_PLAIN_PACKET_MAC_CAPS = "start.91-1E-DD-EF-76-48.end";
static const char *TEST_ANONYMIZED_PACKET_MAC_CAPS = "start.*EF-76-48.end";
static const char *TEST_PLAIN_PACKET_KEY = "start.bDUnXjCTqbaCVxA7OSGImOLU8ZkpwRtbckfkqYpHiLx=.end";
static const char *TEST_ANONYMIZED_PACKET_KEY = "start.*LU8ZkpwRtbckfkqYpHiLx=.end";
} // namespace

namespace OHOS {
class AnonymizerTest : public testing::Test { };

/**
 * @tc.name: AnonymizeTest001
 * @tc.desc: Test plainStr is null
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest001, TestSize.Level0)
{
    const char *plainStr = nullptr;
    char *anonymizedStr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("NULL", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest002
 * @tc.desc: Test plainStr length < 2
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest002, TestSize.Level0)
{
    const char *plainStr = "a";
    char *anonymizedStr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("*", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest003
 * @tc.desc: Test plainStr length = 2
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest003, TestSize.Level0)
{
    const char *plainStr = "ab";
    char *anonymizedStr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("*b", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest004
 * @tc.desc: Test plainStr length > 2
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest004, TestSize.Level0)
{
    const char *plainStr = "abc";
    char *anonymizedStr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("*c", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest005
 * @tc.desc: Test free
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest005, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    AnonymizeFree(anonymizedStr);
    EXPECT_EQ(nullptr, anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest006
 * @tc.desc: Test AnonymizePacket ID
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest006, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_ID;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_ID, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest007
 * @tc.desc: Test AnonymizePacket IDT
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest007, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_IDT;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_IDT, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest008
 * @tc.desc: Test AnonymizePacket IP
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest008, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_IP;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_IP, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest009
 * @tc.desc: Test AnonymizePacket ID
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest009, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_MAC;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_MAC, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest010
 * @tc.desc: Test AnonymizePacket MAC_CAPS
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest010, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_MAC_CAPS;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_MAC_CAPS, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest011
 * @tc.desc: Test AnonymizePacket KEY
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest011, TestSize.Level0)
{
    const char *plainStr = TEST_PLAIN_PACKET_KEY;
    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_PACKET_KEY, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest012
 * @tc.desc: Test AnonymizePacket for IP and MAC
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest012, TestSize.Level0)
{
    size_t plainStrLen = strlen(TEST_PLAIN_PACKET_IP) + strlen(TEST_PLAIN_PACKET_MAC);
    char plainStr[plainStrLen + 1];
    (void)sprintf_s(plainStr, plainStrLen + 1, "%s|%s", TEST_PLAIN_PACKET_IP, TEST_PLAIN_PACKET_MAC);

    size_t expectedStrLen = strlen(TEST_ANONYMIZED_PACKET_IP) + strlen(TEST_ANONYMIZED_PACKET_MAC);
    char expectedStr[expectedStrLen + 1];
    (void)sprintf_s(expectedStr, expectedStrLen + 1, "%s|%s", TEST_ANONYMIZED_PACKET_IP, TEST_ANONYMIZED_PACKET_MAC);

    char *anonymizedStr;
    AnonymizePacket(plainStr, &anonymizedStr);
    EXPECT_STREQ(expectedStr, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}
} // namespace OHOS