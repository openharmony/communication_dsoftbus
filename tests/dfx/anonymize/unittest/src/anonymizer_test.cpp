/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <string>

#include "anonymizer.h"

using namespace std;
using namespace testing::ext;

namespace {
const char *TEST_PLAIN_UDID = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm";
const char *TEST_ANONYMIZED_UDID = "a8ynv**t50fm";
const char *TEST_PLAIN_UDID_CAPS = "A8YNVPDAIHW1F6NKNJD2HKFHXLJXYPKR6KVJSBHNHPP16974UO4FVSRPFA6T50FM";
const char *TEST_ANONYMIZED_UDID_CAPS = "A8YNV**T50FM";
const char *TEST_PLAIN_MAC = "dd-15-bc-b9-f2-04";
const char *TEST_ANONYMIZED_MAC = "dd-15-bc-**-**-04";
const char *TEST_PLAIN_MAC_COLON = "dd:15:bc:b9:f2:04";
const char *TEST_ANONYMIZED_MAC_COLON = "dd:15:bc:**:**:04";
const char *TEST_PLAIN_MAC_CAPS = "91-1E-DD-EF-76-48";
const char *TEST_ANONYMIZED_MAC_CAPS = "91-1E-DD-**-**-48";
const char *TEST_PLAIN_MAC_CAPS_COLON = "91:1E:DD:EF:76:48";
const char *TEST_ANONYMIZED_MAC_CAPS_COLON = "91:1E:DD:**:**:48";
const char *TEST_PLAIN_IP_ONE = "10.11.12.1";
const char *TEST_ANONYMIZED_IP_ONE = "10.11.12.*";
const char *TEST_PLAIN_IP_TWO = "10.11.12.13";
const char *TEST_ANONYMIZED_IP_TWO = "10.11.12.**";
const char *TEST_PLAIN_IP_THREE = "10.11.12.133";
const char *TEST_ANONYMIZED_IP_THREE = "10.11.12.***";
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
    char *anonymizedStr = nullptr;
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
    char *anonymizedStr = nullptr;
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
    char *anonymizedStr = nullptr;
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
    char *anonymizedStr = nullptr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("**c", anonymizedStr);
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
 * @tc.desc: Test plainStr is empty
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest006, TestSize.Level0)
{
    const char *plainStr = "";
    char *anonymizedStr = nullptr;
    Anonymize(plainStr, &anonymizedStr);
    EXPECT_STREQ("EMPTY", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest007
 * @tc.desc: Test anonymize udid
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest007, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    Anonymize(TEST_PLAIN_UDID, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_UDID, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_UDID_CAPS, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_UDID_CAPS, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest008
 * @tc.desc: Test anonymize mac
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest008, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    Anonymize(TEST_PLAIN_MAC, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_MAC, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_MAC_CAPS, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_MAC_CAPS, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_MAC_COLON, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_MAC_COLON, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_MAC_CAPS_COLON, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_MAC_CAPS_COLON, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest009
 * @tc.desc: Test anonymize ip
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest009, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    Anonymize(TEST_PLAIN_IP_ONE, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_IP_ONE, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_IP_TWO, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_IP_TWO, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize(TEST_PLAIN_IP_THREE, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_IP_THREE, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest010
 * @tc.desc: Should return "NULL" when anonymizedStr is nullptr
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest010, TestSize.Level0)
{
    const char *anonymizedStr = nullptr;

    const char *ret = AnonymizeWrapper(anonymizedStr);
    EXPECT_STREQ(ret, "NULL");
}

/**
 * @tc.name: AnonymizeTest011
 * @tc.desc: Should return anonymizedStr when anonymizedStr is not nullptr
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest011, TestSize.Level0)
{
    const char *anonymizedStr = TEST_ANONYMIZED_UDID;

    const char *ret = AnonymizeWrapper(anonymizedStr);
    EXPECT_STREQ(ret, anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest012
 * @tc.desc: Test anonymize device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeTest012, TestSize.Level0)
{
    char *anonymizedStr = nullptr;

    Anonymize("1234", &anonymizedStr);
    EXPECT_STREQ("1**4", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("一二三四", &anonymizedStr);
    EXPECT_STREQ("一**四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("12345678", &anonymizedStr);
    EXPECT_STREQ("12****78", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("一二三四五六七八", &anonymizedStr);
    EXPECT_STREQ("一二****七八", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("12三四", &anonymizedStr);
    EXPECT_STREQ("1**四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("一二34", &anonymizedStr);
    EXPECT_STREQ("一**4", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("1二3四", &anonymizedStr);
    EXPECT_STREQ("1**四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("一2三4", &anonymizedStr);
    EXPECT_STREQ("一**4", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest013
 * @tc.desc: Test anonymize device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeTest013, TestSize.Level0)
{
    char *anonymizedStr = nullptr;

    Anonymize("1", &anonymizedStr);
    EXPECT_STREQ("*", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("12", &anonymizedStr);
    EXPECT_STREQ("*2", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("123", &anonymizedStr);
    EXPECT_STREQ("**3", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("1234", &anonymizedStr);
    EXPECT_STREQ("1**4", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("12345", &anonymizedStr);
    EXPECT_STREQ("1***5", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("123456", &anonymizedStr);
    EXPECT_STREQ("1***56", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("1234567", &anonymizedStr);
    EXPECT_STREQ("1****67", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("12345678", &anonymizedStr);
    EXPECT_STREQ("12****78", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("123456789", &anonymizedStr);
    EXPECT_STREQ("12*****89", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    Anonymize("1234567890", &anonymizedStr);
    EXPECT_STREQ("12*****890", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTest014
 * @tc.desc: Test anonymize invalid utf-8 str
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeTest014, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    const char *invalidUTF8Str = "invalid \xC0";

    Anonymize(invalidUTF8Str, &anonymizedStr);
    EXPECT_STREQ(invalidUTF8Str, anonymizedStr);
    AnonymizeFree(anonymizedStr);
}
} // namespace OHOS
