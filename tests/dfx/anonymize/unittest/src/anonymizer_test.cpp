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
const char *TEST_PLAIN_IP_CIDR = "10.0.0.0/32";
const char *TEST_ANONYMIZED_IP_CIDR = "10.0.0.****";
const uint32_t DEVICE_NAME_MAX_LEN = 128;
} // namespace

namespace OHOS {
class AnonymizerTest : public testing::Test { };

/*
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

/*
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

/*
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

/*
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

/*
 * @tc.name: AnonymizeTest005
 * @tc.desc: AnonymizeFree nullptr pointer test
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest005, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    AnonymizeFree(anonymizedStr);
    EXPECT_EQ(nullptr, anonymizedStr);
}

/*
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

/*
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

/*
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

/*
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
 * @tc.name: AnonymizeTestIpCidr001
 * @tc.desc: Test anonymize ip
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTestIpCidr001, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    Anonymize(TEST_PLAIN_IP_CIDR, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_IP_CIDR, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr1[] = "255.255.255.255/322";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr1, &anonymizedStr));
    EXPECT_STREQ("255.**********5/322", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr2[] = "255.255.255.255/";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr2, &anonymizedStr));
    EXPECT_STREQ("255.********255/", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr3[] = "255.255.255.255//2";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr3, &anonymizedStr));
    EXPECT_STREQ("255.*********55//2", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr4[] = "255.255.1.1/8";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr4, &anonymizedStr));
    EXPECT_STREQ("255.255.1.***", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr5[] = "255.255.1.1/24";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr5, &anonymizedStr));
    EXPECT_STREQ("255.255.1.****", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr6[] = "255.255.1.1/245";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr6, &anonymizedStr));
    EXPECT_STREQ("255********/245", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr7[] = "255.255.1/.1";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr7, &anonymizedStr));
    EXPECT_STREQ("255******/.1", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/**
 * @tc.name: AnonymizeTestIpCidr002
 * @tc.desc: Test anonymize not ip
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTestIpCidr002, TestSize.Level0)
{
    char *anonymizedStr = nullptr;
    Anonymize(TEST_PLAIN_IP_CIDR, &anonymizedStr);
    EXPECT_STREQ(TEST_ANONYMIZED_IP_CIDR, anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr1[] = "192.168.12.12.";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr1, &anonymizedStr));
    EXPECT_STREQ("192*******.12.", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr2[] = ".192.168.12.12";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr2, &anonymizedStr));
    EXPECT_STREQ(".19*******2.12", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr3[] = "192.168.12.";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr3, &anonymizedStr));
    EXPECT_STREQ("19******12.", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr4[] = ".192.168.12";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr4, &anonymizedStr));
    EXPECT_STREQ(".1******.12", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    constexpr char ipCidr5[] = "192.168.12";
    EXPECT_NO_FATAL_FAILURE(Anonymize(ipCidr5, &anonymizedStr));
    EXPECT_STREQ("19*****.12", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/*
 * @tc.name: AnonymizeTest010
 * @tc.desc: Should return "NULL"
 *           when anonymizedStr is nullptr
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest010, TestSize.Level0)
{
    const char *anonymizedStr = nullptr;

    const char *ret = AnonymizeWrapper(anonymizedStr);
    EXPECT_STREQ(ret, "NULL");
}

/*
 * @tc.name: AnonymizeTest011
 * @tc.desc: Should return anonymizedStr
 *           when anonymizedStr is not nullptr
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AnonymizerTest, AnonymizeTest011, TestSize.Level0)
{
    const char *anonymizedStr = TEST_ANONYMIZED_UDID;

    const char *ret = AnonymizeWrapper(anonymizedStr);
    EXPECT_STREQ(ret, anonymizedStr);
}

/*
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

/*
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

/*
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

/*
 * @tc.name: AnonymizeDeviceNameTest001
 * @tc.desc: Test anonymize device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeDeviceNameTest001, TestSize.Level0)
{
    const char *plainStr = nullptr;
    EXPECT_NO_FATAL_FAILURE(Anonymize(plainStr, nullptr));

    char *anonymizedStr = nullptr;
    AnonymizeDeviceName(plainStr, &anonymizedStr);
    EXPECT_STREQ("NULL", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    char emptyStr[DEVICE_NAME_MAX_LEN] = {0};
    AnonymizeDeviceName(emptyStr, &anonymizedStr);
    EXPECT_STREQ("EMPTY", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/*
 * @tc.name: AnonymizeDeviceNameTest002
 * @tc.desc: Test anonymize nick device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeDeviceNameTest002, TestSize.Level0)
{
    char *anonymizedStr = nullptr;

    AnonymizeDeviceName("张的Mxxe 00 Pxx", &anonymizedStr);
    EXPECT_STREQ("张*********Pxx", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三-Mxxe 00 Pxx", &anonymizedStr);
    EXPECT_STREQ("张**********Pxx", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三的Mxxe 00 Pxx+", &anonymizedStr);
    EXPECT_STREQ("张***********xx+", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("abcdefghijklmnopqrst的Mxxe 00 Pxx+", &anonymizedStr);
    EXPECT_STREQ("a*****************************xx+", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈的Mxxe 00 Pxx+", &anonymizedStr);
    EXPECT_STREQ("哈*****************************xx+", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("zhang-san-sanaaaaaaa-Mxxe 00 Pxx+", &anonymizedStr);
    EXPECT_STREQ("z*****************************xx+", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张的三的四的一二三四-1234-5678-Mxxe 00 Pxx+", &anonymizedStr);
    EXPECT_STREQ("张*****************************xx+", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}

/*
 * @tc.name: AnonymizeDeviceNameTest003
 * @tc.desc: Test anonymize user defined device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnonymizerTest, AnonymizeDeviceNameTest003, TestSize.Level0)
{
    char *anonymizedStr = nullptr;

    AnonymizeDeviceName("a", &anonymizedStr);
    EXPECT_STREQ("*", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("ab", &anonymizedStr);
    EXPECT_STREQ("*b", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三1", &anonymizedStr);
    EXPECT_STREQ("**1", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三李四", &anonymizedStr);
    EXPECT_STREQ("张**四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三w李四王", &anonymizedStr);
    EXPECT_STREQ("张***四王", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三w李12四", &anonymizedStr);
    EXPECT_STREQ("张****2四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("张三w李123四", &anonymizedStr);
    EXPECT_STREQ("张****23四", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("zhagnsan李si", &anonymizedStr);
    EXPECT_STREQ("z*******李si", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb"
        "aaaaaaaaaaaaaaaaaaaa", &anonymizedStr);
    EXPECT_STREQ("a**************************************************************************************"
        "**********aaa", anonymizedStr);
    AnonymizeFree(anonymizedStr);

    AnonymizeDeviceName("一二三四五六七八九十一二三四五六七八九十一二三四五六七八九十一二三1", &anonymizedStr);
    EXPECT_STREQ("一******************************二三1", anonymizedStr);
    AnonymizeFree(anonymizedStr);
}
} // namespace OHOS
