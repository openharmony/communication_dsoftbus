/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cJSON.h"
#include "disc_coap_parser.h"
#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

class DiscCoapParserTest : public testing::Test {
public:
    DiscCoapParserTest() { }
    ~DiscCoapParserTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscCoapParserTest::SetUpTestCase(void) { }

void DiscCoapParserTest::TearDownTestCase(void) { }

/*
 * @tc.name: DiscCoapParseDeviceUdid001
 * @tc.desc: UDID should parse fail when call DiscCoapParseDeviceUdid with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseDeviceUdid001, TestSize.Level1)
{
    std::string jsonStr;
    DeviceInfo deviceInfo;

    int32_t ret = DiscCoapParseDeviceUdid(nullptr, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseDeviceUdid("test", nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseDeviceUdid("test", &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    jsonStr = R"({"UDID":""})";
    ret = DiscCoapParseDeviceUdid(jsonStr.c_str(), &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    jsonStr = R"({"key":"value"})";
    ret = DiscCoapParseDeviceUdid(jsonStr.c_str(), &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: DiscCoapParseDeviceUdid002
 * @tc.desc: UDID should parse success when call DiscCoapParseDeviceUdid with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseDeviceUdid002, TestSize.Level1)
{
    std::string jsonStr = R"({"UDID":"123456789udidtest"})";
    DeviceInfo deviceInfo;

    int32_t ret = DiscCoapParseDeviceUdid(jsonStr.c_str(), &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(deviceInfo.devId, "3d8f8983c8fb9825");
}

/*
 * @tc.name: DiscCoapParseWifiIpAddr001
 * @tc.desc: wifiIpAddr should parse success when call DiscCoapParseWifiIpAddr with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseWifiIpAddr001, TestSize.Level1)
{
    std::string dataStr = R"({"wifiIpAddr":"0.0.0.0"})";
    cJSON *dataJson = cJSON_Parse(dataStr.c_str());
    DeviceInfo deviceInfo;

    DiscCoapParseWifiIpAddr(dataJson, &deviceInfo);
    EXPECT_EQ(deviceInfo.addrNum, 1);
    EXPECT_STREQ(deviceInfo.addr[0].info.ip.ip, "0.0.0.0");
}

/*
 * @tc.name: DiscCoapParseKeyValueStr001
 * @tc.desc: key:value should parse fail when call DiscCoapParseKeyValueStr with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseKeyValueStr001, TestSize.Level1)
{
    std::string srcTest(DISC_MAX_CUST_DATA_LEN, 'a');
    char outValueTest[MAX_PORT_STR_LEN] = { 0 };

    int32_t ret = DiscCoapParseKeyValueStr(nullptr, SERVICE_DATA_PORT, outValueTest, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseKeyValueStr(srcTest.c_str(), nullptr, outValueTest, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseKeyValueStr(srcTest.c_str(), SERVICE_DATA_PORT, nullptr, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseKeyValueStr(srcTest.c_str(), SERVICE_DATA_PORT, outValueTest, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    srcTest = "serviceDataTest";
    ret = DiscCoapParseKeyValueStr(srcTest.c_str(), SERVICE_DATA_PORT, outValueTest, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_PARSE_DATA_FAIL);
}

/*
 * @tc.name: DiscCoapParseKeyValueStr002
 * @tc.desc: key:value should parse success when call DiscCoapParseKeyValueStr with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseKeyValueStr002, TestSize.Level1)
{
    std::string srcTest;
    char outValue[MAX_PORT_STR_LEN] = { 0 };

    srcTest = "port:1234";
    int32_t ret = DiscCoapParseKeyValueStr(srcTest.c_str(), SERVICE_DATA_PORT, outValue, MAX_PORT_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(outValue, "1234");
}

/*
 * @tc.name: DiscCoapParseServiceData001
 * @tc.desc: serviceData should parse fail when call DiscCoapParseServiceData with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseServiceData001, TestSize.Level1)
{
    std::string dataStr = R"({"key":"value"})";
    cJSON *dataJson = cJSON_Parse(dataStr.c_str());
    cJSON cjsonTest;
    DeviceInfo deviceInfo;

    int32_t ret = DiscCoapParseServiceData(nullptr, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseServiceData(&cjsonTest, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapParseServiceData(dataJson, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    dataStr = R"({"serviceData":"serviceDataTest"})";
    dataJson = cJSON_Parse(dataStr.c_str());
    ret = DiscCoapParseServiceData(dataJson, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_PARSE_DATA_FAIL);

    dataStr = R"({"serviceData":"port:0"})";
    dataJson = cJSON_Parse(dataStr.c_str());
    ret = DiscCoapParseServiceData(dataJson, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_PARSE_DATA_FAIL);
}

/*
 * @tc.name: DiscCoapParseServiceData002
 * @tc.desc: serviceData should parse success when call DiscCoapParseServiceData with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseServiceData002, TestSize.Level1)
{
    std::string dataStr;
    cJSON *dataJson = cJSON_Parse(dataStr.c_str());
    DeviceInfo deviceInfo;

    dataStr = R"({"serviceData":"port:1234"})";
    dataJson = cJSON_Parse(dataStr.c_str());
    int32_t ret = DiscCoapParseServiceData(dataJson, &deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(deviceInfo.addr[0].info.ip.port, 1234);
}

/*
 * @tc.name: DiscCoapParseHwAccountHash001
 * @tc.desc: hwAccountHashVal should parse success when call DiscCoapParseHwAccountHash with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapParserTest, DiscCoapParseHwAccountHash001, TestSize.Level1)
{
    std::string dataStr = R"({"hwAccountHashVal":"test"})";
    cJSON *dataJson = cJSON_Parse(dataStr.c_str());
    DeviceInfo deviceInfo;

    DiscCoapParseHwAccountHash(dataJson, &deviceInfo);
    EXPECT_STREQ(deviceInfo.accountHash,
        "\x9F\x86\xD0\x81\x88L}e\x9A/\xEA\xA0\xC5Z\xD0\x15\xA3\xBFO\x1B+\v\x82,\xD1]l\x15\xB0\xF0\n\b");
}
} // namespace OHOS
