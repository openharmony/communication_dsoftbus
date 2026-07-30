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
#include "protocol/json_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "data/negotiate_message.h"

using namespace testing::ext;

namespace OHOS::SoftBus {

class JsonProtocolTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

namespace {
constexpr int32_t ROLE_GO = static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
constexpr int32_t ROLE_GC = static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GC);
constexpr int32_t VERSION_VALUE = 2;
constexpr int32_t STATION_FREQUENCY_VALUE = 5180;
constexpr int32_t GO_PORT_VALUE = 8888;
constexpr bool WIDE_BAND_SUPPORTED_VALUE = true;
constexpr bool BRIDGE_SUPPORTED_VALUE = false;
constexpr int EXPECTED_FIELD_COUNT = 14;
const std::string GC_IP_VALUE = "192.168.49.2";
const std::string MAC_VALUE = "AA:BB:CC:DD:EE:FF";
const std::string GO_IP_VALUE = "192.168.49.1";
const std::string GO_MAC_VALUE = "11:22:33:44:55:66";
const std::string GROUP_CONFIG_VALUE = "OHOS-1234\n00:01:02:03:04:05\n00001111\n5180";
const std::string GC_CHANNEL_LIST_VALUE = "36#40#44";
const std::string IP_VALUE = "192.168.43.4";

void WriteAllLegacyP2pFields(JsonProtocol &protocol)
{
    auto writeInt = [&protocol](int key, int32_t v) {
        protocol.Write(key, Serializable::ValueType::INT,
            reinterpret_cast<const uint8_t *>(&v), sizeof(int32_t));
    };
    auto writeStr = [&protocol](int key, const std::string &v) {
        protocol.Write(key, Serializable::ValueType::STRING,
            reinterpret_cast<const uint8_t *>(v.c_str()), v.size());
    };
    auto writeBool = [&protocol](int key, bool v) {
        protocol.Write(key, Serializable::ValueType::BOOL,
            reinterpret_cast<const uint8_t *>(&v), sizeof(bool));
    };
    writeInt(static_cast<int>(NegotiateMessageKey::ROLE), ROLE_GO);
    writeInt(static_cast<int>(NegotiateMessageKey::EXPECTED_ROLE), ROLE_GC);
    writeInt(static_cast<int>(NegotiateMessageKey::VERSION), VERSION_VALUE);
    writeInt(static_cast<int>(NegotiateMessageKey::STATION_FREQUENCY), STATION_FREQUENCY_VALUE);
    writeInt(static_cast<int>(NegotiateMessageKey::GO_PORT), GO_PORT_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::GC_IP), GC_IP_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::MAC), MAC_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::GO_IP), GO_IP_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::GO_MAC), GO_MAC_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::GROUP_CONFIG), GROUP_CONFIG_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::GC_CHANNEL_LIST), GC_CHANNEL_LIST_VALUE);
    writeStr(static_cast<int>(NegotiateMessageKey::IP), IP_VALUE);
    writeBool(static_cast<int>(NegotiateMessageKey::WIDE_BAND_SUPPORTED), WIDE_BAND_SUPPORTED_VALUE);
    writeBool(static_cast<int>(NegotiateMessageKey::BRIDGE_SUPPORTED), BRIDGE_SUPPORTED_VALUE);
}
} // namespace

HWTEST_F(JsonProtocolTest, GetType, TestSize.Level1)
{
    JsonProtocol protocol;
    EXPECT_EQ(protocol.GetType(), ProtocolType::JSON);
}

HWTEST_F(JsonProtocolTest, SetAndGetFormat, TestSize.Level1)
{
    JsonProtocol protocol;
    ProtocolFormat format = { 1, 2 };
    protocol.SetFormat(format);
    ProtocolFormat result = protocol.GetFormat();
    EXPECT_EQ(result.tagSize, format.tagSize);
    EXPECT_EQ(result.lengthSize, format.lengthSize);
}

HWTEST_F(JsonProtocolTest, SetFormatDoesNotAffectJsonBehavior, TestSize.Level1)
{
    JsonProtocol protocol;
    ProtocolFormat format = { 4, 8 };
    protocol.SetFormat(format);
    EXPECT_EQ(protocol.GetFormat().tagSize, 4u);
    EXPECT_EQ(protocol.GetFormat().lengthSize, 8u);

    int32_t value = 42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    JsonProtocol readProtocol;
    readProtocol.SetFormat(format);
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 42);
}

HWTEST_F(JsonProtocolTest, WriteAndReadBoolTrue, TestSize.Level1)
{
    JsonProtocol protocol;
    bool value = true;
    protocol.Write(static_cast<int>(NegotiateMessageKey::WIDE_BAND_SUPPORTED),
        Serializable::ValueType::BOOL, reinterpret_cast<const uint8_t *>(&value), sizeof(bool));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::WIDE_BAND_SUPPORTED));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), true);
}

HWTEST_F(JsonProtocolTest, WriteAndReadBoolFalse, TestSize.Level1)
{
    JsonProtocol protocol;
    bool value = false;
    protocol.Write(static_cast<int>(NegotiateMessageKey::BRIDGE_SUPPORTED),
        Serializable::ValueType::BOOL, reinterpret_cast<const uint8_t *>(&value), sizeof(bool));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::BRIDGE_SUPPORTED));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), false);
}

HWTEST_F(JsonProtocolTest, WriteAndReadInt, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t value = 42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::GO_PORT));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 42);
}

HWTEST_F(JsonProtocolTest, WriteAndReadNegativeInt, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t value = -25;
    protocol.Write(static_cast<int>(NegotiateMessageKey::RESULT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), -25);
}

HWTEST_F(JsonProtocolTest, WriteAndReadString, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string value = "AA:BB:CC:DD:EE:FF";
    protocol.Write(static_cast<int>(NegotiateMessageKey::MAC),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::MAC));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "AA:BB:CC:DD:EE:FF");
}

HWTEST_F(JsonProtocolTest, WriteAndReadEmptyString, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string value = "";
    protocol.Write(static_cast<int>(NegotiateMessageKey::MAC),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(readSize, 0u);
}

HWTEST_F(JsonProtocolTest, WriteAndReadStringWithSpecialChars, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string value = "36#40#44#48";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GC_CHANNEL_LIST),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "36#40#44#48");
}

HWTEST_F(JsonProtocolTest, WriteAndReadStringWithNewlines, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string value = "line1\nline2\nline3";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GROUP_CONFIG),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "line1\nline2\nline3");
}

HWTEST_F(JsonProtocolTest, WriteAndReadStringWithChinese, TestSize.Level2)
{
    JsonProtocol protocol;
    std::string value = "测试设备ID";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GC_IP),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "测试设备ID");
}

HWTEST_F(JsonProtocolTest, WriteMultipleInts, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t goPort = 100;
    int32_t resultCode = 204010;
    int32_t stationFreq = 5180;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&goPort), sizeof(int32_t));
    protocol.Write(static_cast<int>(NegotiateMessageKey::RESULT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&resultCode), sizeof(int32_t));
    protocol.Write(static_cast<int>(NegotiateMessageKey::STATION_FREQUENCY),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&stationFreq), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;

    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 100);
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 204010);
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 5180);
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, WriteWithUnsupportedValueType, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t value = 42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::UINT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, WriteOverwriteSameKey, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t val1 = 10;
    int32_t val2 = 20;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&val1), sizeof(int32_t));
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&val2), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 20);
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, MultipleReadReturnsFalseConsistently, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t value = 10;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, GetOutputFormatIsJson, TestSize.Level1)
{
    JsonProtocol protocol;
    int32_t value = 42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    std::string jsonStr(output.begin(), output.end());
    EXPECT_NE(jsonStr.find("KEY_GO_PORT"), std::string::npos);
    EXPECT_NE(jsonStr.find("42"), std::string::npos);
    EXPECT_EQ(jsonStr.front(), '{');
    EXPECT_EQ(jsonStr.back(), '}');
}

HWTEST_F(JsonProtocolTest, SetInputWithInvalidJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::vector<uint8_t> invalidInput = { 'i', 'n', 'v', 'a', 'l', 'i', 'd' };
    protocol.SetInput(invalidInput);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithNonObjectJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string arrayJson = "[1,2,3]";
    std::vector<uint8_t> input(arrayJson.begin(), arrayJson.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithNullAndPrimitiveJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "null";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));

    std::string numJson = "42";
    std::vector<uint8_t> numInput(numJson.begin(), numJson.end());
    protocol.SetInput(numInput);
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));

    std::string strJson = "\"hello\"";
    std::vector<uint8_t> strInput(strJson.begin(), strJson.end());
    protocol.SetInput(strInput);
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithEmptyObject, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string emptyObj = "{}";
    std::vector<uint8_t> input(emptyObj.begin(), emptyObj.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, ReadFromEmptyInput, TestSize.Level1)
{
    JsonProtocol protocol;
    std::vector<uint8_t> emptyInput;
    protocol.SetInput(emptyInput);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithWhitespaceJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{  \"KEY_GO_PORT\" : 42  }";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::GO_PORT));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 42);
}

HWTEST_F(JsonProtocolTest, SetInputWithUnknownKeyJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_GO_PORT\":42, \"unknown_key\":\"test\"}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::GO_PORT));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 42);
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithOnlyUnknownKeys, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"foo\":1, \"bar\":2}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, SetInputWithBooleanJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_WIDE_BAND_SUPPORTED\":true}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::WIDE_BAND_SUPPORTED));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), true);
}

HWTEST_F(JsonProtocolTest, SetInputWithIntegerJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_GO_PORT\":55}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::GO_PORT));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 55);
}

HWTEST_F(JsonProtocolTest, SetInputWithNegativeIntegerJson, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_RESULT\":-25}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), -25);
}

HWTEST_F(JsonProtocolTest, SetInputWithStringJson, TestSize.Level2)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_MAC\":\"my_device\"}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::MAC));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "my_device");
}

HWTEST_F(JsonProtocolTest, SetInputWithFalseBooleanAndEmptyString, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"KEY_BRIDGE_SUPPORTED\":false}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), false);

    std::string emptyStrJson = "{\"KEY_MAC\":\"\"}";
    std::vector<uint8_t> emptyInput(emptyStrJson.begin(), emptyStrJson.end());
    protocol.SetInput(emptyInput);
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(readSize, 0u);
}

HWTEST_F(JsonProtocolTest, MultipleSetInputOnSameProtocol, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string json1 = "{\"KEY_GO_PORT\":10}";
    std::vector<uint8_t> input1(json1.begin(), json1.end());
    protocol.SetInput(input1);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 10);

    std::string json2 = "{\"KEY_GO_PORT\":20}";
    std::vector<uint8_t> input2(json2.begin(), json2.end());
    protocol.SetInput(input2);
    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 20);
}

HWTEST_F(JsonProtocolTest, SetInputWithMixedKnownAndUnknownKeys, TestSize.Level1)
{
    JsonProtocol protocol;
    std::string jsonStr = "{\"foo\":1, \"KEY_GO_PORT\":42, \"bar\":3, \"KEY_MAC\":\"test\"}";
    std::vector<uint8_t> input(jsonStr.begin(), jsonStr.end());
    protocol.SetInput(input);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;

    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::GO_PORT));
    EXPECT_EQ(*reinterpret_cast<int *>(readValue), 42);

    EXPECT_TRUE(protocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::MAC));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "test");

    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(JsonProtocolTest, FactoryCreateJsonProtocol, TestSize.Level1)
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    ASSERT_NE(protocol, nullptr);
    EXPECT_EQ(protocol->GetType(), ProtocolType::JSON);
}

HWTEST_F(JsonProtocolTest, FactoryProtocolSetFormatAndWrite, TestSize.Level1)
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    ASSERT_NE(protocol, nullptr);
    ProtocolFormat format = { 2, 4 };
    protocol->SetFormat(format);
    EXPECT_EQ(protocol->GetFormat().tagSize, 2u);
    EXPECT_EQ(protocol->GetFormat().lengthSize, 4u);

    int32_t value = 10;
    protocol->Write(static_cast<int>(NegotiateMessageKey::GO_PORT),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol->GetOutput(output);
    EXPECT_FALSE(output.empty());
}

HWTEST_F(JsonProtocolTest, WriteAndReadAllLegacyP2pKeys, TestSize.Level2)
{
    JsonProtocol writeProtocol;
    WriteAllLegacyP2pFields(writeProtocol);

    std::vector<uint8_t> output;
    writeProtocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    JsonProtocol readProtocol;
    readProtocol.SetInput(output);
    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    int readCount = 0;
    while (readProtocol.Read(key, readValue, readSize)) {
        readCount++;
    }
    EXPECT_EQ(readCount, EXPECTED_FIELD_COUNT);
}

} // namespace OHOS::SoftBus
