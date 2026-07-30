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
#include "protocol/tlv_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "data/negotiate_message.h"

using namespace testing::ext;

namespace OHOS::SoftBus {

class TlvProtocolTest : public testing::Test {
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
constexpr int EXPECTED_FIELD_COUNT = 13;
const std::string GC_IP_VALUE = "192.168.49.2";
const std::string MAC_VALUE = "AA:BB:CC:DD:EE:FF";
const std::string GO_IP_VALUE = "192.168.49.1";
const std::string GO_MAC_VALUE = "11:22:33:44:55:66";
const std::string GROUP_CONFIG_VALUE = "OHOS-Test\n00:11:22:33:44:55\nPass123\n5180";
const std::string GC_CHANNEL_LIST_VALUE = "36#40#44";

void WriteAllLegacyP2pFields(TlvProtocol &protocol)
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
    writeBool(static_cast<int>(NegotiateMessageKey::WIDE_BAND_SUPPORTED), WIDE_BAND_SUPPORTED_VALUE);
    writeBool(static_cast<int>(NegotiateMessageKey::BRIDGE_SUPPORTED), BRIDGE_SUPPORTED_VALUE);
}
} // namespace

HWTEST_F(TlvProtocolTest, GetType, TestSize.Level1)
{
    TlvProtocol protocol;
    EXPECT_EQ(protocol.GetType(), ProtocolType::TLV);
}

HWTEST_F(TlvProtocolTest, DefaultFormatValues, TestSize.Level1)
{
    TlvProtocol protocol;
    ProtocolFormat format = protocol.GetFormat();
    EXPECT_EQ(format.tagSize, TlvProtocol::TLV_TAG_SIZE);
    EXPECT_EQ(format.lengthSize, TlvProtocol::TLV_LENGTH_SIZE2);
    EXPECT_EQ(TlvProtocol::TLV_TAG_SIZE, 1);
    EXPECT_EQ(TlvProtocol::TLV_LENGTH_SIZE1, 1);
    EXPECT_EQ(TlvProtocol::TLV_LENGTH_SIZE2, 2);
}

HWTEST_F(TlvProtocolTest, SetAndGetFormat, TestSize.Level1)
{
    TlvProtocol protocol;
    ProtocolFormat defaultFormat = protocol.GetFormat();
    EXPECT_EQ(defaultFormat.tagSize, TlvProtocol::TLV_TAG_SIZE);
    EXPECT_EQ(defaultFormat.lengthSize, TlvProtocol::TLV_LENGTH_SIZE2);

    ProtocolFormat newFormat = { 2, 4 };
    protocol.SetFormat(newFormat);
    ProtocolFormat result = protocol.GetFormat();
    EXPECT_EQ(result.tagSize, 2u);
    EXPECT_EQ(result.lengthSize, 4u);
}

HWTEST_F(TlvProtocolTest, WriteAndReadSingleField, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0x01, 0x02, 0x03 };
    protocol.Write(1, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    bool ret = readProtocol.Read(key, readValue, readSize);
    EXPECT_TRUE(ret);
    EXPECT_EQ(key, 1);
    EXPECT_EQ(readSize, 3u);
    EXPECT_EQ(readValue[0], 0x01);
    EXPECT_EQ(readValue[1], 0x02);
    EXPECT_EQ(readValue[2], 0x03);
}

HWTEST_F(TlvProtocolTest, WriteAndReadMultipleFields, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    uint8_t data1[] = { 0xAA, 0xBB };
    uint8_t data2[] = { 0xCC, 0xDD, 0xEE, 0xFF };
    protocol.Write(10, Serializable::ValueType::BYTE_ARRAY, data1, sizeof(data1));
    protocol.Write(20, Serializable::ValueType::BYTE_ARRAY, data2, sizeof(data2));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 10);
    EXPECT_EQ(readSize, 2u);
    EXPECT_EQ(readValue[0], 0xAA);
    EXPECT_EQ(readValue[1], 0xBB);

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 20);
    EXPECT_EQ(readSize, 4u);
    EXPECT_EQ(readValue[0], 0xCC);

    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, WriteAndReadBoolTrue, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    bool value = true;
    protocol.Write(static_cast<int>(NegotiateMessageKey::IS_MODE_STRICT),
        Serializable::ValueType::BOOL, reinterpret_cast<const uint8_t *>(&value), sizeof(bool));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::IS_MODE_STRICT));
    EXPECT_EQ(readSize, sizeof(bool));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), true);
}

HWTEST_F(TlvProtocolTest, WriteAndReadBoolFalse, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    bool value = false;
    protocol.Write(static_cast<int>(NegotiateMessageKey::IS_BRIDGE_SUPPORTED),
        Serializable::ValueType::BOOL, reinterpret_cast<const uint8_t *>(&value), sizeof(bool));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), false);
}

HWTEST_F(TlvProtocolTest, WriteAndReadInt32, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int32_t value = 42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::SESSION_ID));
    EXPECT_EQ(readSize, sizeof(int32_t));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), 42);
}

HWTEST_F(TlvProtocolTest, WriteAndReadNegativeInt32, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int32_t value = -1;
    protocol.Write(static_cast<int>(NegotiateMessageKey::RESULT_CODE),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), -1);
}

HWTEST_F(TlvProtocolTest, WriteAndReadInt32Max, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int32_t value = INT32_MAX;
    protocol.Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), INT32_MAX);
}

HWTEST_F(TlvProtocolTest, WriteAndReadInt32Min, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int32_t value = INT32_MIN;
    protocol.Write(static_cast<int>(NegotiateMessageKey::RESULT_CODE),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), INT32_MIN);
}

HWTEST_F(TlvProtocolTest, WriteAndReadZeroInt32, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int32_t value = 0;
    protocol.Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), 0);
}

HWTEST_F(TlvProtocolTest, WriteAndReadStringAsBytes, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string value = "test_device";
    protocol.Write(static_cast<int>(NegotiateMessageKey::REMOTE_DEVICE_ID),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::REMOTE_DEVICE_ID));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "test_device");
}

HWTEST_F(TlvProtocolTest, WriteAndReadMacAddress, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string mac = "AA:BB:CC:DD:EE:FF";
    protocol.Write(static_cast<int>(NegotiateMessageKey::MAC),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(mac.c_str()), mac.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "AA:BB:CC:DD:EE:FF");
}

HWTEST_F(TlvProtocolTest, WriteAndReadIpAddress, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string ip = "192.168.49.1";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GO_IP),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(ip.c_str()), ip.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "192.168.49.1");
}

HWTEST_F(TlvProtocolTest, WriteAndReadChannelList, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string channelList = "36#40#44#48";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GC_CHANNEL_LIST),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(channelList.c_str()), channelList.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "36#40#44#48");
}

HWTEST_F(TlvProtocolTest, WriteAndReadStringWithNewlines, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string value = "OHOS-1234\n00:01:02:03:04:05\n00001111\n5180";
    protocol.Write(static_cast<int>(NegotiateMessageKey::GROUP_CONFIG),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(value.c_str()), value.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "OHOS-1234\n00:01:02:03:04:05\n00001111\n5180");
}

HWTEST_F(TlvProtocolTest, WriteMultipleBoolIntStringMixed, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    bool boolVal = true;
    int32_t intVal = 12345;
    std::string strVal = "device_id_test";
    uint8_t byteVal = 0x42;
    protocol.Write(static_cast<int>(NegotiateMessageKey::IS_MODE_STRICT),
        Serializable::ValueType::BOOL, reinterpret_cast<const uint8_t *>(&boolVal), sizeof(bool));
    protocol.Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&intVal), sizeof(int32_t));
    protocol.Write(static_cast<int>(NegotiateMessageKey::REMOTE_DEVICE_ID),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(strVal.c_str()), strVal.size());
    protocol.Write(static_cast<int>(NegotiateMessageKey::WIFI_CFG_TYPE),
        Serializable::ValueType::BYTE, &byteVal, 1);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::IS_MODE_STRICT));
    EXPECT_EQ(*reinterpret_cast<bool *>(readValue), true);

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::SESSION_ID));
    EXPECT_EQ(*reinterpret_cast<int32_t *>(readValue), 12345);

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, static_cast<int>(NegotiateMessageKey::REMOTE_DEVICE_ID));
    std::string readStr(reinterpret_cast<char *>(readValue), readSize);
    EXPECT_EQ(readStr, "device_id_test");

    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(readValue[0], 0x42);

    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, MultipleWriteReadCycles, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    for (int i = 0; i < 10; i++) {
        uint8_t data = static_cast<uint8_t>(i);
        protocol.Write(i, Serializable::ValueType::BYTE_ARRAY, &data, 1);
    }

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    for (int i = 0; i < 10; i++) {
        ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
        EXPECT_EQ(key, i);
        EXPECT_EQ(readSize, 1u);
        EXPECT_EQ(readValue[0], static_cast<uint8_t>(i));
    }
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, ReadFromEmptyInput, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> emptyInput;
    protocol.SetInput(emptyInput);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, MultipleReadReturnsFalseConsistently, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data = 0x01;
    protocol.Write(1, Serializable::ValueType::BYTE, &data, 1);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, WriteWithNullValue, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    protocol.Write(1, Serializable::ValueType::BYTE_ARRAY, nullptr, 3);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_TRUE(output.empty());
}

HWTEST_F(TlvProtocolTest, WriteWithZeroSize, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0x01 };
    protocol.Write(1, Serializable::ValueType::BYTE_ARRAY, data, 0);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_TRUE(output.empty());
}

HWTEST_F(TlvProtocolTest, WriteAndReadEmptyStringAsBytes, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::string emptyStr = "";
    protocol.Write(static_cast<int>(NegotiateMessageKey::REMOTE_DEVICE_ID),
        Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(emptyStr.c_str()), emptyStr.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_TRUE(output.empty());
}

HWTEST_F(TlvProtocolTest, ReadTruncatedDataWithTagOnly, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> truncated = { 0x01 };
    protocol.SetInput(truncated);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, ReadTruncatedDataWithPartialLength, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> truncated = { 0x01, 0x00 };
    protocol.SetInput(truncated);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, ReadTruncatedValue, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> truncated = { 0x01, 0x00, 0x05 };
    protocol.SetInput(truncated);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(protocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, VerifyOutputByteStructureWithLengthSize1, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });
    uint8_t data[] = { 0x03 };
    protocol.Write(10, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_EQ(output.size(), 3u);
    EXPECT_EQ(output[0], 10);
    EXPECT_EQ(output[1], 1);
    EXPECT_EQ(output[2], 0x03);
}

HWTEST_F(TlvProtocolTest, GetOutputAfterWrite, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0x01, 0x02 };
    protocol.Write(5, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_EQ(output.size(), 1u + 2u + 2u);
}

HWTEST_F(TlvProtocolTest, SetInputAndGetOutputRoundTrip, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0xAA, 0xBB, 0xCC };
    protocol.Write(42, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol protocol2;
    protocol2.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    protocol2.SetInput(output);

    std::vector<uint8_t> output2;
    protocol2.GetOutput(output2);
    EXPECT_EQ(output, output2);
}

HWTEST_F(TlvProtocolTest, SetInputAndGetOutputAreEqual, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    uint8_t data1[] = { 0x01 };
    uint8_t data2[] = { 0x02, 0x03 };
    protocol.Write(10, Serializable::ValueType::BYTE_ARRAY, data1, sizeof(data1));
    protocol.Write(20, Serializable::ValueType::BYTE_ARRAY, data2, sizeof(data2));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol protocol2;
    protocol2.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    protocol2.SetInput(output);
    std::vector<uint8_t> output2;
    protocol2.GetOutput(output2);

    EXPECT_EQ(output, output2);
}

HWTEST_F(TlvProtocolTest, WriteAndReadWithLengthSize1, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });
    uint8_t data[] = { 0x01, 0x02, 0x03 };
    protocol.Write(5, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_EQ(output.size(), 1u + 1u + 3u);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 5);
    EXPECT_EQ(readSize, 3u);
}

HWTEST_F(TlvProtocolTest, WriteWithTagSize2, TestSize.Level2)
{
    TlvProtocol protocol;
    protocol.SetFormat({ 2, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data = 0x42;
    protocol.Write(300, Serializable::ValueType::BYTE, &data, 1);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    EXPECT_EQ(output.size(), 2u + 2u + 1u);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ 2, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 300);
    EXPECT_EQ(readValue[0], 0x42);
}

HWTEST_F(TlvProtocolTest, WriteWithKeyZero, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data = 0xFF;
    protocol.Write(0, Serializable::ValueType::BYTE, &data, 1);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 0);
    EXPECT_EQ(readValue[0], 0xFF);
}

HWTEST_F(TlvProtocolTest, WriteWithLargeKey, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0xFF };
    protocol.Write(200, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(key, 200);
    EXPECT_EQ(readSize, 1u);
    EXPECT_EQ(readValue[0], 0xFF);
}

HWTEST_F(TlvProtocolTest, WriteAndReadLargeByteArray, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> largeData(200, 0xAB);
    protocol.Write(static_cast<int>(NegotiateMessageKey::WIFI_CFG_INFO),
        Serializable::ValueType::BYTE_ARRAY, largeData.data(), largeData.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(readSize, 200u);
    for (size_t i = 0; i < readSize; i++) {
        EXPECT_EQ(readValue[i], 0xAB);
    }
}

HWTEST_F(TlvProtocolTest, FormatMismatchBetweenWriteAndRead, TestSize.Level1)
{
    TlvProtocol writeProtocol;
    writeProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data[] = { 0x01, 0x02 };
    writeProtocol.Write(10, Serializable::ValueType::BYTE_ARRAY, data, sizeof(data));

    std::vector<uint8_t> output;
    writeProtocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ 2, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    EXPECT_FALSE(readProtocol.Read(key, readValue, readSize));
}

HWTEST_F(TlvProtocolTest, SetInputOverwritesPreviousData, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    uint8_t data1[] = { 0xAA };
    protocol.Write(1, Serializable::ValueType::BYTE_ARRAY, data1, sizeof(data1));
    std::vector<uint8_t> output1;
    protocol.GetOutput(output1);

    uint8_t data2[] = { 0xBB };
    protocol.Write(2, Serializable::ValueType::BYTE_ARRAY, data2, sizeof(data2));
    std::vector<uint8_t> output2;
    protocol.GetOutput(output2);

    EXPECT_NE(output1, output2);
}

HWTEST_F(TlvProtocolTest, FactoryCreateTlvProtocol, TestSize.Level1)
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    ASSERT_NE(protocol, nullptr);
    EXPECT_EQ(protocol->GetType(), ProtocolType::TLV);
}

HWTEST_F(TlvProtocolTest, FactoryCreateInvalidProtocol, TestSize.Level1)
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(static_cast<ProtocolType>(99));
    EXPECT_EQ(protocol, nullptr);
}

HWTEST_F(TlvProtocolTest, FactoryCreateAndUseBothProtocols, TestSize.Level2)
{
    auto jsonProtocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    auto tlvProtocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);

    ASSERT_NE(jsonProtocol, nullptr);
    ASSERT_NE(tlvProtocol, nullptr);
    EXPECT_EQ(jsonProtocol->GetType(), ProtocolType::JSON);
    EXPECT_EQ(tlvProtocol->GetType(), ProtocolType::TLV);

    int32_t value = 42;
    jsonProtocol->Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));
    std::vector<uint8_t> jsonOutput;
    jsonProtocol->GetOutput(jsonOutput);
    EXPECT_FALSE(jsonOutput.empty());

    tlvProtocol->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    tlvProtocol->Write(static_cast<int>(NegotiateMessageKey::SESSION_ID),
        Serializable::ValueType::INT, reinterpret_cast<const uint8_t *>(&value), sizeof(int32_t));
    std::vector<uint8_t> tlvOutput;
    tlvProtocol->GetOutput(tlvOutput);
    EXPECT_FALSE(tlvOutput.empty());

    EXPECT_NE(jsonOutput, tlvOutput);
}

HWTEST_F(TlvProtocolTest, WriteAndReadLegacyP2pFields, TestSize.Level2)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    WriteAllLegacyP2pFields(protocol);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);
    ASSERT_FALSE(output.empty());

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
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

HWTEST_F(TlvProtocolTest, WriteAndReadWifiConfigInfo, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> wifiConfig = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    protocol.Write(static_cast<int>(NegotiateMessageKey::WIFI_CFG_INFO),
        Serializable::ValueType::BYTE_ARRAY, wifiConfig.data(), wifiConfig.size());

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(readSize, 6u);
    EXPECT_EQ(readValue[0], 0xAA);
    EXPECT_EQ(readValue[5], 0xFF);
}

HWTEST_F(TlvProtocolTest, WriteAndReadSingleByte, TestSize.Level1)
{
    TlvProtocol protocol;
    protocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    uint8_t data = 0x42;
    protocol.Write(1, Serializable::ValueType::BYTE, &data, 1);

    std::vector<uint8_t> output;
    protocol.GetOutput(output);

    TlvProtocol readProtocol;
    readProtocol.SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    readProtocol.SetInput(output);

    int key = 0;
    uint8_t *readValue = nullptr;
    size_t readSize = 0;
    ASSERT_TRUE(readProtocol.Read(key, readValue, readSize));
    EXPECT_EQ(readValue[0], 0x42);
}

} // namespace OHOS::SoftBus
