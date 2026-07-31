/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "general_negotiation_mock.h"
#include "softbus_conn_general_negotiation.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;
using namespace testing;

namespace {
constexpr int32_t DATA_LEN = 5;

cJSON *AllocCjson()
{
    return static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
}

void FillGeneralConnectionInfo(GeneralConnectionInfo &info,
    const char *name = "testGeneralPackMsgName",
    const char *bundleName = "testGeneralConnectionPackMsgBundleName")
{
    EXPECT_EQ(strcpy_s(info.name, GENERAL_NAME_LEN, name), EOK);
    EXPECT_EQ(strcpy_s(info.bundleName, BUNDLE_NAME_MAX, bundleName), EOK);
}
}

namespace OHOS {
class GeneralNegotiationTest : public testing::Test {
public:
    GeneralNegotiationTest() = default;
    ~GeneralNegotiationTest() override = default;
};

/*
 * @tc.name: TestGeneralConnectionPackMsgHandshake
 * @tc.desc: test general connection pack msg HANDSHAKE with AddStringToJsonObject failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgHandshake, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgHandshake in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE;
    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestGeneralConnectionPackMsgHandshakeAck
 * @tc.desc: test general connection pack msg HANDSHAKE_ACK with AddNumberToJsonObject failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgHandshakeAck, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgHandshakeAck in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK;
    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestGeneralConnectionPackMsgMerge
 * @tc.desc: test general connection pack msg MERGE with AddNumberToJsonObject failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgMerge, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgMerge in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_MERGE;
    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestGeneralConnectionPackMsgNormal
 * @tc.desc: test general connection pack msg NORMAL returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgNormal, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgNormal in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;
    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));

    OutData *outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestGeneralConnectionPackMsgResetInvalidData
 * @tc.desc: test general connection pack msg RESET with invalid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgResetInvalidData, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgResetInvalidData in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 1;
    info.localId = 2;
    info.abilityBitSet = 2;
    info.ackStatus = SOFTBUS_OK;
    info.updateHandle = 3;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));

    char *data = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(data, nullptr);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(data));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestGeneralConnectionPackMsgResetSuccess
 * @tc.desc: test general connection pack msg RESET success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsgResetSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsgResetSuccess in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 1;
    info.localId = 2;
    info.abilityBitSet = 2;
    info.ackStatus = SOFTBUS_OK;
    info.updateHandle = 3;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));

    char *data = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(strcpy_s(data, DATA_LEN, "1234"), EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(data));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    EXPECT_NE(outData, nullptr);
    SoftBusFree(outData->data);
    SoftBusFree(outData);
}

/*
 * @tc.name: TestGeneralConnectionUnpackMsgHandshake
 * @tc.desc: test general connection unpack msg HANDSHAKE with GetJsonObjectStringItem failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsgHandshake, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionUnpackMsgHandshake in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectStringItem).WillOnce(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestGeneralConnectionUnpackMsgHandshakeAck
 * @tc.desc: test general connection unpack msg HANDSHAKE_ACK with GetJsonObjectSignedNumberItem failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsgHandshakeAck, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionUnpackMsgHandshakeAck in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestGeneralConnectionUnpackMsgMerge
 * @tc.desc: test general connection unpack msg MERGE with GetJsonObjectNumberItem failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsgMerge, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionUnpackMsgMerge in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillOnce(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    EXPECT_EQ(status, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: TestGeneralConnectionUnpackMsgNormal
 * @tc.desc: test general connection unpack msg NORMAL returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsgNormal, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionUnpackMsgNormal in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_NORMAL);
    EXPECT_EQ(status, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestGeneralConnectionUnpackMsgReset
 * @tc.desc: test general connection unpack msg RESET success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsgReset, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionUnpackMsgReset in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    EXPECT_EQ(status, SOFTBUS_OK);
}

/*
 * @tc.name: TestPackMsgInfoNull
 * @tc.desc: test GeneralConnectionPackMsg with null info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgInfoNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgInfoNull in");
    OutData *outData = GeneralConnectionPackMsg(nullptr, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgCreateJsonFail
 * @tc.desc: test GeneralConnectionPackMsg with cJSON_CreateObject returning null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgCreateJsonFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgCreateJsonFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(nullptr));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgHandshakeAddNameFail
 * @tc.desc: test HANDSHAKE with AddStringToJsonObject(name) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAddNameFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAddNameFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgHandshakeSuccess
 * @tc.desc: test HANDSHAKE success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeSuccess in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 100;
    info.localId = 200;
    info.abilityBitSet = 1;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));

    char *payload = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(payload, nullptr);
    EXPECT_EQ(strcpy_s(payload, DATA_LEN, "abcd"), EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(payload));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_NE(outData, nullptr);
    if (outData != nullptr) {
        EXPECT_GT(outData->dataLen, GENERAL_CONNECTION_HEADER_SIZE);
        SoftBusFree(outData->data);
        SoftBusFree(outData);
    }
}

/*
 * @tc.name: TestPackMsgHandshakeAckAddErrFail
 * @tc.desc: test HANDSHAKE_ACK with first AddNumberToJsonObject(ERR) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAckAddErrFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAckAddErrFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.ackStatus = SOFTBUS_OK;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgHandshakeAckSuccess
 * @tc.desc: test HANDSHAKE_ACK success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAckSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAckSuccess in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 10;
    info.localId = 20;
    info.ackStatus = SOFTBUS_OK;
    info.abilityBitSet = 3;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));

    char *payload = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(payload, nullptr);
    EXPECT_EQ(strcpy_s(payload, DATA_LEN, "abc"), EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(payload));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_NE(outData, nullptr);
    if (outData != nullptr) {
        SoftBusFree(outData->data);
        SoftBusFree(outData);
    }
}

/*
 * @tc.name: TestPackMsgMergeSuccess
 * @tc.desc: test MERGE success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgMergeSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgMergeSuccess in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 5;
    info.localId = 6;
    info.updateHandle = 99;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));

    char *payload = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(payload, nullptr);
    EXPECT_EQ(strcpy_s(payload, DATA_LEN, "ab"), EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(payload));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    EXPECT_NE(outData, nullptr);
    if (outData != nullptr) {
        SoftBusFree(outData->data);
        SoftBusFree(outData);
    }
}

/*
 * @tc.name: TestPackMsgResetSuccess
 * @tc.desc: test RESET success path with ConstructOutData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgResetSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgResetSuccess in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.peerId = 1;
    info.localId = 2;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));

    char *payload = static_cast<char *>(SoftBusCalloc(DATA_LEN));
    ASSERT_NE(payload, nullptr);
    EXPECT_EQ(strcpy_s(payload, DATA_LEN, "abcd"), EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(payload));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    EXPECT_NE(outData, nullptr);
    if (outData != nullptr) {
        EXPECT_GT(outData->dataLen, GENERAL_CONNECTION_HEADER_SIZE);
        SoftBusFree(outData->data);
        SoftBusFree(outData);
    }
}

/*
 * @tc.name: TestPackMsgPrintUnformattedFail
 * @tc.desc: test GeneralConnectionPackMsg with cJSON_PrintUnformatted returning null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgPrintUnformattedFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgPrintUnformattedFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestUnpackMsgDataNull
 * @tc.desc: test GeneralConnectionUnpackMsg with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgDataNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgDataNull in");
    GeneralConnectionInfo info = {};
    int32_t status = GeneralConnectionUnpackMsg(nullptr, 0, &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestUnpackMsgInfoNull
 * @tc.desc: test GeneralConnectionUnpackMsg with null info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgInfoNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgInfoNull in");
    uint8_t data[DATA_LEN] = {};
    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), nullptr, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestUnpackMsgParseJsonFail
 * @tc.desc: test GeneralConnectionUnpackMsg with cJSON_ParseWithLength returning null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgParseJsonFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgParseJsonFail in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(nullptr));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestUnpackMsgHandshakeSuccess
 * @tc.desc: test HANDSHAKE unpack success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgHandshakeSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgHandshakeSuccess in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_OK);
}

/*
 * @tc.name: TestUnpackMsgHandshakeAckSuccess
 * @tc.desc: test HANDSHAKE_ACK unpack success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgHandshakeAckSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgHandshakeAckSuccess in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_EQ(status, SOFTBUS_OK);
}

/*
 * @tc.name: TestUnpackMsgMergeSuccess
 * @tc.desc: test MERGE unpack success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgMergeSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgMergeSuccess in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    EXPECT_EQ(status, SOFTBUS_OK);
}

/*
 * @tc.name: TestUnpackMsgHandshakeGetNameFail
 * @tc.desc: test HANDSHAKE unpack with GetJsonObjectStringItem(NAME) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgHandshakeGetNameFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgHandshakeGetNameFail in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectStringItem).WillRepeatedly(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestUnpackMsgHandshakeAckGetErrFail
 * @tc.desc: test HANDSHAKE_ACK unpack with GetJsonObjectSignedNumberItem(ERR) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgHandshakeAckGetErrFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgHandshakeAckGetErrFail in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestUnpackMsgMergeGetHandleFail
 * @tc.desc: test MERGE unpack with GetJsonObjectNumberItem failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackMsgMergeGetHandleFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackMsgMergeGetHandleFail in");
    uint8_t data[DATA_LEN] = {};
    GeneralConnectionInfo info = {};

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillOnce(Return(false));

    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    EXPECT_EQ(status, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: TestFreeOutDataNullptr
 * @tc.desc: test FreeOutData with nullptr input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestFreeOutDataNullptr, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestFreeOutDataNullptr in");
    FreeOutData(nullptr);
}

/*
 * @tc.name: TestUnpackGeneralHeadNullptr
 * @tc.desc: test UnpackGeneralHead with nullptr input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackGeneralHeadNullptr, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackGeneralHeadNullptr in");
    UnpackGeneralHead(nullptr);
}

/*
 * @tc.name: TestPackGeneralHeadNormal
 * @tc.desc: test PackGeneralHead normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackGeneralHeadNormal, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackGeneralHeadNormal in");
    GeneralConnectionHead head = {};
    head.msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE;
    head.localId = 1;
    head.peerId = 2;
    head.headLen = GENERAL_CONNECTION_HEADER_SIZE;

    PackGeneralHead(&head);
    UnpackGeneralHead(&head);
    EXPECT_EQ(head.msgType, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(head.localId, 1u);
    EXPECT_EQ(head.peerId, 2u);
    EXPECT_EQ(head.headLen, GENERAL_CONNECTION_HEADER_SIZE);
}

/*
 * @tc.name: TestUnpackGeneralHeadNormal
 * @tc.desc: test UnpackGeneralHead normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestUnpackGeneralHeadNormal, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestUnpackGeneralHeadNormal in");
    GeneralConnectionHead head = {};
    head.msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE;
    head.localId = 1;
    head.peerId = 2;
    head.headLen = GENERAL_CONNECTION_HEADER_SIZE;

    PackGeneralHead(&head);
    UnpackGeneralHead(&head);
    EXPECT_EQ(head.msgType, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(head.localId, 1u);
    EXPECT_EQ(head.peerId, 2u);
    EXPECT_EQ(head.headLen, GENERAL_CONNECTION_HEADER_SIZE);
}

/*
 * @tc.name: TestPackMsgHandshakeAddBundleNameFail
 * @tc.desc: test HANDSHAKE with AddStringToJsonObject(bundleName) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAddBundleNameFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAddBundleNameFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(true)).WillOnce(Return(false));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(true));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgHandshakeAddAbilityFail
 * @tc.desc: test HANDSHAKE with AddNumberToJsonObject(ABILITY) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAddAbilityFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAddAbilityFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    EXPECT_EQ(outData, nullptr);
}

/*
 * @tc.name: TestPackMsgHandshakeAckAddAbilityFail
 * @tc.desc: test HANDSHAKE_ACK with AddNumberToJsonObject(ABILITY) failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralNegotiationTest, TestPackMsgHandshakeAckAddAbilityFail, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestPackMsgHandshakeAckAddAbilityFail in");
    GeneralConnectionInfo info = {};
    FillGeneralConnectionInfo(info);
    info.ackStatus = SOFTBUS_OK;

    cJSON *msg = AllocCjson();
    ASSERT_NE(msg, nullptr);
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(true)).WillOnce(Return(false));

    OutData *outData = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_EQ(outData, nullptr);
}
}