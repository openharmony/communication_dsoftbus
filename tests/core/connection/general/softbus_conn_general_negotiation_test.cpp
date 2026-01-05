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
using namespace std;

#define DATA_LEN (5)

namespace OHOS {
class GeneralNegotiationTest : public testing::Test {
public:
    GeneralNegotiationTest() { }
    ~GeneralNegotiationTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GeneralNegotiationTest::SetUpTestCase(void) { }

void GeneralNegotiationTest::TearDownTestCase(void) { }

void GeneralNegotiationTest::SetUp(void) { }

void GeneralNegotiationTest::TearDown(void) { }

/*
* @tc.name: TestGeneralConnectionPackMsg1
* @tc.desc: test general connection pack msg
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsg1, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsg1 in");
    GeneralConnectionInfo info;
    const char *name = "testGeneralPackMsgName";
    int32_t ret = strcpy_s(info.name, GENERAL_NAME_LEN, name);
    EXPECT_EQ(ret, EOK);
    const char *bundleName = "testGeneralConnectionPackMsgBundleName";
    ret = strcpy_s(info.bundleName, BUNDLE_NAME_MAX, bundleName);
    EXPECT_EQ(ret, EOK);

    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE;
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(false));

    OutData *outData = nullptr;
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);

    msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);

    msgType = GENERAL_CONNECTION_MSG_TYPE_MERGE;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);

    msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);
}

/*
* @tc.name: TestGeneralConnectionPackMsg2
* @tc.desc: test general connection pack msg
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionPackMsg2, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test TestGeneralConnectionPackMsg2 in");
    GeneralConnectionInfo info;
    const char *name = "testGeneralPackMsgName";
    int32_t ret = strcpy_s(info.name, GENERAL_NAME_LEN, name);
    EXPECT_EQ(ret, EOK);
    const char *bundleName = "testGeneralConnectionPackMsgBundleName";
    ret = strcpy_s(info.bundleName, BUNDLE_NAME_MAX, bundleName);
    EXPECT_EQ(ret, EOK);
    info.peerId = 1;
    info.localId = 2;
    info.abilityBitSet = 2;
    info.ackStatus = SOFTBUS_OK;
    info.updateHandle = 3;
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));

    char *data = reinterpret_cast<char *>(SoftBusCalloc(DATA_LEN));
    if (data == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(data));
    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_RESET;

    OutData *outData = nullptr;
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_EQ(outData, nullptr);

    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    data = reinterpret_cast<char *>(SoftBusCalloc(DATA_LEN));
    if (data == nullptr) {
        return;
    }
    ret = strcpy_s(data, DATA_LEN, "1234");
    EXPECT_EQ(ret, EOK);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(data));
    msgType = GENERAL_CONNECTION_MSG_TYPE_RESET;
    outData = GeneralConnectionPackMsg(&info, msgType);
    EXPECT_NE(outData, nullptr);
    SoftBusFree(outData->data);
    SoftBusFree(outData);
}

/*
* @tc.name: TestGeneralConnectionUnpackMsg
* @tc.desc: test general connection unpack msg
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(GeneralNegotiationTest, TestGeneralConnectionUnpackMsg, TestSize.Level1)
{
    uint8_t *data = reinterpret_cast<uint8_t *>(SoftBusCalloc(DATA_LEN));
    GeneralConnectionInfo info;
    GeneralConnectionMsgType msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE;

    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    GeneralNegotiationInterfaceMock mock;
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectStringItem).WillOnce(Return(false));
    int32_t status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, msgType);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);

    msgType = GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));
    status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, msgType);
    EXPECT_EQ(status, SOFTBUS_PARSE_JSON_ERR);

    msgType = GENERAL_CONNECTION_MSG_TYPE_MERGE;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    EXPECT_CALL(mock, GetJsonObjectNumberItem).WillOnce(Return(false));
    status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, msgType);
    EXPECT_EQ(status, SOFTBUS_CREATE_JSON_ERR);

    msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, msgType);
    EXPECT_EQ(status, SOFTBUS_INVALID_PARAM);

    msgType = GENERAL_CONNECTION_MSG_TYPE_RESET;
    msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(mock, cJSON_ParseWithLength).WillOnce(Return(msg));
    status = GeneralConnectionUnpackMsg(data, sizeof(data), &info, msgType);
    EXPECT_EQ(status, SOFTBUS_OK);
    SoftBusFree(data);
}
}