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

#include "trans_tcp_direct_json.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_error_code.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "trans_tcp_direct_json_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define SOCKET_PORT 1111
#define SOCKET_IP "1112"
#define ERR_DESC "P2p Pack Err Test"
#define JSON_STR "{\"test\":\"jsontest\"}"

class TransTcpDirectJsonMockTest : public testing::Test {
public:
    TransTcpDirectJsonMockTest()
    {}
    ~TransTcpDirectJsonMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectJsonMockTest::SetUpTestCase(void)
{}

void TransTcpDirectJsonMockTest::TearDownTestCase(void)
{}


/**
 * @tc.name: VerifyP2pPackErrorTest001
 * @tc.desc: VerifyP2pPackError test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pPackErrorTest001, TestSize.Level1)
{
    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    int32_t code = 0;
    int32_t errCode = 0;
    const char *errDesc = ERR_DESC;

    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    char *ret = VerifyP2pPackError(code, errCode, errDesc);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: VerifyP2pPackErrorTest002
 * @tc.desc: VerifyP2pPackError test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pPackErrorTest002, TestSize.Level1)
{
    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    int32_t code = 0;
    int32_t errCode = 0;
    const char *errDesc = ERR_DESC;
    cJSON *json = nullptr;

    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(tcpDirectJsonMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, AddStringToJsonObject).WillRepeatedly(Return(false));
    char *ret = VerifyP2pPackError(code, errCode, errDesc);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: VerifyP2pPackTest001
 * @tc.desc: VerifyP2pPack test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pPackTest001, TestSize.Level1)
{
    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    const char *myIp = SOCKET_IP;
    int32_t myPort = SOCKET_PORT;
    const char *peerIp = SOCKET_IP;

    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    char *ret = VerifyP2pPack(myIp, myPort, peerIp, 0, 0);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: VerifyP2pPackTest002
 * @tc.desc: VerifyP2pPack test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pPackTest002, TestSize.Level1)
{
    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    const char *myIp = SOCKET_IP;
    int32_t myPort = SOCKET_PORT;
    const char *peerIp = SOCKET_IP;
    cJSON *json = nullptr;

    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(tcpDirectJsonMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, AddStringToJsonObject).WillRepeatedly(Return(false));
    char *ret = VerifyP2pPack(myIp, myPort, peerIp, 0, 0);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: VerifyP2pUnPackTest001
 * @tc.desc: VerifyP2pUnPack test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pUnPackTest001, TestSize.Level1)
{
    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    char tmpIp[] = SOCKET_IP;
    int32_t tmpPort = SOCKET_PORT;
    int32_t uid = SOCKET_PORT;
    const char *jsonStr = JSON_STR;
    cJSON *json = cJSON_Parse(jsonStr);
    ProtocolType protocol = 0;
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(true))
        .WillRepeatedly(Return(false));
    VerifyP2pUnPack(json, tmpIp, &tmpPort, &protocol, &uid);
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectNumberItem).WillRepeatedly(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));
    int32_t ret = VerifyP2pUnPack(json, tmpIp, &tmpPort, &protocol, &uid);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
 * @tc.name: VerifyP2pPackWithProtocolTest001
 * @tc.desc: VerifyP2pPack test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pPackWithProtocolTest001, TestSize.Level1)
{
    const char *myIp = SOCKET_IP;
    int32_t myPort = SOCKET_PORT;
    const char *peerIp = SOCKET_IP;
    cJSON json;
    EXPECT_EQ(VerifyP2pPack(nullptr, -1, nullptr, LNN_PROTOCOL_MINTP, 0), nullptr);
    EXPECT_EQ(VerifyP2pPack(myIp, -1, nullptr, LNN_PROTOCOL_MINTP, 0), nullptr);

    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    EXPECT_EQ(VerifyP2pPack(myIp, myPort, peerIp, LNN_PROTOCOL_MINTP, 0), nullptr);

    EXPECT_CALL(tcpDirectJsonMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(tcpDirectJsonMock, AddNumberToJsonObject).WillOnce(Return(false));
    EXPECT_EQ(VerifyP2pPack(myIp, myPort, peerIp, LNN_PROTOCOL_MINTP, 0), nullptr);

    EXPECT_CALL(tcpDirectJsonMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(tcpDirectJsonMock, AddNumberToJsonObject).WillOnce(Return(false));
    EXPECT_EQ(VerifyP2pPack(myIp, myPort, peerIp, LNN_PROTOCOL_MINTP, 0), nullptr);
}

/**
 * @tc.name: VerifyP2pUnPackWithProtocolTest001
 * @tc.desc: VerifyP2pUnPack test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonMockTest, VerifyP2pUnPackWithProtocolTest001, TestSize.Level1)
{
    char myIp[IP_LEN] = { 0 };
    int32_t myPort = SOCKET_PORT;
    int32_t uid = SOCKET_PORT;
    ProtocolType protocol = LNN_PROTOCOL_MINTP;
    cJSON json;
    EXPECT_EQ(VerifyP2pUnPack(nullptr, nullptr, nullptr, nullptr, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(VerifyP2pUnPack(&json, nullptr, nullptr, nullptr, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, nullptr, nullptr, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, &myPort, nullptr, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, nullptr), SOFTBUS_INVALID_PARAM);

    NiceMock<TransTcpDirectJsonInterfaceMock> tcpDirectJsonMock;
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(false));
    EXPECT_NE(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, &uid), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(true));
    EXPECT_NE(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, &uid), SOFTBUS_PARSE_JSON_ERR);

    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectNumberItem).WillOnce(Return(false));
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, &uid), SOFTBUS_PARSE_JSON_ERR);

    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectNumberItem).WillOnce(Return(true));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectStringItem).WillOnce(Return(false));
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, &uid), SOFTBUS_PARSE_JSON_ERR);

    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectInt32Item).WillOnce(Return(false));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(tcpDirectJsonMock, GetJsonObjectStringItem).WillOnce(Return(true));
    EXPECT_EQ(VerifyP2pUnPack(&json, myIp, &myPort, &protocol, &uid), SOFTBUS_OK);
}
} // OHOS

