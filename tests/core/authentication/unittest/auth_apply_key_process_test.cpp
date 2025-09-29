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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_apply_key_manager.h"
#include "auth_apply_key_process.c"
#include "auth_apply_key_process.h"
#include "auth_apply_key_process_mock.h"
#include "auth_log.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager_struct.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

#define D2D_CLOSE_ACK   "d2d_close_ack"

constexpr char NODE1_ACCOUNT_HASH[D2D_ACCOUNT_HASH_STR_LEN] = "abcd";
constexpr char NODE1_UDID_HASH[] = "123";
constexpr char TEST_DATA[] = "testdata";
constexpr uint8_t TEST_APPLY_KEY_DATA[] = "apply_key_data";
constexpr uint64_t APPLY_KEY_DECAY_TIME = 15552000000;
constexpr uint32_t AUTH_CONN_DATA_HEAD_SIZE = 24;
int32_t g_ret = 0;

class AuthApplyKeyProcessTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthApplyKeyProcessTest::SetUpTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyProcessTest start");
}

void AuthApplyKeyProcessTest::TearDownTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyProcessTest end");
}

void AuthApplyKeyProcessTest::SetUp() { }

void AuthApplyKeyProcessTest::TearDown() { }

static void OnGenSuccessTest(uint32_t requestId, uint8_t *applyKey, uint32_t applyKeyLen)
{
    AUTH_LOGI(AUTH_CONN, "OnGenSuccessTest called");
    (void)requestId;
    (void)applyKey;
    (void)applyKeyLen;
}

static void OnGenFailedTest(uint32_t requestId, int32_t reason)
{
    AUTH_LOGI(AUTH_CONN, "OnGenFailedTest called");
    (void)requestId;
    (void)reason;
}

/*
 * @tc.name: REQUIRE_APPLY_KEY_NEGO_LIST_LOCK_Test_001
 * @tc.desc: require ApplyKey NegoList Lock test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, REQUIRE_APPLY_KEY_NEGO_LIST_LOCK_Test_001, TestSize.Level1)
{
    bool ret = RequireApplyKeyNegoListLock();
    EXPECT_EQ(ret, false);
    ReleaseApplyKeyNegoListLock();
}

/*
 * @tc.name: INIT_APPLY_KEY_NEGO_INSTANCE_LIST_Test_001
 * @tc.desc: Init ApplyKey NegoInstance List test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, INIT_APPLY_KEY_NEGO_INSTANCE_LIST_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    DeInitApplyKeyNegoInstanceList();
    int32_t ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeInitApplyKeyNegoInstanceList();
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: GET_SAMPLE_APPLY_KEY_INSTANCE_NUM_Test_001
 * @tc.desc: Get applyKeyInstance number by same info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, GET_SAMPLE_APPLY_KEY_INSTANCE_NUM_Test_001, TestSize.Level1)
{
    RequestBusinessInfo info;
    uint32_t requestId = 0;
    uint32_t connId = 0;
    GenApplyKeyCallback cb;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    uint32_t num = GetSameApplyKeyInstanceNum(&info);
    EXPECT_EQ(num, 0);
    DeleteApplyKeyNegoInstance(requestId);
    int32_t ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    num = GetSameApplyKeyInstanceNum(&info);
    EXPECT_EQ(num, 0);
    DeleteApplyKeyNegoInstance(requestId);
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, connId, true, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateApplyKeyNegoInstance(&info, requestId, connId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    num = GetSameApplyKeyInstanceNum(&info);
    EXPECT_EQ(num, 0);
    EXPECT_EQ(strcpy_s(info.accountHash, D2D_ACCOUNT_HASH_STR_LEN, NODE1_ACCOUNT_HASH), EOK);
    EXPECT_EQ(strcpy_s(info.udidHash, D2D_UDID_HASH_STR_LEN, NODE1_UDID_HASH), EOK);
    ret = CreateApplyKeyNegoInstance(&info, requestId, connId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetApplyKeyStartState(requestId, GEN_APPLY_KEY_STATE_START);
    EXPECT_EQ(ret, SOFTBUS_OK);
    num = GetSameApplyKeyInstanceNum(&info);
    EXPECT_EQ(num, 1);
    DeleteApplyKeyNegoInstance(requestId + 1);
    DeleteApplyKeyNegoInstance(requestId);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: GET_GEN_APPLY_KEY_INSTANCE_BY_REQ_Test_001
 * @tc.desc: Get applyKeyInstance by req test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, GET_GEN_APPLY_KEY_INSTANCE_BY_REQ_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    uint32_t connId = 0;
    ApplyKeyNegoInstance instance;
    RequestBusinessInfo info;
    GenApplyKeyCallback cb;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    (void)memset_s(&instance, sizeof(instance), 0, sizeof(instance));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    int32_t ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByReq(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, connId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByReq(requestId + 1, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: GET_GEN_APPLY_KEY_INSTANCE_BY_CHANNEL_Test_001
 * @tc.desc: Get applyKeyInstance by channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, GET_GEN_APPLY_KEY_INSTANCE_BY_CHANNEL_Test_001, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t requestId = 0;
    ApplyKeyNegoInstance instance;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    (void)memset_s(&instance, sizeof(instance), 0, sizeof(instance));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    int32_t ret = GetGenApplyKeyInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByChannel(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetGenApplyKeyInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetGenApplyKeyInstanceByChannel(channelId + 1, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    ret = GetGenApplyKeyInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: SET_APPLY_KEY_NEGO_INFO_Test_001
 * @tc.desc: set apply key instance info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, SET_APPLY_KEY_NEGO_INFO_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t channelId = 0;
    ApplyKeyNegoInstance instance;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AuthInsertApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    (void)memset_s(&instance, sizeof(instance), 0, sizeof(instance));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(accountHash, SHA_256_HEX_HASH_LEN, NODE1_ACCOUNT_HASH), EOK);
    uint8_t sessionKey[D2D_APPLY_KEY_LEN] = { 0 };

    int32_t ret = SetNegoInfoRecvSessionKey(requestId, true, sessionKey, D2D_APPLY_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = SetNegoInfoRecvFinish(requestId, true, accountHash);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = SetNegoInfoRecvCloseAck(requestId, true);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetNegoInfoRecvSessionKey(requestId, true, sessionKey, D2D_APPLY_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = SetNegoInfoRecvFinish(requestId, true, accountHash);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = SetNegoInfoRecvCloseAck(requestId, true);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetNegoInfoRecvSessionKey(requestId, true, sessionKey, D2D_APPLY_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    ret = SetNegoInfoRecvFinish(requestId, true, accountHash);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    ret = SetNegoInfoRecvCloseAck(requestId, true);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetNegoInfoRecvSessionKey(requestId, true, sessionKey, D2D_APPLY_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetNegoInfoRecvFinish(requestId, true, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetNegoInfoRecvCloseAck(requestId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: SET_APPLY_KEY_STAR_STATE_Test_001
 * @tc.desc: set apply key instance state test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, SET_APPLY_KEY_STAR_STATE_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t channelId = 0;
    ApplyKeyNegoInstance instance;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    GenApplyKeyStartState state = GEN_APPLY_KEY_STATE_START;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    (void)memset_s(&instance, sizeof(instance), 0, sizeof(instance));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = SetApplyKeyStartState(requestId, state);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitApplyKeyNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetApplyKeyStartState(requestId, state);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetApplyKeyStartState(requestId, state);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND);
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetApplyKeyStartState(requestId, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: AUTH_FIND_APPLY_KEY_Test_001
 * @tc.desc: Find ApplyKey by businessInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, AUTH_FIND_APPLY_KEY_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    RequestBusinessInfo info;
    uint8_t applyKey[D2D_APPLY_KEY_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(accountHash, SHA_256_HEX_HASH_LEN, NODE1_ACCOUNT_HASH), EOK);

    int32_t ret = AuthFindApplyKey(nullptr, applyKey, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(authApplyKeyMock, GetApplyKeyByBusinessInfo).WillOnce(Return(SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND));
    ret = AuthFindApplyKey(&info, applyKey, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND);

    EXPECT_CALL(authApplyKeyMock, GetApplyKeyByBusinessInfo).WillOnce(Return(SOFTBUS_OK));
    ret = AuthFindApplyKey(&info, applyKey, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_GEN_APPLY_KEY_ID_Test_001
 * @tc.desc: Get ApplyKey by businessInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, AUTH_GEN_APPLY_KEY_ID_Test_001, TestSize.Level1)
{
    RequestBusinessInfo info;
    uint32_t requestId = 1;
    uint32_t connId = 1;
    GenApplyKeyCallback genCb;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    int32_t ret = AuthGenApplyKey(nullptr, requestId, connId, &genCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthGenApplyKey(&info, requestId, connId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthGenApplyKey(&info, requestId, connId, &genCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

int32_t startLightAccountAuthStub(
    int32_t osAccountId, int64_t requestId, const char *serviceId, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)serviceId;
    (void)laCallBack;

    return SOFTBUS_ERR;
}

int32_t processLightAccountAuthStub(
    int32_t osAccountId, int64_t requestId, DataBuff *inMsg, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)inMsg;
    (void)laCallBack;

    return SOFTBUS_ERR;
}

/*
 * @tc.name: ON_COMM_DATA_RECEIVED_Test_001
 * @tc.desc: Received Data process test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_COMM_DATA_RECEIVED_Test_001, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnModule moduleId = MODULE_SLE_AUTH_CMD;
    int64_t seq = 1;
    const char *data = "123456";
    int32_t len = 7;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnCommDataReceived(connectionId, moduleId, seq, (char *)data, len);
    AuthDataHead head;
    uint8_t body = '1';
    head.dataType = DATA_TYPE_DEVICE_ID;
    head.seq = 1;
    EXPECT_CALL(authApplyKeyMock, UnpackAuthData).WillRepeatedly(DoAll(SetArgPointee<2>(head), Return(&body)));
    EXPECT_CALL(authApplyKeyMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    moduleId = MODULE_APPLY_KEY_CONNECTION;
    OnCommDataReceived(connectionId, moduleId, seq, (char *)data, len);
    head.dataType = DATA_TYPE_AUTH;
    LightAccountVerifier accountVerifier;
    accountVerifier.processLightAccountAuth = processLightAccountAuthStub;
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetLightAccountVerifierInstance).WillRepeatedly(Return(&accountVerifier));
    OnCommDataReceived(connectionId, moduleId, seq, (char *)data, len);

    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: ON_REQUEST_Test_001
 * @tc.desc: OnRequest func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_REQUEST_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int operationCode = 0;
    const char *reqParams = "123456";
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;

    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    char *msg = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(msg, nullptr);

    msg = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_NE(msg, nullptr);
    cJSON_free(msg);
}

/*
 * @tc.name: ON_ERROR_Test_001
 * @tc.desc: OnError func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_ERROR_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int operationCode = 0;
    int32_t errCode = 1;
    const char *errorReturn = "123456";

    EXPECT_NO_FATAL_FAILURE(OnError(authSeq, operationCode, errCode, errorReturn));
}

/*
 * @tc.name: ON_FINISHED_Test_001
 * @tc.desc: On Finished func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_FINISHED_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int operationCode = 0;
    const char *returnData = "123456";
    uint32_t requestId = 0;
    int32_t channelId = 0;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(authApplyKeyMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));
    OnFinished(authSeq, operationCode, returnData);
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char returnData1[] = "{\"peerUserId\":\"3003131321323131132321\"}";
    OnFinished(authSeq, operationCode, returnData1);
    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: ON_SESSION_KEY_RETURNED_Test_001
 * @tc.desc: On SessionKey Returned func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_SESSION_KEY_RETURNED_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t sessionKeyLen = 5;
    int32_t channelId = 0;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnSessionKeyReturned(authSeq, nullptr, sessionKeyLen);
    OnSessionKeyReturned(authSeq, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, authSeq, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnSessionKeyReturned(authSeq, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    OnSessionKeyReturned(authSeq, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));

    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: ON_SESSION_KEY_RETURNED_Test_001
 * @tc.desc: On Transmitted func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_TRANSMITTED_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 5;
    int32_t channelId = 0;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool isSuc = OnTransmitted(authSeq, nullptr, len);
    EXPECT_EQ(isSuc, false);
    isSuc = OnTransmitted(authSeq, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    EXPECT_EQ(isSuc, false);
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, authSeq, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE + len));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillOnce(Return(SOFTBUS_OK));
    isSuc = OnTransmitted(authSeq, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    EXPECT_EQ(isSuc, true);

    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: ON_GEN_FAILED_Test_001
 * @tc.desc: On GenFailed func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_GEN_FAILED_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t reason = 0;
    int32_t channelId = 0;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));

    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnGenFailed(requestId, reason);
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    GenApplyKeyTimeoutProcess(&requestId);

    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: ON_GEN_SUCCESS_Test_001
 * @tc.desc: On GenSuccess func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, ON_GEN_SUCCESS_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t channelId = 0;
    GenApplyKeyCallback cb;
    RequestBusinessInfo info;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));

    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnGenSuccess(requestId);
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnGenSuccess(requestId);

    ApplyKeyNegoDeinit();
}

/*
 * @tc.name: POST_APPLY_KEY_DATA_Test_001
 * @tc.desc: Post ApplyKey Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, POST_APPLY_KEY_DATA_Test_001, TestSize.Level1)
{
    uint32_t connId = 0;
    AuthDataHead head;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    int32_t ret = PostApplyKeyData(connId, true, &head, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE + head.len));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillOnce(Return(SOFTBUS_NO_ENOUGH_DATA));
    ret = PostApplyKeyData(connId, true, &head, TEST_APPLY_KEY_DATA);
    EXPECT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);

    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillOnce(Return(SOFTBUS_OK));
    ret = PostApplyKeyData(connId, true, &head, TEST_APPLY_KEY_DATA);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: APPLY_KEY_GET_LIGHT_ACCOUNT_Test_001
 * @tc.desc: ApplyKey Get LightAccount Instance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, APPLY_KEY_GET_LIGHT_ACCOUNT_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillOnce(Return(HC_ERR_ALLOC_MEMORY));
    const LightAccountVerifier *verifier = ApplyKeyGetLightAccountInstance();
    EXPECT_EQ(verifier, nullptr);
    LightAccountVerifier *retVerifier = (LightAccountVerifier *)SoftBusCalloc(sizeof(LightAccountVerifier));
    ASSERT_NE(retVerifier, nullptr);
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillOnce(Return(HC_SUCCESS));
    EXPECT_CALL(authApplyKeyMock, GetLightAccountVerifierInstance).WillOnce(Return(retVerifier));
    verifier = ApplyKeyGetLightAccountInstance();
    EXPECT_EQ(verifier, retVerifier);
    SoftBusFree((void *)verifier);
}

int32_t StartLightAccountAuth(
    int32_t osAccountId, int64_t requestId, const char *serviceId, const DeviceAuthCallback *laCallBack)
{
    return g_ret;
}

/*
 * @tc.name: PROCES_AUTH_HICHAIN_PARAM_Test_001
 * @tc.desc: Process AuthHichain Param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PROCES_AUTH_HICHAIN_PARAM_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    LightAccountVerifier *retVerifier = (LightAccountVerifier *)SoftBusCalloc(sizeof(LightAccountVerifier));
    ASSERT_NE(retVerifier, nullptr);
    retVerifier->startLightAccountAuth = StartLightAccountAuth;
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillRepeatedly(Return(HC_SUCCESS));
    EXPECT_CALL(authApplyKeyMock, GetLightAccountVerifierInstance).WillRepeatedly(Return(retVerifier));
    uint32_t requestId = 0;
    g_ret = HC_ERROR;
    int32_t ret = ProcessAuthHichainParam(requestId, nullptr);
    EXPECT_EQ(ret, HC_ERROR);
    g_ret = HC_SUCCESS;
    ret = ProcessAuthHichainParam(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree((void *)retVerifier);
}

/*
 * @tc.name: GET_UDID_AND_ACCOUNT_SHORT_HASH_Test_001
 * @tc.desc: Get UdidAndAccount ShortHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, GET_UDID_AND_ACCOUNT_SHORT_HASH_Test_001, TestSize.Level1)
{
    char localUdidShortHash[D2D_UDID_HASH_STR_LEN];
    char localAccountShortHash[D2D_ACCOUNT_HASH_STR_LEN];
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    (void)memset_s(localUdidShortHash, D2D_UDID_HASH_STR_LEN, 0, D2D_UDID_HASH_STR_LEN);
    (void)memset_s(localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN, 0, D2D_ACCOUNT_HASH_STR_LEN);
    int32_t ret = GetUdidAndAccountShortHash(nullptr, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    ret = GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    ret = GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    ret = GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_APPLY_KEY_ACL_PARAM_Test_001
 * @tc.desc: Pack ApplyKey AclParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PACK_APPLY_KEY_ACL_PARAM_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    char *data = PackApplyKeyAclParam(BUSINESS_TYPE_D2D);
    EXPECT_EQ(data, nullptr);
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillOnce(Return(false));
    data = PackApplyKeyAclParam(BUSINESS_TYPE_D2D);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: UNPACK_APPLY_KEY_ACL_PARAM_Test_001
 * @tc.desc: Unpack ApplyKey AclParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, UNPACK_APPLY_KEY_ACL_PARAM_Test_001, TestSize.Level1)
{
    RequestBusinessInfo info;
    int32_t ret = UnpackApplyKeyAclParam(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UnpackApplyKeyAclParam(TEST_DATA, strlen(TEST_DATA), &info);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    char *data = PackApplyKeyAclParam(BUSINESS_TYPE_D2D);
    EXPECT_NE(data, nullptr);
    EXPECT_CALL(authApplyKeyMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    ret = UnpackApplyKeyAclParam(data, strlen(data), &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ProcessApplyKeyDeviceId(0, 0, data, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SEND_APPLY_KEY_NEGO_DEVICE_ID_Test_001
 * @tc.desc: Send ApplyKey Nego DeviceId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, SEND_APPLY_KEY_NEGO_DEVICE_ID_Test_001, TestSize.Level1)
{
    uint32_t connId = 0;
    RequestBusinessInfo info;
    uint32_t requestId = 0;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = SendApplyKeyNegoDeviceId(connId, nullptr, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SendApplyKeyNegoDeviceId(connId, &info, requestId);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SendApplyKeyNegoDeviceId(connId, &info, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_APPLY_KEY_NEGO_STATE_Test_001
 * @tc.desc: Process ApplyKey NegoState test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PROCESS_APPLY_KEY_NEGO_STATE_Test_001, TestSize.Level1)
{
    RequestBusinessInfo info;
    bool isGreater;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    int32_t ret = ProcessApplyKeyNegoState(nullptr, &isGreater);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    ret = ProcessApplyKeyNegoState(&info, &isGreater);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ProcessApplyKeyNegoState(&info, &isGreater);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: START_APPLY_KEY_HICHAIN_Test_001
 * @tc.desc: Start ApplyKey Hichain test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, START_APPLY_KEY_HICHAIN_Test_001, TestSize.Level1)
{
    uint32_t connId = 0;
    RequestBusinessInfo info;
    uint32_t requestId = 0;
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    int32_t ret = StartApplyKeyHichain(connId, nullptr, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    ret = StartApplyKeyHichain(connId, &info, requestId);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: PROCESS_APPLY_KEY_DEVICE_ID_Test_001
 * @tc.desc: Process ApplyKey DeviceId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PROCESS_APPLY_KEY_DEVICE_ID_Test_001, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t requestId = 0;
    int32_t ret = ProcessApplyKeyDeviceId(channelId, requestId, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PROCESS_APPLY_KEY_DATA_Test_001
 * @tc.desc: Process ApplyKey Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PROCESS_APPLY_KEY_DATA_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    LightAccountVerifier accountVerifier;
    accountVerifier.processLightAccountAuth = processLightAccountAuthStub;
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetLightAccountVerifierInstance).WillRepeatedly(Return(&accountVerifier));
    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t requestId = GenApplyKeySeq();
    GenApplyKeyCallback cb = {
        .onGenSuccess = OnGenSuccessTest,
        .onGenFailed = OnGenFailedTest,
    };
    RequestBusinessInfo info;
    info.type = (RequestBusinessType)0;
    EXPECT_EQ(strcpy_s(info.accountHash, D2D_ACCOUNT_HASH_STR_LEN, NODE1_ACCOUNT_HASH), EOK);
    EXPECT_EQ(strcpy_s(info.udidHash, D2D_UDID_HASH_STR_LEN, NODE1_UDID_HASH), EOK);
    ret = AuthGenApplyKey(&info, requestId, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ProcessApplyKeyData(requestId, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: CREATE_INSTANCE_STATIC_FUNC_Test_001
 * @tc.desc: create instance static func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, CREATE_INSTANCE_STATIC_FUNC_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, GetApplyKeyByBusinessInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LightAccountVerifier accountVerifier;
    accountVerifier.processLightAccountAuth = processLightAccountAuthStub;
    EXPECT_CALL(authApplyKeyMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetLightAccountVerifierInstance).WillRepeatedly(Return(&accountVerifier));
    uint32_t requestId = GenApplyKeySeq();
    GenApplyKeyCallback cb = {
        .onGenSuccess = OnGenSuccessTest,
        .onGenFailed = OnGenFailedTest,
    };
    RequestBusinessInfo info;
    info.type = (RequestBusinessType)0;
    EXPECT_EQ(strcpy_s(info.accountHash, D2D_ACCOUNT_HASH_STR_LEN, NODE1_ACCOUNT_HASH), EOK);
    EXPECT_EQ(strcpy_s(info.udidHash, D2D_UDID_HASH_STR_LEN, NODE1_UDID_HASH), EOK);
    int32_t ret = AuthGenApplyKey(&info, requestId, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(AsyncCallbackGenResultReceived(nullptr));
    ret = CreateApplyKeyNegoInstance(&info, requestId, 0, true, &cb);
    SyncGenApplyKeyResult *result = (SyncGenApplyKeyResult *)SoftBusCalloc(sizeof(SyncGenApplyKeyResult));
    EXPECT_NE(result, nullptr);
    result->requestId = requestId;
    result->isGenApplyKeySuccess = true;
    EXPECT_NO_FATAL_FAILURE(AsyncCallbackGenResultReceived((void *)result));
    ret = CreateApplyKeyNegoInstance(&info, requestId, 0, true, &cb);
    SyncGenApplyKeyResult *result1 = (SyncGenApplyKeyResult *)SoftBusCalloc(sizeof(SyncGenApplyKeyResult));
    EXPECT_NE(result1, nullptr);
    result1->requestId = requestId;
    result1->isGenApplyKeySuccess = false;
    EXPECT_NO_FATAL_FAILURE(AsyncCallbackGenResultReceived((void *)result1));
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(nullptr, true, 0));
    ret = CreateApplyKeyNegoInstance(&info, requestId, 0, true, &cb);
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, true, 0));
    ret = CreateApplyKeyNegoInstance(&info, requestId, 0, true, &cb);
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, false, 0));
    info.type = (RequestBusinessType)1;
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, true, 0));
}

/*
 * @tc.name: SOFTBUS_GENERATE_STR_HASH_FUNC_Test_001
 * @tc.desc: SoftBusGenerateStrHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, SOFTBUS_GENERATE_STR_HASH_FUNC_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    EXPECT_NO_FATAL_FAILURE(OnCommConnected(0, &info));
    EXPECT_NO_FATAL_FAILURE(OnCommDisconnected(0, &info));
    char hichainReturnAccountId[SHA_256_HEX_HASH_LEN];
    char hichainReturnAccountHash[SHA_256_HEX_HASH_LEN];
    int32_t ret = GenerateAccountHash(hichainReturnAccountId, hichainReturnAccountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_IS_APPLY_KEY_EXPIRED_Test_001
 * @tc.desc: AuthIsApplyKeyExpired test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, AUTH_IS_APPLY_KEY_EXPIRED_Test_001, TestSize.Level1)
{
    bool ret = AuthIsApplyKeyExpired(0);
    EXPECT_EQ(ret, false);
    uint64_t currentTime = SoftBusGetSysTimeMs();
    ret = AuthIsApplyKeyExpired(currentTime - APPLY_KEY_DECAY_TIME + 1);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: SEND_APPLY_NEGO_CLOSE_EVENT_Test_001
 * @tc.desc: Send ApplyKey NegoCloseAck Event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, SEND_APPLY_NEGO_CLOSE_EVENT_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = SendApplyKeyNegoCloseAckEvent(0, 0, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_APPLY_KEY_CLOSE_ACK_DATA_Test_001
 * @tc.desc: Process ApplyKey CloseAck Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyProcessTest, PROCESS_APPLY_KEY_CLOSE_ACK_DATA_Test_001, TestSize.Level1)
{
    AuthApplyKeyProcessInterfaceMock authApplyKeyMock;
    EXPECT_CALL(authApplyKeyMock, ConnSetConnectCallback).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, GetAuthDataSize).WillRepeatedly(Return(AUTH_CONN_DATA_HEAD_SIZE));
    EXPECT_CALL(authApplyKeyMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authApplyKeyMock, PackAuthData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authApplyKeyMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(authApplyKeyMock, GetApplyKeyByBusinessInfo).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = ApplyKeyNegoInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t requestId = GenApplyKeySeq();
    GenApplyKeyCallback cb = {
        .onGenSuccess = OnGenSuccessTest,
        .onGenFailed = OnGenFailedTest,
    };
    RequestBusinessInfo info;
    info.type = (RequestBusinessType)0;
    EXPECT_EQ(strcpy_s(info.accountHash, D2D_ACCOUNT_HASH_STR_LEN, NODE1_ACCOUNT_HASH), EOK);
    EXPECT_EQ(strcpy_s(info.udidHash, D2D_UDID_HASH_STR_LEN, NODE1_UDID_HASH), EOK);
    ret = AuthGenApplyKey(&info, requestId, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ProcessApplyKeyCloseAckData(requestId, TEST_APPLY_KEY_DATA, sizeof(TEST_APPLY_KEY_DATA));
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS