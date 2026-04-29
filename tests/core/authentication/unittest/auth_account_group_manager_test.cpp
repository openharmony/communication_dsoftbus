/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_account_group_manager.h"
#include "auth_account_group_manager.c"
#include "auth_account_group_manager_mock.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthAccountManagerTest::SetUpTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthAccountManagerTest start");
}

void AuthAccountManagerTest::TearDownTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthAccountManagerTest end");
}

void AuthAccountManagerTest::SetUp() { }

void AuthAccountManagerTest::TearDown() { }

/*
 * @tc.name: AUTH_ACCOUNT_REGISTER_ACCOUNT_AUTH_Test_001
 * @tc.desc: RegisterAccountAuth invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_REGISTER_ACCOUNT_AUTH_Test_001, TestSize.Level1)
{
    IAccountAuthCallback cb = {
        .onTransmit = nullptr,
        .onSessionKeyReturned = nullptr,
        .onFinish = nullptr,
        .onError = nullptr,
    };
    SoftBusList list;
    EXPECT_NO_FATAL_FAILURE(RegisterAccountAuth(nullptr));
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, CreateSoftBusList).WillOnce(Return(nullptr)).WillRepeatedly(Return(&list));
    EXPECT_CALL(authAccountManagerMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(RegisterAccountAuth(&cb));
    EXPECT_NO_FATAL_FAILURE(RegisterAccountAuth(&cb));
    EXPECT_EQ(LooperInit(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RegisterAccountAuth(&cb));
    g_accountAuthList = nullptr;
    g_isAccountAuthCbInited = false;
}

static bool OnTransmitSuccess(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return true;
}

static bool OnTransmitFailed(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return false;
}

static void OnSessionKeyReturnedSuccess(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)authSeq;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static void OnFinishedSuccess(int64_t authSeq, int32_t operationCode, const char *returnData)
{
    (void)authSeq;
    (void)operationCode;
    (void)returnData;
}

static void OnErrorSuccess(int64_t authSeq, int32_t operationCode, int32_t errCode, const char *returnData)
{
    (void)authSeq;
    (void)operationCode;
    (void)errCode;
    (void)returnData;
}

IAccountAuthCallback accountAuthSuccessCb = {
    .onTransmit = nullptr,
    .onSessionKeyReturned = nullptr,
    .onFinish = nullptr,
    .onError = nullptr,
};

/*
 * @tc.name: AUTH_ON_TRANSMITTED_CALLBACK_Test_001
 * @tc.desc: OnTransmitted test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ON_TRANSMITTED_CALLBACK_Test_001, TestSize.Level1)
{
    uint8_t data[] = "OnTransmittedReturnData";
    g_accountAuthCallback = nullptr;
    bool ret = OnTransmitted(0, nullptr, 0);
    EXPECT_EQ(ret, false);
    ret = OnTransmitted(0, data, 0);
    EXPECT_EQ(ret, false);
    ret = OnTransmitted(0, data, sizeof(data));
    EXPECT_EQ(ret, false);
    g_accountAuthCallback = &accountAuthSuccessCb;
    ret = OnTransmitted(0, data, sizeof(data));
    EXPECT_EQ(ret, false);
    accountAuthSuccessCb.onTransmit = OnTransmitFailed;
    ret = OnTransmitted(0, data, sizeof(data));
    EXPECT_EQ(ret, false);
    accountAuthSuccessCb.onTransmit = OnTransmitSuccess;
    ret = OnTransmitted(0, data, sizeof(data));
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_ON_SESSIONKEY_RETURN_CALLBACK_Test_001
 * @tc.desc: OnSessionKeyReturned test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ON_SESSIONKEY_RETURN_CALLBACK_Test_001, TestSize.Level1)
{
    uint8_t data[] = "OnSessionKeyReturnData";
    g_accountAuthCallback = nullptr;
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(0, nullptr, 0));
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(0, data, D2D_SESSION_KEY_LEN + 1));
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(0, data, D2D_SESSION_KEY_LEN));
    g_accountAuthCallback = &accountAuthSuccessCb;
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(0, data, D2D_SESSION_KEY_LEN));
    accountAuthSuccessCb.onSessionKeyReturned = OnSessionKeyReturnedSuccess;
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(0, data, D2D_SESSION_KEY_LEN));
}

/*
 * @tc.name: AUTH_ON_FINISH_CALLBACK_Test_001
 * @tc.desc: OnFinished test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ON_FINISH_CALLBACK_Test_001, TestSize.Level1)
{
    char data[] = "OnFinishReturnData";
    g_accountAuthCallback = nullptr;
    EXPECT_NO_FATAL_FAILURE(OnFinished(0, 0, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnFinished(0, 0, data));
    g_accountAuthCallback = &accountAuthSuccessCb;
    EXPECT_NO_FATAL_FAILURE(OnFinished(0, 0, data));
    accountAuthSuccessCb.onFinish = OnFinishedSuccess;
    CreateAccountAuthInstance(0);
    EXPECT_NO_FATAL_FAILURE(OnFinished(0, 0, data));
}

/*
 * @tc.name: AUTH_ON_ERROR_CALLBACK_Test_001
 * @tc.desc: OnError test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ON_ERROR_CALLBACK_Test_001, TestSize.Level1)
{
    char data[] = "OnErrorReturnData";
    g_accountAuthCallback = nullptr;
    EXPECT_NO_FATAL_FAILURE(OnError(0, SOFTBUS_INVALID_PARAM, SOFTBUS_INVALID_PARAM, data));
    g_accountAuthCallback = &accountAuthSuccessCb;
    EXPECT_NO_FATAL_FAILURE(OnError(0, SOFTBUS_INVALID_PARAM, SOFTBUS_INVALID_PARAM, data));
    accountAuthSuccessCb.onError = OnErrorSuccess;
    CreateAccountAuthInstance(0);
    EXPECT_NO_FATAL_FAILURE(OnError(0, SOFTBUS_INVALID_PARAM, SOFTBUS_INVALID_PARAM, data));
}

/*
 * @tc.name: AUTH_ON_REQUEST_CALLBACK_Test_001
 * @tc.desc: OnError test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ON_REQUEST_CALLBACK_Test_001, TestSize.Level1)
{
    char data[] = "OnRequestData";
    cJSON msg;
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, cJSON_CreateObject).WillOnce(Return(nullptr)).WillRepeatedly(Return(&msg));
    char *ret = OnRequest(0, 0, data);
    EXPECT_EQ(ret, nullptr);
    EXPECT_CALL(authAccountManagerMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ret = OnRequest(0, 0, data);
    EXPECT_EQ(ret, nullptr);
    char returnData[] = "ReturnMsg";
    EXPECT_CALL(authAccountManagerMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(returnData));
    ret = OnRequest(0, 0, data);
    EXPECT_EQ(ret, nullptr);
    ret = OnRequest(0, 0, data);
    EXPECT_EQ(strcmp(ret, "ReturnMsg"), 0);
}

int32_t StartLightAccountAuthSuccess(int32_t osAccountId, int64_t requestId,
    const char *serviceId, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)serviceId;
    (void)laCallBack;
    return SOFTBUS_OK;
}

int32_t StartLightAccountAuthFailed(int32_t osAccountId, int64_t requestId,
    const char *serviceId, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)serviceId;
    (void)laCallBack;
    return SOFTBUS_INVALID_PARAM;
}

int32_t ProcessLightAccountAuthSuccess(int32_t osAccountId, int64_t requestId,
    DataBuff *inMsg, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)inMsg;
    (void)laCallBack;
    return SOFTBUS_OK;
}

int32_t ProcessLightAccountAuthFailed(int32_t osAccountId, int64_t requestId,
    DataBuff *inMsg, const DeviceAuthCallback *laCallBack)
{
    (void)osAccountId;
    (void)requestId;
    (void)inMsg;
    (void)laCallBack;
    return SOFTBUS_INVALID_PARAM;
}

static LightAccountVerifier g_lightAccountVerifier = {
    .startLightAccountAuth = nullptr,
    .processLightAccountAuth = nullptr,
};

/*
 * @tc.name: AUTH_GET_LIGHT_ACCOUNT_INSTANCE_Test_001
 * @tc.desc: GetLightAccountInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_GET_LIGHT_ACCOUNT_INSTANCE_Test_001, TestSize.Level1)
{
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    EXPECT_EQ(GetLightAccountInstance(), nullptr);
    EXPECT_NO_FATAL_FAILURE(GetLightAccountInstance());
}

/*
 * @tc.name: AUTH_ACCOUNT_AUTH_LOCK_ERROR_Test_001
 * @tc.desc: lock g_accountAuthList->lock error test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_AUTH_LOCK_ERROR_Test_001, TestSize.Level1)
{
    g_isAccountAuthCbInited = true;
    int32_t ret = CreateAccountAuthInstance(1);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    EXPECT_NO_FATAL_FAILURE(DeleteAccountAuthInstance(1));

    uint8_t data[] = "ProcessData";
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    g_lightAccountVerifier.startLightAccountAuth = StartLightAccountAuthSuccess;
    g_lightAccountVerifier.processLightAccountAuth = ProcessLightAccountAuthSuccess;
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    g_isAccountAuthCbInited = false;
    g_lightAccountVerifier.startLightAccountAuth = nullptr;
    g_lightAccountVerifier.processLightAccountAuth = nullptr;
}

/*
 * @tc.name: AUTH_INIT_ACCOUNT_AUTH_INSTANCE_LIST_Test_001
 * @tc.desc: InitAccountAuthInstanceList invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_INIT_ACCOUNT_AUTH_INSTANCE_LIST_Test_001, TestSize.Level1)
{
    AuthAccountManagerMock authAccountManagerMock;
    using GetRealFunc = SoftBusList *(*)(void);
    auto realGetFunc = reinterpret_cast<GetRealFunc>(dlsym(RTLD_NEXT, "CreateSoftBusList"));
    EXPECT_NE(realGetFunc, nullptr);
    EXPECT_CALL(authAccountManagerMock, CreateSoftBusList).WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(realGetFunc));
    int32_t ret = InitAccountAuthInstanceList();
    EXPECT_EQ(ret, SOFTBUS_CREATE_LIST_ERR);
    ret = InitAccountAuthInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitAccountAuthInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_START_GROUP_ACCOUNT_Test_001
 * @tc.desc: StartGroupAccount invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_START_GROUP_ACCOUNT_Test_001, TestSize.Level1)
{
    int32_t ret = StartGroupAccountAuth(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = StartGroupAccountAuth(nullptr, 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = StartGroupAccountAuth("auth_test", 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL);

    EXPECT_CALL(authAccountManagerMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(0));
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL);

    g_lightAccountVerifier.startLightAccountAuth = StartLightAccountAuthFailed;
    g_isAccountAuthCbInited = false;
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    g_isAccountAuthCbInited = true;
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_lightAccountVerifier.startLightAccountAuth = StartLightAccountAuthSuccess;
    ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_PROCESS_GROUP_ACCOUNT_Test_001
 * @tc.desc: ProcessGroupAccountAuth invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_PROCESS_GROUP_ACCOUNT_Test_001, TestSize.Level1)
{
    uint8_t data[] = "ProcessData";
    int32_t ret = ProcessGroupAccountAuth(nullptr, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ProcessGroupAccountAuth(nullptr, 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ProcessGroupAccountAuth("auth_test", 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL);

    EXPECT_CALL(authAccountManagerMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(0));
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL);

    g_lightAccountVerifier.processLightAccountAuth = ProcessLightAccountAuthFailed;
    g_isAccountAuthCbInited = false;
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    g_isAccountAuthCbInited = true;
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_lightAccountVerifier.processLightAccountAuth = ProcessLightAccountAuthSuccess;
    ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_ACCOUNT_AUTH_INSTANCE_Test_001
 * @tc.desc: CreateAccountAuthInstance invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_AUTH_INSTANCE_Test_001, TestSize.Level1)
{
    g_isAccountAuthCbInited = true;
    int32_t ret = CreateAccountAuthInstance(1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateAccountAuthInstance(2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_isAccountAuthCbInited = false;
    bool isExist = IsAccountAuthInstanceExist(1);
    EXPECT_EQ(isExist, false);
    g_isAccountAuthCbInited = true;
    isExist = IsAccountAuthInstanceExist(1);
    EXPECT_EQ(isExist, true);
    isExist = IsAccountAuthInstanceExist(3);
    EXPECT_EQ(isExist, false);

    g_isAccountAuthCbInited = false;
    EXPECT_NO_FATAL_FAILURE(DeleteAccountAuthInstance(1));
    g_isAccountAuthCbInited = true;
    EXPECT_NO_FATAL_FAILURE(DeleteAccountAuthInstance(3));
    EXPECT_NO_FATAL_FAILURE(DeleteAccountAuthInstance(1));
    EXPECT_NO_FATAL_FAILURE(DeleteAccountAuthInstance(2));
}

/*
 * @tc.name: AUTH_ACCOUNT_AUTH_TIMEOUT_Test_001
 * @tc.desc: GenAccountAuthTimeoutProcess invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_AUTH_TIMEOUT_Test_001, TestSize.Level1)
{
    SoftBusMessage msg = {
        .what = MSG_AUTH_ACCOUNT_TIMEOUT,
        .arg1 = 1,
    };
    g_isAccountAuthCbInited = true;
    int32_t ret = CreateAccountAuthInstance(1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(GenAccountAuthTimeoutProcess(&msg));
    msg.arg1 = 2;
    EXPECT_NO_FATAL_FAILURE(GenAccountAuthTimeoutProcess(&msg));
}

/*
 * @tc.name: AUTH_ACCOUNT_FREE_MESSAGE_Test_001
 * @tc.desc: AuthFreeMessage invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_FREE_MESSAGE_Test_001, TestSize.Level1)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    EXPECT_NO_FATAL_FAILURE(AuthFreeMessage(nullptr));
    msg->obj = nullptr;
    EXPECT_NO_FATAL_FAILURE(AuthFreeMessage(msg));
    msg = static_cast<SoftBusMessage *>(SoftBusCalloc(sizeof(SoftBusMessage)));
    msg->obj = static_cast<int32_t *>(SoftBusCalloc(sizeof(int32_t)));
    EXPECT_NO_FATAL_FAILURE(AuthFreeMessage(msg));
}

/*
 * @tc.name: AUTH_ACCOUNT_COMPARE_LOOPER_Test_001
 * @tc.desc: CompareLooperEventFunc invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_ACCOUNT_COMPARE_LOOPER_Test_001, TestSize.Level1)
{
    SoftBusMessage msg = {
        .what = MSG_AUTH_ACCOUNT_TIMEOUT,
        .arg1 = 1,
        .arg2 = 0,
        .obj = nullptr,
    };
    SoftBusMessage ctx = {
        .what = -1,
        .arg1 = -1,
        .arg2 = -1,
        .obj = nullptr,
    };
    int32_t ret = CompareLooperEventFunc(nullptr, nullptr);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ret = CompareLooperEventFunc(&msg, nullptr);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ret = CompareLooperEventFunc(nullptr, &ctx);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ret = CompareLooperEventFunc(&msg, &ctx);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ctx.what = MSG_AUTH_ACCOUNT_TIMEOUT;
    ret = CompareLooperEventFunc(&msg, &ctx);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ctx.arg1 = 1;
    ret = CompareLooperEventFunc(&msg, &ctx);
    EXPECT_EQ(ret, COMPARE_FAILED);
    ctx.arg2 = 0;
    ret = CompareLooperEventFunc(&msg, &ctx);
    EXPECT_EQ(ret, COMPARE_SUCCESS);
}
} // namespace OHOS
