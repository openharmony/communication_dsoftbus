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
 * @tc.name: AUTH_START_GROUP_ACCOUNT_Test_001
 * @tc.desc: StartGroupAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_START_GROUP_ACCOUNT_Test_001, TestSize.Level1)
{
    AuthAccountManagerMock authAccountManagerMock;
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    int32_t ret = StartGroupAccountAuth("auth_test", 0, "auth_service");
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
 * @tc.desc: ProcessGroupAccountAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthAccountManagerTest, AUTH_PROCESS_GROUP_ACCOUNT_Test_001, TestSize.Level1)
{
    AuthAccountManagerMock authAccountManagerMock;
    uint8_t data[] = "ProcessData";
    EXPECT_CALL(authAccountManagerMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authAccountManagerMock, GetLightAccountVerifierInstance)
        .WillRepeatedly(Return(&g_lightAccountVerifier));
    int32_t ret = ProcessGroupAccountAuth("auth_test", 0, data, sizeof(data));
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
} // namespace OHOS