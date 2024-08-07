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

#define private public

#include "auth_interface.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_server.h"
#include "softbus_server_frame.h"
#include "softbus_server_stub.h"
#include "softbus_server_stub_test_mock.h"
#include "system_ability_definition.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME_SIZE_MAX 256
#define TEST_DEVICE_ID_SIZE_MAX    50
#define TEST_GROUP_ID_SIZE_MAX     50
#define TEST_PKG_NAME_SIZE_MAX     65

char g_mySessionName[TEST_SESSION_NAME_SIZE_MAX] = "com.test.trans.session";
char g_peerSessionName[TEST_SESSION_NAME_SIZE_MAX] = "com.test.trans.session.sendfile";
char g_peerDeviceId[TEST_DEVICE_ID_SIZE_MAX] = "com.test.trans.session.sendfile";
char g_groupId[TEST_GROUP_ID_SIZE_MAX] = "com.test.trans.session.sendfile";
char g_myPkgName[TEST_PKG_NAME_SIZE_MAX] = "test";

class SoftbusServerStubTest : public testing::Test {
public:
    SoftbusServerStubTest()
    {}
    ~SoftbusServerStubTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusServerStubTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
}

void SoftbusServerStubTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
}

SessionParam *GenerateSessionParam()
{
    SetAceessTokenPermission("SoftBusServerStubTest");
    SessionParam *sessionParam = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    EXPECT_NE(nullptr, sessionParam);
    SessionAttribute attr;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    sessionParam->sessionName = g_mySessionName;
    sessionParam->peerSessionName = g_peerSessionName;
    sessionParam->peerDeviceId = g_peerDeviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = &attr;
    return sessionParam;
}

void DeGenerateSessionParam(SessionParam *sessionParam)
{
    if (sessionParam != nullptr) {
        SoftBusFree(sessionParam);
    }
}

static SessionServer *GenerateSessionServer()
{
    SessionServer *sessionServer = (SessionServer*)SoftBusCalloc(sizeof(SessionServer));
    EXPECT_NE(nullptr, sessionServer);
    int32_t ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_mySessionName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_myPkgName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }
    return sessionServer;
}

void DeGenerateSessionServer(SessionServer *sessionServer)
{
    if (sessionServer != nullptr) {
        SoftBusFree(sessionServer);
    }
}

/**
 * @tc.name: SoftbusServerStubTest001
 * @tc.desc: Verify the CheckOpenSessionPermission function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerStubTest, SoftbusServerStubTest001, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionServer *sessionServer = GenerateSessionServer();
    EXPECT_NE(nullptr, sessionServer);
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SessionParam *sessionParam001 = GenerateSessionParam();
    ASSERT_NE(nullptr, sessionParam001);
    sptr<OHOS::SoftBusServerStub> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    NiceMock<SoftbusServerStubTestInterfaceMock> softbusServerStubMock;
    EXPECT_CALL(softbusServerStubMock, CheckTransPermission).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(softbusServerStubMock, CheckTransSecLevel).WillRepeatedly(Return(SOFTBUS_OK));
    ret = softBusServer->CheckOpenSessionPermission(sessionParam001);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeGenerateSessionParam(sessionParam001);

    SessionParam *sessionParam002 = nullptr;
    ret = softBusServer->CheckOpenSessionPermission(sessionParam002);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    DeGenerateSessionParam(sessionParam002);

    SessionParam *sessionParam003 = GenerateSessionParam();
    ASSERT_NE(nullptr, sessionParam003);
    sessionParam003->peerSessionName = nullptr;
    EXPECT_CALL(softbusServerStubMock, CheckTransSecLevel).WillRepeatedly(Return(SOFTBUS_PERMISSION_DENIED));
    ret = softBusServer->CheckOpenSessionPermission(sessionParam003);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
    DeGenerateSessionParam(sessionParam003);

    DeGenerateSessionServer(sessionServer);
    TransSessionMgrDeinit();
}
}