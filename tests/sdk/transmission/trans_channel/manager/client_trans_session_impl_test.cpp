/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "securec.h"

#include "client_trans_session_manager.h"
#include "session_impl.h"
#include "session_service_impl.h"
#include "ISessionListener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_access_token_test.h"

#define TEST_DATA_LENGTH 1024
#define MAX_BYTE_LENGTH (128 * 1024 * 1024)

using namespace std;
using namespace testing::ext;

namespace OHOS {
std::string g_sessionName1;
std::string g_sessionName2 = "security.dpms_channel";
std::string g_pkgName1;
std::string g_pkgName2 = "ohos.security.distributed_permission";
std::string g_pkgName3 = "test";
std::string g_peerNetWorkId1;
std::string g_peerNetWorkId2 = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
std::string g_groupId;
int g_flags = 0;

class ISessionListenerTest : public Communication::SoftBus::ISessionListener {
public:
    ISessionListenerTest() = default;
    ~ISessionListenerTest() = default;

    int OnSessionOpened(std::shared_ptr<Communication::SoftBus::Session> session)
    {
        return SOFTBUS_OK;
    }

    void OnSessionClosed(std::shared_ptr<Communication::SoftBus::Session> session)
    {
        return;
    }

    void OnMessageReceived(std::shared_ptr<Communication::SoftBus::Session> session, const char *data, ssize_t len)
    {
        return;
    }

    void OnBytesReceived(std::shared_ptr<Communication::SoftBus::Session> session, const char *data, ssize_t len)
    {
        return;
    }

    bool OnDataAvailable(std::shared_ptr<Communication::SoftBus::Session> session, uint32_t status)
    {
        return true;
    }
};

class ClientTransSessionImplTest : public testing::Test {
public:
    ClientTransSessionImplTest() {}
    ~ClientTransSessionImplTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransSessionImplTest::SetUpTestCase(void)
{
    SetAceessTokenPermission("dsoftbusTransTest");
}

void ClientTransSessionImplTest::TearDownTestCase(void) {}

/**
 * @tc.name: ClientTransSessionServerImplTest001
 * @tc.desc: client trans session server impl test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSessionImplTest, ClientTransSessionServerImplTest001, TestSize.Level0)
{
    Communication::SoftBus::SessionServiceImpl testSessionServiceImpl;
    std::shared_ptr<Communication::SoftBus::ISessionListener> listern = std::make_shared<ISessionListenerTest>();

    int ret = testSessionServiceImpl.CreateSessionServer(g_pkgName1, g_sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.CreateSessionServer(g_pkgName2, g_sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.CreateSessionServer(g_pkgName2, g_sessionName2, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.CreateSessionServer(g_pkgName3, g_sessionName2, listern);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = testSessionServiceImpl.CreateSessionServer(g_pkgName2, g_sessionName2, listern);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = testSessionServiceImpl.RemoveSessionServer(g_pkgName2, g_sessionName2);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransSessionServerImplTest002
 * @tc.desc: client trans session server impl test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSessionImplTest, ClientTransSessionServerImplTest002, TestSize.Level0)
{
    Communication::SoftBus::SessionServiceImpl testSessionServiceImpl;
    int ret;
    std::shared_ptr<Communication::SoftBus::Session> session = testSessionServiceImpl.OpenSession(g_sessionName1,
        g_sessionName2, g_peerNetWorkId2, g_groupId, g_flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(g_sessionName2, g_sessionName1, g_peerNetWorkId2, g_groupId, g_flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(g_sessionName2, g_sessionName2, g_peerNetWorkId1, g_groupId, g_flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(g_sessionName2, g_sessionName2, g_peerNetWorkId2, g_groupId, g_flags);
    EXPECT_EQ(nullptr, session);

    int uid = 0;
    int pid = 0;
    ret = testSessionServiceImpl.GrantPermission(-1, -1, g_pkgName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.GrantPermission(uid, pid, g_pkgName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.GrantPermission(uid, pid, g_pkgName2);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    int sessionId = 1;
    ret = testSessionServiceImpl.OpenSessionCallback(sessionId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testSessionServiceImpl.CloseSessionCallback(sessionId);
    const char data[TEST_DATA_LENGTH] = "test";
    testSessionServiceImpl.BytesReceivedCallback(sessionId, data, TEST_DATA_LENGTH);
    testSessionServiceImpl.MessageReceivedCallback(sessionId, data, TEST_DATA_LENGTH);

    ret = testSessionServiceImpl.CloseSession(session);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.RemoveSessionServer(g_pkgName1, g_sessionName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.RemoveSessionServer(g_pkgName2, g_sessionName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.RemoveSessionServer(g_pkgName3, g_sessionName2);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransSessionServerImplTest003
 * @tc.desc: client trans session server impl test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSessionImplTest, ClientTransSessionServerImplTest003, TestSize.Level0)
{
    Communication::SoftBus::SessionImpl testSessionImpl;
    ssize_t len = 0;
    int ret = testSessionImpl.SendBytes(nullptr, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *data = "test";
    ret = testSessionImpl.SendBytes(data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    len = MAX_BYTE_LENGTH + 1;
    ret = testSessionImpl.SendBytes(data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    len = TEST_DATA_LENGTH;
    ret = testSessionImpl.SendBytes(data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransSessionServerImplTest004
 * @tc.desc: client trans session server impl test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSessionImplTest, ClientTransSessionServerImplTest004, TestSize.Level0)
{
    Communication::SoftBus::SessionServiceImpl testSessionServiceImpl;
    std::shared_ptr<Communication::SoftBus::ISessionListener> listern = std::make_shared<ISessionListenerTest>();
    int ret = testSessionServiceImpl.CreateSessionServer(g_pkgName2, g_sessionName2, listern);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *groupId = "test";
    SessionAttribute attr;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    SessionParam param = {
        .sessionName = g_sessionName2.c_str(),
        .peerSessionName = g_sessionName2.c_str(),
        .peerDeviceId = g_peerNetWorkId2.c_str(),
        .groupId = groupId,
        .attr = &attr,
    };
    int32_t sessionId = 0;
    bool isEnabled = 0;
    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
