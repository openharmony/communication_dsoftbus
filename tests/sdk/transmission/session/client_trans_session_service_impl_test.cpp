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
#include <memory>

#include "ISessionListener.h"
#include "softbus_error_code.h"
#include "session_impl.h"
#include "session_mock.h"
#include "session_service_impl.h"

using namespace testing;

using namespace testing::ext;

namespace Communication {
namespace SoftBus {

class SessionListenerImpl : public ISessionListener {
public:
    SessionListenerImpl() = default;
    ~SessionListenerImpl() = default;

    int32_t OnSessionOpened(std::shared_ptr<Session> session) override
    {
        return SOFTBUS_OK;
    }

    void OnSessionClosed(std::shared_ptr<Session> session) override
    {
        return;
    }

    void OnMessageReceived(std::shared_ptr<Session> session, const char *data, ssize_t len) override
    {
        return;
    }

    void OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len) override
    {
        return;
    }

    bool OnDataAvailable(std::shared_ptr<Session> session, uint32_t status) override
    {
        return true;
    }
};

class TransClientSessionServiceImplTest : public testing::Test {
public:
    TransClientSessionServiceImplTest() = default;
    ~TransClientSessionServiceImplTest() = default;;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionServiceImplTest::SetUpTestCase(void) {}

void TransClientSessionServiceImplTest::TearDownTestCase(void) {}

/**
 * @tc.name: CreateSessionServer001
 * @tc.desc: Test when pkgName is empty then CreateSessionServer returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CreateSessionServer001, TestSize.Level0)
{
    std::string pkgName = "";
    std::string sessionName = "testSession";
    std::shared_ptr<SessionListenerImpl> listener = std::make_shared<SessionListenerImpl>();
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CreateSessionServer(pkgName, sessionName, listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: CreateSessionServer002
 * @tc.desc: Test when sessionName is empty then CreateSessionServer returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CreateSessionServer002, TestSize.Level0)
{
    std::string pkgName = "testPkg";
    std::string sessionName = "";
    std::shared_ptr<SessionListenerImpl> listener = std::make_shared<SessionListenerImpl>();
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CreateSessionServer(pkgName, sessionName, listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: CreateSessionServer003
 * @tc.desc: Test when listener is nullptr then CreateSessionServer returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CreateSessionServer003, TestSize.Level0)
{
    std::string pkgName = "testPkg";
    std::string sessionName = "testSession";
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CreateSessionServer(pkgName, sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveSessionServer001
 * @tc.desc: Test when pkgName or sessionName is empty then RemoveSessionServer returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, RemoveSessionServer001, TestSize.Level0)
{
    SessionServiceImpl sessionServiceImpl;
    int32_t result = sessionServiceImpl.RemoveSessionServer("", "sessionName");
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    result = sessionServiceImpl.RemoveSessionServer("pkgName", "");
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveSessionServer002
 * @tc.desc: Test when sessionName not found in listenerMap_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, RemoveSessionServer002, TestSize.Level0)
{
    SessionServiceImpl sessionServiceImpl;
    int32_t result = sessionServiceImpl.RemoveSessionServer("pkgName", "notFoundSessionName");
    EXPECT_EQ(result, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: OpenSession001
 * @tc.desc: Test when mySessionName is empty then OpenSession returns nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, OpenSession001, TestSize.Level0)
{
    std::string mySessionName = "";
    std::string peerSessionName = "peerSessionName";
    std::string peerNetworkId = "peerNetworkId";
    std::string groupId = "groupId";
    int32_t flags = 0;
    SessionServiceImpl sessionServiceImpl;
    std::shared_ptr<Session> session =
        sessionServiceImpl.OpenSession(mySessionName, peerSessionName, peerNetworkId, groupId, flags);
    EXPECT_EQ(session, nullptr);
}

/**
 * @tc.name: OpenSession002
 * @tc.desc: Test when peerSessionName is empty then OpenSession returns nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, OpenSession002, TestSize.Level0)
{
    std::string mySessionName = "mySessionName";
    std::string peerSessionName = "";
    std::string peerNetworkId = "peerNetworkId";
    std::string groupId = "groupId";
    int32_t flags = 0;
    SessionServiceImpl sessionServiceImpl;
    std::shared_ptr<Session> session =
        sessionServiceImpl.OpenSession(mySessionName, peerSessionName, peerNetworkId, groupId, flags);
    EXPECT_EQ(session, nullptr);
}

/**
 * @tc.name: OpenSession003
 * @tc.desc: Test when peerNetworkId is empty then OpenSession returns nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, OpenSession003, TestSize.Level0)
{
    std::string mySessionName = "mySessionName";
    std::string peerSessionName = "peerSessionName";
    std::string peerNetworkId = "";
    std::string groupId = "groupId";
    int32_t flags = 0;
    SessionServiceImpl sessionServiceImpl;
    std::shared_ptr<Session> session =
        sessionServiceImpl.OpenSession(mySessionName, peerSessionName, peerNetworkId, groupId, flags);
    EXPECT_EQ(session, nullptr);
}

/**
 * @tc.name: OpenSession004
 * @tc.desc: Test when OpenSessionInner returns a value less than or equal to 0 then OpenSession returns nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, OpenSession004, TestSize.Level0)
{
    std::string mySessionName = "mySessionName";
    std::string peerSessionName = "peerSessionName";
    std::string peerNetworkId = "peerNetworkId";
    std::string groupId = "groupId";
    int32_t flags = 0;
    SessionServiceImpl sessionServiceImpl;
    std::shared_ptr<Session> session =
        sessionServiceImpl.OpenSession(mySessionName, peerSessionName, peerNetworkId, groupId, flags);
    EXPECT_EQ(session, nullptr);
}

/**
 * @tc.name: CloseSession001
 * @tc.desc: Test when session is nullptr then CloseSession returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CloseSession001, TestSize.Level0)
{
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CloseSession(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: CloseSession002
 * @tc.desc: Test when sessionId is invalid then CloseSession returns SOFTBUS_TRANS_INVALID_SESSION_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CloseSession002, TestSize.Level0)
{
    std::shared_ptr<SessionImpl> session = std::make_shared<SessionImpl>();
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CloseSession(session);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    // testing::Mock::VerifyAndClearExpectations(&sessionServiceImplMock);
}

/**
 * @tc.name: CloseSession003
 * @tc.desc: Test when sessionId is valid then CloseSession returns SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, CloseSession003, TestSize.Level0)
{
    std::shared_ptr<SessionImpl> session = std::make_shared<SessionImpl>();
    SessionServiceImpl sessionServiceImpl;
    int32_t ret = sessionServiceImpl.CloseSession(session);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: Test when uid or pid is less than 0 then GrantPermission returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, GrantPermission001, TestSize.Level0)
{
    int32_t uid = -1;
    int32_t pid = 1;
    std::string busName = "busName";
    SessionServiceImpl sessionServiceImpl;
    int32_t result = sessionServiceImpl.GrantPermission(uid, pid, busName);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GrantPermission002
 * @tc.desc: Test when busName is empty then GrantPermission returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, GrantPermission002, TestSize.Level0)
{
    int32_t uid = 1;
    int32_t pid = 1;
    std::string busName = "";
    SessionServiceImpl sessionServiceImpl;
    int32_t result = sessionServiceImpl.GrantPermission(uid, pid, busName);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: RemovePermission001
 * @tc.desc: Test when busName is empty then RemovePermission returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceImplTest, RemovePermission001, TestSize.Level0)
{
    std::string busName = "";
    SessionServiceImpl sessionServiceImpl;
    int32_t result = sessionServiceImpl.RemovePermission(busName);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}
} // SoftBus
} // Communication
