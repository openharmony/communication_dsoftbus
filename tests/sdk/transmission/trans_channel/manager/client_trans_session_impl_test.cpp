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

#include "session_service_impl.h"
#include "ISessionListener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_access_token_test.h"

#define TEST_DATA_LENGTH 1024

using namespace std;
using namespace testing::ext;

namespace OHOS {
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
    std::string pkgName1;
    std::string sessionName1;
    std::shared_ptr<Communication::SoftBus::ISessionListener> listern;
    int ret = testSessionServiceImpl.CreateSessionServer(pkgName1, sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    sessionName1 = "test";
    ret = testSessionServiceImpl.CreateSessionServer(pkgName1, sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    std::string pkgName2 ="ohos.security.distributed_permission";
    ret = testSessionServiceImpl.CreateSessionServer(pkgName2, sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.CreateSessionServer(pkgName2, sessionName1, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.CreateSessionServer(pkgName2, sessionName1, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    std::string sessionName2 = "security.dpms_channel";
    ret = testSessionServiceImpl.CreateSessionServer(pkgName2, sessionName2, listern);
    EXPECT_EQ(SOFTBUS_ERR, ret);
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
    std::string pkgName1;
    std::string sessionName1;
    std::string sessionName2 = "security.dpms_channel";
    std::string pkgName2 ="ohos.security.distributed_permission";
    std::string peerNetWorkId1;
    std::string peerNetWorkId2 = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
    std::string groupId;
    int flags = 0;
    int ret;
    std::shared_ptr<Communication::SoftBus::Session> session = testSessionServiceImpl.OpenSession(sessionName1,
        sessionName2, peerNetWorkId2, groupId, flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(sessionName2, sessionName1, peerNetWorkId2, groupId, flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(sessionName2, sessionName2, peerNetWorkId1, groupId, flags);
    EXPECT_EQ(nullptr, session);

    session = testSessionServiceImpl.OpenSession(sessionName2, sessionName2, peerNetWorkId2, groupId, flags);
    EXPECT_EQ(nullptr, session);

    int uid = 0;
    int pid = 0;
    ret = testSessionServiceImpl.GrantPermission(-1, -1, pkgName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = testSessionServiceImpl.GrantPermission(uid, pid, pkgName2);
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

    ret = testSessionServiceImpl.RemoveSessionServer(pkgName2, sessionName1);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = testSessionServiceImpl.RemoveSessionServer(pkgName2, sessionName2);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // namespace OHOS nvv