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
#include <string>

#include "dfs_session.h"
#include "inner_session.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_session_service.h"
#include "trans_log.h"

using namespace testing::ext;

namespace OHOS {

ConnectionAddr g_addrInfo;

const char *g_testSessionName = "ohos.distributedschedule.dms.test";
std::string g_testData = "TranSessionTest_GetSessionKeyTestData";

#define TEST_FILE_NAME "test.filename.01"
#define TEST_PKG_NAME_LEN (64)
#define TEST_SESSION_NAME_LEN (64)
#define TEST_NETWORK_ID_LEN (64)
#define TEST_GROUP_ID_LEN (64)

class TransSessionTest : public testing::Test {
public:
    TransSessionTest()
    {}
    ~TransSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSessionTest::SetUpTestCase(void)
{
    (void)TransClientInit();
}

void TransSessionTest::TearDownTestCase(void)
{
}
static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sesisonId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
};

/**
 * @tc.name: GetSessionKeyTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, GetSessionKeyTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    char *key = (char *)g_testData.c_str();
    unsigned int len = strlen(key);

    ret = GetSessionKey(-1, key, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, key, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, key, SESSION_KEY_LEN - 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetSessionKeyTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, GetSessionKeyTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    char *key = (char *)g_testData.c_str();
    unsigned int len = strlen(key);

    ret = GetSessionKey(sessionId, key, len);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: GetSessionHandleTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, GetSessionHandleTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    int32_t handle = 1;

    ret = GetSessionHandle(-1, &handle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionHandle(sessionId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetSessionHandleTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, GetSessionHandleTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    int32_t handle = 1;

    ret = GetSessionHandle(sessionId, &handle);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: DisableSessionListenerTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, DisableSessionListenerTest001, TestSize.Level0)
{
    int32_t ret;

    ret = DisableSessionListener(-1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: DisableSessionListenerTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, DisableSessionListenerTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;

    ret = DisableSessionListener(sessionId);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: OpenAuthSessionTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(TransSessionTest, OpenAuthSessionTest001, TestSize.Level0)
{
    int32_t ret;

    ret = OpenAuthSession(NULL, &(g_addrInfo), 1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = OpenAuthSession(g_testSessionName, NULL, 1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = OpenAuthSession(g_testSessionName, &(g_addrInfo), -1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OpenAuthSessionTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, OpenAuthSessionTest002, TestSize.Level0)
{
    int32_t ret;

    ret = OpenAuthSession(g_testSessionName, &(g_addrInfo), 1, NULL);
    EXPECT_GE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: NotifyAuthSuccessTest001
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, NotifyAuthSuccessTest001, TestSize.Level0)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t sessionId = 1;
    NotifyAuthSuccess(sessionId);
}

/**
 * @tc.name: SendFileTest001
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, SendFileTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    int32_t ret = SendFile(sessionId, NULL, NULL, 1);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *sFileList[] = { TEST_FILE_NAME };
    ret = SendFile(sessionId, sFileList, NULL, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendFile(sessionId, sFileList, NULL, 1);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendFileTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, SendFileTest002, TestSize.Level0)
{
    char pkgName[TEST_PKG_NAME_LEN] = "com.test.trans.session";
    char mySessionName[TEST_SESSION_NAME_LEN] = "com.test.trans.session.sendfile";
    char peerSessionName[TEST_SESSION_NAME_LEN] = "com.test.trans.session.sendfile";
    char peerNetworkId[TEST_NETWORK_ID_LEN] = "1234567789";
    char groupId[TEST_GROUP_ID_LEN] = "123";
    SessionAttribute attr;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
        .groupId = groupId,
        .attr = &attr,
    };

    const char *sFileList[] = { TEST_FILE_NAME };
    int32_t sessionId = INVALID_SESSION_ID;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    (void)ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, mySessionName, &g_sessionlistener);
    (void)ClientAddSession(&param, &sessionId, &isEnabled);

    int32_t ret = SendFile(sessionId, sFileList, NULL, 1);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: QosReportTest001
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, QosReportTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    int32_t appType = 1;
    int32_t quality = -1;
    int32_t ret = QosReport(sessionId, appType, quality);
    EXPECT_NE(SOFTBUS_OK, ret);

    quality = 1;
    ret = QosReport(sessionId, appType, quality);
    EXPECT_NE(SOFTBUS_OK, ret);
}


/**
 * @tc.name: ClientCleanAllSessionWhenServerDeathTest001
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, ClientCleanAllSessionWhenServerDeathTest001, TestSize.Level0)
{
    ListNode sessionServerList;
    ListInit(&sessionServerList);
    ClientCleanAllSessionWhenServerDeath(&sessionServerList);
    SessionServerInfo *infoNode = NULL;
    SessionServerInfo *infoNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, &(sessionServerList), SessionServerInfo, node) {
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }

    char pkgName[TEST_PKG_NAME_LEN] = "com.test.trans.session";
    char mySessionName[TEST_SESSION_NAME_LEN] = "com.test.trans.session.sendfile";
    char peerSessionName[TEST_SESSION_NAME_LEN] = "com.test.trans.session.sendfile";
    char peerNetworkId[TEST_NETWORK_ID_LEN] = "1234567789";
    char groupId[TEST_GROUP_ID_LEN] = "123";
    SessionAttribute attr;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
        .groupId = groupId,
        .attr = &attr,
    };

    int32_t sessionId = INVALID_SESSION_ID;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, mySessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NAME_REPEATED);
    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientCleanAllSessionWhenServerDeath(&sessionServerList);
    infoNode = NULL;
    infoNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, &(sessionServerList), SessionServerInfo, node) {
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }
}

} // namespace OHOS
