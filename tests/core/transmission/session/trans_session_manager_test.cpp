/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "trans_session_account_adapter.h"
#include "trans_session_ipc_adapter.h"
#include "trans_session_manager.c"
#include "trans_session_manager.h"
#include "trans_session_service.h"

#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)

#define MAX_SESSION_SERVER_NUM 100
#define TEST_UID 488
#define TEST_PID 1335

using namespace testing::ext;

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
class TransSessionManagerTest : public testing::Test {
public:
    TransSessionManagerTest()
    {}
    ~TransSessionManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSessionManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
}

void TransSessionManagerTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
}

static SessionServer *BuildSessionServer()
{
    SessionServer *sessionServer = (SessionServer*)SoftBusCalloc(sizeof(SessionServer));
    if (sessionServer == nullptr) {
        return nullptr;
    }
    int32_t ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }
    return sessionServer;
}

/*
 * @tc.name: TransSessionManagerTest01
 * @tc.desc: Transmission session manager initialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest01, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    TransSessionMgrDeinit();
    ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest02
 * @tc.desc: Transmission session manager judge whether session exists with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest02, TestSize.Level1)
{
    bool res = TransSessionServerIsExist(nullptr);
    EXPECT_FALSE(res);
    res = TransSessionServerIsExist(g_sessionName);
    EXPECT_FALSE(res);
}

/*
 * @tc.name: TransSessionManagerTest03
 * @tc.desc: Transmission session manager add item with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest03, TestSize.Level1)
{
    int32_t ret = TransSessionServerAddItem(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    ASSERT_TRUE(sessionServer != nullptr);
    memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransSessionManagerTest04
 * @tc.desc: Transmission session manager del item with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest04, TestSize.Level1)
{
    int32_t ret = TransSessionServerDelItem(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransGetCallingFullTokenId(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetUserIdFromUid(TEST_UID);
    EXPECT_NE(ret, INVALID_USER_ID);

    int32_t UID_1 = 30001000; // test value
    ret = TransGetUserIdFromUid(UID_1);
    EXPECT_NE(ret, INVALID_USER_ID);
}

/*
 * @tc.name: TransSessionManagerTest05
 * @tc.desc: Transmission session manager del item with not existed item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest05, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    TransSessionServerDelItem(g_sessionName);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest06
 * @tc.desc: Transmission session manager get package name by session name with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest06, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    ret = TransGetPkgNameBySessionName(nullptr, pkgName, PKG_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransGetPkgNameBySessionName(g_sessionName, nullptr, PKG_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransGetPkgNameBySessionName(g_sessionName, pkgName, 0);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest07
 * @tc.desc: Transmission session manager delete item by package name with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest07, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool res = TransSessionServerIsExist(g_sessionName);
    EXPECT_TRUE(res);
    TransDelItemByPackageName(nullptr, TRANS_TEST_INVALID_PID);
    res = TransSessionServerIsExist(g_sessionName);
    EXPECT_TRUE(res);
    TransSessionMgrDeinit();
    TransDelItemByPackageName(g_pkgName, TRANS_TEST_INVALID_PID);
}

/*
 * @tc.name: TransSessionManagerTest08
 * @tc.desc: Transmission session manager get uid and pid by session name with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest08, TestSize.Level1)
{
    int32_t pid = 0;
    int32_t uid = 0;
    int32_t ret = TransGetUidAndPid(nullptr, &uid, &pid);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransGetUidAndPid(g_sessionName, nullptr, &pid);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransGetUidAndPid(g_sessionName, &uid, nullptr);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransGetUidAndPid(g_sessionName, &uid, &pid);
    EXPECT_NE(ret,  SOFTBUS_OK);
}

/*
 * @tc.name: TransSessionManagerTest09
 * @tc.desc: Transmission session manager get package name by session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest09, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    ret = TransGetPkgNameBySessionName(g_sessionName, pkgName, PKG_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = strncmp(pkgName, g_pkgName, strlen(g_pkgName));
    EXPECT_EQ(ret,  EOK);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest10
 * @tc.desc: Transmission session manager delete item by package name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest10, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDelItemByPackageName(g_pkgName, TRANS_TEST_INVALID_PID);
    bool res = TransSessionServerIsExist(g_sessionName);
    EXPECT_FALSE(res);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest11
 * @tc.desc: Transmission session manager judge whether session exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest11, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool res = TransSessionServerIsExist(g_sessionName);
    EXPECT_TRUE(res);
    SessionServer *newSessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    EXPECT_TRUE(newSessionServer != nullptr);
    memset_s(newSessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    ret = strcpy_s(newSessionServer->sessionName, sizeof(newSessionServer->sessionName), g_sessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(newSessionServer->pkgName, sizeof(newSessionServer->pkgName), g_pkgName);
    EXPECT_EQ(ret, EOK);
    newSessionServer->pid = TRANS_TEST_INVALID_PID;
    ret = TransSessionServerAddItem(newSessionServer);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NAME_REPEATED);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(newSessionServer);
    TransSessionMgrDeinit();
}
/*
 * @tc.name: TransSessionManagerTest12
 * @tc.desc: Transmission session manager get pid and uid by session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest12, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    sessionServer->uid = TRANS_TEST_INVALID_UID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t pid = 0;
    int32_t uid = 0;
    ret = TransGetUidAndPid(g_sessionName, &uid, &pid);
    EXPECT_EQ(uid,  TRANS_TEST_INVALID_UID);
    EXPECT_EQ(pid, TRANS_TEST_INVALID_PID);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest13
 * @tc.desc: Transmission session manager onLink down with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest13, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    TransOnLinkDown(nullptr, nullptr, nullptr, nullptr, WIFI_P2P);
    TransSessionMgrDeinit();
    TransOnLinkDown(g_networkid, nullptr, nullptr, nullptr, WIFI_P2P);
}

/*
 * @tc.name: TransSessionManagerTest14
 * @tc.desc: Transmission session manager onLink down with wrong parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest14, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    sessionServer->uid = TRANS_TEST_INVALID_UID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    TransOnLinkDown(g_networkid, nullptr, nullptr, nullptr, WIFI_P2P);
}

/*
 * @tc.name: TransSessionManagerTest15
 * @tc.desc: Transmission session manager add item to maxmun
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest15, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    for (int32_t i = 0; i < MAX_SESSION_SERVER_NUM - 1; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = {0};
        char pkgName[PKG_NAME_SIZE_MAX] = {0};
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = sprintf_s(pkgName, PKG_NAME_SIZE_MAX, "%s%d", g_pkgName, i);
        EXPECT_GT(ret, 0);
        SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
        EXPECT_TRUE(sessionServer != nullptr);
        memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
        ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), sessionNme);
        EXPECT_EQ(ret, EOK);
        ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), pkgName);
        EXPECT_EQ(ret, EOK);
        ret = TransSessionServerAddItem(sessionServer);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }

    SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    EXPECT_TRUE(sessionServer != nullptr);
    memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    EXPECT_EQ(ret, EOK);
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_NUM);
    SoftBusFree(sessionServer);

    for (int32_t i = 0; i < MAX_SESSION_SERVER_NUM - 1; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = {0};
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = TransSessionServerDelItem(sessionNme);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest16
 * @tc.desc: Transmission session manager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest16, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = BuildSessionServer();
    EXPECT_TRUE(sessionServer != nullptr);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    sessionServer->uid = 0;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret,  SOFTBUS_OK);

    int32_t pid = 0;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    ret = TransGetPidAndPkgName(g_sessionName, 0, &pid, pkgName, PKG_NAME_SIZE_MAX);
    EXPECT_EQ(SOFTBUS_OK, ret);
    char sessionNme0[SESSION_NAME_SIZE_MAX] = {0};
    ret = sprintf_s(sessionNme0, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, 0);
    EXPECT_GT(ret, 0);
    ret = TransGetPidAndPkgName(sessionNme0, 0, &pid, pkgName, PKG_NAME_SIZE_MAX);
    EXPECT_EQ(SOFTBUS_TRANS_GET_PID_FAILED, ret);

    uint64_t tokenId = 0;
    ret = TransGetTokenIdBySessionName(g_sessionName, &tokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetTokenIdBySessionName(sessionNme0, &tokenId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST, ret);
    ret = TransGetTokenIdBySessionName(nullptr, &tokenId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetTokenIdBySessionName(sessionNme0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

static SessionServer *GenerateSessionServer()
{
    SessionServer *sessionServer = static_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    EXPECT_NE(nullptr, sessionServer);

    int32_t ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }

    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return nullptr;
    }

    return sessionServer;
}

/*
 * @tc.name: TransSessionManagerTest17
 * @tc.desc: Transmission session manager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest17, TestSize.Level1)
{
    int32_t ret = TransGetUserIdFromSessionName(nullptr);
    EXPECT_EQ(INVALID_USER_ID, ret);

    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    SessionServer *sessionServer = GenerateSessionServer();
    EXPECT_NE(nullptr, sessionServer);

    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransGetUserIdFromSessionName(g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest20
 * @tc.desc: test AddAccessInfoBySessionName invalid value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest20, TestSize.Level1)
{
    char *sessionName = NULL;
    AccessInfo accessInfo;
    memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    pid_t callingPid = (pid_t)TEST_PID;
    int32_t ret = AddAccessInfoBySessionName(nullptr, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddAccessInfoBySessionName(sessionName, nullptr, callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSessionManagerTest21
 * @tc.desc: test AddAccessInfoBySessionName not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest21, TestSize.Level1)
{
    char sessionName[] = "testSessionName";
    AccessInfo accessInfo;
    pid_t callingPid = (pid_t)TEST_PID;
    memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    int32_t ret = AddAccessInfoBySessionName(sessionName, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransSessionManagerTest22
 * @tc.desc: test AddAccessInfoBySessionName already init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest22, TestSize.Level1)
{
    char sessionName[] = "testSessionName";
    AccessInfo accessInfo;
    memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    pid_t callingPid = (pid_t)TEST_PID;
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddAccessInfoBySessionName(sessionName, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest23
 * @tc.desc: test AddAccessInfoBySessionName success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest23, TestSize.Level1)
{
    AccessInfo accessInfo;
    memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    accessInfo.extraAccessInfo = (char *)SoftBusCalloc(EXTRA_ACCESS_INFO_LEN_MAX);
    ASSERT_TRUE(accessInfo.extraAccessInfo != nullptr);
    memset_s(accessInfo.extraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX - 1, 'm', EXTRA_ACCESS_INFO_LEN_MAX - 1);
    pid_t callingPid = (pid_t)TEST_PID;
    int32_t userId = TEST_PID;
    uint64_t tokenId = TEST_PID;
    char businessAccountId[] = "testBusinessAccountId";
    char extraAccessInfo[] = "testExtraAccessInfo";

    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    ASSERT_TRUE(newNode != nullptr);
    char sessionName[] = "testSessionNametest";
    strcpy_s(newNode->sessionName, sizeof(sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    int32_t ret = GetAccessInfoBySessionName(sessionName, &userId, &tokenId, businessAccountId, extraAccessInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddAccessInfoBySessionName(sessionName, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetAccessInfoBySessionName(nullptr, &userId, &tokenId, businessAccountId, extraAccessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAccessInfoBySessionName(sessionName, nullptr, &tokenId, businessAccountId, extraAccessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAccessInfoBySessionName(sessionName, &userId, nullptr, businessAccountId, extraAccessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAccessInfoBySessionName(sessionName, &userId, &tokenId, businessAccountId, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
    SoftBusFree(accessInfo.extraAccessInfo);
}

/*
 * @tc.name: TransSessionManagerTest24
 * @tc.desc: test AddAccessInfoBySessionName extraAccessInfo is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest24, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    AccessInfo accessInfo;
    memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    ASSERT_TRUE(newNode != nullptr);
    strcpy_s(newNode->sessionName, strlen(sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    pid_t callingPid = (pid_t)TEST_PID;

    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddAccessInfoBySessionName(sessionName, &accessInfo, callingPid);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);
    ret = AddAccessInfoBySessionName(sessionName, &accessInfo, 0);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest25
 * @tc.desc: test AddAccessInfoBySessionName extraAccessInfo is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest25, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, strlen(sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    uint64_t time = 1;
    int32_t ret = CheckAndUpdateTimeBySessionName(nullptr, time);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CheckAndUpdateTimeBySessionName(sessionName, time);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckAndUpdateTimeBySessionName(sessionName, time);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckAndUpdateTimeBySessionName(sessionName, time);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);
    ret = CheckAndUpdateTimeBySessionName(sessionName, time);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest26
 * @tc.desc: test TransSessionForEachShowInfo, when g_sessionServerList not create should return SOFTBUS_NO_INIT
 * @tc.desc: test TransSessionForEachShowInfo, valid param should return SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest26, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    uint64_t fd = 1;
    int32_t ret = TransSessionForEachShowInfo(fd);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSessionForEachShowInfo(fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest27
 * @tc.desc: test CheckUidAndPid, when g_sessionServerList not create should return false
 * @tc.desc: test CheckUidAndPid, when sessionName is null should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest27, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    pid_t callingUid = 1;
    pid_t callingPid = 1;
    bool ret = CheckUidAndPid(nullptr, callingUid, callingPid);
    EXPECT_FALSE(ret);
    ret = CheckUidAndPid(sessionName, callingUid, callingPid);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: TransSessionManagerTest28
 * @tc.desc: test TransGetPidAndPkgName, when given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest28, TestSize.Level1)
{
    SessionServer pos;
    char sessionName[] = "testSessionName1";
    char pkgName[] = "testPkgName1";
    int32_t callingUid = 1;
    int32_t callingPid = 1;
    uint32_t len = 0;
    int32_t ret = TransGetPidAndPkgName(nullptr, callingUid, &callingPid, pkgName, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetPidAndPkgName(sessionName, callingUid, nullptr, pkgName, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetPidAndPkgName(sessionName, callingUid, &callingPid, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = PKG_NAME_SIZE_MAX + 1;
    ret = TransGetPidAndPkgName(sessionName, callingUid, &callingPid, pkgName, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = EXTRA_ACCESS_INFO_LEN_MAX + 1;
    ret = CheckAccessInfoAndCalloc(&pos, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSessionManagerTest29
 * @tc.desc: test GetTokenTypeBySessionName, when sessionName not in list should return NO_EXIST
 * @tc.desc: test GetTokenTypeBySessionName, when sessionName ot tokentype is null should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest29, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    int32_t tokenType = 1;
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    newNode->tokenType = 1;
    int32_t ret = GetTokenTypeBySessionName(nullptr, &tokenType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetTokenTypeBySessionName(sessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetTokenTypeBySessionName(sessionName, &tokenType);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetTokenTypeBySessionName(sessionName, &tokenType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSessionManagerTest30
 * @tc.desc: test TransGetPidAndPkgName, when sessionName not in list should return NO_EXIST
 * @tc.desc: test TransGetPidAndPkgName, when sessionName ot tokenid is null should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransSessionManagerTest30, TestSize.Level1)
{
    char sessionName[] = "testSessionName1";
    uint64_t tokenId = 1;
    int32_t callingUid = 1;
    int32_t callingPid = 1;
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName);
    newNode->pid = (pid_t)TEST_PID;
    newNode->tokenType = 1;
    int32_t ret = TransGetAclInfoBySessionName(nullptr, &tokenId, &callingUid, &callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetAclInfoBySessionName(sessionName, nullptr, &callingUid, &callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetAclInfoBySessionName(sessionName, &tokenId, &callingUid, &callingPid);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetAclInfoBySessionName(sessionName, &tokenId, &callingUid, &callingPid);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransListCopyTest001
 * @tc.desc: test TransListCopy, when sessionServerList is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, TransListCopyTest001, TestSize.Level1)
{
    int32_t ret = TransListCopy(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: CheckAccessInfoAndCallocTest001
 * @tc.desc: test CheckAccessInfoAndCalloc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, CheckAccessInfoAndCallocTest001, TestSize.Level1)
{
    SessionServer pos;
    pos.accessInfo .extraAccessInfo = static_cast<char *>(SoftBusCalloc(EXTRA_ACCESS_INFO_LEN_MAX));
    ASSERT_TRUE(pos.accessInfo .extraAccessInfo != nullptr);
    int32_t ret = CheckAccessInfoAndCalloc(&pos, EXTRA_ACCESS_INFO_LEN_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetAccessInfoBySessionNameTest001
 * @tc.desc: test GetAccessInfoBySessionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionManagerTest, GetAccessInfoBySessionNameTest001, TestSize.Level1)
{
    char sessionName[] = "wanna.yeel.sessionName";
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName);

    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    int32_t userId = TEST_PID;
    uint64_t tokenId = TEST_PID;
    char businessAccountId[] = "testBusinessAccountId";
    char extraAccessInfo[] = "testExtraAccessInfo";
    ret = GetAccessInfoBySessionName("sessionName.test", &userId, &tokenId, businessAccountId, extraAccessInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}
}
