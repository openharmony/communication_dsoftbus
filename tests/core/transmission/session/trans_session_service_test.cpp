/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"

using namespace testing::ext;

#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define INVALID_SESSION_ID (-1)

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};

class TransSessionServiceTest : public testing::Test {
public:
    TransSessionServiceTest()
    {}
    ~TransSessionServiceTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSessionServiceTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
}

void TransSessionServiceTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
}

/**
 * @tc.name: TransSessionServiceTest01
 * @tc.desc: Transmission session service create session with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest01, TestSize.Level1)
{
    int32_t ret = TransCreateSessionServer(NULL, g_sessionName, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransCreateSessionServer(g_pkgName, NULL, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransSessionServiceTest02
 * @tc.desc: Transmission session service create session with existed session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest02, TestSize.Level1)
{
    SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    EXPECT_TRUE(sessionServer != NULL);
    memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    int32_t ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    EXPECT_EQ(ret, EOK);
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransSessionServiceTest03
 * @tc.desc: Transmission session service create session with invalid and wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest03, TestSize.Level1)
{
    int32_t ret = TransRemoveSessionServer(NULL, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransRemoveSessionServer(g_pkgName, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransRemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransSessionServiceTest04
 * @tc.desc: Transmission session service open session with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest04, TestSize.Level1)
{
    SessionParam sessionPara;
    memset_s(&sessionPara, sizeof(SessionParam), 0, sizeof(SessionParam));
    TransInfo *transInfo = (TransInfo*)SoftBusCalloc(sizeof(TransInfo));
    EXPECT_TRUE(transInfo != NULL);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    int32_t ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    sessionPara.sessionName = g_sessionName;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    sessionPara.peerSessionName = g_sessionName;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    sessionPara.peerDeviceId = g_deviceId;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_GROUP_INVALID);
    char groupId[] = {"ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00AB"};
    sessionPara.groupId = groupId;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);
    sessionPara.groupId = g_groupid;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransSessionServiceTest05
 * @tc.desc: Transmission session service open session with not wrong session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest05, TestSize.Level1)
{
    SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    EXPECT_TRUE(sessionServer != NULL);
    memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    int32_t ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    EXPECT_EQ(ret, EOK);
    ret = TransSessionServerAddItem(sessionServer);
    TransInfo *transInfo = (TransInfo*)SoftBusCalloc(sizeof(TransInfo));
    EXPECT_TRUE(transInfo != NULL);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    SessionParam sessionPara;
    memset_s(&sessionPara, sizeof(SessionParam), 0, sizeof(SessionParam));
    sessionPara.sessionName = g_sessionName;
    sessionPara.peerSessionName = g_sessionName;
    sessionPara.peerDeviceId = g_deviceId;
    sessionPara.groupId = g_groupid;
    sessionPara.attr = &g_sessionAttr;
    ret = TransOpenSession(&sessionPara, transInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransSessionServerDelItem(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransSessionServiceTest06
 * @tc.desc: Transmission session service initialize and deinitialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionServiceTest, TransSessionServiceTest06, TestSize.Level1)
{
    TransServerDeathCallback(g_pkgName, TRANS_TEST_INVALID_PID);
    int32_t ret = TransServerInit();
    EXPECT_EQ(ret, SOFTBUS_CONN_INTERNAL_ERR);
    TransServerDeinit();
}
}