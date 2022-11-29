/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <securec.h>

#include <gtest/gtest.h>
#include "softbus_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_server_frame.h"
#include "trans_auth_manager.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"
#include "trans_channel_callback.h"
#include "softbus_conn_interface.h"

using namespace testing::ext;

#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 60000
#define TEST_AUTH_DATA "test auth message data"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_AUTH_ID 12345
#define TRANS_TEST_INVALID_AUTH_ID (-1)
#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define TRANS_TEST_CHANNEL_ID 12345
#define TRANS_TEST_INVALID_CHANNEL_ID (-1)
#define TRANS_TEST_INVALID_SESSION_ID (-1)
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_STATE 1

#define MAX_SESSION_SERVER_NUM 32

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
static IServerChannelCallBack *cb = NULL;

class TransAuthManagerTest : public testing::Test {
public:
    TransAuthManagerTest()
    {}
    ~TransAuthManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthManagerTest::SetUpTestCase(void)
{
    InitSoftBusServer();
    cb = TransServerGetChannelCb();
}

void TransAuthManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransAuthManagerTest01
 * @tc.desc: Transmission auth manager get name by channel id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthManagerTest01, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, NULL, sessionName,
                                           PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, nullptr,
                             PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, sessionName,
                             PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
}

/**
 * @tc.name: TransAuthManagerTest02
 * @tc.desc: Transmission auth manager open autn message channel with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthManagerTest02, TestSize.Level1)
{
    ConnectOption *connOpt = (ConnectOption*)SoftBusMalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t channelId = 0;
    int32_t ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, &channelId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    connOpt->type = CONNECT_TCP;
    ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransOpenAuthMsgChannel(g_sessionName, NULL, &channelId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    SoftBusFree(connOpt);
}

/**
 * @tc.name: TransAuthManagerTest03
 * @tc.desc: Transmission auth manager close autn channel with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthManagerTest03, TestSize.Level1)
{
    int32_t ret = TransAuthInit(cb);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = TransCloseAuthChannel(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    TransAuthDeinit();
}
}