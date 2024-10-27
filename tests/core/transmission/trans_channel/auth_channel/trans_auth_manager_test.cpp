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

#include <gtest/gtest.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "trans_auth_manager.h"
#include "trans_session_service.h"

using namespace testing::ext;

#define TRANS_TEST_CHANNEL_ID 1000

namespace OHOS {

const char *g_sessionName = "ohos.distributedschedule.dms.test";
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
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    cb = TransServerGetChannelCb();
}

void TransAuthManagerTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
}

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
    EXPECT_EQ(ret,  SOFTBUS_TRANS_NODE_NOT_FOUND);
}

/**
 * @tc.name: TransAuthManagerTest02
 * @tc.desc: Transmission auth manager open autn message channel with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthManagerTest02, TestSize.Level1)
{
    ConnectOption *connOpt = (ConnectOption*)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != NULL);
    int32_t channelId = 0;
    int32_t ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, &channelId, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    connOpt->type = CONNECT_TCP;
    ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, NULL, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransOpenAuthMsgChannel(g_sessionName, NULL, &channelId, NULL);
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
    ASSERT_EQ(ret,  SOFTBUS_OK);
    ret = TransCloseAuthChannel(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_NODE_NOT_FOUND);
    TransAuthDeinit();
}
}