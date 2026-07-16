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
#include "device_auth.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "trans_auth_manager.h"
#include "trans_session_service.h"

using namespace testing::ext;

#define TRANS_TEST_CHANNEL_ID 1000

namespace OHOS {

const char *g_sessionName = "ohos.distributedschedule.dms.test";
static IServerChannelCallBack *cb = nullptr;

class TransAuthManagerTest : public testing::Test {
public:
    TransAuthManagerTest(void)
    {}
    ~TransAuthManagerTest(void)
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
    InitDeviceAuthService();
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

/*
 * @tc.name: TransAuthGetNameByChanIdTest001
 * @tc.desc: TransAuthGetNameByChanId with null params returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthGetNameByChanIdTest001, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, nullptr, sessionName,
                                           PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, nullptr,
                             PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransAuthGetNameByChanIdTest002
 * @tc.desc: TransAuthGetNameByChanId with valid params and non-existent channel returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthGetNameByChanIdTest002, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, sessionName,
                             PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
}

/*
 * @tc.name: TransOpenAuthMsgChannelTest001
 * @tc.desc: TransOpenAuthMsgChannel with null connOpt and null channelId returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransOpenAuthMsgChannelTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = TransOpenAuthMsgChannel(g_sessionName, nullptr, &channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ConnectOption *connOpt = reinterpret_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    ASSERT_TRUE(connOpt != nullptr);
    connOpt->type = CONNECT_TCP;
    ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(connOpt);
}

/*
 * @tc.name: TransOpenAuthMsgChannelTest002
 * @tc.desc: TransOpenAuthMsgChannel with connOpt of unspecified type returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransOpenAuthMsgChannelTest002, TestSize.Level1)
{
    ConnectOption *connOpt = reinterpret_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    ASSERT_TRUE(connOpt != nullptr);
    int32_t channelId = 0;
    int32_t ret = TransOpenAuthMsgChannel(g_sessionName, connOpt, &channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(connOpt);
}

/*
 * @tc.name: TransCloseAuthChannelTest001
 * @tc.desc: TransCloseAuthChannel with non-existent channel returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransCloseAuthChannelTest001, TestSize.Level1)
{
    int32_t ret = TransAuthInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCloseAuthChannel(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    TransAuthDeinit();
}

/*
 * @tc.name: GetAuthChannelListHeadTest001
 * @tc.desc: GetAuthChannelListHead with initialized list returns non-null head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, GetAuthChannelListHeadTest001, TestSize.Level1)
{
    int32_t ret = TransAuthInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SoftBusList *head = GetAuthChannelListHead();
    EXPECT_NE(head, nullptr);
    TransAuthDeinit();
}

/*
 * @tc.name: TransAuthGetRoleByAuthIdTest001
 * @tc.desc: TransAuthGetRoleByAuthId without init returns SOFTBUS_NO_INIT, null isClient returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthGetRoleByAuthIdTest001, TestSize.Level1)
{
    int32_t authId = TRANS_TEST_CHANNEL_ID;
    bool *isClient = nullptr;
    int32_t ret = TransAuthGetRoleByAuthId(authId, isClient);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = TransAuthInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthGetRoleByAuthId(authId, isClient);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransAuthDeinit();
}

/*
 * @tc.name: TransAuthGetRoleByAuthIdTest002
 * @tc.desc: TransAuthGetRoleByAuthId with valid params and non-existent authId returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthManagerTest, TransAuthGetRoleByAuthIdTest002, TestSize.Level1)
{
    int32_t authId = TRANS_TEST_CHANNEL_ID;
    bool isClient = false;

    int32_t ret = TransAuthInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthGetRoleByAuthId(authId, &isClient);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    TransAuthDeinit();
}
}