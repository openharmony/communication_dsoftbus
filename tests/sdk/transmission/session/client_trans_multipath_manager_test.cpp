/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "client_trans_multipath_manager.h"
#include "client_trans_session_manager.h"
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "softbus_def.h"
#include "trans_log.h"

using namespace testing::ext;

namespace OHOS {
class TransMultipathManagerTest : public testing::Test {
public:
    TransMultipathManagerTest() {}
    ~TransMultipathManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override {}
    void TearDown(void) override {}
};

void TransMultipathManagerTest::SetUpTestCase(void)
{
    (void)TransClientInit();
}

void TransMultipathManagerTest::TearDownTestCase(void)
{
    TransClientDeinit();
}

HWTEST_F(TransMultipathManagerTest, TransMultipathGetEnabledInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransMultipathGetEnabled(-1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    bool enabled = false;
    ret = TransMultipathGetEnabled(-1, &enabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathSetEnabledInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransMultipathSetEnabled(-1, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = TransMultipathSetEnabled(-1, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathSetStrategyInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransMultipathSetStrategy(-1, MULTIPATH_STRATEGY_PARALLEL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransMultipathSetStrategy(0, MULTIPATH_STRATEGY_PARALLEL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathIsSessionActiveInvalidParamTest001, TestSize.Level1)
{
    bool ret = TransMultipathIsSessionActive(nullptr, nullptr);
    EXPECT_FALSE(ret);
    int32_t id = 0;
    ret = TransMultipathIsSessionActive("testSession", &id);
    EXPECT_FALSE(ret);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathGetReserveChannelInvalidParamTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t routeType = 0;
    int32_t ret = TransMultipathGetReserveChannel(-1, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransMultipathGetReserveChannel(-1, &channelId, &channelType, &routeType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathClearReserveChannelInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransMultipathClearReserveChannel(-1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathGetChannelRoleInvalidParamTest001, TestSize.Level1)
{
    ChannelUseChooseState useType = CHANNEL_USE_CHOOSE_INIT;
    int32_t ret = TransMultipathGetChannelRole(-1, -1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransMultipathGetChannelRole(-1, -1, &useType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathNeedDelReserveInvalidParamTest001, TestSize.Level1)
{
    bool onlyReserve = false;
    bool ret = TransMultipathNeedDelReserve(nullptr, -1, nullptr);
    EXPECT_FALSE(ret);
    SessionInfo sessionNode = {};
    ret = TransMultipathNeedDelReserve(&sessionNode, -1, &onlyReserve);
    EXPECT_FALSE(ret);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathUpdateClosingStateTest001, TestSize.Level1)
{
    TransMultipathUpdateClosingState(nullptr, true);
    SessionInfo sessionNode = {};
    sessionNode.enableMultipath = false;
    TransMultipathUpdateClosingState(&sessionNode, true);
    EXPECT_FALSE(sessionNode.isClosingReserve);
    sessionNode.enableMultipath = true;
    TransMultipathUpdateClosingState(&sessionNode, true);
    EXPECT_TRUE(sessionNode.isClosingReserve);
    TransMultipathUpdateClosingState(&sessionNode, false);
    EXPECT_FALSE(sessionNode.isClosingReserve);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathUpdateReserveChannelInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransMultipathUpdateReserveChannel(INVALID_SESSION_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransMultipathUpdateReserveChannel(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(TransMultipathManagerTest, TransMultipathNeedDelReserveValidTest001, TestSize.Level1)
{
    int32_t routeType = 100;
    bool onlyReserveLinkDown = false;
    SessionInfo sessionNode = {};
    sessionNode.enableMultipath = true;
    sessionNode.routeType = routeType;
    sessionNode.routeTypeReserve = 200;
    bool ret = TransMultipathNeedDelReserve(&sessionNode, routeType, &onlyReserveLinkDown);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(onlyReserveLinkDown, false);
    sessionNode.routeType = 200;
    sessionNode.routeTypeReserve = routeType;
    ret = TransMultipathNeedDelReserve(&sessionNode, routeType, &onlyReserveLinkDown);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(onlyReserveLinkDown, true);
}

}