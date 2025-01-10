/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "lnn_connId_callback_manager.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

constexpr int32_t CHANNEL_ID = 2050;
constexpr int32_t CONNID_ID = 99;
constexpr int32_t CONNID_ID_TWO = 100;
constexpr int32_t CONNID_ID_ERROR = 0;
char g_peerUdud[] = "123456ABCDEF";

namespace OHOS {
using namespace testing::ext;


class LnnConnIdCbManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LnnConnIdCbManagerTest::SetUpTestCase(void) { }

void LnnConnIdCbManagerTest::TearDownTestCase(void) { }


void LnnConnIdCbManagerTest::SetUp()
{
    LnnInitConnIdCallbackManager();
}

void LnnConnIdCbManagerTest::TearDown()
{
    LnnDeinitConnIdCallbackManager();
}

static void OnLnnServerJoinExtCb(const ConnectionAddr *addr, int32_t ret)
{
    (void)addr;
    return;
}

static LnnServerJoinExtCallBack cb = {
    .lnnServerJoinExtCallback = OnLnnServerJoinExtCb
};

/**
 * @tc.name: LnnConnIdCbManagerTest001
 * @tc.desc: AddConnIdCallbackInfoItem test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConnIdCbManagerTest, LnnConnIdCbManagerTest001, TestSize.Level1)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_SESSION, .info.session.channelId = CHANNEL_ID };
    int32_t ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID_TWO, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_EXISTED);
    ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID_TWO, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_JOIN_LNN_START_ERR);
    ret = AddConnIdCallbackInfoItem(nullptr, &cb, CONNID_ID_TWO, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID_TWO, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddConnIdCallbackInfoItem(&addr, nullptr, CONNID_ID_TWO, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID_ERROR, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnConnIdCbManagerTest002
 * @tc.desc: DelConnIdCallbackInfoItem test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConnIdCbManagerTest, LnnConnIdCbManagerTest002, TestSize.Level1)
{
    int32_t ret = DelConnIdCallbackInfoItem(CONNID_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelConnIdCallbackInfoItem(CONNID_ID_ERROR);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnConnIdCbManagerTest003
 * @tc.desc: InvokeCallbackForJoinExt test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConnIdCbManagerTest, LnnConnIdCbManagerTest003, TestSize.Level1)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_SESSION, .info.session.channelId = CHANNEL_ID };
    int32_t ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(InvokeCallbackForJoinExt(g_peerUdud, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(InvokeCallbackForJoinExt(nullptr, SOFTBUS_OK));
}

/**
 * @tc.name: LnnConnIdCbManagerTest004
 * @tc.desc: GetConnIdCbInfoByAddr test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConnIdCbManagerTest, LnnConnIdCbManagerTest004, TestSize.Level1)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_SESSION, .info.session.channelId = CHANNEL_ID };
    ConnIdCbInfo connIdCbInfo;
    (void)memset_s(&connIdCbInfo, sizeof(ConnIdCbInfo), 0, sizeof(ConnIdCbInfo));
    int32_t ret = GetConnIdCbInfoByAddr(nullptr, &connIdCbInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetConnIdCbInfoByAddr(&addr, &connIdCbInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = AddConnIdCallbackInfoItem(&addr, &cb, CONNID_ID, g_peerUdud);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetConnIdCbInfoByAddr(&addr, &connIdCbInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS