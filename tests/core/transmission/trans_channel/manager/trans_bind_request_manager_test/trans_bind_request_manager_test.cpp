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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_timer.h"
#include "trans_bind_request_manager.c"

#define WATI_TIME_MS 1

const char *g_mySocketName = "mySocket";
const char *g_peerSocketName = "peerSocket";
const char *g_peerNetworkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";

using namespace testing;
using namespace testing::ext;
namespace OHOS {
class TransBindRequestManagerTest : public testing::Test {
public:
    TransBindRequestManagerTest()
    {}
    ~TransBindRequestManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransBindRequestManagerTest::SetUpTestCase(void)
{
    (void)LooperInit();
    (void)TransBindRequestManagerInit();
}

void TransBindRequestManagerTest::TearDownTestCase(void)
{
    TransBindRequestManagerDeinit();
    LooperDeinit();
}

/**
 * @tc.name: TransAddTimestampToList001
 * @tc.desc: Use the wrong parameter and legal parameter to add timestamp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBindRequestManagerTest, TransAddTimestampToList001, TestSize.Level1)
{
    uint32_t ret = TransAddTimestampToList(NULL, NULL, NULL, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAddTimestampToList(g_mySocketName, g_peerSocketName, g_peerNetworkid, SoftBusGetSysTimeMs());
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetDeniedFlagByPeer001
 * @tc.desc: Use the wrong parameter and legal parameter to get flag.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBindRequestManagerTest, GetDeniedFlagByPeer001, TestSize.Level1)
{
    bool ret = GetDeniedFlagByPeer(NULL, NULL, NULL);
    EXPECT_EQ(false, ret);
    ret = GetDeniedFlagByPeer(g_mySocketName, g_peerSocketName, g_peerNetworkid);
    EXPECT_EQ(false, ret);

    for (uint32_t count = 0; count < BIND_FAILED_COUNT_MAX; count ++) {
        SoftBusSleepMs(WATI_TIME_MS);
        TransAddTimestampToList(g_mySocketName, g_peerSocketName, g_peerNetworkid, SoftBusGetSysTimeMs());
    }
    ret = GetDeniedFlagByPeer(g_mySocketName, g_peerSocketName, g_peerNetworkid);
    EXPECT_EQ(true, ret);
    BindRequestParam bindRequestParam = { {0} };
    GenerateParam(g_mySocketName, g_peerSocketName, g_peerNetworkid, &bindRequestParam);
    TransResetBindDeniedFlag(&bindRequestParam);
    ret = GetDeniedFlagByPeer(g_mySocketName, g_peerSocketName, g_peerNetworkid);
    EXPECT_EQ(false, ret);
}
} // OHOS
