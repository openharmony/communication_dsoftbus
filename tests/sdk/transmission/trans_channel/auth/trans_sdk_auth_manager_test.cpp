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

#include "client_trans_auth_manager.c"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

const char *g_invalidSessionName = "invalid sessionName";

class TransClientSdkAuthManagerTest : public testing::Test {
public:
    TransClientSdkAuthManagerTest() { }
    ~TransClientSdkAuthManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransClientSdkAuthManagerTest::SetUpTestCase(void) { }

void TransClientSdkAuthManagerTest::TearDownTestCase(void) { }

/**
 * @tc.name: ClientTransAuthInitAndOnChannelOpenedTest001
 * @tc.desc: ClientTransAuthInit with null callback and ClientTransAuthOnChannelOpened with
             null sessionName return SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSdkAuthManagerTest, ClientTransAuthInitAndOnChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret = ClientTransAuthInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ChannelInfo channel;
    ret = ClientTransAuthOnChannelOpened(nullptr, &channel, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransAuthOnDataReceivedTest001
 * @tc.desc: ClientTransAuthOnDataReceived with null data and invalid len returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSdkAuthManagerTest, ClientTransAuthOnDataReceivedTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t len = -1;
    SessionPktType type = TRANS_SESSION_BYTES;
    int32_t ret = ClientTransAuthOnDataReceived(channelId, nullptr, len, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
