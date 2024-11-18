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

#include "client_trans_auth_manager.c"
#include "softbus_adapter_mem.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

const char *g_invalidSessionName = "invalid sessionName";

class TransClientSdkAuthManagerTest : public testing::Test {
public:
    TransClientSdkAuthManagerTest() {}
    ~TransClientSdkAuthManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void TransClientSdkAuthManagerTest::SetUpTestCase(void) {}

void TransClientSdkAuthManagerTest::TearDownTestCase(void) {}

/**
 * @tc.name: TransClientSdkAuthManagerTest001
 * @tc.desc: client trans auth init use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSdkAuthManagerTest, TransClientSdkAuthManagerTest001, TestSize.Level0)
{
    int32_t ret = ClientTransAuthInit(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransClientSdkAuthManagerTest002
 * @tc.desc: client trans auth init use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSdkAuthManagerTest, TransClientSdkAuthManagerTest002, TestSize.Level0)
{
    ChannelInfo channel;
    int32_t ret = ClientTransAuthOnChannelOpened(NULL, &channel);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransClientSdkAuthManagerTest003
 * @tc.desc: client trans auth init use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSdkAuthManagerTest, TransClientSdkAuthManagerTest003, TestSize.Level0)
{
    int32_t channelId = 0;
    uint32_t len = -1;
    SessionPktType type = TRANS_SESSION_BYTES;
    int32_t ret = ClientTransAuthOnDataReceived(channelId, NULL, len, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientTransAuthOnDataReceived(channelId, NULL, len, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS