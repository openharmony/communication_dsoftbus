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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "trans_link_listener.h"
#include "trans_channel_manager.h"

using namespace testing::ext;

namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"

class TransLinkListenerTest : public testing::Test {
public:
    TransLinkListenerTest()
    {}
    ~TransLinkListenerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLinkListenerTest::SetUpTestCase(void)
{}

void TransLinkListenerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: OnP2pRoleChange001
 * @tc.desc: OnP2pRoleChange001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnP2pRoleChange001, TestSize.Level1)
{
    int32_t ret = TransChannelInit();
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}
} // OHOS