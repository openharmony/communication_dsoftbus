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

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "trans_auth_manager.h"

using namespace testing::ext;

namespace OHOS {

class TransAuthChannelTest : public testing::Test {
public:
    TransAuthChannelTest()
    {}
    ~TransAuthChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthChannelTest::SetUpTestCase(void)
{}

void TransAuthChannelTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransOpenAuthMsgChannelTest001
 * @tc.desc: TransOpenAuthMsgChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest001, TestSize.Level1)
{
    const char* sessionName = "com.softbus.transmission.test";
    int32_t channelId = 0;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = 6000,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), "192.168.8.1") != EOK) {
        return;
    }
    
    int ret = TransOpenAuthMsgChannel(sessionName, NULL, &channelId);
    EXPECT_TRUE(ret != 0);

    ret = TransOpenAuthMsgChannel(sessionName, &connInfo, NULL);
    EXPECT_TRUE(ret != 0);

    connInfo.type = CONNECT_BR;
    ret = TransOpenAuthMsgChannel(sessionName, &connInfo, &channelId);
    EXPECT_TRUE(ret != 0);
}
} // namespace OHOS