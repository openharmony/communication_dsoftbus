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

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_session.c"
#include "softbus_proxychannel_session.h"
#include "softbus_utils.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class TransProxySessionStaticTest : public testing::Test {
public:
    TransProxySessionStaticTest() { }
    ~TransProxySessionStaticTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransProxySessionStaticTest::SetUpTestCase(void)
{
}

void TransProxySessionStaticTest::TearDownTestCase(void)
{
}


/**
 * @tc.name: TransProxyTransNormalMsgTest001
 * @tc.desc: test proxy post trans normal msg.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionStaticTest, TransProxyTransNormalMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.businessType = BUSINESS_TYPE_D2D_VOICE;

    char payLoad[] = "111111";
    int32_t payLoadLen = 7;
    ProxyPacketType flag = PROXY_FLAG_BYTES;
    int32_t ret = TransProxyTransNormalMsg(&info, payLoad, payLoadLen, flag);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.appInfo.businessType = BUSINESS_TYPE_D2D_MESSAGE;
    ret = TransProxyTransNormalMsg(&info, payLoad, payLoadLen, flag);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    ret = TransProxyTransNormalMsg(&info, payLoad, payLoadLen, flag);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPackD2DMsgTest001
 * @tc.desc: test proxy post pack d2d msg.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionStaticTest, TransProxyPackD2DMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.myId = 1;
    info.peerId = 1;
    info.appInfo.businessType = BUSINESS_TYPE_D2D_VOICE;

    char payLoad[] = "111111";
    int32_t payLoadLen = 7;
    int32_t outLen = 0;
    char *ret = TransProxyPackD2DMsg(&info, payLoad, payLoadLen, &outLen);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: TransProxyPackAppNormalMsgTest001
 * @tc.desc: test proxy post pack normal msg.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionStaticTest, TransProxyPackAppNormalMsgTest001, TestSize.Level1)
{
    char payLoad[] = "111111";
    int32_t payLoadLen = 7;
    int32_t outLen = 0;
    ProxyMessageHead head;
    char *ret = TransProxyPackAppNormalMsg(&head, payLoad, payLoadLen, &outLen);
    EXPECT_EQ(nullptr, ret);
}

} // namespace OHOS
