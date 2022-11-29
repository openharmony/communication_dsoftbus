/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>
#include "p2plink_manager.h"
#include "softbus_log.h"
#include "p2plink_interface.h"
#include "p2plink_message.c"

using namespace testing::ext;
namespace OHOS {
class ConnectionP2PFuncTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: testP2pLinkLoopDisconnectDev001
* @tc.desc: arg is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkLoopDisconnectDev001, TestSize.Level1)
{
    P2pLinkLoopDisconnectDev(P2PLOOP_P2PAUTHCHAN_OK, nullptr);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkLoopDisconnectDev002
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkLoopDisconnectDev002, TestSize.Level1)
{
    auto *info = static_cast<P2pLinkDisconnectInfo *>(SoftBusMalloc(sizeof(P2pLinkDisconnectInfo)));
    ASSERT_TRUE(info != nullptr);
    info->pid = 11;
    info->authId = 11;
    (void)strcpy_s(info->peerMac, sizeof(info->peerMac), "abc");

    P2pLinkLoopDisconnectDev(P2PLOOP_P2PAUTHCHAN_OK, info);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkNeoDataProcess001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNeoDataProcess001, TestSize.Level1)
{
    P2pLinkNeoDataProcess(P2PLOOP_P2PAUTHCHAN_OK, nullptr);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkNegoDataRecv001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoDataRecv001, TestSize.Level1)
{
    int64_t authId = 11;
    AuthTransData *data = nullptr;
    P2pLinkNegoDataRecv(authId, data);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkSendMessage001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkSendMessage001, TestSize.Level1)
{
    char data[] = "data";
    int ret = P2pLinkSendMessage(11, data, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_ERR);
}
} // namespace OHOS