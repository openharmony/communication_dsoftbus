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
#include <securec.h>
#include "softbus_error_code.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "trans_client_proxy.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
    class TransClientProxyGitpidTest : public testing::Test {
    public:
        TransClientProxyGitpidTest() {}
        ~TransClientProxyGitpidTest() {}
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp() override {}
        void TearDown() override {}
    };
    
void TransClientProxyGitpidTest::SetUpTestCase(void) {}
void TransClientProxyGitpidTest::TearDownTestCase(void) {}

/*
 * @tc.name: ClientIpcOnChannelOpenedTest001
 * @tc.desc: ClientIpcOnChannelOpened test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelOpenedTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *sessionName = "testName";
    int32_t pid = getpid();
    
    ChannelInfo *channel = static_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);

    int32_t ret = ClientIpcOnChannelOpened(pkgName, sessionName, channel, pid);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientIpcOnChannelBindTest001
 * @tc.desc: ClientIpcOnChannelBind test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelBindTest001, TestSize.Level1)
{
    ChannelMsg *data = static_cast<ChannelMsg *>(SoftBusCalloc(sizeof(ChannelMsg)));
    ASSERT_TRUE(data != nullptr);
    data->msgPid = getpid();

    int32_t ret = ClientIpcOnChannelBind(data);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(data);
}

 /*
 * @tc.name: ClientIpcOnChannelOpenFailedTest001
 * @tc.desc: ClientIpcOnChannelOpenFailed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelOpenFailedTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    ChannelMsg *data = static_cast<ChannelMsg *>(SoftBusCalloc(sizeof(ChannelMsg)));
    ASSERT_TRUE(data != nullptr);
    data->msgPid = getpid();
    int32_t errCode = 0;
    data->msgPkgName = pkgName;

    int32_t ret = ClientIpcOnChannelOpenFailed(data, errCode);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(data);
}

/*
 * @tc.name: ClientIpcOnChannelLinkDownTest001
 * @tc.desc: ClientIpcOnChannelLinkDown test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelLinkDownTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    ChannelMsg *data = static_cast<ChannelMsg *>(SoftBusCalloc(sizeof(ChannelMsg)));
    ASSERT_TRUE(data != nullptr);
    data->msgPid = getpid();
    data->msgPkgName = pkgName;
    const char *networkId = "1111"; // test value
    const char *peerIp = "1111"; // test value
    int32_t routeType = 1;

    int32_t ret = ClientIpcOnChannelLinkDown(data, networkId, peerIp, routeType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(data);
}

/*
 * @tc.name: ClientIpcOnChannelClosedTest001
 * @tc.desc: ClientIpcOnChannelClosed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelClosedTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    ChannelMsg *data = static_cast<ChannelMsg *>(SoftBusCalloc(sizeof(ChannelMsg)));
    ASSERT_TRUE(data != nullptr);

    data->msgPid = getpid();
    data->msgPkgName = pkgName;

    int32_t ret = ClientIpcOnChannelClosed(data);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(data);
}

/*
 * @tc.name: ClientIpcSetChannelInfoTest001
 * @tc.desc: ClientIpcSetChannelInfon test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcSetChannelInfoTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *sessionName = "testName";
    int32_t pid = getpid();
    int32_t sessionId = 1;
    
    TransInfo *transInfo = static_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);

    int32_t ret = ClientIpcSetChannelInfo(pkgName, sessionName, sessionId, transInfo, pid);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: ClientIpcOnChannelMsgReceivedTest001
 * @tc.desc: ClientIpcOnChannelMsgReceived test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyGitpidTest, ClientIpcOnChannelMsgReceivedTest001, TestSize.Level1)
{
    const char *pkgName = "testName";
    ChannelMsg *data = static_cast<ChannelMsg *>(SoftBusCalloc(sizeof(ChannelMsg)));
    ASSERT_TRUE(data != nullptr);
    TransReceiveData *receiveData = static_cast<TransReceiveData *>(SoftBusCalloc(sizeof(TransReceiveData)));
    ASSERT_TRUE(receiveData != nullptr);

    data->msgPid = getpid();
    data->msgPkgName = pkgName;

    int32_t ret = ClientIpcOnChannelMsgReceived(data, receiveData);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    SoftBusFree(data);
    SoftBusFree(receiveData);
}
}