/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <pthread.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "wifi_direct_fast_connect.h"
#include "negotiate_message.h"
#include "wifi_direct_types.h"
#include "wifi_direct_processor.h"
#include "wifi_direct_negotiate_channel.h"

using namespace testing::ext;
using namespace std;
namespace OHOS {

class WifiDirectFastConnect : public testing::Test {
public:
    WifiDirectFastConnect()
    {}
    ~WifiDirectFastConnect()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectFastConnect::SetUpTestCase(void)
{}

void WifiDirectFastConnect::TearDownTestCase(void)
{}

void WifiDirectFastConnect::SetUp(void)
{}

void WifiDirectFastConnect::TearDown(void)
{}

/*
* @tc.name: WifiDirectFastConnect001
* @tc.desc: test FastConnectReset FastConnectInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectFastConnect, WifiDirectFastConnect001, TestSize.Level1)
{
    bool releaseChannel = true;
    FastConnectReset(releaseChannel);
    int32_t ret = FastConnectInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectFastConnect002
* @tc.desc: test GetProcessorByNegoChannel FastConnectReuseLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectFastConnect, WifiDirectFastConnect002, TestSize.Level1)
{
    struct WifiDirectConnectInfo connectInfo;
    struct WifiDirectProcessor processor;
    int ret = FastConnectReuseLink(&connectInfo, &processor);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = FastConnectReuseLink(&connectInfo, &processor);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: WifiDirectFastConnect003
* @tc.desc: test GetProcessorByNegoChannelAndConnectType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectFastConnect, WifiDirectFastConnect003, TestSize.Level1)
{
    int result = 0;
    const char* remoteMac = "remoteMac";
    struct WifiDirectNegotiateChannel channel;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    enum WifiDirectNegotiateCmdType cmd = CMD_INVALID;
    (void)memset_s(&channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    EXPECT_NE(msg, nullptr);
    FastConnectHandleFailure(result);
    FastConnectClientConnected(remoteMac);
    FastConnectCloseChannel(&channel);
    int32_t ret = FastConnectProcessNegotiateMessage(cmd, msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};
}