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


#include <string>
#include <gtest/gtest.h>
#include <securec.h>

#include "link_manager.h"
#include "interface_info.h"
#include "resource_manager.h"
#include "p2p_v1_processor.h"
#include "negotiate_message.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_command.h"
#include "default_negotiate_channel.h"
#include "wifi_direct_negotiate_channel.h"
#include "fast_connect_negotiate_channel.h"


namespace OHOS {
using namespace testing::ext;
using namespace testing;
using namespace std;
extern "C"{
class WifiDirectChannelTest : public testing::Test {
public:
    WifiDirectChannelTest()
    {}
    ~WifiDirectChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OnConnectSuccess(uint32_t requestId, int64_t authId)
{
    (void)requestId;
    (void)authId;
}

void OnConnectFailure(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

int32_t PostData(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size)
{
    base = nullptr;
    data = nullptr;
    (void)size;
    return SOFTBUS_OK;
}

int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    base = nullptr;
    (void)deviceId;
    (void)deviceIdSize;
    return SOFTBUS_OK;
}

int32_t GetP2pMac(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize)
{
    base = nullptr;
    (void)p2pMac;
    (void)p2pMacSize;
    return SOFTBUS_OK;
}

void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    base = nullptr;
}

bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    base = nullptr;
    return true;
}

bool IsMetaChannel(struct WifiDirectNegotiateChannel *base)
{
    base = nullptr;
    return false;
}

struct WifiDirectNegotiateChannel* Duplicate(struct WifiDirectNegotiateChannel *base)
{
    base = nullptr;
    return base;
}

void Destructor(struct WifiDirectNegotiateChannel *base)
{
    SoftBusFree(base);
}

void WifiDirectNegotiateChannelConstructorTest(struct WifiDirectNegotiateChannel *self)
{
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));
    self->postData = PostData;
    self->getDeviceId = GetDeviceId;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->isMetaChannel = IsMetaChannel;
    self->duplicate = Duplicate;
    self->destructor = Destructor;
}

struct WifiDirectNegotiateChannel *WifiDirectNegotiateChannelNew(void)
{
    struct WifiDirectNegotiateChannel *self
                     = static_cast<struct WifiDirectNegotiateChannel *>(SoftBusCalloc(sizeof(*self)));
    WifiDirectNegotiateChannelConstructorTest(self);
    return self;
}
void WifiDirectChannelTest::SetUpTestCase(void) {}
void WifiDirectChannelTest::TearDownTestCase(void) {}
void WifiDirectChannelTest::SetUp(void) {}
void WifiDirectChannelTest::TearDown(void) {}

/* default_negotiate_channel.c */
/*
* @tc.name: testDirectChannelTest001
* @tc.desc: test OpenDefaultNegotiateChannel
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest001, TestSize.Level0)
{
    struct DefaultNegoChannelOpenCallback callback;
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    EXPECT_NE(msg, nullptr);
    
    struct WifiDirectNegotiateChannel *channel = WifiDirectNegotiateChannelNew();
    EXPECT_NE(channel, nullptr);
    const char *remoteMac = "1a:2b:3c:4d:5e:6f:7g";
    const char *remoteIp = "192.168.1.1";
    channel->setP2pMac(channel, remoteMac);
    callback.onConnectFailure = OnConnectFailure;
    callback.onConnectSuccess = OnConnectSuccess;
    int ret = OpenDefaultNegotiateChannel(remoteIp, self->goPort, channel, &callback);
    EXPECT_EQ(SOFTBUS_ERR, ret);
};

/*
* @tc.name: testDirectChannelTest002
* @tc.desc: test getDeviceId
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest003, TestSize.Level0)
{
    WifiDirectNegotiateChannel channel;
    char deviceId[] = {'d', 'e', 'v', 'i', 'c', 'e', 'I', 'd'};
    size_t size = sizeof(deviceId) / sizeof(deviceId[0]);
    int32_t ret = DefaultNegotiateChannelNew(1)->getDeviceId(&channel, deviceId, size);
    EXPECT_EQ(SOFTBUS_NOT_IMPLEMENT, ret);
};

/*
* @tc.name: testDirectChannelTest003
* @tc.desc: test getP2pMac
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest004, TestSize.Level0)
{
    DefaultNegotiateChannel *base = DefaultNegotiateChannelNew(1);
    EXPECT_NE(base, nullptr);
    char p2pMac[] = {'p', '2', 'p', 'M', 'a', 'c'};
    size_t p2pMacSize = sizeof(p2pMac) / sizeof(p2pMac[0]);
    int32_t ret = base->getP2pMac((WifiDirectNegotiateChannel*)base, p2pMac, p2pMacSize);
    EXPECT_EQ(SOFTBUS_NOT_IMPLEMENT, ret);
};

/*
* @tc.name: testDirectChannelTest004
* @tc.desc: test isMetaChannel isP2pChannel SetP2pMac
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest005, TestSize.Level0)
{
    DefaultNegotiateChannel *base = DefaultNegotiateChannelNew(1);
    EXPECT_NE(base, nullptr);
    const char *p2pMac = "test345";
    base->setP2pMac((WifiDirectNegotiateChannel*)base, p2pMac);
    bool ret = base->isP2pChannel((WifiDirectNegotiateChannel*)base);
    EXPECT_EQ(false, ret);
    ret = base->isMetaChannel((WifiDirectNegotiateChannel*)base);
    EXPECT_EQ(true, ret);

    base->authId = 0;
    base->setP2pMac((WifiDirectNegotiateChannel*)base, p2pMac);
    ret = base->isP2pChannel((WifiDirectNegotiateChannel*)base);
    EXPECT_EQ(false, ret);
    ret = base->isMetaChannel((WifiDirectNegotiateChannel*)base);
    EXPECT_EQ(true, ret);
};

/*
* @tc.name: testDirectChannelTest005
* @tc.desc: test Duplicate
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest006, TestSize.Level0)
{
    DefaultNegotiateChannel *base = DefaultNegotiateChannelNew(1);
    EXPECT_NE(base, nullptr);
    WifiDirectNegotiateChannel *ret = base->duplicate((WifiDirectNegotiateChannel*)base);
    EXPECT_NE(ret, nullptr);
};

/*
* @tc.name: testDirectChannelTest006
* @tc.desc: test StartListeningForDefaultChannel
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest007, TestSize.Level0)
{
    const char *localIp = "0A:2B:3C:4D:5E6";
    int32_t ret = StartListeningForDefaultChannel(localIp);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
};

/* fast_connect_negotiate_channel.c */
/*
* @tc.name: testDirectChannelTest007
* @tc.desc: test FastConnectNegotiateChannelInit
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest008, TestSize.Level0)
{
    int ret = FastConnectNegotiateChannelInit();
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
};

/*
* @tc.name: testDirectChannelTest008
* @tc.desc: test FastConnectNegotiateChannelNew
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest009, TestSize.Level0)
{
    int32_t channelId = 1;
    FastConnectNegotiateChannel *channel = FastConnectNegotiateChannelNew(channelId);
    EXPECT_NE(nullptr, channel);
};

/*
* @tc.name: testDirectChannelTest009
* @tc.desc: test Duplicate
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectChannelTest, testDirectChannelTest010, TestSize.Level0)
{
    DefaultNegotiateChannel *base = DefaultNegotiateChannelNew(1);
    EXPECT_NE(base, nullptr);
    WifiDirectNegotiateChannel *ret = base->duplicate((WifiDirectNegotiateChannel*)base);
    EXPECT_NE(nullptr, ret);
};
}
} //namespace OHOS
