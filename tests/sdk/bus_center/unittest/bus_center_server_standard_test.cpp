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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_server_proxy_standard.h"
#include "iremote_object.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;

#define ADDRTYPE_LEN 2
#define INFOTYPE_LEN 6
#define LEN          0

static const int32_t KEY = 1;
static const int32_t INFONUM = 6;
static const int32_t ACCURACY = 10;
static const int32_t PERIOD = 10;
static const int32_t PUBLISHID = 0;
static const int32_t REFRESHID = 0;
static const uint32_t QOSCOUNT = 10;

class BusCenterServerProxyStandardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterServerProxyStandardTest::SetUpTestCase() { }

void BusCenterServerProxyStandardTest::TearDownTestCase() { }

void BusCenterServerProxyStandardTest::SetUp() { }

void BusCenterServerProxyStandardTest::TearDown() { }

/*
 * @tc.name: SoftbusRegisterService_TEST_001
 * @tc.desc: SoftbusRegisterService return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, SoftbusRegisterService_TEST_001, TestSize.Level1)
{
    const char *clientPkgName = "000";
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.SoftbusRegisterService(clientPkgName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CreateSessionServer_TEST_001
 * @tc.desc: CreateSessionServer return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, CreateSessionServer_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    const char *sessionName = "111";
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.CreateSessionServer(pkgName, sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RemoveSessionServer_TEST_001
 * @tc.desc: RemoveSessionServer return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, RemoveSessionServer_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    const char *sessionName = "111";
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.RemoveSessionServer(pkgName, sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenSession_TEST_001
 * @tc.desc: OpenSession return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, OpenSession_TEST_001, TestSize.Level1)
{
    SessionParam param;
    TransInfo info;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.OpenSession(&param, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenAuthSession_TEST_001
 * @tc.desc: OpenAuthSession return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, OpenAuthSession_TEST_001, TestSize.Level1)
{
    const char *sessionName = "000";
    ConnectionAddr addrInfo;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.OpenAuthSession(sessionName, &addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NotifyAuthSuccess_TEST_001
 * @tc.desc: NotifyAuthSuccess return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, NotifyAuthSuccess_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.NotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ReleaseResources_TEST_001
 * @tc.desc: ReleaseResources return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, ReleaseResources_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.ReleaseResources(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CloseChannel_TEST_001
 * @tc.desc: CloseChannel return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, CloseChannel_TEST_001, TestSize.Level1)
{
    const char *sessionName = "000";
    int32_t channelId = 0;
    int32_t channelType = 0;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.CloseChannel(sessionName, channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CloseChannelWithStatistics_TEST_001
 * @tc.desc: CloseChannelWithStatistics return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, CloseChannelWithStatistics_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    uint64_t laneId = 0;
    uint32_t len = 1;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.CloseChannelWithStatistics(channelId, channelType, laneId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SendMessage_TEST_001
 * @tc.desc: SendMessage return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, SendMessage_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    uint32_t len = 1;
    int32_t msgType = 0;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.SendMessage(channelId, channelType, nullptr, len, msgType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: QosReport_TEST_001
 * @tc.desc: QosReport return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, QosReport_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t chanType = 0;
    int32_t appType = 1;
    int32_t quality = 1;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.QosReport(channelId, chanType, appType, quality);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: StreamStats_TEST_001
 * @tc.desc: StreamStats return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, StreamStats_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    const StreamSendStats *data = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.StreamStats(channelId, channelType, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RippleStats_TEST_001
 * @tc.desc: RippleStats return value is equal to SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, RippleStats_TEST_001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    const TrafficStats *data = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.RippleStats(channelId, channelType, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: JoinLNN_TEST_001
 * @tc.desc: JoinLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, JoinLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *addr = "testaddr";
    uint32_t addrTypeLen = ADDRTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.JoinLNN(pkgName, (void *)addr, addrTypeLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: JoinLNN_TEST_002
 * @tc.desc: JoinLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, JoinLNN_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    uint32_t addrTypeLen = ADDRTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.JoinLNN(pkgName, nullptr, addrTypeLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LeaveLNN_TEST_001
 * @tc.desc: LeaveLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, LeaveLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *networkId = "testNetworkId";
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.LeaveLNN(pkgName, networkId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LeaveLNN_TEST_002
 * @tc.desc: LeaveLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, LeaveLNN_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *networkId = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.LeaveLNN(pkgName, networkId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllOnlineNodeInfo_TEST_001
 * @tc.desc: GetAllOnlineNodeInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetAllOnlineNodeInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *testInfo = "testinfo";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    int32_t infoNum = INFONUM;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetAllOnlineNodeInfo(pkgName, (void **)&testInfo, infoTypeLen, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllOnlineNodeInfo_TEST_002
 * @tc.desc: GetAllOnlineNodeInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetAllOnlineNodeInfo_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    int32_t infoNum = INFONUM;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetAllOnlineNodeInfo(pkgName, nullptr, infoTypeLen, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllOnlineNodeInfo_TEST_003
 * @tc.desc: GetAllOnlineNodeInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetAllOnlineNodeInfo_TEST_003, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *testInfo = "testinfo";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetAllOnlineNodeInfo(pkgName, (void **)&testInfo, infoTypeLen, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalDeviceInfo_TEST_001
 * @tc.desc: GetLocalDeviceInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetLocalDeviceInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *testInfo = "testinfo";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetLocalDeviceInfo(pkgName, (void *)testInfo, infoTypeLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalDeviceInfo_TEST_002
 * @tc.desc: GetLocalDeviceInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetLocalDeviceInfo_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetLocalDeviceInfo(pkgName, nullptr, infoTypeLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalDeviceInfo_TEST_003
 * @tc.desc: GetLocalDeviceInfo return value is equal to SOFTBUS_IPC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetLocalDeviceInfo_TEST_003, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *info = "testinfo";
    uint32_t infoTypeLen = INFOTYPE_LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    servertest.BusCenterServerProxyStandardDeInit();
    int32_t ret = servertest.GetLocalDeviceInfo(pkgName, (void *)info, infoTypeLen);
    EXPECT_EQ(ret, SOFTBUS_IPC_ERR);
}

/*
 * @tc.name: GetNodeKeyInfo_TEST_001
 * @tc.desc: GetNodeKeyInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetNodeKeyInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *networkId = "testNetworkId";
    unsigned char arr[] = { 0x01, 0x02, 0x03 };
    unsigned char *buf = arr;
    uint32_t len = sizeof(arr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetNodeKeyInfo(pkgName, networkId, KEY, buf, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetNodeKeyInfo_TEST_002
 * @tc.desc: GetNodeKeyInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetNodeKeyInfo_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *networkId = nullptr;
    unsigned char arr[] = { 0x01, 0x02, 0x03 };
    unsigned char *buf = arr;
    uint32_t len = sizeof(arr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetNodeKeyInfo(pkgName, networkId, KEY, buf, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetNodeKeyInfo_TEST_003
 * @tc.desc: GetNodeKeyInfo return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, GetNodeKeyInfo_TEST_003, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *networkId = "testNetworkId";
    unsigned char *buf = nullptr;
    uint32_t len = LEN;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.GetNodeKeyInfo(pkgName, networkId, KEY, buf, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RegDataLevelChangeCb_TEST_001
 * @tc.desc: RegDataLevelChangeCb return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, RegDataLevelChangeCb_TEST_003, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.RegDataLevelChangeCb(pkgName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UnregDataLevelChangeCb_TEST_001
 * @tc.desc: UnregDataLevelChangeCb return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, UnregDataLevelChangeCb_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.UnregDataLevelChangeCb(pkgName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetDataLevel_TEST_001
 * @tc.desc: SetDataLevel return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, SetDataLevel_TEST_001, TestSize.Level1)
{
    const DataLevel *dataLevel = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.SetDataLevel(dataLevel);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: StartTimeSync_TEST_001
 * @tc.desc: StartTimeSync return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, StartTimeSync_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *targetNetworkId = "testTargetNetworkId";
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.StartTimeSync(pkgName, targetNetworkId, ACCURACY, PERIOD);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: StartTimeSync_TEST_002
 * @tc.desc: StartTimeSync return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, StartTimeSync_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *targetNetworkId = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.StartTimeSync(pkgName, targetNetworkId, ACCURACY, PERIOD);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PublishLNN_TEST_001
 * @tc.desc: PublishLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, PublishLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    PublishInfo *info = (PublishInfo *)SoftBusCalloc(sizeof(PublishInfo));
    ASSERT_TRUE(info != nullptr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.PublishLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(info);
}

/*
 * @tc.name: PublishLNN_TEST_002
 * @tc.desc: PublishLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, PublishLNN_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const PublishInfo *info = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.PublishLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: StopPublishLNN_TEST_001
 * @tc.desc: StopPublishLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, StopPublishLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.StopPublishLNN(pkgName, PUBLISHID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RefreshLNN_TEST_001
 * @tc.desc: RefreshLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, RefreshLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    SubscribeInfo *info = (SubscribeInfo *)SoftBusCalloc(sizeof(SubscribeInfo));
    ASSERT_TRUE(info != nullptr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.RefreshLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(info);
}

/*
 * @tc.name: RefreshLNN_TEST_002
 * @tc.desc: RefreshLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, RefreshLNN_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const SubscribeInfo *info = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.RefreshLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:StopRefreshLNN_TEST_001
 * @tc.desc: StopRefreshLNN return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, StopRefreshLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.StopRefreshLNN(pkgName, REFRESHID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DeactiveMetaNode_TEST_001
 * @tc.desc: DeactiveMetaNode return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, DeactiveMetaNode_TEST_001, TestSize.Level1)
{
    const char *metaNodeId = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.DeactiveMetaNode(metaNodeId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ShiftLNNGear_TEST_001
 * @tc.desc: ShiftLNNGear return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, ShiftLNNGear_TEST_001, TestSize.Level1)
{
    const char *pkgName = nullptr;
    const char *callerId = "testCallerId";
    const char *targetNetworkId = "tesetTargetNetworkId";
    GearMode *mode = (GearMode *)SoftBusCalloc(sizeof(GearMode));
    ASSERT_TRUE(mode != nullptr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(mode);
}

/*
 * @tc.name: ShiftLNNGear_TEST_002
 * @tc.desc: ShiftLNNGear return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, ShiftLNNGear_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *callerId = nullptr;
    const char *targetNetworkId = "tesetTargetNetworkId";
    GearMode *mode = (GearMode *)SoftBusCalloc(sizeof(GearMode));
    ASSERT_TRUE(mode != nullptr);
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(mode);
}

/*
 * @tc.name: ShiftLNNGear_TEST_003
 * @tc.desc: ShiftLNNGear return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, ShiftLNNGear_TEST_003, TestSize.Level1)
{
    const char *pkgName = "testName";
    const char *callerId = "testCallerId";
    const char *targetNetworkId = "tesetTargetNetworkId";
    const GearMode *mode = nullptr;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: EvaluateQos_TEST_001
 * @tc.desc: EvaluateQos return value is equal to SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyStandardTest, EvaluateQos_TEST_001, TestSize.Level1)
{
    const char *peerNetworkId = "testPeerNetworkId";
    TransDataType dataType = DATA_TYPE_BUTT;
    const sptr<IRemoteObject> impl = nullptr;
    BusCenterServerProxy servertest(impl);
    int32_t ret = servertest.EvaluateQos(peerNetworkId, dataType, nullptr, QOSCOUNT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

} // namespace OHOS
