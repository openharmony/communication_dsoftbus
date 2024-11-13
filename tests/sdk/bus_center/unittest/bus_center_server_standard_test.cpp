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
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;

class BusCenterServerProxyStandardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterServerProxyStandardTest::SetUpTestCase()
{
}

void BusCenterServerProxyStandardTest::TearDownTestCase()
{
}

void BusCenterServerProxyStandardTest::SetUp()
{
}

void BusCenterServerProxyStandardTest::TearDown()
{
}

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

} // namespace OHOS
