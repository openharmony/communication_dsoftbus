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

#include <gtest/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_mock.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
class NetBuilderMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetBuilderMockTest::SetUpTestCase()
{
    LooperInit();
}

void NetBuilderMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void NetBuilderMockTest::SetUp() { }

void NetBuilderMockTest::TearDown() { }

/*
 * @tc.name: NET_BUILDER_TEST_001
 * @tc.desc: test LnnNotifyDiscoveryDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderMockTest, NET_BUILDER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    ret = LnnNotifyDiscoveryDevice(nullptr, &infoReport, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_BR;
    (void)memcpy_s(addr.info.br.brMac, BT_MAC_LEN, "1A:22:3C:4D:5E:66", BT_MAC_LEN);
    ret = LnnNotifyDiscoveryDevice(&addr, &infoReport, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnDeinitNetBuilder();
}

/*
 * @tc.name: NET_BUILDER_TEST_002
 * @tc.desc: test LnnServerJoin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderMockTest, NET_BUILDER_TEST_002, TestSize.Level1)
{
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnServerJoin(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_BR;
    (void)memcpy_s(addr.info.br.brMac, BT_MAC_LEN, "1A:22:3C:4D:5E:66", BT_MAC_LEN);
    ret = LnnServerJoin(&addr);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnDeinitNetBuilder();
}

/*
 * @tc.name: NET_BUILDER_TEST_003
 * @tc.desc: test LnnSyncOfflineComplete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderMockTest, NET_BUILDER_TEST_003, TestSize.Level1)
{
    LnnSyncInfoType type = LNN_INFO_TYPE_DEVICE_NAME;
    LnnSyncOfflineComplete(type, nullptr, nullptr, 0);

    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSyncOfflineComplete(type, nullptr, nullptr, 0);

    LnnSyncOfflineComplete(type, "123456xxx", nullptr, 0);

    LnnDeinitNetBuilder();
}

/*
 * @tc.name: NET_BUILDER_TEST_004
 * @tc.desc: test LnnServerLeave
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderMockTest, NET_BUILDER_TEST_004, TestSize.Level1)
{
    const char *networkId = "123456xxx";
    int32_t ret = LnnServerLeave(networkId, "pkaName");
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerLeave(networkId, "pkaName");
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnDeinitNetBuilder();
}

/*
 * @tc.name: NET_BUILDER_TEST_004
 * @tc.desc: test LnnNotifyAuthHandleLeaveLNN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderMockTest, NET_BUILDER_TEST_005, TestSize.Level1)
{
    AuthInterfaceMock authMock;
    ON_CALL(authMock, AuthHandleLeaveLNN(_)).WillByDefault(Return());
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = LnnNotifyAuthHandleLeaveLNN(authHandle);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnNotifyAuthHandleLeaveLNN(authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnDeinitNetBuilder();
}
} // namespace OHOS
