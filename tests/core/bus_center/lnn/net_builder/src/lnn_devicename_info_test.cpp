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

#include "bus_center_info_key.h"
#include "lnn_connection_mock.h"
#include "lnn_devicename_info.h"
#include "lnn_net_builder_deps_mock.h"
#include "lnn_node_info.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_p2p_info.h"
#include "lnn_service_mock.h"
#include "lnn_settingdata_event_monitor.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

NodeInfo *info = {0};
constexpr char *DEVICE_NAME1 = nullptr;
constexpr char DEVICE_NAME2[] = "ABCDEFG";

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class LnnDeviceNameInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnDeviceNameInfoTest::SetUpTestCase()
{
}

void LnnDeviceNameInfoTest::TearDownTestCase()
{
}

void LnnDeviceNameInfoTest::SetUp()
{
}

void LnnDeviceNameInfoTest::TearDown()
{
}

/*
* @tc.name: LNN_UPDATE_DEVICE_NAME_TEST_001
* @tc.desc: no retry
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_UPDATE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> netbuilderMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnConnectInterfaceMock> connMock;
    LooperInit();
    EXPECT_CALL(netbuilderMock, LnnGetSettingDeviceName).WillRepeatedly(
        NetBuilderDepsInterfaceMock::ActionOfLnnGetSettingDeviceName);
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(info));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillRepeatedly(Return(DEVICE_NAME1));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillRepeatedly(Return(DEVICE_NAME2));
    EXPECT_CALL(serviceMock, LnnInitGetDeviceName).WillRepeatedly(
        LnnServicetInterfaceMock::ActionOfLnnInitGetDeviceName);
    EXPECT_CALL(serviceMock, RegisterNameMonitor).WillRepeatedly(Return());
    EXPECT_CALL(connMock, DiscDeviceInfoChanged).WillRepeatedly(Return());
    UpdateDeviceName(nullptr);
    LnnDeviceNameHandler HandlerGetDeviceName = LnnServicetInterfaceMock::g_deviceNameHandler;
    HandlerGetDeviceName();
    LooperDeinit();
}

/*
* @tc.name: LNN_UPDATE_DEVICE_NAME_TEST_002
* @tc.desc: looper is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_UPDATE_DEVICE_NAME_TEST_002, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> netbuilderMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnInitGetDeviceName).WillRepeatedly(
        LnnServicetInterfaceMock::ActionOfLnnInitGetDeviceName);
    EXPECT_CALL(netbuilderMock, LnnGetSettingDeviceName(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    UpdateDeviceName(nullptr);
}
} // namespace OHOS
