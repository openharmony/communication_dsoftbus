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
#include "../wifi_direct_mock.h"
#include "data/interface_info.h"
#include "data/interface_manager.h"
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {
class InterfaceManagerTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }
};

static bool g_enabledFlag = false;

static int updateInterfaceInfoTrue(InterfaceInfo &info)
{
    info.SetIsEnable(true);
    return SOFTBUS_OK;
}

static int updateInterfaceInfoFalse(InterfaceInfo &info)
{
    info.SetIsEnable(false);
    return SOFTBUS_OK;
}

static int readInterfaceInfo(InterfaceInfo &info)
{
    g_enabledFlag = info.IsEnable();
    return SOFTBUS_OK;
}

/*
 * @tc.name: InitInterfaceManagerTest
 * @tc.desc: Test manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceManagerTest, InitInterfaceManagerTest, TestSize.Level1)
{
    WifiDirectInterfaceMock wifiDirectInterfaceMock;

    EXPECT_CALL(wifiDirectInterfaceMock, Hid2dGetChannelListFor5G).WillRepeatedly(Return(WIFI_SUCCESS));
    EXPECT_CALL(wifiDirectInterfaceMock, GetP2pEnableStatus).WillRepeatedly(Return(WIFI_SUCCESS));

    InterfaceManager interfaceManager;
    interfaceManager.InitInterface(InterfaceInfo::InterfaceType::HML);
    interfaceManager.InitInterface(InterfaceInfo::InterfaceType::P2P);
    interfaceManager.UpdateInterface(InterfaceInfo::InterfaceType::HML, updateInterfaceInfoTrue);
    int hmlResult = interfaceManager.UpdateInterface(InterfaceInfo::InterfaceType::HML, readInterfaceInfo);
    EXPECT_EQ(hmlResult, SOFTBUS_OK);
    EXPECT_EQ(g_enabledFlag, true);

    interfaceManager.UpdateInterface(InterfaceInfo::InterfaceType::P2P, updateInterfaceInfoFalse);
    int p2pResult = interfaceManager.UpdateInterface(InterfaceInfo::InterfaceType::P2P, readInterfaceInfo);
    EXPECT_EQ(p2pResult, SOFTBUS_OK);
    EXPECT_EQ(g_enabledFlag, false);
}
} // namespace OHOS::SoftBus