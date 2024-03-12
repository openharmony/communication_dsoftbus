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

#include "securec.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <gtest/gtest.h>

#include "link_manager.h"
#include "softbus_error_code.h"
#include "softbus_hidumper_conn.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_role_option.h"
#include "command/wifi_direct_connect_command.h"
#include "command/wifi_direct_disconnect_command.h"
#include "command/wifi_direct_command_manager.h"
#include "conn_log.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_perf_recorder.h"
#include "utils/wifi_direct_anonymous.h"
#include "conn_event.h"
#include "wifi_direct_statistic.h"
#include "wifi_direct_manager.h"


using namespace testing::ext;

namespace OHOS {

class WifiDirectManagerTest : public testing::Test {
public:
    WifiDirectManagerTest()
    {}
    ~WifiDirectManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectManagerTest::SetUpTestCase(void)
{}

void WifiDirectManagerTest::TearDownTestCase(void)
{}

void WifiDirectManagerTest::SetUp(void)
{}

void WifiDirectManagerTest::TearDown(void)
{}

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test GetRemoteUuidByIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectManagerTest, WifiDirectManager001, TestSize.Level1)
{
    struct WifiDirectManager* manager = GetWifiDirectManager();
    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    struct WifiDirectConnectCallback callback;
    (void)memset_s(&callback, sizeof(callback), 0, sizeof(callback));
    int32_t ret = manager->connectDevice(&connectInfo, &callback);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    std::string networkId = "abcdefghijk";
    strcpy_s(connectInfo.remoteNetworkId, sizeof(connectInfo.remoteNetworkId), networkId.c_str());
    ret = manager->connectDevice(&connectInfo, &callback);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    ret = manager->connectDevice(&connectInfo, &callback);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    ret = manager->connectDevice(&connectInfo, &callback);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    connectInfo.connectType = static_cast<enum WifiDirectConnectType>(4);
    ret = manager->connectDevice(&connectInfo, &callback);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test GetInterfaceNameByLocalIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectManagerTest, WifiDirectManager002, TestSize.Level1)
{
    struct WifiDirectManager* manager = GetWifiDirectManager();

    const char *loaclIp = "130.30.0.1";
    std::string interfaceName = "p2p";
    size_t interfaceNameSize = interfaceName.size();
    int32_t ret = manager->getInterfaceNameByLocalIp(nullptr, (char*)interfaceName.c_str(), interfaceNameSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = manager->getInterfaceNameByLocalIp(loaclIp, (char*)interfaceName.c_str(), interfaceNameSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test GetLocalAndRemoteMacByLocalIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectManagerTest, WifiDirectManager003, TestSize.Level1)
{
    struct WifiDirectManager* manager = GetWifiDirectManager();

    const char *loaclIp = "130.30.0.1";
    std::string localMac = "0A:1B:2C:3D:4E";
    size_t localMacSize = localMac.size();
    std::string remoteMac = "AVADACAWAFADABAN";
    size_t remoteMacSize = remoteMac.size();
    int32_t ret = manager->getLocalAndRemoteMacByLocalIp(nullptr, (char*)localMac.c_str(),
        localMacSize, (char*)remoteMac.c_str(), remoteMacSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = manager->getLocalAndRemoteMacByLocalIp(loaclIp, (char*)localMac.c_str(),
        localMacSize, (char*)remoteMac.c_str(), remoteMacSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};
}