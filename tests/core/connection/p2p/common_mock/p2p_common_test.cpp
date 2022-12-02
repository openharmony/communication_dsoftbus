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
#include <fstream>
#include <thread>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "p2plink_common.h"
#include "softbus_log.h"
#include "p2plink_type.h"
#include "adapter_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using testing::Return;

namespace OHOS {
class P2pCommonMockTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: P2pLinkSetRole001
* @tc.desc: test P2pLinkSetRole and P2pLinkGetRole
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetRole001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetRole001, Start");
    P2pLinkSetRole(ROLE_GO);
    P2pLinkRole p2pLinkRole = P2pLinkGetRole();
    EXPECT_EQ(p2pLinkRole, ROLE_GO);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetRole001, End");
}

/*
* @tc.name: P2pLinkCommonInit001
* @tc.desc: test P2pLinkCommonInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkCommonInit001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkCommonInit001, Start");
    P2pLinkSetRole(ROLE_GO);
    P2pLinkRole p2pLinkRole = P2pLinkGetRole();
    EXPECT_EQ(p2pLinkRole, ROLE_GO);
    P2pLinkCommonInit();
    p2pLinkRole = P2pLinkGetRole();
    EXPECT_EQ(p2pLinkRole, ROLE_NONE);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkCommonInit001, End");
}

/*
* @tc.name: P2pLinkCommonClean001
* @tc.desc: test P2pLinkCommonClean
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkCommonClean001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkCommonClean001, Start");
    P2pLinkSetRole(ROLE_GO);
    P2pLinkRole p2pLinkRole = P2pLinkGetRole();
    EXPECT_EQ(p2pLinkRole, ROLE_GO);
    P2pLinkCommonClean();
    p2pLinkRole = P2pLinkGetRole();
    EXPECT_EQ(p2pLinkRole, ROLE_NONE);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkCommonClean001, End");
}

/*
* @tc.name: P2pLinkSetMyMacExpired001
* @tc.desc: test P2pLinkSetMyMacExpired
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetMyMacExpired001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetMyMacExpired001, Start");
    AdapterMock adapterMock;
    adapterMock.SetupSuccessStub();
    bool isExpired = false;
    P2pLinkCommonClean();
    P2pLinkSetMyMacExpired(isExpired);
    char* myMac = P2pLinkGetMyMac();
    EXPECT_EQ(myMac[0], 0);

    isExpired = true;
    P2pLinkSetMyMacExpired(isExpired);
    myMac = P2pLinkGetMyMac();
    EXPECT_EQ(myMac[0], 't');

    EXPECT_CALL(adapterMock, P2pLinkGetBaseMacAddress).WillRepeatedly(Return(SOFTBUS_ERR));
    myMac = P2pLinkGetMyMac();
    EXPECT_EQ(myMac[0], 't');
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetMyMacExpired001, End");
}

/*
* @tc.name: P2pLinkSetMyIp001
* @tc.desc: test P2pLinkSetMyIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetMyIp001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetMyIp001, Start");
    AdapterMock adapterMock;
    adapterMock.SetupSuccessStub();
    char myIpTest[P2P_IP_LEN] = {0};
    P2pLinkSetMyIp(myIpTest);
    char *myIpTestRes = P2pLinkGetMyIp();
    EXPECT_EQ(myIpTestRes[0], myIpTest[0]);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetMyIp001, End");
}

/*
* @tc.name: P2pLinkSetGoIp001
* @tc.desc: test P2pLinkSetGoIp and P2pLinkGetGoIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetGoIp001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoIp001, Start");
    char goIpTest[P2P_IP_LEN] = {0};
    goIpTest[0] = 't';
    goIpTest[1] = '\0';
    P2pLinkCommonInit();
    P2pLinkSetGoIp(goIpTest);
    char* goIp = P2pLinkGetGoIp();
    EXPECT_EQ(goIp[0], goIpTest[0]);

    P2pLinkSetRole(ROLE_GO);
    char myIpTest[P2P_IP_LEN] = {0};
    P2pLinkSetMyIp(myIpTest);
    goIp = P2pLinkGetGoIp();
    EXPECT_EQ(goIp[0], myIpTest[0]);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoIp001, End");
}

/*
* @tc.name: P2pLinkSetGoMac001
* @tc.desc: test P2pLinkSetGoMac and P2pLinkGetGoMac
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetGoMac001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoMac001, Start");
    char goMacTest[P2P_MAC_LEN] = {0};
    goMacTest[0] = 't';
    goMacTest[1] = '\0';
    P2pLinkCommonInit();
    P2pLinkSetGoMac(goMacTest);
    char* goMac = P2pLinkGetGoMac();
    EXPECT_EQ(goMac[0], goMacTest[0]);

    P2pLinkCommonClean();
    P2pLinkSetRole(ROLE_GO);
    char myMacTest[P2P_MAC_LEN] = {0};
    bool isExpired = false;
    P2pLinkSetMyMacExpired(isExpired);
    goMac = P2pLinkGetGoMac();
    EXPECT_EQ(goMac[0], myMacTest[0]);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoMac001, End");
}

/*
* @tc.name: P2pLinkSetGoPort001
* @tc.desc: test P2pLinkSetGoPort and P2pLinkGetGoPort
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetGoPort001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoPort001, Start");
    int32_t portTest = 1;
    P2pLinkSetGoPort(portTest);
    int32_t port = P2pLinkGetGoPort();
    EXPECT_EQ(port, portTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGoPort001, End");
}

/*
* @tc.name: P2pLinkSetGcPort001
* @tc.desc: test P2pLinkSetGcPort and P2pLinkGetGcPort
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetGcPort001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGcPort001, Start");
    int32_t portTest = 1;
    P2pLinkSetGcPort(portTest);
    int32_t port = P2pLinkGetGcPort();
    EXPECT_EQ(port, portTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetGcPort001, End");
}

/*
* @tc.name: P2pLinkSetState001
* @tc.desc: test P2pLinkSetState and P2pLinkIsEnable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetState001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetState001, Start");
    bool stateTest = true;
    P2pLinkSetState(stateTest);
    bool state = P2pLinkIsEnable();
    EXPECT_EQ(state, stateTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetState001, End");
}

/*
* @tc.name: P2pLinkSetDhcpState001
* @tc.desc: test P2pLinkSetDhcpState and P2pLinkGetDhcpState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetDhcpState001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetDhcpState001, Start");
    bool isNeedDhcpTest = true;
    P2pLinkSetDhcpState(isNeedDhcpTest);
    bool isNeedDhcp = P2pLinkGetDhcpState();
    EXPECT_EQ(isNeedDhcp, isNeedDhcpTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkGetDhcpState001, End");
}

/*
* @tc.name: P2pLinkSetDisconnectState001
* @tc.desc: test P2pLinkSetDisconnectState and P2pLinkIsDisconnectState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pCommonMockTest, P2pLinkSetDisconnectState001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetDisconnectState001, Start");
    bool stateTest = true;
    P2pLinkSetDisconnectState(stateTest);
    bool state = P2pLinkIsDisconnectState();
    EXPECT_EQ(state, stateTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pCommonMockTest, P2pLinkSetDisconnectState001, End");
}
};