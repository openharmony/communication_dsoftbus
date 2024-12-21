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
#include "gtest/gtest.h"
#include <securec.h>

#include "bus_center_event.h"
#include "lnn_bt_monitor.c"
#include "lnn_event_monitor_impl.h"
#include "lnn_netlink_monitor.c"
#include "network_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
#define TEST_LEN          5
#define TEST_LEN2         65
#define TEST_LISTENER_ID  20
#define TEST_LISTENER_ID2 (-1)
#define TEST_STATE1       1
#define TEST_STATE2       3
#define TEST_STATE3       5
#define TEST_STATE4       7
#define TEST_ACL_STATE    0
#define TEST_ACL_STATE2   1
using namespace testing::ext;
using namespace testing;
class AdapterDsoftbusNetworkTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdapterDsoftbusNetworkTest::SetUpTestCase(void) { }
void AdapterDsoftbusNetworkTest::TearDownTestCase(void) { }
void AdapterDsoftbusNetworkTest::SetUp() { }
void AdapterDsoftbusNetworkTest::TearDown() { }

/*
 * @tc.name: CreateNetlinkSocket
 * @tc.desc: softbus network test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusNetworkTest, CreateNetlinkSocketTest001, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> networkMock;
    ON_CALL(networkMock, SoftBusSocketCreate).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketSetOpt).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketClose).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketBind).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = CreateNetlinkSocket();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(networkMock, SoftBusSocketCreate)
        .WillOnce(Return(SOFTBUS_ADAPTER_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = CreateNetlinkSocket();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CREATE_SOCKET_FAILED);
    EXPECT_CALL(networkMock, SoftBusSocketSetOpt)
        .WillOnce(Return(SOFTBUS_ADAPTER_ERR))
        .WillOnce(Return(SOFTBUS_ADAPTER_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = CreateNetlinkSocket();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_SET_SOCKET_OPTION_FAILED);
    EXPECT_CALL(networkMock, SoftBusSocketBind)
        .WillOnce(Return(SOFTBUS_ADAPTER_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = CreateNetlinkSocket();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_BIND_SOCKET_FAILED);
}

/*
 * @tc.name: ProcessAddrEvent
 * @tc.desc: softbus network test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusNetworkTest, ProcessAddrEventTest001, TestSize.Level1)
{
    nlmsghdr nlh1 = {
        .nlmsg_len = TEST_LEN,
    };
    NiceMock<NetworkInterfaceMock> networkMock;
    ON_CALL(networkMock, LnnGetNetIfTypeByName).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketCreate).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketSetOpt).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketClose).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketBind).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusSocketRecv).WillByDefault(Return(TEST_LISTENER_ID2));
    ProcessAddrEvent(&nlh1);
    nlmsghdr nlh2 = {
        .nlmsg_len = TEST_LEN2,
    };
    ProcessAddrEvent(&nlh2);
    EXPECT_TRUE(NetlinkOnConnectEvent(NETLINK, -1, nullptr) == SOFTBUS_OK);
    EXPECT_TRUE(NetlinkOnDataEvent(NETLINK, SOFTBUS_SOCKET_OUT, -1) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(networkMock, SoftBusSocketRecv).WillOnce(Return(TEST_LEN)).WillRepeatedly(Return(TEST_LISTENER_ID2));
    EXPECT_TRUE(NetlinkOnDataEvent(NETLINK, SOFTBUS_SOCKET_IN, 0) == SOFTBUS_SOCKET_EXCEPTION);
}

/*
 * @tc.name: LnnOnBtStateChanged
 * @tc.desc: softbus network test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusNetworkTest, LnnOnBtStateChangedTest001, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> networkMock;
    ON_CALL(networkMock, LnnAsyncCallbackHelper).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(networkMock, SoftBusAddBtStateListener).WillByDefault(Return(TEST_LISTENER_ID));

    int32_t listenerId = TEST_LISTENER_ID;
    int32_t state = TEST_STATE1;
    SoftBusBtAddr addr;
    int32_t aclState = TEST_ACL_STATE;
    LnnOnBtStateChanged(listenerId, state);
    state = TEST_STATE2;
    LnnOnBtStateChanged(listenerId, state);
    state = TEST_STATE3;
    LnnOnBtStateChanged(listenerId, state);
    state = TEST_STATE4;
    LnnOnBtStateChanged(listenerId, state);
    EXPECT_CALL(networkMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LnnOnBtStateChanged(listenerId, state);
    LnnOnBtAclStateChanged(listenerId, &addr, aclState, 0);
    aclState = TEST_ACL_STATE2;
    LnnOnBtAclStateChanged(listenerId, &addr, aclState, 0);
    aclState = TEST_STATE1;
    LnnOnBtAclStateChanged(listenerId, &addr, aclState, 0);
    int32_t ret = LnnInitBtStateMonitorImpl();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(networkMock, SoftBusAddBtStateListener).WillRepeatedly(Return(TEST_LISTENER_ID2));
    ret = LnnInitBtStateMonitorImpl();
    EXPECT_TRUE(ret == SOFTBUS_COMM_BLUETOOTH_ADD_STATE_LISTENER_ERR);
}
} // namespace OHOS