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
#include <cstring>
#include <mutex>
#include <vector>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_network_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor.h"
#include "lnn_local_net_ledger.h"
#include "lnn_sync_item_info.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "lnn_ipc_utils.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "lnn_bus_center_ipc.h"

namespace OHOS {
using namespace testing::ext;
    constexpr uint8_t DEFAULT_LEN = 32;
    constexpr uint8_t DEFAULT_SIZE = 5;

    class LnnBusCenterIpcTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void LnnBusCenterIpcTest::SetUpTestCase()
    {
    }

    void LnnBusCenterIpcTest::TearDownTestCase()
    {
    }

    void LnnBusCenterIpcTest::SetUp()
    {
    }

    void LnnBusCenterIpcTest::TearDown()
    {
    }

    /*
    * @tc.name: META_NODE_IPC_SERVER_JOIN_Test_001
    * @tc.desc: Meta Node Ipc Server Join test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(LnnBusCenterIpcTest, META_NODE_IPC_SERVER_JOIN_Test_001, TestSize.Level0)
    {
        char *pkgName = nullptr;
        void *addr = nullptr;
        CustomData customData;
        memcpy_s(customData.data, sizeof(CustomData), "test", DEFAULT_SIZE);
        uint32_t addrTypeLen = 0;
        ConnectionAddr addrValue;
        (void)memset_s(&addrValue, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
        char pkgNameValue[DEFAULT_LEN] = "test";
        int32_t ret = MetaNodeIpcServerJoin(pkgName, addr, &customData, addrTypeLen);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
        ret = MetaNodeIpcServerJoin(pkgNameValue, (void *)&addrValue, &customData, addrTypeLen);
        EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    }

    /*
    * @tc.name: META_NODE_IPC_SERVER_LEAVE_Test_001
    * @tc.desc: Meta Node Ipc Server Leave test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(LnnBusCenterIpcTest, META_NODE_IPC_SERVER_LEAVE_Test_001, TestSize.Level0)
    {
        char *pkgName = nullptr;
        char *networkId = nullptr;
        char pkgNameValue[DEFAULT_LEN] = "test";
        char networkIdValue[DEFAULT_LEN] = "12345";
        int32_t ret = MetaNodeIpcServerLeave(pkgName, networkId);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
        ret = MetaNodeIpcServerLeave(pkgNameValue, networkId);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
        ret = MetaNodeIpcServerLeave(pkgNameValue, networkIdValue);
        EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    }

    /*
    * @tc.name: META_NODE_IPC_NOTIFY_JOIN_RESULT_Test_001
    * @tc.desc: Meta Node Ipc Notify Join Result test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(LnnBusCenterIpcTest, META_NODE_IPC_NOTIFY_JOIN_RESULT_Test_001, TestSize.Level0)
    {
        void *addr = nullptr;
        uint32_t addrTypeLen = 0;
        ConnectionAddr addrValue;
        (void)memset_s(&addrValue, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
        char *networkId = nullptr;
        char networkIdValue[DEFAULT_LEN] = "1234";
        int32_t retCode = 0;
        CustomData customData;
        memcpy_s(customData.data, sizeof(CustomData), "test", DEFAULT_SIZE);
        int32_t ret = MetaNodeIpcNotifyJoinResult(addr, addrTypeLen, networkId, retCode);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
        ret = MetaNodeIpcNotifyJoinResult((void *)&addrValue, addrTypeLen, networkIdValue, retCode);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }

    /*
    * @tc.name: META_NODE_IPC_NOTIFY_LEAVE_RESULT_Test_001
    * @tc.desc: Meta Node Ipc Notify Leave Result test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(LnnBusCenterIpcTest, META_NODE_IPC_NOTIFY_LEAVE_RESULT_Test_001, TestSize.Level0)
    {
        char *networkId = nullptr;
        char networkIdValue[DEFAULT_LEN] = "12345";
        int32_t retCode = 0;
        int32_t ret = MetaNodeIpcNotifyLeaveResult(networkId, retCode);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
        ret = MetaNodeIpcNotifyLeaveResult(networkIdValue, retCode);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
} // namespace OHOS
