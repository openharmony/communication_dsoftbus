/*
* Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "bus_center_client_proxy_standard.h"
#include "bus_center_client_proxy.h"
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
#include "softbus_client_info_manager.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "message_parcel.h"
#include "softbus_permission.h"
#include "lnn_bus_center_ipc.h"

namespace OHOS {
using namespace testing::ext;
    static sptr<BusCenterClientProxy> GetClientProxy(const char *pkgName)
    {
        sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName);
        sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(clientObject);
        return clientProxy;
    }
    
    class BusCenterClientProxyStandardTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void BusCenterClientProxyStandardTest::SetUpTestCase()
    {
    }

    void BusCenterClientProxyStandardTest::TearDownTestCase()
    {
    }

    void BusCenterClientProxyStandardTest::SetUp()
    {
    }

    void BusCenterClientProxyStandardTest::TearDown()
    {
    }

    /*
    * @tc.name: ON_JOIN_META_NODE_RESULT_Test_001
    * @tc.desc: On Join Meta Node Result test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(BusCenterClientProxyStandardTest, ON_JOIN_META_NODE_RESULT_Test_001, TestSize.Level0)
    {
        void *addr = nullptr;
        uint32_t addrTypeLen = 0;
        ConnectionAddr addrValue;
        (void)memset_s(&addrValue, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
        char *networkId = nullptr;
        char networkIdValue[] = "12345";
        int32_t retCode = 0;
        char pkgNameValue[] = "test";
        sptr<BusCenterClientProxy> clientProxy =  GetClientProxy(pkgNameValue);
        int32_t ret = clientProxy->BusCenterClientProxy::OnJoinMetaNodeResult(addr, addrTypeLen, networkId, retCode);
        EXPECT_EQ(ret, SOFTBUS_ERR);
        retCode = 1;
        ret = clientProxy->BusCenterClientProxy::OnJoinMetaNodeResult(addr, addrTypeLen, networkIdValue, retCode);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
        ret = clientProxy->BusCenterClientProxy::OnJoinMetaNodeResult(&addrValue, addrTypeLen, networkIdValue, retCode);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
    }

    /*
    * @tc.name: ON_LEAVE_META_NODE_RESULT_Test_001
    * @tc.desc: On Leave Meta Node Result test
    * @tc.type: FUNC
    * @tc.require:
    */
    HWTEST_F(BusCenterClientProxyStandardTest, ON_LEAVE_META_NODE_RESULT_Test_001, TestSize.Level0)
    {
        char *networkId = nullptr;
        char pkgNameValue[] = "test";
        char networkIdValue[] = "12345";
        int32_t retCode = 0;
        sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgNameValue);
        int32_t ret = clientProxy->BusCenterClientProxy::OnLeaveMetaNodeResult(networkId, retCode);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
        ret = clientProxy->BusCenterClientProxy::OnLeaveMetaNodeResult(networkIdValue, retCode);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
    }
} // namespace OHOS
