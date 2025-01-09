/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ble_protocol_interface_factory.h"
#include "softbus_conn_ble_manager_mock.h"
#include "softbus_adapter_ble_conflict.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_snapshot.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static ConnectFuncInterface *g_bleInterface = NULL;
#define SLEEP_TIME_MS 1000

void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
}

void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

extern "C" {
int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener)
{
    return SOFTBUS_OK;
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return SOFTBUS_OK;
}

void SoftbusBleConflictNotifyDateReceive(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)underlayerHandle;
    (void)data;
    (void)dataLen;
}

void SoftbusBleConflictNotifyDisconnect(const char *addr, const char *udid)
{
    (void)addr;
    (void)udid;
}

void SoftbusBleConflictNotifyConnectResult(uint32_t requestId, int32_t underlayerHandle, bool status)
{
    (void)requestId;
    (void)underlayerHandle;
    (void)status;
}

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener) { }
}

class SoftbusConnBleHiDumperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase();
    void SetUp() override
    {
        ConnectCallback connectCb = { 0 };
        connectCb.OnConnected = OnConnected;
        connectCb.OnReusedConnected = OnReusedConnected;
        connectCb.OnDisconnected = OnDisconnected;
        connectCb.OnDataReceived = OnDataReceived;

        LooperInit();
        SoftbusConfigInit();

        NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
        EXPECT_CALL(bleMock, ConnGattInitClientModule).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, ConnGattInitServerModule).WillRepeatedly(Return(SOFTBUS_OK));

        g_bleInterface = ConnInitBle(&connectCb);
    }
    void TearDown() override
    {
        LooperDeinit();
    }
};

void SoftbusConnBleHiDumperTest::TearDownTestCase()
{
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: BleHiDumperTest
 * @tc.desc: test dump method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusConnBleHiDumperTest, BleHiDumperTest, TestSize.Level1)
{
    const char *addr1 = "11:22:33:44:55:66";
    const char *addr2 = "22:33:44:55:66:77";

    ConnBleConnection *connection1 =
        ConnBleCreateConnection(addr1, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection1, NULL);

    ConnBleConnection *connection2 =
        ConnBleCreateConnection(addr2, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection2, NULL);

    auto ret = ConnBleSaveConnection(connection1);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = ConnBleSaveConnection(connection2);
    ASSERT_EQ(SOFTBUS_OK, ret);
    int fd = 1;
    ret = BleHiDumper(fd);
    ASSERT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS