/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_snapshot.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

class BleSnapshotTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

static void InitBleConnection(ConnBleConnection *conn, uint32_t connectionId, ConnSideType side,
    const char *addr, enum ConnBleConnectionState state, uint32_t mtu, int32_t connectionRc)
{
    (void)memset_s(conn, sizeof(ConnBleConnection), 0, sizeof(ConnBleConnection));
    ListInit(&conn->node);
    conn->connectionId = connectionId;
    conn->side = side;
    conn->state = state;
    conn->mtu = mtu;
    conn->connectionRc = connectionRc;
    if (addr != nullptr) {
        (void)memcpy_s(conn->addr, BT_MAC_LEN, addr, strlen(addr) + 1);
    }
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_001
* @tc.desc: Test ConnBleCreateConnectionSnapshot creates snapshot with correct fields
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_001, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 1, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionId, 1u);
    EXPECT_EQ(snapshot->side, CONN_SIDE_CLIENT);
    EXPECT_EQ(snapshot->state, BLE_CONNECTION_STATE_CONNECTED);
    EXPECT_EQ(snapshot->mtu, 512u);
    EXPECT_EQ(snapshot->connectionRc, 1);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_002
* @tc.desc: Test ConnBleCreateConnectionSnapshot with server side
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_002, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 2, CONN_SIDE_SERVER, "11:22:33:44:55:66",
        BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO, 256, 3);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionId, 2u);
    EXPECT_EQ(snapshot->side, CONN_SIDE_SERVER);
    EXPECT_EQ(snapshot->state, BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO);
    EXPECT_EQ(snapshot->mtu, 256u);
    EXPECT_EQ(snapshot->connectionRc, 3);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_003
* @tc.desc: Test ConnBleCreateConnectionSnapshot with zero connectionId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_003, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 0, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTING, 0, 0);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionId, 0u);
    EXPECT_EQ(snapshot->connectionRc, 0);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_004
* @tc.desc: Test ConnBleCreateConnectionSnapshot with max mtu
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_004, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 100, CONN_SIDE_CLIENT, "FF:EE:DD:CC:BB:AA",
        BLE_CONNECTION_STATE_MTU_SETTED, UINT32_MAX, INT32_MAX);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionId, 100u);
    EXPECT_EQ(snapshot->mtu, UINT32_MAX);
    EXPECT_EQ(snapshot->connectionRc, INT32_MAX);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_005
* @tc.desc: Test ConnBleCreateConnectionSnapshot with negative connectionRc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_005, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 50, CONN_SIDE_SERVER, "11:22:33:44:55:66",
        BLE_CONNECTION_STATE_CLOSING, 512, -5);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionRc, -5);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_006
* @tc.desc: Test ConnBleCreateConnectionSnapshot with empty addr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_006, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 10, CONN_SIDE_CLIENT, "",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->connectionId, 10u);

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_CREATE_SNAPSHOT_007
* @tc.desc: Test ConnBleCreateConnectionSnapshot with various states
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_CREATE_SNAPSHOT_007, TestSize.Level1)
{
    enum ConnBleConnectionState states[] = {
        BLE_CONNECTION_STATE_CONNECTING,
        BLE_CONNECTION_STATE_CONNECTED,
        BLE_CONNECTION_STATE_SERVICE_SEARCHING,
        BLE_CONNECTION_STATE_SERVICE_SEARCHED,
        BLE_CONNECTION_STATE_CONN_NOTIFICATING,
        BLE_CONNECTION_STATE_CONN_NOTIFICATED,
        BLE_CONNECTION_STATE_NET_NOTIFICATING,
        BLE_CONNECTION_STATE_NET_NOTIFICATED,
        BLE_CONNECTION_STATE_MTU_SETTING,
        BLE_CONNECTION_STATE_MTU_SETTED,
        BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO,
        BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO,
        BLE_CONNECTION_STATE_NEGOTIATION_CLOSING,
        BLE_CONNECTION_STATE_CLOSING,
        BLE_CONNECTION_STATE_CLOSED,
    };

    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
        ConnBleConnection conn;
        InitBleConnection(&conn, static_cast<uint32_t>(i + 1), CONN_SIDE_CLIENT,
            "AA:BB:CC:DD:EE:FF", states[i], 512, 1);

        ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
        ASSERT_NE(snapshot, nullptr);
        EXPECT_EQ(snapshot->state, states[i]);
        ConnBleDestroyConnectionSnapshot(snapshot);
    }
}

/*
* @tc.name: CONN_BLE_DESTROY_SNAPSHOT_001
* @tc.desc: Test ConnBleDestroyConnectionSnapshot with null does not crash
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_DESTROY_SNAPSHOT_001, TestSize.Level1)
{
    ConnBleDestroyConnectionSnapshot(nullptr);
}

/*
* @tc.name: CONN_BLE_DESTROY_SNAPSHOT_002
* @tc.desc: Test ConnBleDestroyConnectionSnapshot with valid snapshot
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_DESTROY_SNAPSHOT_002, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 1, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_LIST_001
* @tc.desc: Test multiple snapshots in a list
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_LIST_001, TestSize.Level1)
{
    ListNode snapshots;
    ListInit(&snapshots);

    ConnBleConnection conn1;
    InitBleConnection(&conn1, 1, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);
    ConnBleConnection conn2;
    InitBleConnection(&conn2, 2, CONN_SIDE_SERVER, "11:22:33:44:55:66",
        BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO, 256, 3);

    ConnBleConnectionSnapshot *snapshot1 = ConnBleCreateConnectionSnapshot(&conn1);
    ASSERT_NE(snapshot1, nullptr);
    ConnBleConnectionSnapshot *snapshot2 = ConnBleCreateConnectionSnapshot(&conn2);
    ASSERT_NE(snapshot2, nullptr);

    ListAdd(&snapshots, &snapshot1->node);
    ListAdd(&snapshots, &snapshot2->node);

    int count = 0;
    ConnBleConnectionSnapshot *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &snapshots, ConnBleConnectionSnapshot, node) {
        count++;
    }
    EXPECT_EQ(count, 2);

    ConnBleConnectionSnapshot *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &snapshots, ConnBleConnectionSnapshot, node) {
        ListDelete(&it->node);
        ConnBleDestroyConnectionSnapshot(it);
    }
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_LIST_002
* @tc.desc: Test empty snapshot list
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_LIST_002, TestSize.Level1)
{
    ListNode snapshots;
    ListInit(&snapshots);

    int count = 0;
    ConnBleConnectionSnapshot *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &snapshots, ConnBleConnectionSnapshot, node) {
        count++;
    }
    EXPECT_EQ(count, 0);
}

static int32_t g_bleDumperRetVal = SOFTBUS_OK;
static int g_bleDumperCallCount = 0;

extern "C" int32_t ConnBleDumper(ListNode *connectionSnapshots)
{
    g_bleDumperCallCount++;
    if (g_bleDumperRetVal != SOFTBUS_OK) {
        return g_bleDumperRetVal;
    }
    return SOFTBUS_OK;
}

class BleHiDumperTest : public testing::Test {
public:
    void SetUp() override
    {
        g_bleDumperRetVal = SOFTBUS_OK;
        g_bleDumperCallCount = 0;
    }
    void TearDown() override {}
};

/*
* @tc.name: CONN_BLE_HI_DUMPER_001
* @tc.desc: Test BleHiDumper with valid fd
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleHiDumperTest, CONN_BLE_HI_DUMPER_001, TestSize.Level1)
{
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        GTEST_SKIP() << "Cannot open /dev/null";
    }
    int32_t ret = BleHiDumper(fd);
    close(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_bleDumperCallCount, 1);
}

/*
* @tc.name: CONN_BLE_HI_DUMPER_002
* @tc.desc: Test BleHiDumper when ConnBleDumper returns error
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleHiDumperTest, CONN_BLE_HI_DUMPER_002, TestSize.Level1)
{
    g_bleDumperRetVal = SOFTBUS_CONN_BLE_INTERNAL_ERR;
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        GTEST_SKIP() << "Cannot open /dev/null";
    }
    int32_t ret = BleHiDumper(fd);
    close(fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_EQ(g_bleDumperCallCount, 1);
}

/*
* @tc.name: CONN_BLE_HI_DUMPER_003
* @tc.desc: Test BleHiDumper with snapshots from ConnBleDumper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleHiDumperTest, CONN_BLE_HI_DUMPER_003, TestSize.Level1)
{
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        GTEST_SKIP() << "Cannot open /dev/null";
    }
    int32_t ret = BleHiDumper(fd);
    close(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_HI_DUMPER_004
* @tc.desc: Test BleHiDumper multiple calls
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleHiDumperTest, CONN_BLE_HI_DUMPER_004, TestSize.Level1)
{
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        GTEST_SKIP() << "Cannot open /dev/null";
    }
    for (int i = 0; i < 5; i++) {
        int32_t ret = BleHiDumper(fd);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    close(fd);
    EXPECT_EQ(g_bleDumperCallCount, 5);
}

/*
* @tc.name: CONN_BLE_HI_DUMPER_005
* @tc.desc: Test BleHiDumper with different error codes
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleHiDumperTest, CONN_BLE_HI_DUMPER_005, TestSize.Level1)
{
    int32_t errorCodes[] = {
        SOFTBUS_INVALID_PARAM,
        SOFTBUS_MALLOC_ERR,
        SOFTBUS_NOT_FIND,
    };
    for (size_t i = 0; i < sizeof(errorCodes) / sizeof(errorCodes[0]); i++) {
        g_bleDumperRetVal = errorCodes[i];
        g_bleDumperCallCount = 0;
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) {
            continue;
        }
        int32_t ret = BleHiDumper(fd);
        close(fd);
        EXPECT_NE(ret, SOFTBUS_OK);
        EXPECT_EQ(g_bleDumperCallCount, 1);
    }
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_ADDR_001
* @tc.desc: Test snapshot address is anonymized
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_ADDR_001, TestSize.Level1)
{
    ConnBleConnection conn;
    InitBleConnection(&conn, 1, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);

    ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_NE(snapshot->addr[0], '\0');
    EXPECT_STRNE(snapshot->addr, "AA:BB:CC:DD:EE:FF");

    ConnBleDestroyConnectionSnapshot(snapshot);
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_ADDR_002
* @tc.desc: Test snapshot address with different MAC addresses
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_ADDR_002, TestSize.Level1)
{
    const char *addrs[] = {
        "11:22:33:44:55:66",
        "AA:BB:CC:DD:EE:FF",
        "FF:EE:DD:CC:BB:AA",
    };

    for (size_t i = 0; i < sizeof(addrs) / sizeof(addrs[0]); i++) {
        ConnBleConnection conn;
        InitBleConnection(&conn, static_cast<uint32_t>(i + 1), CONN_SIDE_CLIENT,
            addrs[i], BLE_CONNECTION_STATE_CONNECTED, 512, 1);

        ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
        ASSERT_NE(snapshot, nullptr);
        EXPECT_NE(snapshot->addr[0], '\0');
        ConnBleDestroyConnectionSnapshot(snapshot);
    }
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_MTU_001
* @tc.desc: Test snapshot with various MTU values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_MTU_001, TestSize.Level1)
{
    uint32_t mtuValues[] = {0, 23, 100, 256, 512, 1024, 2048, UINT32_MAX};

    for (size_t i = 0; i < sizeof(mtuValues) / sizeof(mtuValues[0]); i++) {
        ConnBleConnection conn;
        InitBleConnection(&conn, static_cast<uint32_t>(i + 1), CONN_SIDE_CLIENT,
            "AA:BB:CC:DD:EE:FF", BLE_CONNECTION_STATE_CONNECTED, mtuValues[i], 1);

        ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
        ASSERT_NE(snapshot, nullptr);
        EXPECT_EQ(snapshot->mtu, mtuValues[i]);
        ConnBleDestroyConnectionSnapshot(snapshot);
    }
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_RC_001
* @tc.desc: Test snapshot with various connectionRc values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_RC_001, TestSize.Level1)
{
    int32_t rcValues[] = {INT32_MIN, -100, -1, 0, 1, 10, 100, INT32_MAX};

    for (size_t i = 0; i < sizeof(rcValues) / sizeof(rcValues[0]); i++) {
        ConnBleConnection conn;
        InitBleConnection(&conn, static_cast<uint32_t>(i + 1), CONN_SIDE_CLIENT,
            "AA:BB:CC:DD:EE:FF", BLE_CONNECTION_STATE_CONNECTED, 512, rcValues[i]);

        ConnBleConnectionSnapshot *snapshot = ConnBleCreateConnectionSnapshot(&conn);
        ASSERT_NE(snapshot, nullptr);
        EXPECT_EQ(snapshot->connectionRc, rcValues[i]);
        ConnBleDestroyConnectionSnapshot(snapshot);
    }
}

/*
* @tc.name: CONN_BLE_SNAPSHOT_SIDE_001
* @tc.desc: Test snapshot with both client and server sides
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleSnapshotTest, CONN_BLE_SNAPSHOT_SIDE_001, TestSize.Level1)
{
    ConnBleConnection clientConn;
    InitBleConnection(&clientConn, 1, CONN_SIDE_CLIENT, "AA:BB:CC:DD:EE:FF",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);
    ConnBleConnection serverConn;
    InitBleConnection(&serverConn, 2, CONN_SIDE_SERVER, "11:22:33:44:55:66",
        BLE_CONNECTION_STATE_CONNECTED, 512, 1);

    ConnBleConnectionSnapshot *clientSnapshot = ConnBleCreateConnectionSnapshot(&clientConn);
    ASSERT_NE(clientSnapshot, nullptr);
    ConnBleConnectionSnapshot *serverSnapshot = ConnBleCreateConnectionSnapshot(&serverConn);
    ASSERT_NE(serverSnapshot, nullptr);

    EXPECT_EQ(clientSnapshot->side, CONN_SIDE_CLIENT);
    EXPECT_EQ(serverSnapshot->side, CONN_SIDE_SERVER);

    ConnBleDestroyConnectionSnapshot(clientSnapshot);
    ConnBleDestroyConnectionSnapshot(serverSnapshot);
}

} // namespace OHOS
