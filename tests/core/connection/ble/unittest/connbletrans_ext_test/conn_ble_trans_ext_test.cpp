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

#include <cstdio>
#include <cstring>
#include "conn_log.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "softbus_error_code.h"
#include "softbus_conn_ble_trans.h"
#include "conn_ble_trans_mock.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_adapter_mem.h"
#include <arpa/inet.h>

using namespace testing::ext;
using namespace testing;

static ConnBleTransEventListener g_extTransEventListener = { 0 };
static const size_t BLE_TRANS_HEADER_SIZE = sizeof(BleTransHeader);

void ExtOnPostBytesFinished(
    uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error)
{
    (void)connectionId;
    (void)len;
    (void)pid;
    (void)flag;
    (void)module;
    (void)seq;
    (void)error;
}

extern "C" {
void ConnBleReturnConnection(ConnBleConnection **connection)
{
    (void)connection;
}

void cJSON_Delete(cJSON *json)
{
    (void)json;
}

void cJSON_free(void *object)
{
    (void)object;
}

void ConnBleRefreshIdleTimeout(ConnBleConnection *connection)
{
    (void)connection;
}

void PackConnPktHead(ConnPktHead *head)
{
    (void)head;
}

void UnpackConnPktHead(ConnPktHead *head)
{
    (void)head;
}
}

namespace OHOS {
class ConnBleTransExtTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void ConnBleTransExtTest::SetUpTestCase()
{
    LooperInit();
    g_extTransEventListener.onPostBytesFinished = ExtOnPostBytesFinished;
    int32_t ret = ConnBleInitTransModule(&g_extTransEventListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ConnBleTransExtTest::TearDownTestCase()
{
    LooperDeinit();
}

/*
 * @tc.name: ConnGattTransRecv026
 * @tc.desc: Test ConnGattTransRecv complete packet with buffer having pending same seq data
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv026, TestSize.Level1)
{
    uint32_t connectionId = 13;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(8);
    header.offset = htonl(0);
    header.total = htonl(8);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 8, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(8, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv027
 * @tc.desc: Test ConnGattTransRecv second segment arriving first mis-order
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv027, TestSize.Level1)
{
    uint32_t connectionId = 14;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(200);
    header.size = htonl(5);
    header.offset = htonl(5);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv028
 * @tc.desc: Test ConnGattTransRecv 3-segment with middle arriving first
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv028, TestSize.Level1)
{
    uint32_t connectionId = 15;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(300);
    header.size = htonl(5);
    header.offset = htonl(5);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv029
 * @tc.desc: Test ConnGattTransRecv duplicate segment after first segment
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv029, TestSize.Level1)
{
    uint32_t connectionId = 16;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(400);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv030
 * @tc.desc: Test ConnGattTransRecv different total in buffer for same seq
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv030, TestSize.Level1)
{
    uint32_t connectionId = 17;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 500;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(500);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv031
 * @tc.desc: Test ConnGattTransRecv 2-segment unequal sizes 8+2
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv031, TestSize.Level1)
{
    uint32_t connectionId = 18;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(600);
    header.size = htonl(8);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 8, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(2);
    header.offset = htonl(8);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv032
 * @tc.desc: Test ConnGattTransRecv gap in offset non-continuous
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv032, TestSize.Level1)
{
    uint32_t connectionId = 19;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(700);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(20);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(10);
    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv033
 * @tc.desc: Test ConnGattTransRecv complete packet size=2
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv033, TestSize.Level1)
{
    uint32_t connectionId = 20;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(800);
    header.size = htonl(2);
    header.offset = htonl(0);
    header.total = htonl(2);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(2, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv034
 * @tc.desc: Test ConnGattTransRecv 6-segment reassembly
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv034, TestSize.Level1)
{
    uint32_t connectionId = 21;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(900);
    header.size = htonl(2);
    header.offset = htonl(0);
    header.total = htonl(12);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = nullptr;
    for (int i = 0; i < 5; i++) {
        header.offset = htonl(i * 2);
        result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
        EXPECT_EQ(nullptr, result);
    }

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(12, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv035
 * @tc.desc: Test ConnGattTransRecv buffer having received=0 but seq!=0
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv035, TestSize.Level1)
{
    uint32_t connectionId = 22;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    buffer.received = 0;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv036
 * @tc.desc: Test ConnGattTransRecv 2-segment reassembly first segment large
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv036, TestSize.Level1)
{
    uint32_t connectionId = 23;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1000);
    header.size = htonl(30);
    header.offset = htonl(0);
    header.total = htonl(35);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 30, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(5);
    header.offset = htonl(30);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(35, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv037
 * @tc.desc: Test ConnGattTransRecv new incomplete packet after buffer discard
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv037, TestSize.Level1)
{
    uint32_t connectionId = 24;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(200);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv038
 * @tc.desc: Test ConnGattTransRecv 4-segment mis-order arriving 4,2,1,3
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv038, TestSize.Level1)
{
    uint32_t connectionId = 25;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1100);
    header.size = htonl(3);
    header.offset = htonl(9);
    header.total = htonl(12);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(3);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(6);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(12, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv039
 * @tc.desc: Test ConnGattTransRecv 2-segment with duplicate of second
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv039, TestSize.Level1)
{
    uint32_t connectionId = 26;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1200);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv040
 * @tc.desc: Test ConnGattTransRecv complete packet after partial reassembly
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv040, TestSize.Level1)
{
    uint32_t connectionId = 27;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1300);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(20);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.seq = htonl(1400);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv041
 * @tc.desc: Test ConnGattTransRecv 2-segment second arriving first then first
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv041, TestSize.Level1)
{
    uint32_t connectionId = 28;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1500);
    header.size = htonl(7);
    header.offset = htonl(7);
    header.total = htonl(14);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 7, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(7);
    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 7, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(14, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv042
 * @tc.desc: Test ConnGattTransRecv 3-segment arriving in reverse order
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv042, TestSize.Level1)
{
    uint32_t connectionId = 29;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1600);
    header.size = htonl(5);
    header.offset = htonl(10);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv043
 * @tc.desc: Test ConnGattTransRecv complete packet total=3
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv043, TestSize.Level1)
{
    uint32_t connectionId = 30;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1700);
    header.size = htonl(3);
    header.offset = htonl(0);
    header.total = htonl(3);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(3, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv044
 * @tc.desc: Test ConnGattTransRecv second segment arriving first then duplicate second
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv044, TestSize.Level1)
{
    uint32_t connectionId = 31;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1800);
    header.size = htonl(5);
    header.offset = htonl(5);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv045
 * @tc.desc: Test ConnGattTransRecv 3-segment unequal sizes 3+7+5
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv045, TestSize.Level1)
{
    uint32_t connectionId = 32;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(1900);
    header.size = htonl(3);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(7);
    header.offset = htonl(3);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 7, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(5);
    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv046
 * @tc.desc: Test ConnGattTransRecv 2-segment buffer received exceeding total
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv046, TestSize.Level1)
{
    uint32_t connectionId = 33;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 2000;
    buffer.total = 10;
    buffer.received = 8;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2000);
    header.size = htonl(5);
    header.offset = htonl(5);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv047
 * @tc.desc: Test ConnGattTransRecv 2-segment different seq in second packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv047, TestSize.Level1)
{
    uint32_t connectionId = 34;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.seq = htonl(2200);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(5, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv048
 * @tc.desc: Test ConnGattTransRecv 7-segment reassembly
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv048, TestSize.Level1)
{
    uint32_t connectionId = 35;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2300);
    header.size = htonl(2);
    header.offset = htonl(0);
    header.total = htonl(14);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = nullptr;
    for (int i = 0; i < 6; i++) {
        header.offset = htonl(i * 2);
        result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
        EXPECT_EQ(nullptr, result);
    }

    header.offset = htonl(12);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 2, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(14, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv049
 * @tc.desc: Test ConnGattTransRecv complete packet size=100
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv049, TestSize.Level1)
{
    uint32_t connectionId = 36;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2400);
    header.size = htonl(100);
    header.offset = htonl(0);
    header.total = htonl(100);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 100, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(100, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv050
 * @tc.desc: Test ConnGattTransRecv 2-segment equal sizes 10+10
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv050, TestSize.Level1)
{
    uint32_t connectionId = 37;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2500);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(20);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(20, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv051
 * @tc.desc: Test ConnGattTransRecv 2-segment second arriving first size 3+3
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv051, TestSize.Level1)
{
    uint32_t connectionId = 38;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2600);
    header.size = htonl(3);
    header.offset = htonl(3);
    header.total = htonl(6);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 3, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(6, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv052
 * @tc.desc: Test ConnGattTransRecv complete packet with buffer pending different seq
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv052, TestSize.Level1)
{
    uint32_t connectionId = 39;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 50;
    buffer.total = 30;
    buffer.received = 15;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2700);
    header.size = htonl(15);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 15, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv053
 * @tc.desc: Test ConnGattTransRecv 2-segment first then new complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv053, TestSize.Level1)
{
    uint32_t connectionId = 40;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(2800);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(20);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.seq = htonl(2900);
    header.size = htonl(8);
    header.offset = htonl(0);
    header.total = htonl(8);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 8, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(8, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv054
 * @tc.desc: Test ConnGattTransRecv 3-segment first and third arrive then second
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv054, TestSize.Level1)
{
    uint32_t connectionId = 41;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(3000);
    header.size = htonl(4);
    header.offset = htonl(0);
    header.total = htonl(12);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 4, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(8);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 4, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(4);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 4, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(12, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv055
 * @tc.desc: Test ConnGattTransRecv 2-segment with first segment then different seq complete
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnGattTransRecv055, TestSize.Level1)
{
    uint32_t connectionId = 42;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(3100);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(20);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.seq = htonl(3200);
    header.size = htonl(6);
    header.offset = htonl(0);
    header.total = htonl(6);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 6, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(6, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv013
 * @tc.desc: Test ConnCocTransRecv head.len=0
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv013, TestSize.Level1)
{
    uint32_t connectionId = 9;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {};
    head.magic = MAGIC_NUMBER;
    head.len = 0;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead), (uint32_t)outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv014
 * @tc.desc: Test ConnCocTransRecv buffer length less than ConnPktHead
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv014, TestSize.Level1)
{
    uint32_t connectionId = 10;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) - 1;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(200));
    ASSERT_NE(nullptr, buf);
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv015
 * @tc.desc: Test ConnCocTransRecv buffer length=0
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv015, TestSize.Level1)
{
    uint32_t connectionId = 11;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = 0;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(200));
    ASSERT_NE(nullptr, buf);
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv016
 * @tc.desc: Test ConnCocTransRecv exact capacity fit
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv016, TestSize.Level1)
{
    uint32_t connectionId = 12;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    uint32_t payloadLen = 30;
    buffer.capacity = sizeof(ConnPktHead) + payloadLen;
    buffer.length = sizeof(ConnPktHead) + payloadLen;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(buffer.capacity));
    ASSERT_NE(nullptr, buf);
    ConnPktHead *head = reinterpret_cast<ConnPktHead *>(buf);
    head->magic = MAGIC_NUMBER;
    head->len = payloadLen;
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + payloadLen, (uint32_t)outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv017
 * @tc.desc: Test ConnCocTransRecv head.len exceeding capacity by 1
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv017, TestSize.Level1)
{
    uint32_t connectionId = 13;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = sizeof(ConnPktHead) + 30;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {};
    head.magic = MAGIC_NUMBER;
    head.len = 31;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv018
 * @tc.desc: Test ConnCocTransRecv complete packet with remaining data
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv018, TestSize.Level1)
{
    uint32_t connectionId = 14;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 500;
    buffer.length = sizeof(ConnPktHead) + 80;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(500));
    ASSERT_NE(nullptr, buf);
    ConnPktHead *head = reinterpret_cast<ConnPktHead *>(buf);
    head->magic = MAGIC_NUMBER;
    head->len = 30;
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 30, (uint32_t)outLen);
    EXPECT_GT(buffer.length, 0);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv019
 * @tc.desc: Test ConnCocTransRecv with different invalid magic number
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv019, TestSize.Level1)
{
    uint32_t connectionId = 15;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {};
    head.magic = 0;
    head.len = 10;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv020
 * @tc.desc: Test ConnCocTransRecv incomplete packet head.len=10 but only 5 bytes
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv020, TestSize.Level1)
{
    uint32_t connectionId = 16;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) + 5;
    ConnPktHead head = {};
    head.magic = MAGIC_NUMBER;
    head.len = 10;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnCocTransRecv021
 * @tc.desc: Test ConnCocTransRecv head.len=1
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv021, TestSize.Level1)
{
    uint32_t connectionId = 17;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) + 1;
    ConnPktHead head = {};
    head.magic = MAGIC_NUMBER;
    head.len = 1;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 1, (uint32_t)outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv022
 * @tc.desc: Test ConnCocTransRecv with 0xFFFFFFFF as invalid magic
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv022, TestSize.Level1)
{
    uint32_t connectionId = 18;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {};
    head.magic = 0xFFFFFFFF;
    head.len = 10;
    buffer.buffer = reinterpret_cast<uint8_t *>(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv023
 * @tc.desc: Test ConnCocTransRecv complete packet with exact remaining data
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv023, TestSize.Level1)
{
    uint32_t connectionId = 19;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    uint32_t payloadLen = 20;
    uint32_t remainingLen = 15;
    buffer.capacity = sizeof(ConnPktHead) + payloadLen + remainingLen;
    buffer.length = sizeof(ConnPktHead) + payloadLen + remainingLen;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(buffer.capacity));
    ASSERT_NE(nullptr, buf);
    ConnPktHead *head = reinterpret_cast<ConnPktHead *>(buf);
    head->magic = MAGIC_NUMBER;
    head->len = payloadLen;
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + payloadLen, (uint32_t)outLen);
    EXPECT_EQ(remainingLen, buffer.length);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv024
 * @tc.desc: Test ConnCocTransRecv large payload 200 bytes
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv024, TestSize.Level1)
{
    uint32_t connectionId = 20;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 500;
    buffer.length = sizeof(ConnPktHead) + 200;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(500));
    ASSERT_NE(nullptr, buf);
    ConnPktHead *head = reinterpret_cast<ConnPktHead *>(buf);
    head->magic = MAGIC_NUMBER;
    head->len = 200;
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 200, (uint32_t)outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnCocTransRecv025
 * @tc.desc: Test ConnCocTransRecv complete packet with 10 bytes remaining
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnCocTransRecv025, TestSize.Level1)
{
    uint32_t connectionId = 21;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    uint32_t payloadLen = 20;
    uint32_t remainingLen = 10;
    buffer.capacity = sizeof(ConnPktHead) + payloadLen + remainingLen;
    buffer.length = sizeof(ConnPktHead) + payloadLen + remainingLen;
    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(buffer.capacity));
    ASSERT_NE(nullptr, buf);
    ConnPktHead *head = reinterpret_cast<ConnPktHead *>(buf);
    head->magic = MAGIC_NUMBER;
    head->len = payloadLen;
    buffer.buffer = buf;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + payloadLen, (uint32_t)outLen);
    EXPECT_EQ(remainingLen, buffer.length);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(buf);
}

/*
 * @tc.name: ConnBlePackCtlMessage012
 * @tc.desc: Test ConnBlePackCtlMessage AddNumberToJsonObject fails on second call
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage012, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject)
        .WillOnce(Return(true))
        .WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage013
 * @tc.desc: Test ConnBlePackCtlMessage AddNumberToJsonObject fails on third call
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage013, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage014
 * @tc.desc: Test ConnBlePackCtlMessage with invalid method value 2
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage014, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = (BleCtlMessageMethod)2;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage015
 * @tc.desc: Test ConnBlePackCtlMessage with delta=0 and referenceNumber=0
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage015, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 1;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 50;
    ctx.referenceRequest.referenceNumber = 0;
    ctx.referenceRequest.delta = 0;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LE(0, ret);
    EXPECT_NE(nullptr, data);
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage016
 * @tc.desc: Test ConnBlePackCtlMessage AddNumber16ToJsonObject fails on first call
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage016, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage017
 * @tc.desc: Test ConnBlePackCtlMessage with invalid method value 99
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage017, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = (BleCtlMessageMethod)99;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage018
 * @tc.desc: Test ConnBlePackCtlMessage with connectionId=0
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage018, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 0;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LE(0, ret);
    EXPECT_NE(nullptr, data);
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage019
 * @tc.desc: Test ConnBlePackCtlMessage AddNumberToJsonObject fails on first call
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage019, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage020
 * @tc.desc: Test ConnBlePackCtlMessage with challengeCode=UINT16_MAX
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePackCtlMessage020, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 65535;
    ctx.referenceRequest.referenceNumber = 100;
    ctx.referenceRequest.delta = 50;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LE(0, ret);
    EXPECT_NE(nullptr, data);
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBleTransConfigPostLimit006
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=false and valid config
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleTransConfigPostLimit006, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = false;
    config.windowInMillis = 200;
    config.quotaInBytes = 2000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit007
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=true and valid window/quota
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleTransConfigPostLimit007, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = false;
    config.windowInMillis = 500;
    config.quotaInBytes = 5000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit008
 * @tc.desc: Test ConnBleTransConfigPostLimit with CONNECT_HML type
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleTransConfigPostLimit008, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_HML;
    config.active = true;
    config.windowInMillis = 100;
    config.quotaInBytes = 1000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit009
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=false and zero window/quota
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleTransConfigPostLimit009, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = false;
    config.windowInMillis = 0;
    config.quotaInBytes = 0;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit010
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=true and large window/quota
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleTransConfigPostLimit010, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = false;
    config.windowInMillis = 10000;
    config.quotaInBytes = 100000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner010
 * @tc.desc: Test ConnBlePostBytesInner with connection state CONNECTING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner010, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONNECTING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner011
 * @tc.desc: Test ConnBlePostBytesInner with connection state CONNECTED
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner011, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner012
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_CONNECTION and CONNECTING state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner012, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONNECTING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_CONNECTION, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner013
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_BLE_NET and CONNECTING state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner013, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONNECTING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_BLE_NET, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner014
 * @tc.desc: Test ConnBlePostBytesInner with connection state SERVICE_SEARCHING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner014, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner015
 * @tc.desc: Test ConnBlePostBytesInner with connection state MTU_SETTING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner015, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_MTU_SETTING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner016
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_CONNECTION and MTU_SETTED state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner016, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_MTU_SETTED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_CONNECTION, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner017
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_BLE_NET and MTU_SETTED state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner017, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_MTU_SETTED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_BLE_NET, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner018
 * @tc.desc: Test ConnBlePostBytesInner with connection state CLOSING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner018, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CLOSING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner019
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_CONNECTION and CLOSING state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner019, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CLOSING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_CONNECTION, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner020
 * @tc.desc: Test ConnBlePostBytesInner with connection state CLOSED
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner020, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CLOSED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner021
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_BLE_NET and EXCHANGED_BASIC_INFO state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner021, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_BLE_NET, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner022
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_CONNECTION and EXCHANGED_BASIC_INFO state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner022, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_CONNECTION, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner023
 * @tc.desc: Test ConnBlePostBytesInner with connection state NEGOTIATION_CLOSING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner023, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_NEGOTIATION_CLOSING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner024
 * @tc.desc: Test ConnBlePostBytesInner with connection state INVALID
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner024, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_INVALID;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner025
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_BLE_NET and CLOSED state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner025, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CLOSED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_BLE_NET, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner026
 * @tc.desc: Test ConnBlePostBytesInner with connection state CONN_NOTIFICATING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner026, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner027
 * @tc.desc: Test ConnBlePostBytesInner with connection state NET_NOTIFICATING
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner027, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_NET_NOTIFICATING;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner028
 * @tc.desc: Test ConnBlePostBytesInner with connection state SERVICE_SEARCHED
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner028, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_SERVICE_SEARCHED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner029
 * @tc.desc: Test ConnBlePostBytesInner with connection state CONN_NOTIFICATED
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner029, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_CONN_NOTIFICATED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner030
 * @tc.desc: Test ConnBlePostBytesInner with connection state NET_NOTIFICATED
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBlePostBytesInner030, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_NET_NOTIFICATED;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillRepeatedly(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBleInitTransModule001
 * @tc.desc: Test ConnBleInitTransModule with null listener
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleInitTransModule001, TestSize.Level1)
{
    int32_t ret = ConnBleInitTransModule(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleInitTransModule002
 * @tc.desc: Test ConnBleInitTransModule with null onPostBytesFinished
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleInitTransModule002, TestSize.Level1)
{
    ConnBleTransEventListener listener = { 0 };
    listener.onPostBytesFinished = nullptr;
    int32_t ret = ConnBleInitTransModule(&listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleInitTransModule003
 * @tc.desc: Test ConnBleInitTransModule with valid listener
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, ConnBleInitTransModule003, TestSize.Level1)
{
    ConnBleTransEventListener listener = { 0 };
    listener.onPostBytesFinished = ExtOnPostBytesFinished;
    int32_t ret = ConnBleInitTransModule(&listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: QueueBlock002
 * @tc.desc: Test multiple enqueue/dequeue operations
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, QueueBlock002, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendQueueNode queueNode1;
    queueNode1.flag = CONN_HIGH;
    queueNode1.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendQueueNode queueNode2;
    queueNode2.flag = CONN_LOW;
    queueNode2.pid = 2;
    ret = ConnBleEnqueueNonBlock(&queueNode2);
    EXPECT_EQ(SOFTBUS_OK, ret);

    void *msg = nullptr;
    ret = ConnBleDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleDeinitSendQueue();
}

/*
 * @tc.name: QueueBlock003
 * @tc.desc: Test ConnBleDequeueBlock with null parameter
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, QueueBlock003, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleDequeueBlock(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ConnBleDeinitSendQueue();
}

/*
 * @tc.name: QueueBlock004
 * @tc.desc: Test deinit and reinit send queue
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, QueueBlock004, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendQueueNode queueNode;
    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleDeinitSendQueue();

    ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    void *msg = nullptr;
    ret = ConnBleDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleDeinitSendQueue();
}

/*
 * @tc.name: QueueBlock005
 * @tc.desc: Test enqueue high priority multiple times
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransExtTest, QueueBlock005, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    for (int i = 0; i < 3; i++) {
        SendQueueNode queueNode;
        queueNode.flag = CONN_HIGH;
        queueNode.pid = i;
        ret = ConnBleEnqueueNonBlock(&queueNode);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }

    void *msg = nullptr;
    for (int i = 0; i < 3; i++) {
        ret = ConnBleDequeueBlock(&msg);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }

    ConnBleDeinitSendQueue();
}
}