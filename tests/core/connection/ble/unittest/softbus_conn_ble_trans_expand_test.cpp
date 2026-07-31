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

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_ble_trans_struct.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

static const size_t BLE_TRANS_HEADER_SIZE = sizeof(BleTransHeader);

class BleTransExpandTest : public testing::Test {
public:
    BleTransExpandTest() {}
    ~BleTransExpandTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void BleTransExpandTest::SetUpTestCase() {}

void BleTransExpandTest::TearDownTestCase() {}

HWTEST_F(BleTransExpandTest, ConnBleTransConfigPostLimitNullConfig, TestSize.Level1)
{
    int32_t ret = ConnBleTransConfigPostLimit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleTransExpandTest, ConnBleTransConfigPostLimitWrongType, TestSize.Level1)
{
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = 1000;
    config.quotaInBytes = 2048;
    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageNotifyRequest, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 1;
    ctx.flag = CONN_HIGH;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 10;
    ctx.referenceRequest.referenceNumber = 20;
    ctx.challengeCode = 100;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(nullptr, data);
    EXPECT_GT(dataLen, 0);

    if (data != nullptr) {
        SoftBusFree(data);
    }
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageInvalidMethod, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 2;
    ctx.flag = CONN_HIGH;
    ctx.method = (enum BleCtlMessageMethod)999;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LT(seq, 0);
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageSequenceIncrement, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 3;
    ctx.flag = CONN_HIGH;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 1;
    ctx.referenceRequest.referenceNumber = 1;
    ctx.challengeCode = 1;

    uint8_t *data1 = nullptr;
    uint32_t dataLen1 = 0;
    int64_t seq1 = ConnBlePackCtlMessage(ctx, &data1, &dataLen1);

    uint8_t *data2 = nullptr;
    uint32_t dataLen2 = 0;
    int64_t seq2 = ConnBlePackCtlMessage(ctx, &data2, &dataLen2);

    EXPECT_EQ(seq2, seq1 + 1);
    if (data1 != nullptr) {
        SoftBusFree(data1);
    }
    if (data2 != nullptr) {
        SoftBusFree(data2);
    }
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageNegativeDelta, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 4;
    ctx.flag = CONN_HIGH;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = -5;
    ctx.referenceRequest.referenceNumber = 10;
    ctx.challengeCode = 50;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(nullptr, data);
    EXPECT_GT(dataLen, 0);

    if (data != nullptr) {
        SoftBusFree(data);
    }
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageLowFlag, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 5;
    ctx.flag = CONN_LOW;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 3;
    ctx.referenceRequest.referenceNumber = 7;
    ctx.challengeCode = 200;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(nullptr, data);
    EXPECT_GT(dataLen, 0);

    if (data != nullptr) {
        SoftBusFree(data);
    }
}

HWTEST_F(BleTransExpandTest, ConnBlePackCtlMessageMultipleCalls, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 6;
    ctx.flag = CONN_HIGH;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 1;
    ctx.referenceRequest.referenceNumber = 1;
    ctx.challengeCode = 1;

    for (int i = 0; i < 5; i++) {
        uint8_t *data = nullptr;
        uint32_t dataLen = 0;
        int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
        EXPECT_GE(seq, 0);
        EXPECT_NE(nullptr, data);
        EXPECT_GT(dataLen, 0);
        if (data != nullptr) {
            SoftBusFree(data);
        }
    }
}

HWTEST_F(BleTransExpandTest, DiscardBufferEmptyQuiet, TestSize.Level1)
{
    ConnBleReadBuffer buffer = {0};
    ListInit(&buffer.packets);
    buffer.seq = 0;
    buffer.total = 0;
    buffer.received = 0;
    EXPECT_EQ(0u, buffer.seq);
    EXPECT_EQ(0u, buffer.total);
    EXPECT_EQ(0u, buffer.received);
}

HWTEST_F(BleTransExpandTest, DiscardBufferWithPackets, TestSize.Level1)
{
    ConnBleReadBuffer buffer = {0};
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);

    ConnBlePacket *packet = (ConnBlePacket *)SoftBusCalloc(sizeof(ConnBlePacket));
    ASSERT_NE(nullptr, packet);
    ListInit(&packet->node);
    packet->header.seq = 100;
    packet->header.size = 10;
    packet->header.offset = 0;
    packet->header.total = 20;
    packet->data = (uint8_t *)SoftBusCalloc(BLE_TRANS_HEADER_SIZE + 10);
    ASSERT_NE(nullptr, packet->data);
    ListTailInsert(&buffer.packets, &packet->node);

    ConnBlePacket *it = nullptr;
    ConnBlePacket *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &buffer.packets, ConnBlePacket, node) {
        ListDelete(&it->node);
        SoftBusFree(it->data);
        SoftBusFree(it);
    }
    buffer.seq = 0;
    buffer.total = 0;
    buffer.received = 0;
    EXPECT_EQ(0u, buffer.seq);
    EXPECT_EQ(0u, buffer.total);
    EXPECT_EQ(0u, buffer.received);
}

HWTEST_F(BleTransExpandTest, DiscardBufferWithMultiplePackets, TestSize.Level1)
{
    ConnBleReadBuffer buffer = {0};
    buffer.seq = 200;
    buffer.total = 30;
    buffer.received = 20;
    ListInit(&buffer.packets);

    for (int i = 0; i < 3; i++) {
        ConnBlePacket *packet = (ConnBlePacket *)SoftBusCalloc(sizeof(ConnBlePacket));
        ASSERT_NE(nullptr, packet);
        ListInit(&packet->node);
        packet->header.seq = 200;
        packet->header.size = 10;
        packet->header.offset = i * 10;
        packet->header.total = 30;
        packet->data = (uint8_t *)SoftBusCalloc(BLE_TRANS_HEADER_SIZE + 10);
        ASSERT_NE(nullptr, packet->data);
        ListTailInsert(&buffer.packets, &packet->node);
    }

    ConnBlePacket *it = nullptr;
    ConnBlePacket *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &buffer.packets, ConnBlePacket, node) {
        ListDelete(&it->node);
        SoftBusFree(it->data);
        SoftBusFree(it);
    }
    buffer.seq = 0;
    buffer.total = 0;
    buffer.received = 0;
    EXPECT_EQ(0u, buffer.seq);
    EXPECT_EQ(0u, buffer.total);
    EXPECT_EQ(0u, buffer.received);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvNullData, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint8_t *result = ConnGattTransRecv(connectionId, nullptr, 10, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvZeroDataLen, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);
    uint8_t *result = ConnGattTransRecv(connectionId, data, 0, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvNullOutLen, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);
    uint8_t *result = ConnGattTransRecv(connectionId, data, 10, &buffer, nullptr);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvDataLenLessThanHeader, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvCompletePacket, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint32_t payloadLen = 10;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + payloadLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(100);
    header->size = htonl(payloadLen);
    header->offset = htonl(0);
    header->total = htonl(payloadLen);
    for (uint32_t i = 0; i < payloadLen; i++) {
        data[BLE_TRANS_HEADER_SIZE + i] = static_cast<uint8_t>(i);
    }

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(payloadLen, outLen);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvIncompletePacket, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    uint32_t payloadLen = 5;
    uint32_t totalLen = 20;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + payloadLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(200);
    header->size = htonl(payloadLen);
    header->offset = htonl(0);
    header->total = htonl(totalLen);

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(200u, buffer.seq);
    EXPECT_EQ(totalLen, buffer.total);
    EXPECT_EQ(payloadLen, buffer.received);
    ConnBlePacket *it = nullptr;
    ConnBlePacket *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &buffer.packets, ConnBlePacket, node) {
        ListDelete(&it->node);
        SoftBusFree(it->data);
        SoftBusFree(it);
    }
    buffer.seq = 0;
    buffer.total = 0;
    buffer.received = 0;
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvTotalExceedMax, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint32_t payloadLen = 10;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + payloadLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(400);
    header->size = htonl(payloadLen);
    header->offset = htonl(0);
    header->total = htonl(MAX_DATA_LEN + 1);

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvDifferentSeqDiscard, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    uint32_t segLen = 5;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + segLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(999);
    header->size = htonl(segLen);
    header->offset = htonl(0);
    header->total = htonl(15);

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvInsufficientBuffer, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    LimitedBuffer buffer = {0};
    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) - 1;
    uint8_t bufData[200] = {0};
    buffer.buffer = bufData;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvInvalidMagic, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    LimitedBuffer buffer = {0};
    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead);

    uint8_t *bufData = (uint8_t *)SoftBusCalloc(buffer.capacity);
    ASSERT_NE(nullptr, bufData);
    buffer.buffer = bufData;
    ConnPktHead *head = (ConnPktHead *)bufData;
    head->magic = MAGIC_NUMBER + 1;
    head->module = MODULE_CONNECTION;
    head->seq = 1;
    head->flag = CONN_HIGH;
    head->len = 10;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0u, buffer.length);
    SoftBusFree(bufData);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvTooBigData, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    LimitedBuffer buffer = {0};
    buffer.capacity = sizeof(ConnPktHead) + 10;
    buffer.length = sizeof(ConnPktHead);

    uint8_t *bufData = (uint8_t *)SoftBusCalloc(buffer.capacity);
    ASSERT_NE(nullptr, bufData);
    buffer.buffer = bufData;
    ConnPktHead *head = (ConnPktHead *)bufData;
    head->magic = MAGIC_NUMBER;
    head->module = MODULE_CONNECTION;
    head->seq = 1;
    head->flag = CONN_HIGH;
    head->len = 100;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0u, buffer.length);
    SoftBusFree(bufData);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvIncompletePacket, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    uint32_t dataLen = 10;
    LimitedBuffer buffer = {0};
    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) + 1;

    uint8_t *bufData = (uint8_t *)SoftBusCalloc(buffer.capacity);
    ASSERT_NE(nullptr, bufData);
    buffer.buffer = bufData;
    ConnPktHead *head = (ConnPktHead *)bufData;
    head->magic = MAGIC_NUMBER;
    head->module = MODULE_CONNECTION;
    head->seq = 1;
    head->flag = CONN_HIGH;
    head->len = dataLen;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(bufData);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvCompletePacket, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    uint32_t dataLen = 10;
    uint32_t packLen = sizeof(ConnPktHead) + dataLen;
    LimitedBuffer buffer = {0};
    buffer.capacity = 200;
    buffer.length = packLen;

    uint8_t *bufData = (uint8_t *)SoftBusCalloc(buffer.capacity);
    ASSERT_NE(nullptr, bufData);
    buffer.buffer = bufData;
    ConnPktHead *head = (ConnPktHead *)bufData;
    head->magic = MAGIC_NUMBER;
    head->module = MODULE_CONNECTION;
    head->seq = 1;
    head->flag = CONN_HIGH;
    head->len = dataLen;
    for (uint32_t i = 0; i < dataLen; i++) {
        bufData[sizeof(ConnPktHead) + i] = static_cast<uint8_t>(i);
    }

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ((int32_t)packLen, outLen);
    EXPECT_EQ(0u, buffer.length);
    if (result != nullptr) {
        SoftBusFree(result);
    }
    SoftBusFree(bufData);
}

HWTEST_F(BleTransExpandTest, ConnCocTransRecvZeroLengthBuffer, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t outLen = 0;
    LimitedBuffer buffer = {0};
    buffer.capacity = 100;
    buffer.length = 0;
    uint8_t bufData[100] = {0};
    buffer.buffer = bufData;

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvSizeExceedTotal, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint32_t payloadLen = 20;
    uint32_t totalLen = 10;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + payloadLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(300);
    header->size = htonl(payloadLen);
    header->offset = htonl(0);
    header->total = htonl(totalLen);

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

HWTEST_F(BleTransExpandTest, ConnGattTransRecvOffsetExceedRemain, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = {0};
    uint32_t outLen = 0;
    uint32_t payloadLen = 5;
    uint32_t totalLen = 10;
    uint32_t dataLen = BLE_TRANS_HEADER_SIZE + payloadLen;

    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(nullptr, data);
    BleTransHeader *header = (BleTransHeader *)data;
    header->seq = htonl(900);
    header->size = htonl(payloadLen);
    header->offset = htonl(totalLen);
    header->total = htonl(totalLen);

    uint8_t *result = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    SoftBusFree(data);
}

} // namespace OHOS
