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

#ifndef CONN_BR_TRANS_TEST_MOCK_H
#define CONN_BR_TRANS_TEST_MOCK_H

#include <gmock/gmock.h>
#include "softbus_adapter_thread.h"
#include "softbus_conn_flow_control.h"
#include "softbus_conn_br_connection_struct.h"
#include "softbus_conn_br_trans.h"

namespace OHOS {
class ConnBrTransTestInterface {
public:
    ConnBrTransTestInterface() {};
    virtual ~ConnBrTransTestInterface() {};
    virtual int32_t ConnBrInnerQueueInit(void) = 0;
    virtual void ConnBrInnerQueueDeinit(void) = 0;
    virtual int32_t ConnBrEnqueueNonBlock(const void *msg) = 0;
    virtual int32_t ConnBrDequeueBlock(void **msg) = 0;
    virtual int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacketById(uint32_t id) = 0;
    virtual int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data) = 0;
    virtual int32_t ConnBrSetBrPendingPacket(uint32_t id, int64_t seq, void *data) = 0;
    virtual struct ConnSlideWindowController *ConnSlideWindowControllerNew(void) = 0;
    virtual void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self) = 0;
    virtual int32_t ConnStartActionAsync(void *arg, void *(*runnable)(void *), const char *taskName) = 0;
    virtual ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId) = 0;
    virtual void ConnBrReturnConnection(ConnBrConnection **connection) = 0;
    virtual void ConnBrRefreshIdleTimeout(ConnBrConnection *connection) = 0;
    virtual void PackConnPktHead(ConnPktHead *data) = 0;
    virtual void UnpackConnPktHead(ConnPktHead *data) = 0;
};

class ConnBrTransTestMock : public ConnBrTransTestInterface {
public:
    ConnBrTransTestMock();
    ~ConnBrTransTestMock() override;
    MOCK_METHOD0(ConnBrInnerQueueInit, int32_t());
    MOCK_METHOD0(ConnBrInnerQueueDeinit, void());
    MOCK_METHOD1(ConnBrEnqueueNonBlock, int32_t(const void *));
    MOCK_METHOD1(ConnBrDequeueBlock, int32_t(void **));
    MOCK_METHOD2(ConnBrCreateBrPendingPacket, int32_t(uint32_t, int64_t));
    MOCK_METHOD2(ConnBrDelBrPendingPacket, void(uint32_t, int64_t));
    MOCK_METHOD1(ConnBrDelBrPendingPacketById, void(uint32_t));
    MOCK_METHOD4(ConnBrGetBrPendingPacket, int32_t(uint32_t, int64_t, uint32_t, void **));
    MOCK_METHOD3(ConnBrSetBrPendingPacket, int32_t(uint32_t, int64_t, void *));
    MOCK_METHOD0(ConnSlideWindowControllerNew, struct ConnSlideWindowController *());
    MOCK_METHOD1(ConnSlideWindowControllerDelete, void(struct ConnSlideWindowController *));
    MOCK_METHOD3(ConnStartActionAsync, int32_t(void *, void *(*)(void *), const char *));
    MOCK_METHOD1(ConnBrGetConnectionById, ConnBrConnection *(uint32_t));
    MOCK_METHOD1(ConnBrReturnConnection, void(ConnBrConnection **));
    MOCK_METHOD1(ConnBrRefreshIdleTimeout, void(ConnBrConnection *));
    MOCK_METHOD1(PackConnPktHead, void(ConnPktHead *));
    MOCK_METHOD1(UnpackConnPktHead, void(ConnPktHead *));
};
} // namespace OHOS
#endif // CONN_BR_TRANS_TEST_MOCK_H
