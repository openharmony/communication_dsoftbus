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

#ifndef CONNECTION_BR_TRANS_MOCK_H
#define CONNECTION_BR_TRANS_MOCK_H

#include <stdint.h>
#include <stdbool.h>
#include <gmock/gmock.h>

namespace OHOS {
class ConnectionBrTransInterface {
public:
    ConnectionBrTransInterface() {};
    virtual ~ConnectionBrTransInterface() {};
    virtual int32_t ConnBrInnerQueueInit(void) = 0;
    virtual void ConnBrInnerQueueDeinit(void) = 0;
    virtual int32_t ConnBrEnqueueNonBlock(const void *msg) = 0;
    virtual int32_t ConnBrDequeueBlock(void **msg) = 0;
    virtual int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacketById(uint32_t id) = 0;
    virtual int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data) = 0;
    virtual void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self) = 0;
    virtual int32_t ConnStartActionAsync(const void *looper, void (*threadEntry)(void *), void *arg) = 0;
    virtual void *ConnBrGetConnectionById(uint32_t connectionId) = 0;
    virtual void ConnBrReturnConnection(void **connection) = 0;
    virtual void ConnBrRefreshIdleTimeout(void *connection) = 0;
};

class ConnectionBrTransMock : public ConnectionBrTransInterface {
public:
    ConnectionBrTransMock();
    ~ConnectionBrTransMock() override;
    MOCK_METHOD0(ConnBrInnerQueueInit, int32_t());
    MOCK_METHOD0(ConnBrInnerQueueDeinit, void());
    MOCK_METHOD1(ConnBrEnqueueNonBlock, int32_t(const void *));
    MOCK_METHOD1(ConnBrDequeueBlock, int32_t(void **));
    MOCK_METHOD2(ConnBrCreateBrPendingPacket, int32_t(uint32_t, int64_t));
    MOCK_METHOD2(ConnBrDelBrPendingPacket, void(uint32_t, int64_t));
    MOCK_METHOD1(ConnBrDelBrPendingPacketById, void(uint32_t));
    MOCK_METHOD4(ConnBrGetBrPendingPacket, int32_t(uint32_t, int64_t, uint32_t, void **));
    MOCK_METHOD1(ConnSlideWindowControllerDelete, void(struct ConnSlideWindowController *));
    MOCK_METHOD3(ConnStartActionAsync, int32_t(const void *, void (*)(void *), void *));
    MOCK_METHOD1(ConnBrGetConnectionById, void *(uint32_t));
    MOCK_METHOD1(ConnBrReturnConnection, void(void **));
    MOCK_METHOD1(ConnBrRefreshIdleTimeout, void(void *));
};
} // namespace OHOS
#endif // CONNECTION_BR_TRANS_MOCK_H
