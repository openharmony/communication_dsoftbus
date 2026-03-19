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

#ifndef CONNECTION_BR_SEND_QUEUE_MOCK_H
#define CONNECTION_BR_SEND_QUEUE_MOCK_H

#include <gmock/gmock.h>

#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_queue.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"

namespace OHOS {
class ConnectionBrSendQueueInterface {
public:
    ConnectionBrSendQueueInterface() {};
    virtual ~ConnectionBrSendQueueInterface() {};
    virtual int32_t SoftBusGetTime(SoftBusSysTime *time) = 0;
    virtual int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time) = 0;
    virtual int32_t WaitQueueLength(const LockFreeQueue *lockFreeQueue, uint32_t maxLen, uint32_t diffLen,
        SoftBusCond *cond, SoftBusMutex *mutex) = 0;
    virtual int32_t GetMsg(ConnectionQueue *queue, void **msg, bool *isFull, QueuePriority leastPriority) = 0;
    virtual int32_t QueueMultiProducerEnqueue(LockFreeQueue *queue, const void *node) = 0;
    virtual int32_t SoftBusCondBroadcast(SoftBusCond *cond) = 0;
};

class ConnectionBrSendQueueInterfaceMock : public ConnectionBrSendQueueInterface {
public:
    ConnectionBrSendQueueInterfaceMock();
    ~ConnectionBrSendQueueInterfaceMock() override;
    MOCK_METHOD1(SoftBusGetTime, int32_t(SoftBusSysTime *));
    MOCK_METHOD3(SoftBusCondWait, int32_t(SoftBusCond *, SoftBusMutex *, SoftBusSysTime *));
    MOCK_METHOD5(WaitQueueLength, int32_t(const LockFreeQueue *, uint32_t, uint32_t, SoftBusCond *, SoftBusMutex *));
    MOCK_METHOD4(GetMsg, int32_t(ConnectionQueue *, void **, bool *, QueuePriority));
    MOCK_METHOD2(QueueMultiProducerEnqueue, int32_t(LockFreeQueue *, const void *));
    MOCK_METHOD1(SoftBusCondBroadcast, int32_t(SoftBusCond *));
};
} // namespace OHOS
#endif // CONNECTION_BR_SEND_QUEUE_MOCK_H
