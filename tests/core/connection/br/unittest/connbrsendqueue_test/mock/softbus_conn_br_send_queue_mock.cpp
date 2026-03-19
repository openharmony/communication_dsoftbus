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

#include "softbus_conn_br_send_queue_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBrSendQueueInterface = nullptr;

ConnectionBrSendQueueInterfaceMock::ConnectionBrSendQueueInterfaceMock()
{
    g_connectionBrSendQueueInterface = reinterpret_cast<void *>(this);
}

ConnectionBrSendQueueInterfaceMock::~ConnectionBrSendQueueInterfaceMock()
{
    g_connectionBrSendQueueInterface = nullptr;
}

static ConnectionBrSendQueueInterface *GetConnectionBrSendQueueInterface()
{
    return reinterpret_cast<ConnectionBrSendQueueInterface *>(g_connectionBrSendQueueInterface);
}

extern "C" {
int32_t SoftBusGetTime(SoftBusSysTime *time)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return SOFTBUS_OK;
    }
    return GetConnectionBrSendQueueInterface()->SoftBusGetTime(time);
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return SOFTBUS_OK;
    }
    return GetConnectionBrSendQueueInterface()->SoftBusCondWait(cond, mutex, time);
}

int32_t WaitQueueLength(const LockFreeQueue *lockFreeQueue, uint32_t maxLen, uint32_t diffLen,
    SoftBusCond *cond, SoftBusMutex *mutex)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return SOFTBUS_OK;
    }
    return GetConnectionBrSendQueueInterface()->WaitQueueLength(lockFreeQueue, maxLen, diffLen, cond, mutex);
}

int32_t GetMsg(ConnectionQueue *queue, void **msg, bool *isFull, QueuePriority leastPriority)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
    }
    return GetConnectionBrSendQueueInterface()->GetMsg(queue, msg, isFull, leastPriority);
}

int32_t QueueMultiProducerEnqueue(LockFreeQueue *queue, const void *node)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return 0;
    }
    return GetConnectionBrSendQueueInterface()->QueueMultiProducerEnqueue(queue, node);
}

int32_t SoftBusCondBroadcast(SoftBusCond *cond)
{
    if (g_connectionBrSendQueueInterface == nullptr) {
        return SOFTBUS_OK;
    }
    return GetConnectionBrSendQueueInterface()->SoftBusCondBroadcast(cond);
}
}
}
