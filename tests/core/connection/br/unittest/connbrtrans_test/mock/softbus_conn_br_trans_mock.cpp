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

#include "softbus_conn_br_trans_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBrTransInterface = nullptr;
static struct ConnSlideWindowController *g_flowController = nullptr;

ConnectionBrTransMock::ConnectionBrTransMock()
{
    g_connectionBrTransInterface = reinterpret_cast<void *>(this);
}

ConnectionBrTransMock::~ConnectionBrTransMock()
{
    g_connectionBrTransInterface = nullptr;
    g_flowController = nullptr;
}

static ConnectionBrTransInterface *GetConnectionBrTransInterface()
{
    return reinterpret_cast<ConnectionBrTransInterface *>(g_connectionBrTransInterface);
}

extern "C" {
int32_t ConnBrInnerQueueInit(void)
{
    return GetConnectionBrTransInterface()->ConnBrInnerQueueInit();
}

void ConnBrInnerQueueDeinit(void)
{
    GetConnectionBrTransInterface()->ConnBrInnerQueueDeinit();
}

int32_t ConnBrEnqueueNonBlock(const void *msg)
{
    return GetConnectionBrTransInterface()->ConnBrEnqueueNonBlock(msg);
}

int32_t ConnBrDequeueBlock(void **msg)
{
    return GetConnectionBrTransInterface()->ConnBrDequeueBlock(msg);
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetConnectionBrTransInterface()->ConnBrCreateBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    GetConnectionBrTransInterface()->ConnBrDelBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacketById(uint32_t id)
{
    GetConnectionBrTransInterface()->ConnBrDelBrPendingPacketById(id);
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
    return GetConnectionBrTransInterface()->ConnBrGetBrPendingPacket(id, seq, waitMillis, data);
}

void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self)
{
    GetConnectionBrTransInterface()->ConnSlideWindowControllerDelete(self);
}

int32_t ConnStartActionAsync(const void *looper, void (*threadEntry)(void *), void *arg)
{
    return GetConnectionBrTransInterface()->ConnStartActionAsync(looper, threadEntry, arg);
}

void *ConnBrGetConnectionById(uint32_t connectionId)
{
    return GetConnectionBrTransInterface()->ConnBrGetConnectionById(connectionId);
}

void ConnBrReturnConnection(void **connection)
{
    GetConnectionBrTransInterface()->ConnBrReturnConnection(connection);
}

void ConnBrRefreshIdleTimeout(void *connection)
{
    GetConnectionBrTransInterface()->ConnBrRefreshIdleTimeout(connection);
}
}
} // namespace OHOS
