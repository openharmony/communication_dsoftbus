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

#include "br_trans_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connBrTransTestInterface = nullptr;

ConnBrTransTestMock::ConnBrTransTestMock()
{
    g_connBrTransTestInterface = reinterpret_cast<void *>(this);
}

ConnBrTransTestMock::~ConnBrTransTestMock()
{
    g_connBrTransTestInterface = nullptr;
}

static ConnBrTransTestInterface *GetConnBrTransTestInterface()
{
    return reinterpret_cast<ConnBrTransTestInterface *>(g_connBrTransTestInterface);
}

extern "C" {
int32_t ConnBrInnerQueueInit(void)
{
    return GetConnBrTransTestInterface()->ConnBrInnerQueueInit();
}

void ConnBrInnerQueueDeinit(void)
{
    GetConnBrTransTestInterface()->ConnBrInnerQueueDeinit();
}

int32_t ConnBrEnqueueNonBlock(const void *msg)
{
    return GetConnBrTransTestInterface()->ConnBrEnqueueNonBlock(msg);
}

int32_t ConnBrDequeueBlock(void **msg)
{
    return GetConnBrTransTestInterface()->ConnBrDequeueBlock(msg);
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetConnBrTransTestInterface()->ConnBrCreateBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    GetConnBrTransTestInterface()->ConnBrDelBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacketById(uint32_t id)
{
    GetConnBrTransTestInterface()->ConnBrDelBrPendingPacketById(id);
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
    return GetConnBrTransTestInterface()->ConnBrGetBrPendingPacket(id, seq, waitMillis, data);
}

int32_t ConnBrSetBrPendingPacket(uint32_t id, int64_t seq, void *data)
{
    return GetConnBrTransTestInterface()->ConnBrSetBrPendingPacket(id, seq, data);
}

struct ConnSlideWindowController *ConnSlideWindowControllerNew(void)
{
    return GetConnBrTransTestInterface()->ConnSlideWindowControllerNew();
}

void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self)
{
    GetConnBrTransTestInterface()->ConnSlideWindowControllerDelete(self);
}

int32_t ConnStartActionAsync(void *arg, void *(*runnable)(void *), const char *taskName)
{
    return GetConnBrTransTestInterface()->ConnStartActionAsync(arg, runnable, taskName);
}

ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId)
{
    return GetConnBrTransTestInterface()->ConnBrGetConnectionById(connectionId);
}

void ConnBrReturnConnection(ConnBrConnection **connection)
{
    GetConnBrTransTestInterface()->ConnBrReturnConnection(connection);
}

void ConnBrRefreshIdleTimeout(ConnBrConnection *connection)
{
    GetConnBrTransTestInterface()->ConnBrRefreshIdleTimeout(connection);
}

void PackConnPktHead(ConnPktHead *data)
{
    GetConnBrTransTestInterface()->PackConnPktHead(data);
}

void UnpackConnPktHead(ConnPktHead *data)
{
    GetConnBrTransTestInterface()->UnpackConnPktHead(data);
}
}
} // namespace OHOS
