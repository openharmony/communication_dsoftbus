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

#include "auth_connection_mock.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
void *g_connInterface;
AuthConnectionInterfaceMock::AuthConnectionInterfaceMock()
{
    g_connInterface = reinterpret_cast<void *>(this);
}

AuthConnectionInterfaceMock::~AuthConnectionInterfaceMock()
{
    g_connInterface = nullptr;
}

static AuthConnectionInterfaceMock *GetCommonInterface()
{
    return reinterpret_cast<AuthConnectionInterfaceMock *>(g_connInterface);
}

extern "C" {
int32_t SoftBusGetBtState(void)
{
    return GetCommonInterface()->SoftBusGetBtState();
}

int32_t PostAuthEvent(EventType event, EventHandler handler, const void *obj, uint32_t size, uint64_t delayMs)
{
    return GetCommonInterface()->PostAuthEvent(event, handler, obj, size, delayMs);
}

bool IsHaveAuthIdByConnId(uint64_t connId)
{
    return GetCommonInterface()->IsHaveAuthIdByConnId(connId);
}

int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode)
{
    return GetCommonInterface()->FindAuthPreLinkNodeById(requestId, reuseNode);
}

int32_t SocketSetDevice(int32_t fd, bool isBlockMode)
{
    return GetCommonInterface()->SocketSetDevice(fd, isBlockMode);
}

void DelAuthPreLinkById(uint32_t requestId)
{
    return GetCommonInterface()->DelAuthPreLinkById(requestId);
}

int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    return GetCommonInterface()->SocketPostBytes(fd, head, data);
}

int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info)
{
    return GetCommonInterface()->StartSocketListening(module, info);
}
}
} // namespace OHOS
