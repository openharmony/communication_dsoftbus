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

#include "client_connection_mock_test.h"

using namespace testing::ext;

namespace OHOS {
static void *g_mock = nullptr;
ClientConnectionInterfaceMock::ClientConnectionInterfaceMock()
{
    g_mock = reinterpret_cast<void *>(this);
}

ClientConnectionInterfaceMock::~ClientConnectionInterfaceMock()
{
    g_mock = nullptr;
}

static ClientConnectionInterfaceMock* GetMock()
{
    return reinterpret_cast<ClientConnectionInterfaceMock*>(g_mock);
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr)
{
    return GetMock()->SoftBusMutexInit(mutex, mutexAttr);
}

int32_t SoftBusMutexLockInner(SoftBusMutex *mutex)
{
    return GetMock()->SoftBusMutexLockInner(mutex);
}

int32_t SoftBusMutexUnlockInner(SoftBusMutex *mutex)
{
    return GetMock()->SoftBusMutexUnlockInner(mutex);
}

int32_t InitSoftBus(const char *pkgName)
{
    return GetMock()->InitSoftBus(pkgName);
}

int32_t ServerIpcCreateServer(const char *pkgName, const char *name)
{
    return GetMock()->ServerIpcCreateServer(pkgName, name);
}

int32_t ServerIpcRemoveServer(const char *pkgName, const char *name)
{
    return GetMock()->ServerIpcRemoveServer(pkgName, name);
}

int32_t ServerIpcConnect(const char *pkgName, const char *name, const Address *address)
{
    return GetMock()->ServerIpcConnect(pkgName, name, address);
}

int32_t ServerIpcDisconnect(uint32_t handle)
{
    return GetMock()->ServerIpcDisconnect(handle);
}

int32_t ServerIpcSend(uint32_t handle, const uint8_t *data, uint32_t len)
{
    return GetMock()->ServerIpcSend(handle, data, len);
}

int32_t ServerIpcGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    return GetMock()->ServerIpcGetPeerDeviceId(handle, deviceId, len);
}

#ifdef __cplusplus
}
#endif
}