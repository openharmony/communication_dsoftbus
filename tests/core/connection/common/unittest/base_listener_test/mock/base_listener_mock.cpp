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

#include "base_listener_mock.h"
#include <cstring>
#include <gtest/gtest.h>
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"

namespace OHOS {

static EventWatcher g_mockEventWatcher = {0};

BaseListenerTestMock::BaseListenerTestMock()
{
    mock.store(this);
}

BaseListenerTestMock::~BaseListenerTestMock()
{
    mock.store(nullptr);
}

std::atomic<BaseListenerTestMock *> BaseListenerTestMock::mock = nullptr;

} // namespace OHOS

extern "C" {

int32_t SoftBusMutexInit(SoftBusMutex *mutex, const SoftBusMutexAttr *attr)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusMutexInit(mutex, attr);
    }
    return -1;
}

int32_t SoftBusMutexLock(SoftBusMutex *mutex)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusMutexLock(mutex);
    }
    return -1;
}

int32_t SoftBusMutexUnlock(SoftBusMutex *mutex)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusMutexUnlock(mutex);
    }
    return -1;
}

void SoftBusMutexDestroy(SoftBusMutex *mutex)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        mock->SoftBusMutexDestroy(mutex);
        return;
    }
}

void *SoftBusCalloc(uint32_t size)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusCalloc(size);
    }
    return nullptr;
}

void SoftBusFree(void *ptr)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        mock->SoftBusFree(ptr);
        return;
    }
}

int32_t SoftBusSocketListen(int32_t fd, int32_t backLog)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusSocketListen(fd, backLog);
    }
    return -1;
}

void ConnShutdownSocket(int32_t fd)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ConnShutdownSocket(fd);
        return;
    }
}

void ConnCloseSocket(int32_t fd)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ConnCloseSocket(fd);
        return;
    }
}

int32_t SoftBusSocketSetOpt(int32_t fd, int32_t level, int32_t optName, const void *optVal, uint32_t optLen)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusSocketSetOpt(fd, level, optName, optVal, optLen);
    }
    return -1;
}

int32_t SoftBusSocketGetError(int32_t fd)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusSocketGetError(fd);
    }
    return 0;
}

EventWatcher *RegisterEventWatcher(int32_t (*onGetAllFdEvent)(ListNode *list))
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->RegisterEventWatcher(onGetAllFdEvent);
    }
    return nullptr;
}

void CloseEventWatcher(EventWatcher *watcher)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        mock->CloseEventWatcher(watcher);
        return;
    }
}

int32_t AddEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->AddEvent(watcher, fd, event);
    }
    return -1;
}

int32_t RemoveEvent(EventWatcher *watcher, int32_t fd)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->RemoveEvent(watcher, fd);
    }
    return -1;
}

int32_t ModifyEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ModifyEvent(watcher, fd, event);
    }
    return -1;
}

int32_t WatchEvent(EventWatcher *watcher, int32_t timeoutMS, ListNode *out)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->WatchEvent(watcher, timeoutMS, out);
    }
    return -1;
}

int32_t ConnStartActionAsync(void *arg, void (*threadEntry)(void *), const char *taskName)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnStartActionAsync(arg, threadEntry, taskName);
    }
    return -1;
}

const SocketInterface *GetSocketInterface(ProtocolType protocol)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->GetSocketInterface(protocol);
    }
    return nullptr;
}

int32_t GetDomainByAddr(const char *addr)
{
    auto mock = OHOS::BaseListenerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->GetDomainByAddr(addr);
    }
    return 0;
}

} // extern "C"
