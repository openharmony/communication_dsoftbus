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

#ifndef BASE_LISTENER_TEST_MOCK_H
#define BASE_LISTENER_TEST_MOCK_H

#include <gmock/gmock.h>
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_socket.h"
#include "softbus_watch_event_interface.h"

namespace OHOS {
class BaseListenerTestInterface {
public:
    BaseListenerTestInterface() {};
    virtual ~BaseListenerTestInterface() {};
    virtual int32_t SoftBusMutexInit(SoftBusMutex *mutex, const SoftBusMutexAttr *attr) = 0;
    virtual int32_t SoftBusMutexLock(SoftBusMutex *mutex) = 0;
    virtual int32_t SoftBusMutexUnlock(SoftBusMutex *mutex) = 0;
    virtual void SoftBusMutexDestroy(SoftBusMutex *mutex) = 0;
    virtual void *SoftBusCalloc(uint32_t size) = 0;
    virtual void SoftBusFree(void *ptr) = 0;
    virtual int32_t SoftBusSocketListen(int32_t fd, int32_t backLog) = 0;
    virtual void ConnShutdownSocket(int32_t fd) = 0;
    virtual void ConnCloseSocket(int32_t fd) = 0;
    virtual int32_t SoftBusSocketSetOpt(int32_t fd, int32_t level, int32_t optName, const void *optVal,
        uint32_t optLen) = 0;
    virtual int32_t SoftBusSocketGetError(int32_t fd) = 0;
    virtual EventWatcher *RegisterEventWatcher(int32_t (*onGetAllFdEvent)(ListNode *list)) = 0;
    virtual void CloseEventWatcher(EventWatcher *watcher) = 0;
    virtual int32_t AddEvent(EventWatcher *watcher, int32_t fd, uint32_t event) = 0;
    virtual int32_t RemoveEvent(EventWatcher *watcher, int32_t fd) = 0;
    virtual int32_t ModifyEvent(EventWatcher *watcher, int32_t fd, uint32_t event) = 0;
    virtual int32_t WatchEvent(EventWatcher *watcher, int32_t timeout, ListNode *fdEvents) = 0;
    virtual int32_t ConnStartActionAsync(void *arg, void (*threadEntry)(void *), const char *taskName) = 0;
    virtual const SocketInterface *GetSocketInterface(ProtocolType protocol) = 0;
    virtual int32_t GetDomainByAddr(const char *addr) = 0;
};

class BaseListenerTestMock : public BaseListenerTestInterface {
public:
    BaseListenerTestMock();
    ~BaseListenerTestMock() override;
    MOCK_METHOD2(SoftBusMutexInit, int32_t(SoftBusMutex *, const SoftBusMutexAttr *));
    MOCK_METHOD1(SoftBusMutexLock, int32_t(SoftBusMutex *));
    MOCK_METHOD1(SoftBusMutexUnlock, int32_t(SoftBusMutex *));
    MOCK_METHOD1(SoftBusMutexDestroy, void(SoftBusMutex *));
    MOCK_METHOD1(SoftBusCalloc, void *(uint32_t));
    MOCK_METHOD1(SoftBusFree, void(void *));
    MOCK_METHOD2(SoftBusSocketListen, int32_t(int32_t, int32_t));
    MOCK_METHOD1(ConnShutdownSocket, void(int32_t));
    MOCK_METHOD1(ConnCloseSocket, void(int32_t));
    MOCK_METHOD5(SoftBusSocketSetOpt, int32_t(int32_t, int32_t, int32_t, const void *, uint32_t));
    MOCK_METHOD1(SoftBusSocketGetError, int32_t(int32_t));
    MOCK_METHOD1(RegisterEventWatcher, EventWatcher *(int32_t (*)(ListNode *)));
    MOCK_METHOD1(CloseEventWatcher, void(EventWatcher *));
    MOCK_METHOD3(AddEvent, int32_t(EventWatcher *, int32_t, uint32_t));
    MOCK_METHOD2(RemoveEvent, int32_t(EventWatcher *, int32_t));
    MOCK_METHOD3(ModifyEvent, int32_t(EventWatcher *, int32_t, uint32_t));
    MOCK_METHOD3(WatchEvent, int32_t(EventWatcher *, int32_t, ListNode *));
    MOCK_METHOD3(ConnStartActionAsync, int32_t(void *, void (*)(void *), const char *));
    MOCK_METHOD1(GetSocketInterface, const SocketInterface *(ProtocolType));
    MOCK_METHOD1(GetDomainByAddr, int32_t(const char *));
};
} // namespace OHOS
#endif // BASE_LISTENER_TEST_MOCK_H
