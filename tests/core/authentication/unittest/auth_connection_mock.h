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

#ifndef AUTH_CONNECTION_MOCK_H
#define AUTH_CONNECTION_MOCK_H

#include <gmock/gmock.h>

#include "auth_connection.h"
#include "auth_pre_link.h"

namespace OHOS {
class AuthConnectionInterface {
public:
    AuthConnectionInterface() {};
    virtual ~AuthConnectionInterface() {};

    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t PostAuthEvent(
        EventType event, EventHandler handler, const void *obj, uint32_t size, uint64_t delayMs) = 0;
    virtual bool IsHaveAuthIdByConnId(uint64_t connId) = 0;
    virtual int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode) = 0;
    virtual int32_t SocketSetDevice(int32_t fd, bool isBlockMode) = 0;
    virtual int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info) = 0;
    virtual void DelAuthPreLinkById(uint32_t requestId);
};

class AuthConnectionInterfaceMock : public AuthConnectionInterface {
public:
    AuthConnectionInterfaceMock();
    ~AuthConnectionInterfaceMock() override;

    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD5(PostAuthEvent, int32_t(EventType, EventHandler, const void *, uint32_t, uint64_t));
    MOCK_METHOD1(IsHaveAuthIdByConnId, bool(uint64_t));
    MOCK_METHOD2(FindAuthPreLinkNodeById, int32_t(uint32_t, AuthPreLinkNode *));
    MOCK_METHOD2(SocketSetDevice, int32_t(int32_t, bool));
    MOCK_METHOD3(SocketPostBytes, int32_t(int32_t, const AuthDataHead *, const uint8_t *));
    MOCK_METHOD2(StartSocketListening, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD1(DelAuthPreLinkById, void(uint32_t));
};
} // namespace OHOS
#endif
