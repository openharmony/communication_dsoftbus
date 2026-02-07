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

#ifndef SOFTBUS_SOCKET_MOCK_H
#define SOFTBUS_SOCKET_MOCK_H

#include <atomic>
#include <string>

#include "gmock/gmock.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"

namespace OHOS::SoftBus {
class SocketTestInterface {
public:
    SocketTestInterface() = default;
    virtual ~SocketTestInterface() = default;

    // Socket operations
    virtual int32_t SocketCreateHook(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd) = 0;
    virtual int32_t SocketBindHook(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen) = 0;
    virtual int32_t SocketSetOptHook(int32_t socketFd, int32_t level, int32_t optName,
        const void *optVal, int32_t optLen) = 0;
    virtual int32_t SocketGetPeerNameHook(int32_t socketFd, SoftBusSockAddr *addr) = 0;
    virtual int32_t SocketCloseHook(int32_t socketFd) = 0;
    virtual int32_t SocketShutDownHook(int32_t socketFd, int32_t how) = 0;
    virtual int32_t SocketSendHook(int32_t socketFd, const void *buf, uint32_t len, uint32_t flags) = 0;
    virtual int32_t SocketRecvHook(int32_t socketFd, void *buf, uint32_t len, int32_t flags) = 0;
    virtual int32_t SocketRecvMsgHook(int32_t socketFd, SoftBusMsgHdr *msg, int32_t flags) = 0;
    virtual int32_t SocketGetErrorHook(int32_t socketFd) = 0;

    // Address conversion operations
    virtual int32_t InetPtoNHook(int32_t af, const char *src, void *dst) = 0;
    virtual const char *InetNtoPHook(int32_t af, const void *src, char *dst, int32_t size) = 0;
    virtual int32_t IfNameToIndexHook(const char *name) = 0;
    virtual int32_t IndexToIfNameHook(int32_t index, char *ifname, uint32_t nameLen) = 0;

    // Event operations
    virtual int32_t WaitEventHook(int32_t fd, int32_t events, int32_t timeout) = 0;

    // System call operations
    virtual int32_t FcntlHook(int32_t fd, int32_t cmd, long flag) = 0;

    // Network interface operations
    virtual int32_t GetIfAddrsHook(void) = 0;
    virtual void FreeIfAddrsHook(void) = 0;
    virtual int32_t InetAtonHook(const char *cp, void *addr) = 0;
};

class SocketTestMock : public SocketTestInterface {
public:
    static SocketTestMock *GetMock()
    {
        return mock.load();
    }

    SocketTestMock();
    ~SocketTestMock() override;

    MOCK_METHOD(int32_t, SocketCreateHook,
        (int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd), (override));
    MOCK_METHOD(int32_t, SocketBindHook, (int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen), (override));
    MOCK_METHOD(int32_t, SocketSetOptHook,
        (int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen), (override));
    MOCK_METHOD(int32_t, SocketGetPeerNameHook, (int32_t socketFd, SoftBusSockAddr *addr), (override));
    MOCK_METHOD(int32_t, SocketCloseHook, (int32_t socketFd), (override));
    MOCK_METHOD(int32_t, SocketShutDownHook, (int32_t socketFd, int32_t how), (override));
    MOCK_METHOD(int32_t, SocketSendHook, (int32_t socketFd, const void *buf, uint32_t len, uint32_t flags), (override));
    MOCK_METHOD(int32_t, SocketRecvHook, (int32_t socketFd, void *buf, uint32_t len, int32_t flags), (override));
    MOCK_METHOD(int32_t, SocketRecvMsgHook, (int32_t socketFd, SoftBusMsgHdr *msg, int32_t flags), (override));
    MOCK_METHOD(int32_t, SocketGetErrorHook, (int32_t socketFd), (override));

    MOCK_METHOD(int32_t, InetPtoNHook, (int32_t af, const char *src, void *dst), (override));
    MOCK_METHOD(const char *, InetNtoPHook, (int32_t af, const void *src, char *dst, int32_t size), (override));
    MOCK_METHOD(int32_t, IfNameToIndexHook, (const char *name), (override));
    MOCK_METHOD(int32_t, IndexToIfNameHook, (int32_t index, char *ifname, uint32_t nameLen), (override));

    MOCK_METHOD(int32_t, WaitEventHook, (int32_t fd, int32_t events, int32_t timeout), (override));

    MOCK_METHOD(int32_t, FcntlHook, (int32_t fd, int32_t cmd, long flag), (override));

    MOCK_METHOD(int32_t, GetIfAddrsHook, (), (override));
    MOCK_METHOD(void, FreeIfAddrsHook, (), (override));
    MOCK_METHOD(int32_t, InetAtonHook, (const char *cp, void *addr), (override));

    // Set test data for getifaddrs
    void SetTestIfAddr(const std::string &ip, const std::string &ifName);
    void ClearTestIfAddr();

private:
    static inline std::atomic<SocketTestMock *> mock = nullptr;

    // Test data for getifaddrs mocking
    std::string testIp_;
    std::string testIfName_;
    bool hasTestIfAddr_ = false;
};

} // namespace OHOS::SoftBus

#endif // SOFTBUS_SOCKET_MOCK_H
