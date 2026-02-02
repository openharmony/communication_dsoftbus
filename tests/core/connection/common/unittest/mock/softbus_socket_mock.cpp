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

#include "softbus_socket_mock.h"
#include <cstring>
#include <cstdarg>
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "softbus_adapter_mem.h"

namespace OHOS::SoftBus {

// Test data for getifaddrs mocking
static struct ifaddrs *g_testIfAddrs = nullptr;

SocketTestMock::SocketTestMock()
{
    mock.store(this);
}

SocketTestMock::~SocketTestMock()
{
    mock.store(nullptr);
    ClearTestIfAddr();
}

void SocketTestMock::SetTestIfAddr(const std::string &ip, const std::string &ifName)
{
    testIp_ = ip;
    testIfName_ = ifName;
    hasTestIfAddr_ = true;

    // Create test ifaddrs structure
    g_testIfAddrs = static_cast<struct ifaddrs *>(SoftBusCalloc(sizeof(struct ifaddrs)));
    if (g_testIfAddrs != nullptr) {
        g_testIfAddrs->ifa_next = nullptr;
        g_testIfAddrs->ifa_name = strdup(ifName.c_str());
        g_testIfAddrs->ifa_flags = IFF_UP;
        g_testIfAddrs->ifa_addr = reinterpret_cast<struct sockaddr *>(SoftBusCalloc(sizeof(struct sockaddr_in)));
        if (g_testIfAddrs->ifa_addr != nullptr) {
            auto *sin = reinterpret_cast<struct sockaddr_in *>(g_testIfAddrs->ifa_addr);
            sin->sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sin->sin_addr);
        }
    }
}

void SocketTestMock::ClearTestIfAddr()
{
    if (g_testIfAddrs != nullptr) {
        if (g_testIfAddrs->ifa_name != nullptr) {
            free(g_testIfAddrs->ifa_name);
        }
        if (g_testIfAddrs->ifa_addr != nullptr) {
            SoftBusFree(g_testIfAddrs->ifa_addr);
        }
        SoftBusFree(g_testIfAddrs);
        g_testIfAddrs = nullptr;
    }
    hasTestIfAddr_ = false;
}

} // namespace OHOS::SoftBus

// Global mock function implementations
extern "C" {
int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketCreateHook(domain, type, protocol, socketFd);
    }
    return -1;
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketBindHook(socketFd, addr, addrLen);
    }
    return -1;
}

int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName,
    const void *optVal, int32_t optLen)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketSetOptHook(socketFd, level, optName, optVal, optLen);
    }
    return -1;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketGetPeerNameHook(socketFd, addr);
    }
    return -1;
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketCloseHook(socketFd);
    }
    return -1;
}

int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketShutDownHook(socketFd, how);
    }
    return -1;
}

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, uint32_t flags)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketSendHook(socketFd, buf, len, flags);
    }
    return -1;
}

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketRecvHook(socketFd, buf, len, flags);
    }
    return -1;
}

int32_t SoftBusSocketRecvMsg(int32_t socketFd, SoftBusMsgHdr *msg, int32_t flags)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketRecvMsgHook(socketFd, msg, flags);
    }
    return -1;
}

int32_t SoftBusSocketGetError(int32_t socketFd)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SocketGetErrorHook(socketFd);
    }
    return 0;
}

int32_t SoftBusInetPtoN(int32_t af, const char *src, void *dst)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->InetPtoNHook(af, src, dst);
    }
    return -1;
}

const char *SoftBusInetNtoP(int32_t af, const void *src, char *dst, int32_t size)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->InetNtoPHook(af, src, dst, size);
    }
    return nullptr;
}

uint32_t SoftBusIfNameToIndex(const char *name)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->IfNameToIndexHook(name);
    }
    return 0;
}

int32_t SoftBusIndexToIfName(int32_t index, char *ifname, uint32_t nameLen)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->IndexToIfNameHook(index, ifname, nameLen);
    }
    return -1;
}

int32_t WaitEvent(int32_t fd, int32_t events, int32_t timeout)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->WaitEventHook(fd, events, timeout);
    }
    return -1;
}

// Mock for fcntl system call
extern "C" int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = 0;
    if (cmd == F_GETFL || cmd == F_SETFL) {
        arg = va_arg(ap, long);
    } else {
        arg = va_arg(ap, long);
    }
    va_end(ap);

    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->FcntlHook(fd, cmd, arg);
    }
    return -1;
}

// Mock for getifaddrs
int getifaddrs(struct ifaddrs **ifap)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        auto ret = mock->GetIfAddrsHook();
        if (ret == 0) {
            *ifap = OHOS::SoftBus::g_testIfAddrs;
        }
        return ret;
    }
    return -1;
}

// Mock for freeifaddrs
void freeifaddrs(struct ifaddrs *ifa)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        mock->FreeIfAddrsHook();
        return;
    }
}

// Mock for inet_aton
int inet_aton(const char *cp, struct in_addr *addr)
{
    auto mock = OHOS::SoftBus::SocketTestMock::GetMock();
    if (mock != nullptr) {
        return mock->InetAtonHook(cp, addr);
    }
    return 0;
}

} // extern "C"
