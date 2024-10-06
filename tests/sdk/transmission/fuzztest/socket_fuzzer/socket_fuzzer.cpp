/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "socket_fuzzer.h"
#include <memory>
#include <string>
#include <securec.h>
#include "socket.h"

namespace OHOS {
static std::string DEFAULT_SOCKET_NAME = "com.communication.fuzz.socketName";
static std::string DEFAULT_SOCKET_PEER_NAME = "com.communication.fuzz.peerName";
static std::string DEFAULT_SOCKET_PEER_NETWORKID =
    "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm";
static std::string DEFAULT_SOCKET_PKG_NAME = "com.communication.fuzz.pkgName";

void SocketTestWithName(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    const size_t bufSize = size + 1;
    std::unique_ptr<char[]> socketName = std::make_unique<char[]>(bufSize);
    if (memset_s(socketName.get(), bufSize, 0, bufSize) != EOK) {
        return;
    }

    if (memcpy_s(socketName.get(), bufSize, data, size) != EOK) {
        return;
    }

    SocketInfo info = {
        .name = socketName.get(),
        .peerName = const_cast<char *>(DEFAULT_SOCKET_PEER_NAME.c_str()),
        .peerNetworkId = const_cast<char *>(DEFAULT_SOCKET_PEER_NETWORKID.c_str()),
        .pkgName = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_MESSAGE,
    };

    (void)Socket(info);
}

void SocketTestWithPeerName(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    const size_t bufSize = size + 1;
    std::unique_ptr<char[]> socketPeerName = std::make_unique<char[]>(bufSize);
    if (memset_s(socketPeerName.get(), bufSize, 0, bufSize) != EOK) {
        return;
    }

    if (memcpy_s(socketPeerName.get(), bufSize, data, size) != EOK) {
        return;
    }

    SocketInfo info = {
        .name = const_cast<char *>(DEFAULT_SOCKET_NAME.c_str()),
        .peerName = socketPeerName.get(),
        .peerNetworkId = const_cast<char *>(DEFAULT_SOCKET_PEER_NETWORKID.c_str()),
        .pkgName = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_MESSAGE,
    };

    (void)Socket(info);
}

void SocketTestWithNetworkId(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    const size_t bufSize = size + 1;
    std::unique_ptr<char[]> socketNetworkId = std::make_unique<char[]>(bufSize);
    if (memset_s(socketNetworkId.get(), bufSize, 0, bufSize) != EOK) {
        return;
    }

    if (memcpy_s(socketNetworkId.get(), bufSize, data, size) != EOK) {
        return;
    }

    SocketInfo info = {
        .name = const_cast<char *>(DEFAULT_SOCKET_NAME.c_str()),
        .peerName = const_cast<char *>(DEFAULT_SOCKET_PEER_NAME.c_str()),
        .peerNetworkId = socketNetworkId.get(),
        .pkgName = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_MESSAGE,
    };

    (void)Socket(info);
}

void SocketTestWithPkgName(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    const size_t bufSize = size + 1;
    std::unique_ptr<char[]> socketPkgName = std::make_unique<char[]>(bufSize);
    if (memset_s(socketPkgName.get(), bufSize, 0, bufSize) != EOK) {
        return;
    }

    if (memcpy_s(socketPkgName.get(), bufSize, data, size) != EOK) {
        return;
    }

    SocketInfo info = {
        .name = const_cast<char *>(DEFAULT_SOCKET_NAME.c_str()),
        .peerName = const_cast<char *>(DEFAULT_SOCKET_PEER_NAME.c_str()),
        .peerNetworkId = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .pkgName = socketPkgName.get(),
        .dataType = DATA_TYPE_MESSAGE,
    };

    (void)Socket(info);
}

void SocketTestWithDataType(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(TransDataType))) {
        return;
    }

    TransDataType socketDataType = DATA_TYPE_BUTT;
    if (memcpy_s(&socketDataType, sizeof(TransDataType), data, sizeof(TransDataType)) != EOK) {
        return;
    }

    SocketInfo info = {
        .name = const_cast<char *>(DEFAULT_SOCKET_NAME.c_str()),
        .peerName = const_cast<char *>(DEFAULT_SOCKET_PEER_NAME.c_str()),
        .peerNetworkId = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .pkgName = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME.c_str()),
        .dataType = socketDataType,
    };

    (void)Socket(info);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::SocketTestWithName(data, size);
    OHOS::SocketTestWithPeerName(data, size);
    OHOS::SocketTestWithNetworkId(data, size);
    OHOS::SocketTestWithPkgName(data, size);
    OHOS::SocketTestWithDataType(data, size);
    return 0;
}
