/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "connectioncommon_fuzzer.h"

#include <vector>
#include <securec.h>
#include <pthread.h>
#include <cstddef>
#include <string>
#include "softbus_datahead_transform.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_conn_manager.h"
#include "softbus_base_listener.h"
#include "softbus_protocol_def.h"
#include "softbus_thread_pool.h"

static pthread_mutex_t g_isInitedLock;
static int g_count = 0;

namespace OHOS {
static void DoDataHeadTransformFuzz(const uint8_t *data, size_t size)
{
    if (size < sizeof(ConnPktHead)) {
        return;
    }
    ConnPktHead head;
    if (memcpy_s(&head, sizeof(head), data, sizeof(head)) != EOK) {
        return;
    }
    PackConnPktHead(&head);
    UnpackConnPktHead(&head);

    if (size < sizeof(ProxyMessageHead)) {
        return;
    }
    ProxyMessageHead  proxyMessageHead;
    if (memcpy_s(&proxyMessageHead, sizeof(proxyMessageHead), data, sizeof(proxyMessageHead)) != EOK) {
        return;
    }
    PackProxyMessageHead(&proxyMessageHead);
    UnpackProxyMessageHead(&proxyMessageHead);
}

static ConnectOption GenerateConnectOption(const uint8_t *data, size_t size)
{
    ConnectOption connectOption = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "127.0.0.1",
            .protocol = LNN_PROTOCOL_IP,
        },
    };
    if (size < sizeof(int32_t)) {
        return connectOption;
    }
    if (memcpy_s(&connectOption.socketOption.port, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return connectOption;
    }
    return connectOption;
}

static constexpr int TCP_KEEP_ALIVE_TIME = 5;
static constexpr int TCP_USER_TIMEOUT = 5;
static void DoSocketFuzz(const uint8_t *data, size_t size)
{
    ConnInitSockets();
    ConnectOption connectOption = GenerateConnectOption(data, size);
    int socketFd = ConnOpenClientSocket(&connectOption, "127.0.0.1", false);
    if (socketFd > 0) {
        ConnSendSocketData(socketFd, reinterpret_cast<const char *>(data), size, 0);
        std::vector<char> recvBuf(size);
        ConnRecvSocketData(socketFd, recvBuf.data(), size, 0);
        ConnSetTcpKeepAlive(socketFd, TCP_KEEP_ALIVE_TIME);
        ConnSetTcpUserTimeOut(socketFd, TCP_USER_TIMEOUT);
        ConnToggleNonBlockMode(socketFd, true);
        ConnGetLocalSocketPort(socketFd);
        ConnGetSocketError(socketFd);
        SocketAddr socketAddr;
        ConnGetPeerSocketAddr(socketFd, &socketAddr);
        ConnCloseSocket(socketFd);
        ConnShutdownSocket(socketFd);
    }
    ConnDeinitSockets();
}

static int32_t ConnectEvent(ListenerModule module, int32_t events, int32_t cfd, const ConnectOption *clientAddr)
{
    return 0;
}

static int32_t DataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    return 0;
}

static void DoBaseListenerFuzz(const uint8_t *data, size_t size)
{
    ListenerModule module = DIRECT_CHANNEL_CLIENT;
    StartBaseClient(module);
    StopBaseListener(module);
    DestroyBaseListener(module);

    LocalListenerInfo info;
    if (memcpy_s(&info, sizeof(LocalListenerInfo), data, size) == EOK) {
        StartBaseListener(&info);
    }

    SoftbusBaseListener listener;
    listener.onConnectEvent = ConnectEvent;
    listener.onDataEvent = DataEvent;
    GetSoftbusBaseListener(module, &listener);
    SetSoftbusBaseListener(module, &listener);
}

static void DoTriggerFuzz()
{
    AddTrigger(AUTH_P2P, 0, WRITE_TRIGGER);
    DelTrigger(AUTH_P2P, 0, WRITE_TRIGGER);
}

static int32_t ThreadPoolTask(void* arg)
{
    pthread_mutex_lock(&g_isInitedLock);
    g_count++;
    pthread_mutex_unlock(&g_isInitedLock);
    return 0;
}

static void DoThreadPoolFuzz()
{
    ThreadPool* pool = ThreadPoolInit(5, 5);
    ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)0);
    ThreadPoolRemoveJob(pool, (uintptr_t)0);
    ThreadPoolDestroy(pool);
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    /* Run your code on data */
    OHOS::DoDataHeadTransformFuzz(data, size);
    OHOS::DoSocketFuzz(data, size);
    OHOS::DoBaseListenerFuzz(data, size);
    OHOS::DoTriggerFuzz();
    OHOS::DoThreadPoolFuzz();
    return 0;
}