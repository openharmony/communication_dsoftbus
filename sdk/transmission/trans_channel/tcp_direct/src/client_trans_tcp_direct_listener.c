/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_listener.h"

#include <stdbool.h>
#include <unistd.h>
#include <securec.h>
#include <stdatomic.h>

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "trans_log.h"

typedef struct {
    SoftBusMutex lock;
    _Atomic bool lockInit;
} SoftBusTcpListenerLock;

static SoftBusTcpListenerLock g_lock = {
    .lockInit = false,
};
static bool g_isInitedFlag = false;


static void TdcLockInit(void)
{
    if (!atomic_load_explicit(&(g_lock.lockInit), memory_order_acquire)) {
        if (SoftBusMutexInit(&g_lock.lock, NULL) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_INIT, "TDC lock init failed");
            return;
        }
        atomic_store_explicit(&(g_lock.lockInit), true, memory_order_release);
    }
}

void TdcLockDeinit(void)
{
    g_lock.lockInit = false;
    (void)SoftBusMutexDestroy(&g_lock.lock);
}

static int32_t ClientTdcOnConnectEvent(ListenerModule module, int cfd,
    const ConnectOption *clientAddr)
{
    (void)module;
    (void)cfd;
    (void)clientAddr;
    return SOFTBUS_OK;
}

static int32_t ClientTdcOnDataEvent(ListenerModule module, int events, int32_t fd)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByFd(fd, &channel) != SOFTBUS_OK) {
        (void)DelTrigger(module, fd, RW_TRIGGER);
        TRANS_LOGE(TRANS_SDK, "can not match fd. release fd=%{public}d", fd);
        return SOFTBUS_MEM_ERR;
    }

    if (events == SOFTBUS_SOCKET_IN) {
        int32_t channelId = channel.channelId;
        int32_t ret = TransTdcRecvData(channelId);
        if (ret == SOFTBUS_DATA_NOT_ENOUGH) {
            TRANS_LOGE(TRANS_SDK, "client process data fail, SOFTBUS_DATA_NOT_ENOUGH. channelId=%{public}d", channelId);
            return SOFTBUS_OK;
        }
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "client process data fail, channelId=%{public}d, ret=%{public}d", channelId, ret);
            TransDelDataBufNode(channelId);
            TransTdcCloseChannel(channelId);
            ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_RECV_DATA_ERR);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransTdcCreateListener(int32_t fd)
{
    TdcLockInit();
    if (SoftBusMutexLock(&g_lock.lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_isInitedFlag == false) {
        g_isInitedFlag = true;

        static SoftbusBaseListener listener = {
            .onConnectEvent = ClientTdcOnConnectEvent,
            .onDataEvent = ClientTdcOnDataEvent,
        };
        int32_t ret = StartBaseClient(DIRECT_CHANNEL_CLIENT, &listener);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "start sdk base listener failed, ret=%{public}d", ret);
            SoftBusMutexUnlock(&g_lock.lock);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "create sdk listener success. fd=%{public}d", fd);
    }
    SoftBusMutexUnlock(&g_lock.lock);

    return AddTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
}

int32_t TransTdcCreateListenerWithoutAddTrigger(int32_t fd)
{
    TdcLockInit();
    if (SoftBusMutexLock(&g_lock.lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_isInitedFlag == false) {
        g_isInitedFlag = true;
        static SoftbusBaseListener listener = {
            .onConnectEvent = ClientTdcOnConnectEvent,
            .onDataEvent = ClientTdcOnDataEvent,
        };
        int32_t ret = StartBaseClient(DIRECT_CHANNEL_CLIENT, &listener);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "start sdk base listener failed, ret=%{public}d", ret);
            SoftBusMutexUnlock(&g_lock.lock);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "create sdk listener success.fd=%{public}d", fd);
    }
    SoftBusMutexUnlock(&g_lock.lock);

    return SOFTBUS_OK;
}

void TransTdcCloseFd(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGI(TRANS_SDK, "fd less than zero");
        return;
    }
    DelTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
    if (ConnGetSocketError(fd) == SOFTBUS_CONN_BAD_FD) {
        TRANS_LOGI(TRANS_SDK, "fd is bad fd=%{public}d", fd);
        return;
    }
    ConnCloseSocket(fd);
}

void TransTdcReleaseFd(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGI(TRANS_SDK, "fd less than zero");
        return;
    }
    (void)DelTrigger(DIRECT_CHANNEL_CLIENT, fd, RW_TRIGGER);
    if (ConnGetSocketError(fd) == SOFTBUS_CONN_BAD_FD) {
        TRANS_LOGI(TRANS_SDK, "fd is bad fd=%{public}d", fd);
        return;
    }
    ConnShutdownSocket(fd);
}

int32_t TransTdcStopRead(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGI(TRANS_SDK, "fd less than zero");
        return SOFTBUS_OK;
    }
    return DelTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
}
