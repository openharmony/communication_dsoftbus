/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"
#include "trans_log.h"

typedef struct {
    SoftBusMutex lock;
    bool lockInit;
} SoftBusTcpListenerLock;

static SoftBusTcpListenerLock g_lock = {
    .lockInit = false,
};


static void TdcLockInit(void)
{
    if (g_lock.lockInit == false) {
        if (SoftBusMutexInit(&g_lock.lock, NULL) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_INIT, "TDC lock init failed");
            return;
        }
        g_lock.lockInit = true;
    }
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
    (void)module;
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByFd(fd, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "can not match fd. fd=%{public}d", fd);
        return SOFTBUS_ERR;
    }

    if (events == SOFTBUS_SOCKET_IN) {
        int32_t channelId = channel.channelId;
        int32_t ret = TransTdcRecvData(channelId);
        if (ret == SOFTBUS_DATA_NOT_ENOUGH) {
            TRANS_LOGE(TRANS_SDK, "client process data fail, SOFTBUS_DATA_NOT_ENOUGH. channelId=%{public}d", channelId);
            return SOFTBUS_OK;
        }
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "client process data fail, channelId=%{public}d", channelId);
            TransDelDataBufNode(channelId);
            TransTdcCloseChannel(channelId);
            ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_RECV_DATA_ERR);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransTdcCreateListener(int32_t fd)
{
    static bool isInitedFlag = false;
    TdcLockInit();
    if (SoftBusMutexLock(&g_lock.lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_ERR;
    }
    if (isInitedFlag == false) {
        isInitedFlag = true;

        static SoftbusBaseListener listener = {
            .onConnectEvent = ClientTdcOnConnectEvent,
            .onDataEvent = ClientTdcOnDataEvent,
        };

        if (StartBaseClient(DIRECT_CHANNEL_CLIENT, &listener) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "start sdk base listener failed.");
            SoftBusMutexUnlock(&g_lock.lock);
            return SOFTBUS_ERR;
        }
        TRANS_LOGI(TRANS_SDK, "create sdk listener success.");
    }
    SoftBusMutexUnlock(&g_lock.lock);

    return AddTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
}

void TransTdcReleaseFd(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGI(TRANS_SDK, "fd less than zero");
        return;
    }
    DelTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
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
