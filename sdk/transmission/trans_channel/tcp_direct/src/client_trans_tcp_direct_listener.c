/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "client_trans_channel_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "securec.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_property.h"
#include "softbus_tcp_socket.h"
#include "softbus_type_def.h"
#include "trans_pending_pkt.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int32_t OnConnectEvent(int events, int cfd, const char *ip)
{
    (void)events;
    (void)cfd;
    (void)ip;
    return SOFTBUS_OK;
}

static int32_t OnDataEvent(int events, int32_t fd)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByFd(fd, &channel) == NULL) {
        LOG_WARN("can not match fd.(%d)", fd);
        return SOFTBUS_ERR;
    }

    if (events == SOFTBUS_SOCKET_IN) {
        int32_t channelId = channel.channelId;
        char *data = (char *)SoftBusCalloc(MAX_BUF_LENGTH);
        if (data == NULL) {
            LOG_ERR("malloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
        int32_t ret = TransTdcPreProcessRecvData(fd, data, MAX_BUF_LENGTH);
        if (ret != SOFTBUS_OK) {
            TransTdcCloseChannel(channelId);
            TransOnChannelClosed(NULL, channelId);
            SoftBusFree(data);
            LOG_ERR("preparing for data processing failed.[%d]", ret);
            return ret;
        }
        if (TransTdcProcessRecvData(channelId, data) != SOFTBUS_OK) {
            TransTdcCloseChannel(channelId);
            TransOnChannelClosed(NULL, channelId);
            SoftBusFree(data);
            LOG_ERR("process data failed.");
            return SOFTBUS_ERR;
        }
        SoftBusFree(data);
    }

    return SOFTBUS_OK;
}

static SoftbusBaseListener g_listener = {
    .onConnectEvent = OnConnectEvent,
    .onDataEvent = OnDataEvent,
};

int32_t TransTdcCreateListener(int32_t fd)
{
    static bool isInitedFlag = false;
    pthread_mutex_lock(&g_lock);
    if (isInitedFlag == false) {
        isInitedFlag = true;

        if (SetSoftbusBaseListener(DIRECT_CHANNEL_CLIENT, &g_listener) != SOFTBUS_OK) {
            LOG_ERR("start sdk base listener failed.");
            pthread_mutex_unlock(&g_lock);
            return SOFTBUS_ERR;
        }
        if (StartBaseClient(DIRECT_CHANNEL_CLIENT) < SOFTBUS_OK) {
            LOG_ERR("client start base listener failed.");
            pthread_mutex_unlock(&g_lock);
            return SOFTBUS_ERR;
        }
        LOG_INFO("create sdk listener success.");
    }
    pthread_mutex_unlock(&g_lock);

    return AddTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
}

void TransTdcReleaseFd(int32_t fd)
{
    if (fd < 0) {
        return;
    }
    DelTrigger(DIRECT_CHANNEL_CLIENT, fd, READ_TRIGGER);
    TcpShutDown(fd);
}
