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

#include "client_trans_tcp_direct_manager.h"

#include <securec.h>

#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "trans_pending_pkt.h"

#define HEART_TIME 300
static SoftBusList *g_tcpDirectChannelInfoList = NULL;

TcpDirectChannelInfo *TransTdcGetInfoById(int32_t channelId, TcpDirectChannelInfo *info)
{
    TcpDirectChannelInfo *item = NULL;

    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            if (info != NULL) {
                (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            }
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

TcpDirectChannelInfo *TransTdcGetInfoByIdWithIncSeq(int32_t channelId, TcpDirectChannelInfo *info)
{
    TcpDirectChannelInfo *item = NULL;

    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            item->detail.sequence++;
            if (info != NULL) {
                (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            }
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

TcpDirectChannelInfo *TransTdcGetInfoByFd(int32_t fd, TcpDirectChannelInfo *info)
{
    TcpDirectChannelInfo *item = NULL;

    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->detail.fd == fd) {
            if (info != NULL) {
                (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            }
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

int32_t TransTdcCheckSeq(int32_t fd, int32_t seq)
{
    TcpDirectChannelInfo *item = NULL;

    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->detail.fd == fd) {
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            if (!IsPassSeqCheck(&(item->detail.verifyInfo), seq)) {
                LOG_WARN("SeqCheck is false");
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_ERR;
}

void TransTdcCloseChannel(int32_t channelId)
{
    LOG_INFO("TransCloseTcpDirectChannel, channelId [%d]", channelId);

    TcpDirectChannelInfo *item = NULL;
    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TransTdcReleaseFd(item->detail.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            item = NULL;
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            DelPendingPacketById(channelId, PENDING_TYPE_DIRECT);
            LOG_INFO("Delete chanel item success.");
            return;
        }
    }

    LOG_ERR("Target channel item not exist.");
    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
}

int32_t TransTdcOnChannelOpened(const ChannelInfo *channel)
{
    if (channel == NULL) {
        LOG_ERR("Para wrong");
        return SOFTBUS_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channel->channelId) {
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            LOG_ERR("tcp direct channel id exist already.");
            return SOFTBUS_ERR;
        }
    }

    item = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    if (item == NULL) {
        (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
        LOG_ERR("create tdc channel info failed");
        return SOFTBUS_ERR;
    }
    item->channelId = channel->channelId;
    item->detail.fd = channel->fd;
    item->detail.type = channel->channelType;
    if (memcpy_s(item->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusFree(item);
        (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
        LOG_ERR("memcpy_s failed");
        return SOFTBUS_ERR;
    }
    ListAdd(&g_tcpDirectChannelInfoList->list, &item->node);

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);

    if (TransTdcCreateListener(item->detail.fd) != SOFTBUS_OK) {
        LOG_ERR("trans tcp direct create listener failed.");
        return SOFTBUS_ERR;
    }

    int32_t ret = SetTcpKeepAlive(channel->fd, HEART_TIME);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("SetTcpKeepAlive failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcManagerInit(void)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    if (g_tcpDirectChannelInfoList == NULL) {
        LOG_ERR("init tcp direct channel info list fail.");
        return SOFTBUS_ERR;
    }
    LOG_INFO("init tcp direct channel info list success.");
    return SOFTBUS_OK;
}

void TransTdcManagerDeinit(void)
{
    if (g_tcpDirectChannelInfoList == NULL) {
        return;
    }

    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = NULL;
}

