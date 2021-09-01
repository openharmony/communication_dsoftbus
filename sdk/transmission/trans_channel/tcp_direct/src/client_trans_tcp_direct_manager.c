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

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_listener.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
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
            if (info != NULL) {
                (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            }
            item->detail.sequence++;
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
            if (!IsPassSeqCheck(&(item->detail.verifyInfo), seq)) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "SeqCheck is false");
                (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
                return SOFTBUS_ERR;
            }
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_ERR;
}

void TransTdcCloseChannel(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransCloseTcpDirectChannel, channelId [%d]", channelId);

    TcpDirectChannelInfo *item = NULL;
    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TransTdcReleaseFd(item->detail.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            item = NULL;
            (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
            DelPendingPacket(channelId, PENDING_TYPE_DIRECT);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Delete chanel item success.");
            return;
        }
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Target channel item not exist.");
    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
}

static TcpDirectChannelInfo *TransGetNewTcpChannel(const ChannelInfo *channel)
{
    TcpDirectChannelInfo *item = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    if (item == NULL) {
        return NULL;
    }
    item->channelId = channel->channelId;
    item->detail.fd = channel->fd;
    item->detail.channelType = channel->channelType;
    if (memcpy_s(item->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusFree(item);
        return NULL;
    }
    return item;
}

int32_t ClientTransTdcOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        return SOFTBUS_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    (void)pthread_mutex_lock(&g_tcpDirectChannelInfoList->lock);
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channel->channelId) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp direct channel id exist already.");
            goto EXIT_ERR;
        }
    }

    item = TransGetNewTcpChannel(channel);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get new channel err");
        goto EXIT_ERR;
    }

    if (TransAddDataBufNode(channel->channelId, channel->fd) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add data buf node fail.");
        SoftBusFree(item);
        goto EXIT_ERR;
    }
    if (TransTdcCreateListener(channel->fd) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans tcp direct create listener failed.");
        TransDelDataBufNode(channel->channelId);
        SoftBusFree(item);
        goto EXIT_ERR;
    }

    int32_t ret = SetTcpKeepAlive(channel->fd, HEART_TIME);
    if (ret != SOFTBUS_OK) {
        TransDelDataBufNode(channel->channelId);
        SoftBusFree(item);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetTcpKeepAlive failed.");
        goto EXIT_ERR;
    }

    ListAdd(&g_tcpDirectChannelInfoList->list, &item->node);
    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);

    if (ClientTransTdcOnSessionOpened(sessionName, channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify on session opened err.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
EXIT_ERR:
    (void)pthread_mutex_unlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_ERR;
}

int32_t TransTdcManagerInit(const IClientSessionCallBack *cb)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    if (g_tcpDirectChannelInfoList == NULL || TransDataListInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init tcp direct channel fail.");
        return SOFTBUS_ERR;
    }
    if (ClientTransTdcSetCallBack(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (PendingInit(PENDING_TYPE_DIRECT) == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans direct pending init failed.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "init tcp direct channel success.");
    return SOFTBUS_OK;
}

void TransTdcManagerDeinit(void)
{
    if (g_tcpDirectChannelInfoList == NULL) {
        return;
    }

    TransDataListDeinit();
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = NULL;
    PendingDeinit(PENDING_TYPE_DIRECT);
}

int32_t ClientTransTdcOnChannelOpenFailed(int32_t channelId)
{
    return ClientTransTdcOnSessionOpenFailed(channelId);
}

