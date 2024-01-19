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
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_server_proxy.h"

#define HEART_TIME 300
#define USER_TIME_OUT (30 * 1000)

static SoftBusList *g_tcpDirectChannelInfoList = NULL;

static bool CheckInfoAndMutexLock(TcpDirectChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return false;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return false;
    }
    return true;
}

TcpDirectChannelInfo *TransTdcGetInfoById(int32_t channelId, TcpDirectChannelInfo *info)
{
    if (!CheckInfoAndMutexLock(info)) {
        return NULL;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

TcpDirectChannelInfo *TransTdcGetInfoByIdWithIncSeq(int32_t channelId, TcpDirectChannelInfo *info)
{
    if (!CheckInfoAndMutexLock(info)) {
        return NULL;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            item->detail.sequence++;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

TcpDirectChannelInfo *TransTdcGetInfoByFd(int32_t fd, TcpDirectChannelInfo *info)
{
    if (!CheckInfoAndMutexLock(info)) {
        return NULL;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->detail.fd == fd) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

void TransTdcCloseChannel(int32_t channelId)
{
    TRANS_LOGI(TRANS_SDK, "Close tdc Channel, channelId=%{public}d.", channelId);
    if (ServerIpcCloseChannel(channelId, CHANNEL_TYPE_TCP_DIRECT) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "close server tdc channelId=%{public}d err.", channelId);
    }

    TcpDirectChannelInfo *item = NULL;
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }

    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TransTdcReleaseFd(item->detail.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            item = NULL;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            DelPendingPacket(channelId, PENDING_TYPE_DIRECT);
            TRANS_LOGI(TRANS_SDK, "Delete tdc item success. channelId=%{public}d", channelId);
            return;
        }
    }

    TRANS_LOGE(TRANS_SDK, "Target item not exist. channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
}

static TcpDirectChannelInfo *TransGetNewTcpChannel(const ChannelInfo *channel)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return NULL;
    }
    TcpDirectChannelInfo *item = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    if (item == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc failed");
        return NULL;
    }
    item->channelId = channel->channelId;
    item->detail.fd = channel->fd;
    item->detail.channelType = channel->channelType;
    if (memcpy_s(item->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "sessionKey copy failed");
        return NULL;
    }
    return item;
}

static int32_t ClientTransCheckTdcChannelExist(int32_t channelId)
{
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_ERR;
    }
    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TRANS_LOGE(TRANS_SDK, "tcp direct already exist. channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_ERR;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_OK;
}

static void TransTdcDelChannelInfo(int32_t channelId)
{
    TRANS_LOGI(TRANS_SDK, "Delete tdc channelId=%{public}d.", channelId);

    TcpDirectChannelInfo *item = NULL;
    TcpDirectChannelInfo *nextNode = NULL;
    if (g_tcpDirectChannelInfoList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextNode, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TransTdcReleaseFd(item->detail.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            item = NULL;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            TRANS_LOGI(TRANS_SDK, "Delete tdc item success. channelId=%{public}d", channelId);
            return;
        }
    }

    TRANS_LOGE(TRANS_SDK, "Target item not exist. channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
}

int32_t ClientTransTdcOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return SOFTBUS_ERR;
    }
    if (ClientTransCheckTdcChannelExist(channel->channelId) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    TcpDirectChannelInfo *item = TransGetNewTcpChannel(channel);
    if (item == NULL) {
        TRANS_LOGE(TRANS_SDK, "get new tcp channel err. channelId=%{public}d", channel->channelId);
        return SOFTBUS_ERR;
    }
    if (TransAddDataBufNode(channel->channelId, channel->fd) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK,
            "add data buf node fail. channelId=%{public}d, fd=%{public}d", channel->channelId, channel->fd);
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    if (TransTdcCreateListener(channel->fd) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans tdc create listener failed. fd=%{public}d", channel->fd);
        goto EXIT_ERR;
    }
    if (ConnSetTcpKeepAlive(channel->fd, HEART_TIME) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpKeepAlive failed, fd=%{public}d.", channel->fd);
        goto EXIT_ERR;
    }
    if (ConnSetTcpUserTimeOut(channel->fd, USER_TIME_OUT) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpUserTimeOut failed, fd=%{public}d.", channel->fd);
        goto EXIT_ERR;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        goto EXIT_ERR;
    }
    ListAdd(&g_tcpDirectChannelInfoList->list, &item->node);
    TRANS_LOGI(TRANS_SDK, "add channelId = %{public}d", item->channelId);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    if (ClientTransTdcOnSessionOpened(sessionName, channel) != SOFTBUS_OK) {
        TransDelDataBufNode(channel->channelId);
        TransTdcDelChannelInfo(channel->channelId);
        TRANS_LOGE(TRANS_SDK, "notify on session opened err.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
EXIT_ERR:
    TransDelDataBufNode(channel->channelId);
    SoftBusFree(item);
    return SOFTBUS_ERR;
}

int32_t TransTdcManagerInit(const IClientSessionCallBack *callback)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    if (g_tcpDirectChannelInfoList == NULL || TransDataListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init tcp direct channel fail.");
        return SOFTBUS_ERR;
    }
    if (ClientTransTdcSetCallBack(callback) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClientTransTdcSetCallBack fail.");
        return SOFTBUS_ERR;
    }
    if (PendingInit(PENDING_TYPE_DIRECT) == SOFTBUS_ERR) {
        TRANS_LOGE(TRANS_INIT, "trans direct pending init failed.");
        return SOFTBUS_ERR;
    }
    TRANS_LOGE(TRANS_INIT, "init tcp direct channel success.");
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

int32_t ClientTransTdcOnChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    return ClientTransTdcOnSessionOpenFailed(channelId, errCode);
}

int32_t TransTdcGetSessionKey(int32_t channelId, char *key, unsigned int len)
{
    if (key == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(key, len, channel.detail.sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "copy session key failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcGetHandle(int32_t channelId, int *handle)
{
    if (handle == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    *handle = channel.detail.fd;
    return SOFTBUS_OK;
}

int32_t TransDisableSessionListener(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    if (channel.detail.fd < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid handle.");
        return SOFTBUS_ERR;
    }
    return TransTdcStopRead(channel.detail.fd);
}
