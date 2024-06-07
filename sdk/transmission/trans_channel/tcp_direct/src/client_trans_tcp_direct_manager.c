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
#define TCP_KEEPALIVE_INTERVAL 2
#define TCP_KEEPALIVE_COUNT 5
#define USER_TIME_OUT (305 * 1000)

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
    if (ServerIpcCloseChannel(NULL, channelId, CHANNEL_TYPE_TCP_DIRECT) != SOFTBUS_OK) {
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
    if (strcpy_s(item->detail.myIp, IP_LEN, channel->myIp) != EOK) {
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "myIp copy failed");
        return NULL;
    }
    return item;
}

static int32_t ClientTransCheckTdcChannelExist(int32_t channelId)
{
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            TRANS_LOGE(TRANS_SDK, "tcp direct already exist. channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_EXIST;
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
    TRANS_CHECK_AND_RETURN_RET_LOGE(sessionName != NULL && channel != NULL,
        SOFTBUS_INVALID_PARAM, TRANS_SDK, "param invalid");

    int32_t ret = ClientTransCheckTdcChannelExist(channel->channelId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_FILE, "check tdc channel fail!");

    TcpDirectChannelInfo *item = TransGetNewTcpChannel(channel);
    TRANS_CHECK_AND_RETURN_RET_LOGE(item != NULL, SOFTBUS_MEM_ERR,
        TRANS_SDK, "get new tcp channel err. channelId=%{public}d", channel->channelId);
    ret = TransAddDataBufNode(channel->channelId, channel->fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add node fail. channelId=%{public}d, fd=%{public}d", channel->channelId, channel->fd);
        SoftBusFree(item);
        return ret;
    }
    ret = TransTdcCreateListener(channel->fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans tdc create listener failed. fd=%{public}d", channel->fd);
        goto EXIT_ERR;
    }
    ret = ConnSetTcpKeepalive(channel->fd, HEART_TIME, TCP_KEEPALIVE_INTERVAL, TCP_KEEPALIVE_COUNT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpKeepalive failed, fd=%{public}d.", channel->fd);
        goto EXIT_ERR;
    }
    ret = ConnSetTcpUserTimeOut(channel->fd, USER_TIME_OUT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpUserTimeOut failed, fd=%{public}d.", channel->fd);
        goto EXIT_ERR;
    }
    ret = SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        goto EXIT_ERR;
    }
    ListAdd(&g_tcpDirectChannelInfoList->list, &item->node);
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d", item->channelId);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    ret = ClientTransTdcOnSessionOpened(sessionName, channel);
    if (ret != SOFTBUS_OK) {
        TransDelDataBufNode(channel->channelId);
        TransTdcDelChannelInfo(channel->channelId);
        TRANS_LOGE(TRANS_SDK, "notify on session opened err.");
        return ret;
    }
    return SOFTBUS_OK;
EXIT_ERR:
    TransDelDataBufNode(channel->channelId);
    SoftBusFree(item);
    return ret;
}

int32_t TransTdcManagerInit(const IClientSessionCallBack *callback)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    if (g_tcpDirectChannelInfoList == NULL || TransDataListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init tcp direct channel fail.");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = ClientTransTdcSetCallBack(callback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClientTransTdcSetCallBack fail, ret=%{public}d", ret);
        return ret;
    }
    ret = PendingInit(PENDING_TYPE_DIRECT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans direct pending init failed, ret=%{public}d", ret);
        return SOFTBUS_NO_INIT;
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
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
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
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    *handle = channel.detail.fd;
    return SOFTBUS_OK;
}

int32_t TransDisableSessionListener(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    if (channel.detail.fd < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid handle.");
        return SOFTBUS_INVALID_FD;
    }
    return TransTdcStopRead(channel.detail.fd);
}
