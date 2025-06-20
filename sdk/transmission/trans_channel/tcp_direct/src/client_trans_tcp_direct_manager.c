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

#include "client_trans_tcp_direct_manager.h"

#include <securec.h>

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_listener.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_server_proxy.h"
#include "client_bus_center_manager.h"
#include "softbus_mintp_socket.h"

#define HEART_TIME             300
#define TCP_KEEPALIVE_INTERVAL 4
#define TCP_KEEPALIVE_COUNT    5
#define USER_TIME_OUT          (320 * 1000)
#define MS_TO_US               1000

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

int32_t TransTdcGetInfoById(int32_t channelId, TcpDirectChannelInfo *info)
{
    if (!CheckInfoAndMutexLock(info)) {
        return SOFTBUS_LOCK_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_NOT_FIND;
}

int32_t TransTdcSetListenerStateById(int32_t channelId, bool needStopListener)
{
    if (g_tcpDirectChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDirectChannelInfoList is NULL, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed, channelId=%{public}d", channelId);
        return SOFTBUS_LOCK_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            item->detail.needStopListener = needStopListener;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            TRANS_LOGI(TRANS_SDK, "succ, channelId=%{public}d, needStopListener=%{public}d", channelId,
                needStopListener);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "channel not found, channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

TcpDirectChannelInfo *TransTdcGetInfoIncFdRefById(int32_t channelId, TcpDirectChannelInfo *info, bool withSeq)
{
    if (!CheckInfoAndMutexLock(info)) {
        return NULL;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            item->detail.sequence = withSeq ? (item->detail.sequence + 1) : (item->detail.sequence);
            item->detail.fdRefCnt++;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return item;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return NULL;
}

int32_t TransTdcGetInfoByFd(int32_t fd, TcpDirectChannelInfo *info)
{
    if (!CheckInfoAndMutexLock(info)) {
        return SOFTBUS_LOCK_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->detail.fd == fd) {
            (void)memcpy_s(info, sizeof(TcpDirectChannelInfo), item, sizeof(TcpDirectChannelInfo));
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_NOT_FIND;
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
        if (item->channelId != channelId) {
            continue;
        }

        item->detail.needRelease = true;
        if (item->detail.fdRefCnt <= 0) {
            TransTdcReleaseFd(item->detail.fd);
            (void)SoftBusMutexDestroy(&(item->detail.fdLock));
            ListDelete(&item->node);
            SoftBusFree(item);
            item = NULL;
        }
        (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
        DelPendingPacket(channelId, PENDING_TYPE_DIRECT);
        TRANS_LOGI(TRANS_SDK, "Delete tdc item success. channelId=%{public}d", channelId);
        return;
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
    item->detail.isLowLatency = channel->isLowLatency;
    item->detail.fdProtocol = channel->fdProtocol;
    item->detail.peerPort = channel->peerPort;
    if (SoftBusMutexInit(&(item->detail.fdLock), NULL) != SOFTBUS_OK) {
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "init fd lock failed");
        return NULL;
    }
    if (memcpy_s(item->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, SESSION_KEY_LENGTH) != EOK) {
        (void)SoftBusMutexDestroy(&(item->detail.fdLock));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "sessionKey copy failed");
        return NULL;
    }
    if (strcpy_s(item->detail.myIp, IP_LEN, channel->myIp) != EOK) {
        (void)SoftBusMutexDestroy(&(item->detail.fdLock));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "myIp copy failed");
        return NULL;
    }
    if (strcpy_s(item->detail.peerIp, IP_LEN, channel->peerIp) != EOK) {
        (void)SoftBusMutexDestroy(&(item->detail.fdLock));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "peerIp copy failed");
        return NULL;
    }
    if (strcpy_s(item->detail.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK) {
        (void)SoftBusMutexDestroy(&(item->detail.fdLock));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "peerDeviceId copy failed");
        return NULL;
    }
    if (strcpy_s(item->detail.pkgName, PKG_NAME_SIZE_MAX, channel->pkgName) != EOK) {
        (void)SoftBusMutexDestroy(&(item->detail.fdLock));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SDK, "pkgName copy failed");
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

static void TransTdcReleaseFdResources(int32_t fd, int32_t errCode)
{
    if (errCode == SOFTBUS_TRANS_NEGOTIATE_REJECTED) {
        TransTdcCloseFd(fd);
        TRANS_LOGI(
            TRANS_SDK, "Server reject conn, fd=%{public}d", fd);
    } else {
        TransTdcReleaseFd(fd);
    }
}

static void TransTdcDelChannelInfo(int32_t channelId, int32_t errCode)
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
            item->detail.needRelease = true;
            if (item->detail.fdRefCnt <= 0) {
                TransTdcReleaseFdResources(item->detail.fd, errCode);
                (void)SoftBusMutexDestroy(&(item->detail.fdLock));
                ListDelete(&item->node);
                SoftBusFree(item);
                item = NULL;
            }
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            TRANS_LOGI(TRANS_SDK, "Delete tdc item success. channelId=%{public}d", channelId);
            return;
        }
    }

    TRANS_LOGE(TRANS_SDK, "Target item not exist. channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
}

static int32_t ClientTransTdcHandleListener(const char *sessionName, const ChannelInfo *channel)
{
    bool isSocket = false;
    int32_t ret = ClientTransTdcIfChannelForSocket(sessionName, &isSocket);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel socket fail, channelId=%{public}d", channel->channelId);
        return ret;
    }

    if (channel->isServer && isSocket) {
        TRANS_LOGI(TRANS_SDK, "no need listen here, channelId=%{public}d", channel->channelId);
        return SOFTBUS_OK;
    }

    ret = TransTdcCreateListenerWithoutAddTrigger(channel->fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "create listener fail, channelId=%{public}d", channel->channelId);
        return ret;
    }
    if (g_tcpDirectChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDirectChannelInfoList is NULL, channelId=%{public}d", channel->channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed, channelId=%{public}d", channel->channelId);
        return SOFTBUS_LOCK_ERR;
    }

    TcpDirectChannelInfo info;
    (void)memset_s(&info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    ret = TransTdcGetInfoById(channel->channelId, &info);
    if (ret != SOFTBUS_OK) {
        DelTrigger(DIRECT_CHANNEL_CLIENT, channel->fd, READ_TRIGGER);
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoById failed, channelId=%{public}d", channel->channelId);
        (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
        return SOFTBUS_NOT_FIND;
    }

    if (!info.detail.needStopListener) {
        TRANS_LOGI(TRANS_SDK, "info.detail.needStopListener false, channelId=%{public}d", channel->channelId);
        AddTrigger(DIRECT_CHANNEL_CLIENT, channel->fd, READ_TRIGGER);
    }
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_OK;
}

static int32_t ClientTransSetTcpOption(int32_t fd)
{
    int32_t ret = ConnSetTcpKeepalive(fd, HEART_TIME, TCP_KEEPALIVE_INTERVAL, TCP_KEEPALIVE_COUNT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpKeepalive failed, fd=%{public}d.", fd);
        return ret;
    }
    ret = ConnSetTcpUserTimeOut(fd, USER_TIME_OUT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ConnSetTcpUserTimeOut failed, fd=%{public}d.", fd);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetFdByPeerIpAndPort(const char *peerIp, uint16_t peerPort, int32_t *fd)
{
    if (g_tcpDirectChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDirectChannelInfoList is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (strcmp(item->detail.peerIp, peerIp) == 0 && item->detail.peerPort == peerPort) {
            *fd = item->detail.fd;
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "channel not found, peerPort=%{public}d", peerPort);
    return SOFTBUS_NOT_FIND;
}

static void OnTimeSyncResultByIp(const TimeSyncResultWithSocket *info, int32_t result)
{
    if (result != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SDK, "time sync err, result=%{public}d", result);
        return;
    }
    if (info == NULL) {
        TRANS_LOGW(TRANS_SDK, "time sync info is null");
        return;
    }
    int32_t fd = -1;
    int32_t ret = GetFdByPeerIpAndPort(info->targetSocketInfo.peerIp, info->targetSocketInfo.peerPort, &fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get fd by peer ip and port failed, ret=%{public}d", ret);
        return;
    }
    MintpTimeSync timeSync;
    timeSync.valid = 1;
    timeSync.offset = info->result.millisecond * MS_TO_US + info->result.microsecond;
    ret = SetMintpSocketTimeSync(fd, &timeSync);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SDK, "SetMintpSocketTimeSync failed, ret=%{public}d", ret);
        return;
    }
    TRANS_LOGI(TRANS_SDK, "time sync success, offset=%{public}d", timeSync.offset);
}

static ITimeSyncCbWithSocket g_timeSyncCallback = {
    .onTimeSyncResultWithSocket = OnTimeSyncResultByIp,
};

static int32_t TransStartTimeSync(const ChannelInfo *channel)
{
    TimeSyncSocketInfo socketInfo;
    if (strcpy_s(socketInfo.peerIp, IP_STR_MAX_LEN, channel->peerIp) != EOK) {
        TRANS_LOGE(TRANS_SDK, "peerIp copy failed");
        return SOFTBUS_STRCPY_ERR;
    }
    socketInfo.peerPort = channel->peerPort;
    if (strcpy_s(socketInfo.targetNetworkId, NETWORK_ID_BUF_LEN, channel->peerDeviceId) != EOK) {
        TRANS_LOGE(TRANS_SDK, "targetNetworkId copy failed");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret =
        StartTimeSyncWithSocketInner(channel->pkgName, &socketInfo, HIGH_ACCURACY, SHORT_PERIOD, &g_timeSyncCallback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "StartTimeSync failed, ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "StartTimeSync success");
    return SOFTBUS_OK;
}

int32_t ClientTransTdcOnChannelOpened(const char *sessionName, const ChannelInfo *channel, SocketAccessInfo *accessInfo)
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
    if (channel->fdProtocol != LNN_PROTOCOL_MINTP) {
        ret = ClientTransSetTcpOption(channel->fd);
        if (ret != SOFTBUS_OK) {
            goto EXIT_ERR;
        }
    }
    ret = SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        goto EXIT_ERR;
    }
    ListAdd(&g_tcpDirectChannelInfoList->list, &item->node);
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d, fd=%{public}d", item->channelId, channel->fd);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    if (channel->fdProtocol == LNN_PROTOCOL_MINTP && !channel->isServer) {
        (void)TransStartTimeSync(channel);
    }
    ret = ClientTransTdcOnSessionOpened(sessionName, channel, accessInfo);
    if (ret != SOFTBUS_OK) {
        TransDelDataBufNode(channel->channelId);
        TransTdcDelChannelInfo(channel->channelId, ret);
        TRANS_LOGE(TRANS_SDK, "notify on session opened err.");
        return ret;
    }

    ret = ClientTransTdcHandleListener(sessionName, channel);
    if (ret != SOFTBUS_OK) {
        ClientTransTdcOnSessionClosed(channel->channelId, SHUTDOWN_REASON_LOCAL);
        TransDelDataBufNode(channel->channelId);
        TransTdcDelChannelInfo(channel->channelId, ret);
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
    TdcLockDeinit();
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
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
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
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    *handle = channel.detail.fd;
    return SOFTBUS_OK;
}

int32_t TransDisableSessionListener(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get tdc info failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    if (channel.detail.fd < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid handle.");
        return SOFTBUS_INVALID_FD;
    }
    if (g_tcpDirectChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDirectChannelInfoList is NULL, channelId=%{public}d", channelId);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed, channelId=%{public}d", channelId);
        return SOFTBUS_LOCK_ERR;
    }

    (void)TransTdcSetListenerStateById(channelId, true);
    int32_t ret = TransTdcStopRead(channel.detail.fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SDK, "stop read failed. channelId=%{public}d, ret=%{public}d", channelId, ret);
    }
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    return SOFTBUS_OK;
}

void TransUpdateFdState(int32_t channelId)
{
    if (g_tcpDirectChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDirectChannelInfoList is NULL, channelId=%{public}d", channelId);
        return;
    }
    if (SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed, channelId=%{public}d", channelId);
        return;
    }

    TcpDirectChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDirectChannelInfoList->list), TcpDirectChannelInfo, node) {
        if (item->channelId == channelId) {
            item->detail.fdRefCnt--;
            if (item->detail.needRelease && item->detail.fdRefCnt <= 0) {
                TransTdcReleaseFd(item->detail.fd);
                (void)SoftBusMutexDestroy(&(item->detail.fdLock));
                ListDelete(&item->node);
                SoftBusFree(item);
                item = NULL;
                TRANS_LOGI(TRANS_SDK, "Delete tdc item success. channelId=%{public}d", channelId);
            }
            (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
            return;
        }
    }

    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "channel not found, channelId=%{public}d", channelId);
    return;
}

int32_t TransStopTimeSync(int32_t channelId)
{
    TcpDirectChannelInfo info;
    (void)memset_s(&info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    int32_t ret = TransTdcGetInfoById(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoById failed, channelId=%{public}d", channelId);
        return ret;
    }
    if (info.detail.fdProtocol != LNN_PROTOCOL_MINTP) {
        return SOFTBUS_OK;
    }
    TimeSyncSocketInfo socketInfo;
    if (strcpy_s(socketInfo.peerIp, IP_STR_MAX_LEN, info.detail.peerIp) != EOK) {
        TRANS_LOGE(TRANS_SDK, "peerIp copy failed");
        return SOFTBUS_STRCPY_ERR;
    }
    socketInfo.peerPort = info.detail.peerPort;
    if (strcpy_s(socketInfo.targetNetworkId, NETWORK_ID_BUF_LEN, info.detail.peerDeviceId) != EOK) {
        TRANS_LOGE(TRANS_SDK, "targetNetworkId copy failed");
        return SOFTBUS_STRCPY_ERR;
    }
    ret = StopTimeSyncWithSocketInner(info.detail.pkgName, &socketInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "StopTimeSync failed, ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "StopTimeSync success");
    return SOFTBUS_OK;
}
