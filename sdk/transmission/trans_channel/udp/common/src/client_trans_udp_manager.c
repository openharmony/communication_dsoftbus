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

#include "client_trans_udp_manager.h"

#include <stdbool.h>
#include "client_trans_file.h"
#include "client_trans_file_listener.h"
#include "client_trans_socket_manager.h"
#include "client_trans_stream.h"
#include "nstackx_dfile.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_server_proxy.h"

#define LIMIT_CHANGE_INFO_NUM 2

static SoftBusList *g_udpChannelMgr = NULL;
static IClientSessionCallBack *g_sessionCb = NULL;

static int32_t ClientTransAddUdpChannel(UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channel->channelId) {
            TRANS_LOGE(TRANS_SDK, "udp channel has exited.channelId=%{public}d.", channel->channelId);
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST;
        }
    }
    ListInit(&(channel->node));
    ListAdd(&(g_udpChannelMgr->list), &(channel->node));
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d", channel->channelId);
    g_udpChannelMgr->cnt++;

    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_OK;
}

int32_t TransDeleteUdpChannel(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            ListDelete(&(channelNode->node));
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(channelNode);
            g_udpChannelMgr->cnt--;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (channel == NULL) {
        TRANS_LOGE(TRANS_INIT, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            if (memcpy_s(channel, sizeof(UdpChannel), channelNode, sizeof(UdpChannel)) != EOK) {
                TRANS_LOGE(TRANS_SDK, "get udp channel memcpy_s failed.");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

static int32_t TransSetUdpChannelEnable(int32_t channelId, bool isEnable)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            channelNode->isEnable = isEnable;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

static int32_t OnUdpChannelOpened(int32_t channelId)
{
    UdpChannel channel;
    if (memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "on udp channel opened memset failed.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = TransGetUdpChannel(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp failed. channelId=%{public}d, ret=%{public}d", channelId, ret);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    ret = TransSetUdpChannelEnable(channelId, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set udp enable failed. channelId=%{public}d, ret=%{public}d", channelId, ret);
        return SOFTBUS_TRANS_UDP_SET_CHANNEL_FAILED;
    }
    SessionType type = TYPE_BUTT;
    switch (channel.businessType) {
        case BUSINESS_TYPE_STREAM:
            type = TYPE_STREAM;
            break;
        case BUSINESS_TYPE_FILE:
            type = TYPE_FILE;
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "unsupport businessType=%{public}d.", channel.businessType);
            return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }
    ChannelInfo info = {0};
    info.channelId = channel.channelId;
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = channel.info.isServer;
    info.peerPid = channel.info.peerPid;
    info.peerUid = channel.info.peerUid;
    info.groupId = channel.info.groupId;
    info.peerDeviceId = channel.info.peerDeviceId;
    info.peerSessionName = channel.info.peerSessionName;
    info.routeType = channel.routeType;
    info.businessType = channel.businessType;
    if ((g_sessionCb != NULL) && (g_sessionCb->OnSessionOpened != NULL)) {
        return g_sessionCb->OnSessionOpened(channel.info.mySessionName, &info, type);
    }
    return SOFTBUS_NO_INIT;
}

static UdpChannel *ConvertChannelInfoToUdpChannel(const char *sessionName, const ChannelInfo *channel)
{
    UdpChannel *newChannel = (UdpChannel *)SoftBusCalloc(sizeof(UdpChannel));
    if (newChannel == NULL) {
        TRANS_LOGE(TRANS_SDK, "new udp channel failed.");
        return NULL;
    }
    newChannel->businessType = channel->businessType;
    newChannel->channelId = channel->channelId;
    newChannel->dfileId = -1;
    newChannel->isEnable = false;
    newChannel->info.isServer = channel->isServer;
    newChannel->info.peerPid = channel->peerPid;
    newChannel->info.peerUid = channel->peerUid;
    newChannel->routeType = channel->routeType;
    if (strcpy_s(newChannel->info.peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK ||
        strcpy_s(newChannel->info.mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        strcpy_s(newChannel->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK ||
        strcpy_s(newChannel->info.groupId, GROUP_ID_SIZE_MAX, channel->groupId) != EOK ||
        strcpy_s(newChannel->info.myIp, sizeof(newChannel->info.myIp), channel->myIp) != EOK) {
        TRANS_LOGE(TRANS_SDK, "udp channel or peer session name, device id, group id, myIp failed");
        SoftBusFree(newChannel);
        return NULL;
    }

    return newChannel;
}

static int32_t TransSetdFileIdByChannelId(int32_t channelId, int32_t value)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            channelNode->dfileId = value;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *udpPort)
{
    TRANS_LOGD(TRANS_SDK, "TransOnUdpChannelOpened enter");
    if (channel == NULL || udpPort == NULL || sessionName == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    UdpChannel *newChannel = ConvertChannelInfoToUdpChannel(sessionName, channel);
    if (newChannel == NULL) {
        TRANS_LOGE(TRANS_SDK, "convert channel info to udp channel failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (ClientTransAddUdpChannel(newChannel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add udp channel failed.");
        SoftBusFree(newChannel);
        return SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED;
    }
    TRANS_LOGI(TRANS_SDK, "add new udp channel success, channelId=%{public}d, businessType=%{public}d",
        channel->channelId, channel->businessType);

    int32_t ret = SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    switch (channel->businessType) {
        case BUSINESS_TYPE_STREAM:
            ret = TransOnstreamChannelOpened(channel, udpPort);
            if (ret != SOFTBUS_OK) {
                (void)TransDeleteUdpChannel(channel->channelId);
                TRANS_LOGE(TRANS_SDK, "on stream channel opened failed.");
            }
            break;
        case BUSINESS_TYPE_FILE:
            ret = TransOnFileChannelOpened(sessionName, channel, udpPort);
            if (ret < SOFTBUS_OK) {
                (void)TransDeleteUdpChannel(channel->channelId);
                TRANS_LOGE(TRANS_SDK, "on file channel open failed.");
                return ret;
            }
            ret = TransSetdFileIdByChannelId(channel->channelId, ret);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "set dfileId failed, ret = %{public}d", ret);
                return ret;
            }
            ret = SOFTBUS_OK;
            break;
        default:
            (void)TransDeleteUdpChannel(channel->channelId);
            TRANS_LOGE(TRANS_SDK, "unsupport businessType=%{public}d.", channel->businessType);
            break;
    }
    return ret;
}

static int32_t TransDeleteBusinnessChannel(UdpChannel *channel)
{
    switch (channel->businessType) {
        case BUSINESS_TYPE_STREAM:
            if (TransCloseStreamChannel(channel->channelId) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "trans close udp channel failed.");
                return SOFTBUS_TRANS_CLOSE_UDP_CHANNEL_FAILED;
            }
            break;
        case BUSINESS_TYPE_FILE:
            TransCloseFileChannel(channel->dfileId);
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "unsupport businessType=%{public}d.", channel->businessType);
            return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }
    return SOFTBUS_OK;
}

int32_t TransOnUdpChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    UdpChannel channel;
    bool isFind = true;
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp channel by channelId=%{public}d failed.", channelId);
        isFind = false;
    }
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "del channelId failed. channelId=%{public}d", channelId);
    }
    if ((isFind) && (channel.isEnable)) {
        int32_t ret = TransDeleteBusinnessChannel(&channel);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "del business channel failed. channelId=%{public}d", channelId);
            return ret;
        }
    }
    if ((g_sessionCb == NULL) || (g_sessionCb->OnSessionOpenFailed == NULL)) {
        TRANS_LOGE(TRANS_SDK, "client trans udp manager seesion callback is null");
        return SOFTBUS_NO_INIT;
    }

    return g_sessionCb->OnSessionOpenFailed(channelId, CHANNEL_TYPE_UDP, errCode);
}

int32_t TransOnUdpChannelBind(int32_t channelId, int32_t channelType)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnChannelBind == NULL)) {
        TRANS_LOGE(TRANS_SDK, "client trans udp manager OnChannelBind is null channelId=%{public}d", channelId);
        return SOFTBUS_NO_INIT;
    }

    int32_t ret = g_sessionCb->OnChannelBind(channelId, CHANNEL_TYPE_UDP);
    if (ret == SOFTBUS_NOT_NEED_UPDATE) {
        ret = SOFTBUS_OK;
    }
    return ret;
}

static int32_t ClosePeerUdpChannel(int32_t channelId)
{
    return ServerIpcCloseChannel(NULL, channelId, CHANNEL_TYPE_UDP);
}

static int32_t RleaseUdpResources(int32_t channelId)
{
    return ServerIpcReleaseResources(channelId);
}

static void NotifyCallback(UdpChannel *channel, int32_t channelId, ShutdownReason reason)
{
    if (channel != NULL && (!channel->isEnable) && g_sessionCb != NULL && g_sessionCb->OnSessionOpenFailed != NULL) {
        SessionState sessionState = SESSION_STATE_INIT;
        if (ClientGetSessionStateByChannelId(channelId, CHANNEL_TYPE_UDP, &sessionState) == SOFTBUS_OK &&
            (sessionState == SESSION_STATE_OPENED || sessionState == SESSION_STATE_CALLBACK_FINISHED)) {
            if (ClosePeerUdpChannel(channelId) != SOFTBUS_OK) {
                TRANS_LOGW(TRANS_SDK, "trans close peer udp channel failed. channelId=%{public}d", channelId);
            }
        }
        g_sessionCb->OnSessionOpenFailed(channelId, CHANNEL_TYPE_UDP, SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT);
        return;
    }
    if (g_sessionCb != NULL && g_sessionCb->OnSessionClosed != NULL) {
        g_sessionCb->OnSessionClosed(channelId, CHANNEL_TYPE_UDP, reason);
        return;
    }
}

static int32_t CloseUdpChannelProc(UdpChannel *channel, int32_t channelId, ShutdownReason reason)
{
    int32_t ret;
    if (channel != NULL) {
        int32_t sessionId = channel->sessionId;
        (void)ClientSetStatusClosingBySocket(sessionId, true);
    }
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SDK, "trans del udp channel failed. channelId=%{public}d", channelId);
    }
    switch (reason) {
        case SHUTDOWN_REASON_PEER:
            break;
        case SHUTDOWN_REASON_SEND_FILE_ERR:
        case SHUTDOWN_REASON_RECV_FILE_ERR:
            if (RleaseUdpResources(channelId) != SOFTBUS_OK) {
                TRANS_LOGW(TRANS_SDK, "trans release udp resources failed. channelId=%{public}d", channelId);
            }
            break;
        case SHUTDOWN_REASON_LOCAL:
            if (ClosePeerUdpChannel(channelId) != SOFTBUS_OK) {
                TRANS_LOGW(TRANS_SDK, "trans close peer udp channel failed. channelId=%{public}d", channelId);
            }
            break;
        default:
            TRANS_LOGW(TRANS_SDK, "there's no reson to match. channelId=%{public}d, reason=%{public}d",
                channelId, (int32_t)reason);
            break;
    }

    if (channel != NULL) {
        ret = TransDeleteBusinnessChannel(channel);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "del business channel failed. channelId=%{public}d", channelId);
            return ret;
        }
    }

    if (reason != SHUTDOWN_REASON_LOCAL) {
        NotifyCallback(channel, channelId, reason);
    }
    return SOFTBUS_OK;
}

static int32_t CloseUdpChannel(int32_t channelId, ShutdownReason reason)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    TRANS_LOGI(TRANS_SDK, "close udp channelId=%{public}d, reason=%{public}d", channelId, reason);
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp channel by channelId=%{public}d failed.", channelId);
        CloseUdpChannelProc(NULL, channelId, reason);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (channel.businessType == BUSINESS_TYPE_FILE) {
        TRANS_LOGD(TRANS_SDK, "close udp channel get file list start");
        int32_t ret = NSTACKX_DFileSessionGetFileList(channel.dfileId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "close udp channel to get file list failed. channelId=%{public}d, ret=%{public}d",
                channelId, ret);
        }
    }
    return CloseUdpChannelProc(&channel, channelId, reason);
}

int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    return CloseUdpChannel(channelId, reason);
}

int32_t TransOnUdpChannelQosEvent(int32_t channelId, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get channel by channelId=%{public}d failed.", channelId);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (g_sessionCb->OnQosEvent != NULL) {
        g_sessionCb->OnQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, tvList);
    }
    return SOFTBUS_OK;
}

int32_t ClientTransCloseUdpChannel(int32_t channelId, ShutdownReason reason)
{
    int32_t ret = AddPendingPacket(channelId, 0, PENDING_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
        return ret;
    }
    ret = CloseUdpChannel(channelId, reason);
    if (ret != SOFTBUS_OK) {
        DelPendingPacketbyChannelId(channelId, 0, PENDING_TYPE_UDP);
        TRANS_LOGE(TRANS_SDK, "close udp channel failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ProcPendingPacket(channelId, 0, PENDING_TYPE_UDP);
    DelSessionStateClosing();
    return ret;
}

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get channel by channelId=%{public}d failed.", channelId);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (!channel.isEnable) {
        TRANS_LOGE(TRANS_STREAM, "udp channel is not enable channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_UDP_CHANNEL_DISABLE;
    }
    return TransSendStream(channelId, data, ext, param);
}

int32_t TransUdpChannelSetStreamMultiLayer(int32_t channelId, const void *optValue)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get channel by channelId=%{public}d failed.", channelId);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (!channel.isEnable) {
        TRANS_LOGE(TRANS_STREAM, "udp channel %{public}d is not enable.", channelId);
        return SOFTBUS_TRANS_UDP_CHANNEL_DISABLE;
    }
    return TransSetStreamMultiLayer(channelId, optValue);
}

static void OnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnSessionClosed == NULL)) {
        return;
    }
    g_sessionCb->OnSessionClosed(channelId, CHANNEL_TYPE_UDP, reason);
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans delete udp channel failed. channelId=%{public}d", channelId);
    }
}

static void OnStreamReceived(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnStreamReceived == NULL)) {
        return;
    }
    g_sessionCb->OnStreamReceived(channelId, CHANNEL_TYPE_UDP, data, ext, param);
}

static int32_t OnFileGetSessionId(int32_t channelId, int32_t *sessionId)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnGetSessionId == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return g_sessionCb->OnGetSessionId(channelId, CHANNEL_TYPE_UDP, sessionId, false);
}

static void OnQosEvent(int channelId, int eventId, int tvCount, const QosTv *tvList)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnQosEvent == NULL)) {
        return;
    }
    g_sessionCb->OnQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, tvList);
}

static int32_t OnIdleTimeoutReset(int32_t sessionId)
{
    if ((g_sessionCb == NULL) || (g_sessionCb->OnIdleTimeoutReset == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return g_sessionCb->OnIdleTimeoutReset(sessionId);
}

static int32_t OnRawStreamEncryptOptGet(int32_t channelId, bool *isEncrypt)
{
    if (channelId < 0 || isEncrypt == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_sessionCb == NULL) {
        TRANS_LOGE(TRANS_SDK, "session callback is null");
        return SOFTBUS_NO_INIT;
    }

    if (g_sessionCb->OnRawStreamEncryptOptGet == NULL) {
        TRANS_LOGE(TRANS_SDK, "OnRawStreamEncryptOptGet of session callback is null");
        return SOFTBUS_NO_INIT;
    }

    UdpChannel channel;
    if (memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "on udp channel opened memset failed.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = TransGetUdpChannel(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udpChannel failed. channelId=%{public}d", channelId);
        return ret;
    }

    if (channel.info.isServer) {
        return g_sessionCb->OnRawStreamEncryptDefOptGet(channel.info.mySessionName, isEncrypt);
    } else {
        return g_sessionCb->OnRawStreamEncryptOptGet(channel.channelId, CHANNEL_TYPE_UDP, isEncrypt);
    }
}

static UdpChannelMgrCb g_udpChannelCb = {
    .OnStreamReceived = OnStreamReceived,
    .OnFileGetSessionId = OnFileGetSessionId,
    .OnMessageReceived = NULL,
    .OnUdpChannelOpened = OnUdpChannelOpened,
    .OnUdpChannelClosed = OnUdpChannelClosed,
    .OnQosEvent = OnQosEvent,
    .OnIdleTimeoutReset = OnIdleTimeoutReset,
    .OnRawStreamEncryptOptGet = OnRawStreamEncryptOptGet,
};

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback)
{
    if (g_udpChannelMgr != NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel info manager has init.");
        return SOFTBUS_OK;
    }
    if (callback == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel info manager init failed, calback is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    g_sessionCb = callback;
    RegisterStreamCb(&g_udpChannelCb);
    TransFileInit();
    TransFileSchemaInit();
    if (PendingInit(PENDING_TYPE_UDP) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans udp pending init failed.");
        return SOFTBUS_TRANS_SERVER_INIT_FAILED;
    }
    NSTACKX_DFileRegisterLogCallback(NstackxLogInnerImpl);
    RegisterFileCb(&g_udpChannelCb);
    g_udpChannelMgr = CreateSoftBusList();
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "create udp channel manager list failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    TRANS_LOGI(TRANS_INIT, "trans udp channel manager init success.");
    return SOFTBUS_OK;
}

void ClientTransUdpMgrDeinit(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    UnregisterStreamCb();
    RegisterFileCb(NULL);
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed");
        return;
    }
    UdpChannel *channel = NULL;
    UdpChannel *nextChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(channel, nextChannel, &g_udpChannelMgr->list, UdpChannel, node) {
        ListDelete(&(channel->node));
        SoftBusFree(channel);
    }
    (void)SoftBusMutexUnlock(&g_udpChannelMgr->lock);
    DestroySoftBusList(g_udpChannelMgr);
    g_udpChannelMgr = NULL;
    TransFileDeinit();
    TransFileSchemaDeinit();
    PendingDeinit(PENDING_TYPE_UDP);
    TRANS_LOGI(TRANS_INIT, "trans udp channel manager deinit success.");
}

int32_t TransUdpChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    UdpChannel channel;
    if (memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel)) != EOK) {
        TRANS_LOGE(TRANS_FILE, "memset failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (!channel.isEnable || channel.dfileId < 0) {
        TRANS_LOGE(TRANS_FILE, "udp channel is not enable.");
        return SOFTBUS_TRANS_UDP_CHANNEL_DISABLE;
    }
    return TransSendFile(channel.dfileId, sFileList, dFileList, fileCnt);
}

int32_t TransGetUdpChannelByFileId(int32_t dfileId, UdpChannel *udpChannel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->dfileId == dfileId) {
            if (memcpy_s(udpChannel, sizeof(UdpChannel), channelNode, sizeof(UdpChannel)) != EOK) {
                TRANS_LOGE(TRANS_FILE, "memcpy_s failed.");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

void TransUdpDeleteFileListener(const char *sessionName)
{
    return TransDeleteFileListener(sessionName);
}

static int32_t TransSendLimitChangeDataToCore(int32_t channelId, uint8_t tos, int32_t setTosResult)
{
    uint32_t len = sizeof(uint32_t) * LIMIT_CHANGE_INFO_NUM + sizeof(uint8_t);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(len);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc buf failed, channelId=%{public}d", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t offSet = 0;
    int32_t ret = SOFTBUS_OK;
    ret = WriteInt32ToBuf(buf, len, &offSet, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write channelId=%{public}d to buf failed! ret=%{public}d", channelId, ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = WriteUint8ToBuf(buf, len, &offSet, tos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write tos=%{public}d to buf failed! ret=%{public}d", tos, ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = WriteInt32ToBuf(buf, len, &offSet, setTosResult);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write setTosResult=%{public}d to buf failed! ret=%{public}d", setTosResult, ret);
        SoftBusFree(buf);
        return ret;
    }
    return ServerIpcProcessInnerEvent(EVENT_TYPE_TRANS_LIMIT_CHANGE, buf, len);
}

int32_t TransLimitChange(int32_t channelId, uint8_t tos)
{
    if (tos != FILE_PRIORITY_BK && tos != FILE_PRIORITY_BE) {
        TRANS_LOGE(TRANS_FILE, "invalid ip tos");
        return SOFTBUS_INVALID_PARAM;
    }
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    int32_t ret = TransGetUdpChannel(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (channel.info.isServer) {
        TRANS_LOGE(TRANS_FILE, "server side no need to set ip tos");
        return SOFTBUS_NOT_NEED_UPDATE;
    }
    if (channel.businessType != BUSINESS_TYPE_FILE) {
        TRANS_LOGE(TRANS_FILE, "bussiness type not match");
        return SOFTBUS_NOT_NEED_UPDATE;
    }
    bool isTosSet = false;
    ret = TransGetUdpChannelTos(channelId, &isTosSet);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "get tos failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    if (isTosSet) {
        TRANS_LOGW(TRANS_FILE, "tos has set");
        return SOFTBUS_NOT_NEED_UPDATE;
    }
    uint8_t dfileTos = tos;
    DFileOpt dfileOpt = {
        .optType = OPT_TYPE_SOCK_PRIO,
        .valLen = sizeof(uint8_t),
        .value = (uint64_t)&dfileTos,
    };
    int32_t setTosResult = NSTACKX_DFileSetSessionOpt(channel.dfileId, &dfileOpt);
    ret = TransSendLimitChangeDataToCore(channelId, tos, setTosResult);
    return ret;
}

int32_t TransUdpOnCloseAckReceived(int32_t channelId)
{
    return SetPendingPacket(channelId, 0, PENDING_TYPE_UDP);
}

// trigger file event FILE_EVENT_TRANS_STATUS when link down
int32_t ClientEmitFileEvent(int32_t channelId)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    int32_t ret = TransGetUdpChannel(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp channel by channelId=%{public}d failed.", channelId);
        return ret;
    }
    if (channel.businessType == BUSINESS_TYPE_FILE) {
        TRANS_LOGD(TRANS_SDK, "linkdown trigger file event, channelId=%{public}d", channelId);
        ret = NSTACKX_DFileSessionGetFileList(channel.dfileId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(
                TRANS_SDK, "linkdown get file list failed. channelId=%{public}d, ret=%{public}d", channelId, ret);
        }
    }
    return ret;
}

int32_t TransSetUdpChanelSessionId(int32_t channelId, int32_t sessionId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            channelNode->sessionId = sessionId;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransSetUdpChannelRenameHook(int32_t channelId, OnRenameFileCallback onRenameFile)
{
    if (onRenameFile == NULL) {
        TRANS_LOGE(TRANS_SDK, "onRenameFile is null");
        return SOFTBUS_INVALID_PARAM;
    }
    
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId && channelNode->businessType == BUSINESS_TYPE_FILE) {
            channelNode->onRenameFile = onRenameFile;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransSetUdpChannelTos(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            channelNode->isTosSet = true;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransGetUdpChannelTos(int32_t channelId, bool *isTosSet)
{
    if (isTosSet == NULL) {
        TRANS_LOGE(TRANS_SDK, "isTosSet is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            *isTosSet = channelNode->isTosSet;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}