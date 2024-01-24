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

#include "client_trans_udp_manager.h"

#include <stdbool.h>
#include "client_trans_file.h"
#include "client_trans_file_listener.h"
#include "client_trans_stream.h"
#include "nstackx_dfile.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"


static SoftBusList *g_udpChannelMgr = NULL;
static IClientSessionCallBack *g_sessionCb = NULL;

static int32_t ClientTransAddUdpChannel(UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_ERR;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channel->channelId) {
            TRANS_LOGE(TRANS_SDK, "udp channel has exited.channelId=%{public}d.",
                channel->channelId);
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_ERR;
        }
    }
    ListInit(&(channel->node));
    ListAdd(&(g_udpChannelMgr->list), &(channel->node));
    TRANS_LOGI(TRANS_SDK, "add channelId = %{public}d", channel->channelId);
    g_udpChannelMgr->cnt++;

    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_OK;
}

int32_t TransDeleteUdpChannel(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            ListDelete(&(channelNode->node));
            TRANS_LOGI(TRANS_SDK, "delete channelId = %{public}d", channelId);
            SoftBusFree(channelNode);
            g_udpChannelMgr->cnt--;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_SDK, "udp channel not found, channelId=%{public}d.", channelId);
    return SOFTBUS_ERR;
}

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_ERR;
    }
    if (channel == NULL) {
        TRANS_LOGE(TRANS_INIT, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != 0) {
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
    return SOFTBUS_ERR;
}

static int32_t TransSetUdpChannelEnable(int32_t channelId, bool isEnable)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_SDK, "udp channel manager hasn't init.");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != 0) {
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
    return SOFTBUS_ERR;
}

static int32_t OnUdpChannelOpened(int32_t channelId)
{
    UdpChannel channel;
    if (memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "on udp channel opened memset failed.");
        return SOFTBUS_ERR;
    }
    int ret = TransGetUdpChannel(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get udp failed. channelId=%{public}d", channelId);
        return ret;
    }
    ret = TransSetUdpChannelEnable(channelId, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set udp enable failed. channelId=%{public}d", channelId);
        return ret;
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
            return SOFTBUS_ERR;
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
    return SOFTBUS_ERR;
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
        TRANS_LOGE(TRANS_SDK,
            "udp channel or peer session name, device id, group id, myIp failed");
        SoftBusFree(newChannel);
        return NULL;
    }

    return newChannel;
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
        newChannel->channelId, newChannel->businessType);

    int32_t ret = SOFTBUS_ERR;
    switch (channel->businessType) {
        case BUSINESS_TYPE_STREAM:
            ret = TransOnstreamChannelOpened(channel, udpPort);
            if (ret != SOFTBUS_OK) {
                (void)TransDeleteUdpChannel(newChannel->channelId);
                TRANS_LOGE(TRANS_SDK, "on stream channel opened failed.");
            }
            break;
        case BUSINESS_TYPE_FILE:
            ret = TransOnFileChannelOpened(sessionName, channel, udpPort);
            if (ret < SOFTBUS_OK) {
                (void)TransDeleteUdpChannel(newChannel->channelId);
                TRANS_LOGE(TRANS_SDK, "on file channel open failed.");
                return SOFTBUS_ERR;
            }
            newChannel->dfileId = ret;
            ret = SOFTBUS_OK;
            break;
        default:
            (void)TransDeleteUdpChannel(newChannel->channelId);
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
                return SOFTBUS_ERR;
            }
            break;
        case BUSINESS_TYPE_FILE:
            TransCloseFileChannel(channel->dfileId);
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "unsupport businessType=%{public}d.", channel->businessType);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnUdpChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    UdpChannel channel;
    bool isFind = true;
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channelId failed. channelId=%{public}d", channelId);
        isFind = false;
    }
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "del channelId failed. channelId=%{public}d", channelId);
    }
    if ((isFind) && (channel.isEnable)) {
        if (TransDeleteBusinnessChannel(&channel) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK,
                "del business channel failed. channelId=%{public}d", channelId);
            return SOFTBUS_ERR;
        }
    }
    if ((g_sessionCb == NULL) || (g_sessionCb->OnSessionOpenFailed == NULL)) {
        TRANS_LOGE(TRANS_SDK, "client trans udp manager seesion callback is null");
        return SOFTBUS_ERR;
    }

    return g_sessionCb->OnSessionOpenFailed(channelId, CHANNEL_TYPE_UDP, errCode);
}

static int32_t ClosePeerUdpChannel(int32_t channelId)
{
    return ServerIpcCloseChannel(channelId, CHANNEL_TYPE_UDP);
}

static int32_t CloseUdpChannel(int32_t channelId, bool isActive, ShutdownReason reason)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    TRANS_LOGI(TRANS_SDK, "close udp channelId=%{public}d.", channelId);
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CloseUdpChannel get channel failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }

    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans del udp channel failed. channelId=%{public}d", channelId);
    }

    if (isActive && (ClosePeerUdpChannel(channelId) != SOFTBUS_OK)) {
        TRANS_LOGE(TRANS_SDK, "trans close peer udp channel failed. channelId=%{public}d", channelId);
    }

    if (TransDeleteBusinnessChannel(&channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CloseUdpChannel del business channel failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }

    if (!isActive && (g_sessionCb != NULL) && (g_sessionCb->OnSessionClosed != NULL)) {
        g_sessionCb->OnSessionClosed(channelId, CHANNEL_TYPE_UDP, reason);
    }
    return SOFTBUS_OK;
}

int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    return CloseUdpChannel(channelId, false, reason);
}

int32_t TransOnUdpChannelQosEvent(int32_t channelId, int32_t eventId, int32_t tvCount,
    const QosTv *tvList)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get channel failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    if (g_sessionCb->OnQosEvent != NULL) {
        g_sessionCb->OnQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, tvList);
    }
    return SOFTBUS_OK;
}

int32_t ClientTransCloseUdpChannel(int32_t channelId, ShutdownReason reason)
{
    return CloseUdpChannel(channelId, true, reason);
}

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get channel failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    if (!channel.isEnable) {
        TRANS_LOGE(TRANS_STREAM, "udp channel is not enable.");
        return SOFTBUS_TRANS_UDP_CHANNEL_DISABLE;
    }
    return TransSendStream(channelId, data, ext, param);
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
        return SOFTBUS_ERR;
    }
    return g_sessionCb->OnGetSessionId(channelId, CHANNEL_TYPE_UDP, sessionId);
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
        return SOFTBUS_ERR;
    }
    return g_sessionCb->OnIdleTimeoutReset(sessionId);
}

static UdpChannelMgrCb g_udpChannelCb = {
    .OnStreamReceived = OnStreamReceived,
    .OnFileGetSessionId = OnFileGetSessionId,
    .OnMessageReceived = NULL,
    .OnUdpChannelOpened = OnUdpChannelOpened,
    .OnUdpChannelClosed = OnUdpChannelClosed,
    .OnQosEvent = OnQosEvent,
    .OnIdleTimeoutReset = OnIdleTimeoutReset,
};

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback)
{
    if (g_udpChannelMgr != NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel info manager has init.");
        return SOFTBUS_OK;
    }
    if (callback == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel info manager init failed, calback is null.");
        return SOFTBUS_ERR;
    }
    g_sessionCb = callback;
    RegisterStreamCb(&g_udpChannelCb);
    TransFileInit();
    TransFileSchemaInit();
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
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != 0) {
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
    TRANS_LOGI(TRANS_INIT, "trans udp channel manager deinit success.");
}

int32_t TransUdpChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    UdpChannel channel;
    if (memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel)) != EOK) {
        TRANS_LOGE(TRANS_FILE, "memset failed.");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != 0) {
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
    return SOFTBUS_ERR;
}

void TransUdpDeleteFileListener(const char *sessionName)
{
    return TransDeleteFileListener(sessionName);
}