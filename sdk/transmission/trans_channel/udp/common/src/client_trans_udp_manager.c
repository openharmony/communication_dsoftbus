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

#include "client_trans_udp_manager.h"

#include <stdbool.h>
#include "client_trans_stream.h"
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

#define MAX_UDP_CHANNEL 10

typedef struct {
    bool isServer;
    int32_t peerUid;
    int32_t peerPid;
    char mySessionName[SESSION_NAME_SIZE_MAX];
    char peerSessionName[SESSION_NAME_SIZE_MAX];
    char peerDeviceId[DEVICE_ID_SIZE_MAX];
    char groupId[GROUP_ID_SIZE_MAX];
} sessionNeed;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t businessType;
    bool isEnable;
    sessionNeed info;
} UdpChannel;

static SoftBusList *g_udpChannelMgr = NULL;
static IClientSessionCallBack *g_sessionCb = NULL;

int32_t TransAddUdpChannel(UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (g_udpChannelMgr->cnt >= MAX_UDP_CHANNEL) {
        (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel num reach max");
        return SOFTBUS_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channel->channelId) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp channel has exited.[channelId = %d]",
                channel->channelId);
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_ERR;
        }
    }
    ListInit(&(channel->node));
    ListAdd(&(g_udpChannelMgr->list), &(channel->node));
    g_udpChannelMgr->cnt++;

    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_OK;
}

int32_t TransDeleteUdpChannel(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            ListDelete(&(channelNode->node));
            SoftBusFree(channelNode);
            g_udpChannelMgr->cnt--;
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *channel)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            if (memcpy_s(channel, sizeof(UdpChannel), channelNode, sizeof(UdpChannel)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
                (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

static int32_t TransSetUdpChannelEnable(int32_t channelId, bool isEnable)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannel *channelNode = NULL;
    LIST_FOR_EACH_ENTRY(channelNode, &(g_udpChannelMgr->list), UdpChannel, node) {
        if (channelNode->channelId == channelId) {
            channelNode->isEnable = isEnable;
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

static void OnUdpChannelOpened(int32_t channelId)
{
    UdpChannel channel = {0};
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        return;
    }
    if (TransSetUdpChannelEnable(channelId, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel enable failed.");
        return;
    }
    SessionType type = TYPE_BUTT;
    switch (channel.businessType) {
        case BUSINESS_TYPE_STREAM:
            type = TYPE_STREAM;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unsupport business type.");
            return;
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
    g_sessionCb->OnSessionOpened(channel.info.mySessionName, &info, type);
}

static UdpChannel *ConvertChannelInfoToUdpChannel(const char *sessionName, const ChannelInfo *channel)
{
    UdpChannel *newChannel = (UdpChannel *)SoftBusCalloc(sizeof(UdpChannel));
    if (newChannel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "new udp channel failed.");
        return NULL;
    }
    newChannel->businessType = channel->businessType;
    newChannel->channelId = channel->channelId;
    newChannel->isEnable = false;
    newChannel->info.isServer = channel->isServer;
    newChannel->info.peerPid = channel->peerPid;
    newChannel->info.peerUid = channel->peerUid;
    if (strcpy_s(newChannel->info.peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK ||
        strcpy_s(newChannel->info.mySessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK ||
        strcpy_s(newChannel->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK ||
        strcpy_s(newChannel->info.groupId, GROUP_ID_SIZE_MAX, channel->groupId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "udp channel add peer session name, device id, group id failed");
        SoftBusFree(newChannel);
        return NULL;
    }
    return newChannel;
}

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *udpPort)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnUdpChannelOpened enter");
    if (channel == NULL || udpPort == NULL || sessionName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    UdpChannel *newChannel = ConvertChannelInfoToUdpChannel(sessionName, channel);
    if (newChannel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "convert channel info to udp channel failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (TransAddUdpChannel(newChannel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add udp channel failed.");
        SoftBusFree(newChannel);
        return SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "add new udp channel success, channelId[%d], business type[%d]",
        newChannel->channelId, newChannel->businessType);

    int32_t ret = SOFTBUS_ERR;
    switch (channel->businessType) {
        case BUSINESS_TYPE_STREAM:
            ret = TransOnstreamChannelOpened(channel, udpPort);
            if (ret != SOFTBUS_OK) {
                (void)TransDeleteUdpChannel(newChannel->channelId);
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "on stream channel opened failed.");
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unsupport businessType.");
            break;
    }
    return ret;
}

int32_t TransOnUdpChannelOpenFailed(int32_t channelId)
{
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "tans delete udp channel failed.");
    }
    if (g_sessionCb == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client trans udp manager seesion callback is null");
        return SOFTBUS_ERR;
    }

    return g_sessionCb->OnSessionOpenFailed(channelId, CHANNEL_TYPE_UDP);
}

static int32_t ClosePeerUdpChannel(int32_t channelId)
{
    return ServerIpcCloseChannel(channelId, CHANNEL_TYPE_UDP);
}

static int32_t CloseUdpChannel(int32_t channelId, bool isActive)
{
    UdpChannel channel = {0};
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransSetUdpChannelEnable(channelId, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel enable failed.");
        return SOFTBUS_ERR;
    }
    if (isActive) {
        if (ClosePeerUdpChannel(channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans close peer udp channel failed.");
            (void)TransCloseStreamChannel(channelId);
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    switch (channel.businessType) {
        case BUSINESS_TYPE_STREAM:
            if (TransCloseStreamChannel(channelId) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans close udp channel failed.");
                return SOFTBUS_ERR;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unsupport business type.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnUdpChannelClosed(int32_t channelId)
{
    return CloseUdpChannel(channelId, false);
}

int32_t TransCloseUdpChannel(int32_t channelId)
{
    return CloseUdpChannel(channelId, true);
}

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const FrameInfo *param)
{
    UdpChannel channel = {0};
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!channel.isEnable) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel is not enable.");
        return SOFTBUS_ERR;
    }
    return TransSendStream(channelId, data, ext, param);
}

static void OnUdpChannelClosed(int32_t channelId)
{
    g_sessionCb->OnSessionClosed(channelId, CHANNEL_TYPE_UDP);
    if (TransDeleteUdpChannel(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans delete udp channel failed.");
    }
}

static void OnStreamReceived(int32_t channelId, const StreamData *data, const StreamData *ext, const FrameInfo *param)
{
    g_sessionCb->OnStreamReceived(channelId, CHANNEL_TYPE_UDP, data, ext, param);
}

static UdpChannelMgrCb g_udpChannelCb = {
    .OnUdpChannelOpened = OnUdpChannelOpened,
    .OnUdpChannelClosed = OnUdpChannelClosed,
    .OnFileReceived = NULL,
    .OnMessageReceived = NULL,
    .OnStreamReceived = OnStreamReceived,
};

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback)
{
    if (g_udpChannelMgr != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp channel info manager has initialized.");
        return SOFTBUS_OK;
    }
    g_sessionCb = callback;
    RegisterStreamCb(&g_udpChannelCb);
    g_udpChannelMgr = CreateSoftBusList();
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create udp channel manager list failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans udp channel manager init success.");
    return SOFTBUS_OK;
}

void ClientTransUdpMgrDeinit(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    UnregisterStreamCb();
    if (pthread_mutex_lock(&g_udpChannelMgr->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    UdpChannel *channel = NULL;
    UdpChannel *nextChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(channel, nextChannel, &g_udpChannelMgr->list, UdpChannel, node) {
        ListDelete(&(channel->node));
        SoftBusFree(channel);
    }
    (void)pthread_mutex_unlock(&g_udpChannelMgr->lock);
    DestroySoftBusList(g_udpChannelMgr);
    g_udpChannelMgr = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans udp channel manager deinit success.");
}
