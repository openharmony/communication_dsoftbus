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

#include "client_trans_stream.h"

#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_udp_stream_interface.h"
#include "session.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

static const UdpChannelMgrCb *g_udpChannelMgrCb = NULL;

void RegisterStreamCb(const UdpChannelMgrCb *streamCb)
{
    if (streamCb == NULL || streamCb->OnUdpChannelOpened == NULL ||
        streamCb->OnUdpChannelClosed == NULL || streamCb->OnStreamReceived == NULL) {
        TRANS_LOGE(TRANS_STREAM, "udp channel callback is invalid");
        return;
    }

    g_udpChannelMgrCb = streamCb;
}

void UnregisterStreamCb(void)
{
    g_udpChannelMgrCb = NULL;
}

static void SetStreamChannelStatus(int32_t channelId, int32_t status)
{
    if (g_udpChannelMgrCb == NULL) {
        TRANS_LOGE(TRANS_STREAM, "udp channel callback is null.");
        return;
    }

    switch (status) {
        case STREAM_CONNECTED:
            TRANS_LOGI(TRANS_STREAM, "dstream connected. channelId=%{public}d", channelId);
            break;
        case STREAM_CLOSED:
            TRANS_LOGI(TRANS_STREAM, "dstream closed. channelId=%{public}d", channelId);
            break;
        case STREAM_INIT:
            TRANS_LOGI(TRANS_STREAM, "dstream init. channelId=%{public}d", channelId);
            break;
        case STREAM_OPENING:
            TRANS_LOGI(TRANS_STREAM, "dstream opening. channelId=%{public}d", channelId);
            break;
        case STREAM_CONNECTING:
            TRANS_LOGI(TRANS_STREAM, "dstream connecting. channelId=%{public}d", channelId);
            break;
        case STREAM_CLOSING:
            TRANS_LOGI(TRANS_STREAM, "dstream closing. channelId=%{public}d", channelId);
            break;
        default:
            TRANS_LOGE(TRANS_STREAM, "unsupport stream. channelId=%{public}d, status=%{public}d.", channelId, status);
            break;
    }
}

static void OnStreamReceived(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    if ((g_udpChannelMgrCb == NULL) || (g_udpChannelMgrCb->OnStreamReceived == NULL)) {
        TRANS_LOGE(TRANS_STREAM, "udp channel callback on stream received is null.");
        return;
    }

    g_udpChannelMgrCb->OnStreamReceived(channelId, data, ext, param);
}

static void OnQosEvent(int channelId, int eventId, int tvCount, const QosTv *tvList)
{
    if ((g_udpChannelMgrCb == NULL) || (g_udpChannelMgrCb->OnQosEvent == NULL)) {
        return;
    }
    g_udpChannelMgrCb->OnQosEvent(channelId, eventId, tvCount, tvList);
}

static void OnFrameStats(int32_t channelId, const StreamSendStats *data)
{
    int32_t ret = ServerIpcStreamStats(channelId, CHANNEL_TYPE_UDP, data);
    TRANS_LOGI(TRANS_STREAM, "notify frame stats to server, channelId=%{public}d", channelId);
    if ((ret != SOFTBUS_OK) && (ret != SOFTBUS_NOT_IMPLEMENT)) {
        TRANS_LOGE(TRANS_STREAM, "ipc to server fail, ret=%{public}d", ret);
        return;
    }
}

static void OnRippleStats(int32_t channelId, const TrafficStats *data)
{
    int32_t ret = ServerIpcRippleStats(channelId, CHANNEL_TYPE_UDP, data);
    TRANS_LOGI(TRANS_STREAM, "notify ripple stats to server, channelId=%{public}d", channelId);
    if ((ret != SOFTBUS_OK) && (ret != SOFTBUS_NOT_IMPLEMENT)) {
        TRANS_LOGE(TRANS_STREAM, "ipc to server fail, ret=%{public}d", ret);
        return;
    }
}

static IStreamListener g_streamCallcb = {
    .OnStatusChange = SetStreamChannelStatus,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
    .OnFrameStats = OnFrameStats,
    .OnRippleStats = OnRippleStats,
};

static int32_t GetRawStreamEncryptOptByChannelId(int32_t channelId, bool *isEncryptRawStream)
{
    if (g_udpChannelMgrCb == NULL) {
        TRANS_LOGE(TRANS_STREAM, "udp channel callback is null.");
        return SOFTBUS_NO_INIT;
    }
    if (g_udpChannelMgrCb->OnRawStreamEncryptOptGet == NULL) {
        TRANS_LOGE(TRANS_STREAM, "OnRawStreamEncryptOptGet of udp channel callback is null.");
        return SOFTBUS_TRANS_UDP_CHANNEL_CALLBACK_NULL;
    }
    return g_udpChannelMgrCb->OnRawStreamEncryptOptGet(channelId, isEncryptRawStream);
}

static int32_t OnStreamUdpChannelOpened(int32_t channelId)
{
    if ((g_udpChannelMgrCb == NULL) || (g_udpChannelMgrCb->OnUdpChannelOpened == NULL)) {
        TRANS_LOGE(TRANS_STREAM, "udp channel callback on udp channel opened is null channelId=%{public}d", channelId);
        return SOFTBUS_NO_INIT;
    }

    int32_t ret = g_udpChannelMgrCb->OnUdpChannelOpened(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "OnUdpChannelOpened fail, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TransOnstreamChannelOpened(const ChannelInfo *channel, int32_t *streamPort)
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    if (channel == NULL || streamPort == NULL) {
        TRANS_LOGW(TRANS_STREAM, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    StreamType streamType = (StreamType)channel->streamType;
    if (streamType != RAW_STREAM && streamType != COMMON_VIDEO_STREAM && streamType != COMMON_AUDIO_STREAM) {
        TRANS_LOGE(TRANS_STREAM, "stream type invalid. type=%{public}d", channel->streamType);
        return SOFTBUS_INVALID_PARAM;
    }
    bool isEncryptedRawStream = false;
    int32_t ret = GetRawStreamEncryptOptByChannelId(channel->channelId, &isEncryptedRawStream);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "failed to get encryption option by channelId=%{public}d", channel->channelId);
        return ret;
    }
    if (channel->isServer) {
        if (IsSessionExceedLimit()) {
            *streamPort = 0;
            return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
        }

        ret = OnStreamUdpChannelOpened(channel->channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_STREAM, "OnUdpChannelOpened fail channelId=%{public}d", channel->channelId);
            return ret;
        }

        VtpStreamOpenParam p1 = { "DSOFTBUS_STREAM", channel->myIp,
            NULL, -1, streamType, (uint8_t*)channel->sessionKey, channel->keyLen, isEncryptedRawStream};

        int32_t port = StartVtpStreamChannelServer(channel->channelId, &p1, &g_streamCallcb);
        if (port <= 0) {
            TRANS_LOGE(TRANS_STREAM, "start stream channel as server failed.");
            return SOFTBUS_TRANS_UDP_START_STREAM_SERVER_FAILED;
        }
        *streamPort = port;
        TRANS_LOGI(TRANS_STREAM, "stream server success, listen port=%{public}d.", port);
    } else {
        VtpStreamOpenParam p1 = { "DSOFTBUS_STREAM", channel->myIp, channel->peerIp,
            channel->peerPort, streamType, (uint8_t *)channel->sessionKey, channel->keyLen, isEncryptedRawStream};

        int32_t ret = StartVtpStreamChannelClient(channel->channelId, &p1, &g_streamCallcb);
        if (ret <= 0) {
            TRANS_LOGE(TRANS_STREAM, "start stream channel as client failed. ret=%{public}d", ret);
            return SOFTBUS_TRANS_UDP_START_STREAM_CLIENT_FAILED;
        }
        TRANS_LOGI(TRANS_STREAM, "stream start client success.");
        return OnStreamUdpChannelOpened(channel->channelId);
    }
    return SOFTBUS_OK;
}

int32_t TransSendStream(int32_t channelId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    if (channelId < 0) {
        TRANS_LOGE(TRANS_STREAM, "param faild");
        return SOFTBUS_INVALID_PARAM;
    }
    return SendVtpStream(channelId, data, ext, param);
}

int32_t TransSetStreamMultiLayer(int32_t channelId, const void *optValue)
{
    if (channelId < 0) {
        TRANS_LOGE(TRANS_STREAM, "param invalid channelId is %{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    return SetVtpStreamMultiLayerOpt(channelId, optValue);
}

int32_t TransCloseStreamChannel(int32_t channelId)
{
    TRANS_LOGI(TRANS_STREAM, "close stream channel. channelId=%{public}d", channelId);
    int32_t ret = CloseVtpStreamChannel(channelId, "DSOFTBUS_STREAM");
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_STREAM, "close stream channel failed.");
    return SOFTBUS_OK;
}
