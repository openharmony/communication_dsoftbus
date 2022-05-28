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

#include "client_trans_proxy_manager.h"

#include <limits.h>
#include <securec.h>
#include <unistd.h>

#include "client_trans_pending.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

static IClientSessionCallBack g_sessionCb;
static uint32_t g_authMaxByteBufSize;
static uint32_t g_authMaxMessageBufSize;

int32_t ClinetTransProxyInit(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    g_sessionCb = *cb;
    if (ClinetTransProxyFileManagerInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ClinetTransProxyFileManagerInit init fail!");
        return SOFTBUS_ERR;
    }

    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH,
        (unsigned char*)&g_authMaxByteBufSize, sizeof(g_authMaxByteBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max bytes length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH,
        (unsigned char*)&g_authMaxMessageBufSize, sizeof(g_authMaxMessageBufSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get auth proxy channel max message length fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "proxy auth byteSize[%u], messageSize[%u]",
        g_authMaxByteBufSize, g_authMaxMessageBufSize);
    return SOFTBUS_OK;
}

void ClientTransProxyDeinit(void)
{
    ClinetTransProxyFileManagerDeinit();
}

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = g_sessionCb.OnSessionOpened(sessionName, channel, TYPE_MESSAGE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session open fail");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelClosed(int32_t channelId)
{
    int ret = g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session openfail err");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId)
{
    int ret = g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify session openfail err");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify data recv err");
        return ret;
    }
    return SOFTBUS_OK;
}

void ClientTransProxyCloseChannel(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransCloseProxyChannel, channelId [%d]", channelId);
    if (ServerIpcCloseChannel(channelId, CHANNEL_TYPE_PROXY) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server close channel err");
    }
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len)
{
#define PROXY_MAX_BYTES_LEN (4 * 1024)
    int32_t encryp = 0;
    int32_t ret = GetEncryptByChannelId(channelId, CHANNEL_TYPE_PROXY, &encryp);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (encryp == 1) {
        if (len > PROXY_MAX_BYTES_LEN) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    } else {
        if (len > g_authMaxByteBufSize) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    }
    ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send bytes: channelId=%d, ret=%d", channelId, ret);
    return ret;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
#define PROXY_MAX_MESSAGE_LEN (1 * 1024)
    int32_t encryp = 0;
    int32_t ret = GetEncryptByChannelId(channelId, CHANNEL_TYPE_PROXY, &encryp);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (encryp == 1) {
        if (len > PROXY_MAX_MESSAGE_LEN) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    } else {
        if (len > g_authMaxMessageBufSize) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
    }
    ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_MESSAGE);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send msg: channelId=%d, ret=%d", channelId, ret);
    return ret;
}

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    FileFrame oneFrame;
    oneFrame.frameType = type;
    oneFrame.frameLength = len;
    oneFrame.data = (uint8_t *)data;
    return ProcessRecvFileFrameData(sessionId, channelId, &oneFrame);
}

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt)
{
    return ProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
}
