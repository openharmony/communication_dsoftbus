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

#include "client_trans_channel_manager.h"

#include "client_trans_auth_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_statistics.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "client_trans_udp_manager.h"
#include "softbus_error_code.h"
#include "trans_log.h"

int32_t ClientTransChannelInit(void)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    TRANS_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_NO_INIT, TRANS_SDK, "get client session Cb failed.");

    int32_t ret = TransTdcManagerInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "trans tcp manager init failed.");

    ret = ClientTransAuthInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "client trans auth init failed.");

    ret = ClientTransStatisticsInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "client trans statistics init failed.");

    ret = ClientTransProxyInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "client trans proxy init failed.");

    ret = ClientTransUdpMgrInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "client trans udp mgr init failed.");
    return SOFTBUS_OK;
}

void ClientTransChannelDeinit(void)
{
    TransTdcManagerDeinit();
    ClientTransUdpMgrDeinit();
    ClientTransProxyDeinit();
    ClientTransStatisticsDeinit();
}

int32_t ClientTransCloseChannel(int32_t channelId, int32_t type)
{
    if (channelId < 0) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    DeleteSocketResourceByChannelId(channelId, type);
    int32_t ret = SOFTBUS_OK;
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            ClientTransProxyCloseChannel(channelId);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            TransDelDataBufNode(channelId);
            TransTdcCloseChannel(channelId);
            break;
        case CHANNEL_TYPE_UDP:
            ret = ClientTransCloseUdpChannel(channelId, SHUTDOWN_REASON_LOCAL);
            break;
        case CHANNEL_TYPE_AUTH:
            ClientTransAuthCloseChannel(channelId, SHUTDOWN_REASON_LOCAL);
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "Invalid type");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return ret;
}

int32_t ClientTransChannelSendBytes(int32_t channelId, int32_t channelType, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0)) {
        TRANS_LOGW(TRANS_BYTES, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    bool needAck = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channelId, channelType, NULL, &needAck);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "GetSupportTlvAndNeedAckById fail, channelId=%{public}d.", channelId);
        return ret;
    }
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthChannelSendBytes(channelId, data, len);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelSendBytes(channelId, data, len, needAck);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcSendBytes(channelId, data, len, needAck);
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "Invalid channelType=%{public}d", channelType);
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return ret;
}

int32_t ClientTransChannelAsyncSendBytes(int32_t channelId, int32_t channelType, const void *data, uint32_t len,
    uint32_t dataSeq)
{
    if ((data == NULL) || (len == 0)) {
        TRANS_LOGW(TRANS_BYTES, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelAsyncSendBytes(channelId, data, len, dataSeq);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcAsyncSendBytes(channelId, data, len, dataSeq);
            break;
        default:
            TRANS_LOGE(TRANS_SDK, "Invalid channelType=%{public}d", channelType);
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return ret;
}

int32_t ClientTransChannelSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0)) {
        TRANS_LOGW(TRANS_MSG, "Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthChannelSendMessage(channelId, data, len);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelSendMessage(channelId, data, len);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcSendMessage(channelId, data, len);
            break;
        default:
            TRANS_LOGE(TRANS_MSG, "Invalid channelType=%{public}d", channelType);
            return SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
    }
    return ret;
}

int32_t ClientTransChannelSendStream(int32_t channelId, int32_t channelType, const StreamData *data,
    const StreamData *ext, const StreamFrameInfo *param)
{
    if ((data == NULL) || (ext == NULL) || (param == NULL)) {
        TRANS_LOGW(TRANS_STREAM, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_UDP:
            ret = TransUdpChannelSendStream(channelId, data, ext, param);
            break;
        default:
            TRANS_LOGE(TRANS_STREAM, "unsupport channelType=%{public}d.", channelType);
            return SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
    }
    return ret;
}

int32_t ClientTransChannelSendFile(int32_t channelId, int32_t channelType, const char *sFileList[],
    const char *dFileList[], uint32_t fileCnt)
{
    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_UDP:
            ret = TransUdpChannelSendFile(channelId, sFileList, dFileList, fileCnt);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
            break;
        default:
            TRANS_LOGE(TRANS_FILE, "unsupport channelType=%{public}d.", channelType);
            return SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
    }
    return ret;
}

void DeleteFileListener(const char *sessionName)
{
    TransUdpDeleteFileListener(sessionName);
}

int32_t ClientGetSessionKey(int32_t channelId, char *key, unsigned int len)
{
    return TransTdcGetSessionKey(channelId, key, len);
}

int32_t ClientGetHandle(int32_t channelId, int *handle)
{
    return TransTdcGetHandle(channelId, handle);
}

int32_t ClientDisableSessionListener(int32_t channelId)
{
    return TransDisableSessionListener(channelId);
}