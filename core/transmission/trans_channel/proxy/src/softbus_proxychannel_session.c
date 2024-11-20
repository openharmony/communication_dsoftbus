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

#include "softbus_proxychannel_session.h"

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_datahead_transform.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_property.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "trans_log.h"

#define TIME_OUT 10
#define USECTONSEC 1000
#define MSG_HEAD_LENGTH (28 + 16 + 16)

int32_t TransProxyTransDataSendMsg(ProxyChannelInfo *chanInfo, const unsigned char *payLoad,
    int32_t payLoadLen, ProxyPacketType flag);

int32_t NotifyClientMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, TransReceiveData *receiveData)
{
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_MSG, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransProxyOnMsgReceived(pkgName, pid, channelId, receiveData);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "notify ret=%{public}d", ret);
    }
    return ret;
}

ProxyPacketType SessionTypeToPacketType(SessionPktType sessionType)
{
    switch (sessionType) {
        case TRANS_SESSION_BYTES:
            return PROXY_FLAG_BYTES;
        case TRANS_SESSION_MESSAGE:
            return PROXY_FLAG_MESSAGE;
        case TRANS_SESSION_FILE_FIRST_FRAME:
            return PROXY_FILE_FIRST_FRAME;
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
            return PROXY_FILE_ONGOINE_FRAME;
        case TRANS_SESSION_FILE_LAST_FRAME:
            return PROXY_FILE_LAST_FRAME;
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
            return PROXY_FILE_ONLYONE_FRAME;
        case TRANS_SESSION_FILE_ALLFILE_SENT:
            return PROXY_FILE_ALLFILE_SENT;
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
            return PROXY_FILE_CRC_CHECK_FRAME;
        case TRANS_SESSION_FILE_RESULT_FRAME:
            return PROXY_FILE_RESULT_FRAME;
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
            return PROXY_FILE_ACK_REQUEST_SENT;
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
            return PROXY_FILE_ACK_RESPONSE_SENT;
        default:
            return PROXY_FLAG_BYTES;
    }
}

SendPriority ProxyTypeToConnPri(ProxyPacketType proxyType)
{
    switch (proxyType) {
        case PROXY_FLAG_BYTES:
            return CONN_MIDDLE;
        case PROXY_FLAG_MESSAGE:
        case PROXY_FLAG_ASYNC_MESSAGE:
        case PROXY_FLAG_ACK:
            return CONN_HIGH;
        default:
            return CONN_DEFAULT;
    }
}

static int32_t TransProxyPostPacketData(int32_t channelId, const unsigned char *data,
    uint32_t len, ProxyPacketType flags)
{
    if (data == NULL || len == 0) {
        TRANS_LOGE(TRANS_MSG, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chanInfo == NULL) {
        TRANS_LOGE(TRANS_MSG, "malloc in channelId=%{public}d", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransProxyGetSendMsgChanInfo(channelId, chanInfo) != SOFTBUS_OK) {
        SoftBusFree(chanInfo);
        TRANS_LOGE(TRANS_MSG, "can not find proxy channel channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
    }
    (void)memset_s(chanInfo->appInfo.sessionKey, sizeof(chanInfo->appInfo.sessionKey), 0,
        sizeof(chanInfo->appInfo.sessionKey));
    int32_t ret = TransProxyTransDataSendMsg(chanInfo, data, len, flags);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "send msg fail, len=%{public}u, flags=%{public}d, ret=%{public}d", len, flags, ret);
    }

    SoftBusFree(chanInfo);
    return ret;
}

int32_t TransProxyPostSessionData(int32_t channelId, const unsigned char *data, uint32_t len, SessionPktType flags)
{
    ProxyPacketType type = SessionTypeToPacketType(flags);
    return TransProxyPostPacketData(channelId, data, len, type);
}

static char *TransProxyPackAppNormalMsg(const ProxyMessageHead *msg, const char *payLoad,
    int32_t datalen, int32_t *outlen)
{
    ProxyMessageHead proxyMessageHead;
    uint32_t connHeadLen = ConnGetHeadSize();
    uint32_t bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + (uint32_t)datalen;

    char *buf = (char *)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_MSG, "buf calloc failed");
        return NULL;
    }
    if (memcpy_s(&proxyMessageHead, sizeof(ProxyMessageHead), msg, sizeof(ProxyMessageHead)) != EOK) {
        TRANS_LOGE(TRANS_MSG, "memcpy_s message failed.");
        SoftBusFree(buf);
        return NULL;
    }
    PackProxyMessageHead(&proxyMessageHead);
    if (memcpy_s(buf + connHeadLen, bufLen - connHeadLen, &proxyMessageHead, sizeof(ProxyMessageHead)) != EOK) {
        TRANS_LOGE(TRANS_MSG, "memcpy_s buf failed.");
        SoftBusFree(buf);
        return NULL;
    }
    uint32_t dstLen = bufLen - connHeadLen - sizeof(ProxyMessageHead);
    if (memcpy_s(buf + connHeadLen + sizeof(ProxyMessageHead), dstLen, payLoad, datalen) != EOK) {
        TRANS_LOGE(TRANS_MSG, "memcpy_s buf failed.");
        SoftBusFree(buf);
        return NULL;
    }
    *outlen = (int32_t)bufLen;

    return buf;
}

static int32_t TransProxyTransNormalMsg(const ProxyChannelInfo *info, const char *payLoad, int32_t payLoadLen,
    ProxyPacketType flag)
{
    ProxyMessageHead msgHead = { 0 };
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    int32_t bufLen = 0;
    char *buf = TransProxyPackAppNormalMsg(&msgHead, payLoad, payLoadLen, &bufLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_MSG, "proxy pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    int32_t ret = TransProxyTransSendMsg(info->connId, (uint8_t *)buf, (uint32_t)bufLen,
        ProxyTypeToConnPri(flag), info->appInfo.myData.pid);
    if (ret == SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL) {
        TRANS_LOGE(TRANS_MSG, "proxy send queue full.");
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "proxy send msg error");
        return SOFTBUS_TRANS_PROXY_SENDMSG_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyTransDataSendMsg(ProxyChannelInfo *info, const unsigned char *payLoad,
    int32_t payLoadLen, ProxyPacketType flag)
{
    if (info == NULL || payLoad == NULL) {
        TRANS_LOGE(TRANS_MSG, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->status != PROXY_CHANNEL_STATUS_COMPLETED && info->status != PROXY_CHANNEL_STATUS_KEEPLIVEING)) {
        TRANS_LOGE(TRANS_MSG, "status is err status=%{public}d", info->status);
        return SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
    }
    if (info->appInfo.appType == APP_TYPE_INNER) {
        TRANS_LOGE(TRANS_MSG, "err app type Inner");
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }

    return TransProxyTransNormalMsg(info, (const char *)payLoad, payLoadLen, flag);
}

int32_t TransOnNormalMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || pkgName == NULL) {
        TRANS_LOGE(TRANS_MSG, "data or pkgname is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    TransReceiveData receiveData;
    receiveData.data = (void *)data;
    receiveData.dataLen = len;

    int32_t ret = NotifyClientMsgReceived(pkgName, pid, channelId, &receiveData);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_MSG, "msg receive err, channelId=%{public}d, len=%{public}u, pid=%{public}d", channelId, len, pid);

    return SOFTBUS_OK;
}
