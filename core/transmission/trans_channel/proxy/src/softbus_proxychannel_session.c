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

#include "softbus_proxychannel_session.h"

#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_property.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_socket.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_pending_pkt.h"
#include "softbus_datahead_transform.h"

#define TIME_OUT 10
#define USECTONSEC 1000
#define MSG_HEAD_LENGTH (28 + 16 + 16)

int32_t TransProxyTransDataSendMsg(ProxyChannelInfo *chanInfo, const unsigned char *payLoad,
    int payLoadLen, ProxyPacketType flag);


int32_t NotifyClientMsgReceived(const char *pkgName, int32_t pid, int32_t channelId,
    TransReceiveData *receiveData)
{
    int32_t ret = TransProxyOnMsgReceived(pkgName, pid, channelId, receiveData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify err[%d]", ret);
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

int32_t TransProxyPostPacketData(int32_t channelId, const unsigned char *data,
    uint32_t len, ProxyPacketType flags)
{
    int32_t seq = 0;
    ConnectType type = 0;

    if ((data == NULL) || (len == 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chanInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc in TransProxyPostPacketData.id[%d]", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransProxyGetSendMsgChanInfo(channelId, chanInfo) != SOFTBUS_OK) {
        SoftBusFree(chanInfo);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not find proxy channel channel id = %d", channelId);
        return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "InLen[%d] seq[%d] flags[%d]", len, seq, flags);
    int32_t ret = TransProxyTransDataSendMsg(chanInfo, data, len, flags);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyTransDataSendMsg fail ret = %d", ret);
    }

    if (ConnGetTypeByConnectionId(chanInfo->connId, &type) != SOFTBUS_OK) {
        TLOGE("obtain link type failed!");
    }

    SoftBusFree(chanInfo);
    return ret;
}

int32_t TransProxyPostSessionData(int32_t channelId, const unsigned char *data, uint32_t len,
    SessionPktType flags)
{
    ProxyPacketType type = SessionTypeToPacketType(flags);
    return TransProxyPostPacketData(channelId, data, len, type);
}

static char *TransProxyPackAppNormalMsg(const ProxyMessageHead *msg, const char *payLoad,
    int32_t datalen, int32_t *outlen)
{
    char *buf = NULL;
    uint32_t dstLen;
    ProxyMessageHead proxyMessageHead;
    uint32_t connHeadLen = ConnGetHeadSize();
    uint32_t bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + (uint32_t)datalen;

    buf = (char*)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        return NULL;
    }
    if (memcpy_s(&proxyMessageHead, sizeof(ProxyMessageHead), msg, sizeof(ProxyMessageHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    PackProxyMessageHead(&proxyMessageHead);
    if (memcpy_s(buf + connHeadLen, bufLen - connHeadLen, &proxyMessageHead, sizeof(ProxyMessageHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    dstLen = bufLen - connHeadLen - sizeof(ProxyMessageHead);
    if (memcpy_s(buf + connHeadLen + sizeof(ProxyMessageHead), dstLen, payLoad, datalen) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    *outlen = (int32_t)bufLen;

    return buf;
}

static int32_t TransProxyTransNormalMsg(const ProxyChannelInfo *info, const char *payLoad, int payLoadLen,
    ProxyPacketType flag)
{
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    int bufLen = 0;
    char *buf = TransProxyPackAppNormalMsg(&msgHead, payLoad, payLoadLen, &bufLen);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    int32_t ret = TransProxyTransSendMsg(info->connId, (uint8_t *)buf, (uint32_t)bufLen,
        ProxyTypeToConnPri(flag), info->appInfo.myData.pid);
    if (ret == SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send queue full!!");
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send msg error");
        return SOFTBUS_TRANS_PROXY_SENDMSG_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyTransDataSendMsg(ProxyChannelInfo *info, const unsigned char *payLoad,
    int payLoadLen, ProxyPacketType flag)
{
    if ((info->status != PROXY_CHANNEL_STATUS_COMPLETED && info->status != PROXY_CHANNEL_STATUS_KEEPLIVEING)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "status is err %d", info->status);
        return SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
    }
    if (info->appInfo.appType == APP_TYPE_INNER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "err app type Inner");
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }

    return TransProxyTransNormalMsg(info, (const char*)payLoad, payLoadLen, flag);
}

int32_t TransOnNormalMsgReceived(const char *pkgName, int32_t pid, int32_t channelId,
    const char *data, uint32_t len)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data null.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "AuthReceived inputLen[%d]", len);

    TransReceiveData receiveData;
    receiveData.data = (void*)data;
    receiveData.dataLen = len;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify receive msg received");
    if (NotifyClientMsgReceived(pkgName, pid, channelId, &receiveData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify receive msg received err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
