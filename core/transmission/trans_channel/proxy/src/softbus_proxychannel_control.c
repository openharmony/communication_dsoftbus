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

#include "softbus_proxychannel_control.h"

#include <securec.h>
#include <string.h>

#include "auth_interface.h"
#include "cJSON.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "trans_log.h"
#include "trans_event.h"

int32_t TransProxySendInnerMessage(ProxyChannelInfo *info, const char *payLoad,
    uint32_t payLoadLen, int32_t priority)
{
    if (info == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;

    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = payLoadLen;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    return TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        priority, info->appInfo.myData.pid);
}

static int32_t SetCipherOfHandshakeMsg(uint32_t channelId, uint8_t *cipher)
{
    int64_t authId = TransProxyGetAuthId((int32_t)channelId);
    if (authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "get authId fail");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (AuthGetConnInfo(authId, &connInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth connInfo fail");
        return SOFTBUS_ERR;
    }
    bool isAuthServer = false;
    if (AuthGetServerSide(authId, &isAuthServer) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth server side fail");
        return SOFTBUS_ERR;
    }

    *cipher |= ENCRYPTED;
    if (isAuthServer) {
        *cipher |= AUTH_SERVER_SIDE;
    }
    if (connInfo.type == AUTH_LINK_TYPE_BLE) {
        *cipher |= USE_BLE_CIPHER;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyHandshake(ProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.cipher = CS_MODE;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        if (SetCipherOfHandshakeMsg(info->channelId, &msgHead.cipher) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "set cipher fail");
            return SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED;
        }
    }
    msgHead.myId = info->myId;
    msgHead.peerId = INVALID_CHANNEL_ID;
    TRANS_LOGI(TRANS_CTRL,
        "handshake myChannelId=%d cipher=0x%02x", msgHead.myId, msgHead.cipher);
    payLoad = TransProxyPackHandshakeMsg(info);
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake fail");
        return SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake head fail");
        cJSON_free(payLoad);
        return SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_HEAD_ERR;
    }
    cJSON_free(payLoad);
    dataInfo.inData = NULL;
    int32_t ret = TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send handshake buf fail");
        return ret;
    }
    TransEventExtra extra = {
        .channelId = info->myId,
        .connectionId = (int32_t)info->connId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    return SOFTBUS_OK;
}

int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode)
{
    if (chan == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    TRANS_LOGI(TRANS_CTRL, "send handshake ack msg myChannelId=%d peerChannelId=%d",
        chan->myId, chan->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (chan->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }
    msgHead.myId = chan->myId;
    msgHead.peerId = chan->peerId;

    if (retCode != SOFTBUS_OK) {
        payLoad = TransProxyPackHandshakeErrMsg(retCode);
    } else {
        payLoad = TransProxyPackHandshakeAckMsg(chan);
    }
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake ack fail");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, chan->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, chan->appInfo.myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send handshakeack buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransProxyKeepalive(uint32_t connId, const ProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return;
    }

    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_KEEPALIVE & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }

    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack keepalive fail");
        return;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack keepalive head fail");
        cJSON_free(payLoad);
        return;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send keepalive buf fail");
        return;
    }
}

int32_t TransProxyAckKeepalive(ProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }

    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack keepalive ack fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack keepalive ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send keepalive ack buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyResetPeer(ProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    TRANS_LOGI(TRANS_CTRL, "send reset msg myChannelId=%d peerChannelId=%d", info->myId, info->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_RESET & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }

    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack reset fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack reset head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, dataInfo.outData,  dataInfo.outLen,
        CONN_LOW, info->appInfo.myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reset buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
