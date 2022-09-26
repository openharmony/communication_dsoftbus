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

#include "softbus_proxychannel_control.h"

#include <securec.h>
#include <string.h>

#include "auth_interface.h"
#include "cJSON.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"

int32_t TransProxySendMessage(ProxyChannelInfo *info, const char *payLoad, uint32_t payLoadLen, int32_t priority)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;

    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = payLoadLen;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    return TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        priority, info->appInfo.myData.pid);
}

static int32_t SetCipherOfHandshakeMsg(uint32_t channelId, uint8_t *cipher)
{
    int64_t authId = TransProxyGetAuthId(channelId);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get authId fail");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (AuthGetConnInfo(authId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth connInfo fail");
        return SOFTBUS_ERR;
    }
    bool isAuthServer = false;
    if (AuthGetServerSide(authId, &isAuthServer) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth server side fail");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        if (SetCipherOfHandshakeMsg(info->channelId, &msgHead.cipher) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set cipher fail");
            return SOFTBUS_ERR;
        }
    }
    msgHead.myId = info->myId;
    msgHead.peerId = INVALID_CHANNEL_ID;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "handshake myId=%d cipher=0x%02x", msgHead.myId, msgHead.cipher);
    payLoad = TransProxyPackHandshakeMsg(info);
    if (payLoad == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack handshake fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack handshake head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    dataInfo.inData = NULL;

    if (TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send handshake buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode)
{
    if (chan == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send handshake ack msg myid %d peerid %d",
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack handshake ack fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, chan->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack handshake ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, chan->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send handshakeack buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransProxyKeepalive(uint32_t connId, const ProxyChannelInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack keepalive fail");
        return;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack keepalive head fail");
        cJSON_free(payLoad);
        return;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send keepalive buf fail");
        return;
    }
}

int32_t TransProxyAckKeepalive(ProxyChannelInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack keepalive ack fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack keepalive ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, info->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send keepalive ack buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyResetPeer(ProxyChannelInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send reset msg myId %d peerid %d", info->myId, info->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_RESET & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }

    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack reset fail");
        return SOFTBUS_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack reset head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, dataInfo.outData,  dataInfo.outLen,
        CONN_LOW, info->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send reset buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
