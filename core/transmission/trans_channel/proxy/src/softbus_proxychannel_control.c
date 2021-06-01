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

int32_t TransProxySendMessage(ProxyChannelInfo *info, char *payLoad, int32_t payLoadLen, int32_t priority)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    ProxyMessageHead msgHead = {0};

    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (info->appInfo.appType != APP_TYPE_NORMAL) {
        msgHead.chiper = (msgHead.chiper | ENCRYPTED);
    }
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (TransProxyPackMessage(&msgHead, info->connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }

    return TransProxyTransSendMsg(info->connId, buf, bufLen, priority);
}

int32_t TransProxyHandshake(ProxyChannelInfo *info)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    char *payLoad = NULL;
    int32_t payLoadLen;
    ProxyMessageHead msgHead = {0};

    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.chiper = (msgHead.chiper | ENCRYPTED);
    msgHead.myId = info->myId;
    msgHead.peerId = INVALID_CHANNEL_ID;
    LOG_INFO("handshake myId %d", msgHead.myId);
    payLoad = TransProxyPackHandshakeMsg(info);
    if (payLoad == NULL) {
        LOG_ERR("pack handshake fail");
        return SOFTBUS_ERR;
    }
    payLoadLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack handshake head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);

    if ((msgHead.chiper & AUTH_SERVER_SIDE)) {
        if (TransProxySetChiperSide(info->channelId, SERVER_SIDE_FLAG) != SOFTBUS_OK) {
            LOG_ERR("set chiper side fail");
            return SOFTBUS_ERR;
        }
    }
    if (TransProxyTransSendMsg(info->connId, buf, bufLen, CONN_HIGH) != SOFTBUS_OK) {
        LOG_ERR("send handshake buf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    char *payLoad = NULL;
    int32_t payLoadLen;
    ProxyMessageHead msgHead = {0};

    LOG_INFO("send handshake ack msg myid %d peerid %d", chan->myId, chan->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.chiper = (msgHead.chiper | ENCRYPTED);
    payLoad = TransProxyPackHandshakeAckMsg(chan);
    if (payLoad == NULL) {
        LOG_ERR("pack handshake ack fail");
        return SOFTBUS_ERR;
    }
    payLoadLen = strlen(payLoad) + 1;
    msgHead.myId = chan->myId;
    msgHead.peerId = chan->peerId;

    if (TransProxyPackMessage(&msgHead, connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack handshake ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, buf, bufLen, CONN_HIGH) != SOFTBUS_OK) {
        LOG_ERR("send handshakeack buf fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void TransProxyKeepalive(uint32_t connId, const ProxyChannelInfo *info)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    char *payLoad = NULL;
    int32_t payLoadLen;
    ProxyMessageHead msgHead = {0};

    msgHead.type = (PROXYCHANNEL_MSG_TYPE_KEEPALIVE & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    payLoad = TransProxyPackIdentity(info->identity);
    LOG_ERR("pack keepalive fail");
    if (payLoad == NULL) {
        return;
    }
    payLoadLen = strlen(payLoad) + 1;
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    msgHead.chiper = (msgHead.chiper | ENCRYPTED);

    if (TransProxyPackMessage(&msgHead, connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack keepalive head fail");
        cJSON_free(payLoad);
        return;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(connId, buf, bufLen, CONN_HIGH) != SOFTBUS_OK) {
        LOG_ERR("send keepalive buf fail");
        return;
    }
    return;
}

int32_t TransProxyAckKeepalive(ProxyChannelInfo *info)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    char *payLoad = NULL;
    int32_t payLoadLen;
    ProxyMessageHead msgHead = {0};

    msgHead.type = (PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        LOG_ERR("pack keepalive ack fail");
        return SOFTBUS_ERR;
    }
    payLoadLen = strlen(payLoad) + 1;
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    msgHead.chiper = (msgHead.chiper | ENCRYPTED);

    if (TransProxyPackMessage(&msgHead, info->connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack keepalive ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, buf, bufLen, CONN_HIGH) != SOFTBUS_OK) {
        LOG_ERR("send keepalive ack buf fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransProxyResetPeer(ProxyChannelInfo *info)
{
    char *buf = NULL;
    int32_t bufLen = 0;
    char *payLoad = NULL;
    int32_t payLoadLen;
    ProxyMessageHead msgHead = {0};

    LOG_INFO("send reset msg myId %d peerid %d", info->myId, info->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_RESET & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        LOG_ERR("pack reset fail");
        return SOFTBUS_ERR;
    }
    payLoadLen = strlen(payLoad) + 1;
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    msgHead.chiper = (msgHead.chiper | ENCRYPTED);

    if (TransProxyPackMessage(&msgHead, info->connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        LOG_ERR("pack reset head fail");
        cJSON_free(payLoad);
        return SOFTBUS_ERR;
    }
    cJSON_free(payLoad);
    if (TransProxyTransSendMsg(info->connId, buf, bufLen, CONN_LOW) != SOFTBUS_OK) {
        LOG_ERR("send reset buf fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}
