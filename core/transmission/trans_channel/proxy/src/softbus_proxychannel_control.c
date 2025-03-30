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
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_event.h"
#include "trans_session_account_adapter.h"

static int32_t TransProxySendEncryptInnerMessage(ProxyChannelInfo *info,
    const char *inData, uint32_t inDataLen, ProxyMessageHead *msgHead, ProxyDataInfo *dataInfo)
{
    uint32_t outPayLoadLen = inDataLen + OVERHEAD_LEN;
    char *outPayLoad = (char *)SoftBusCalloc(outPayLoadLen);
    if (outPayLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc len failed");
        return SOFTBUS_MALLOC_ERR;
    }

    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, info->appInfo.sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        SoftBusFree(outPayLoad);
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret =
        SoftBusEncryptData(&cipherKey, (unsigned char *)inData, inDataLen, (unsigned char *)outPayLoad, &outPayLoadLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SoftBusEncryptData failed, ret=%{public}d", ret);
        SoftBusFree(outPayLoad);
        return SOFTBUS_ENCRYPT_ERR;
    }

    dataInfo->inData = (uint8_t *)outPayLoad;
    dataInfo->inLen = outPayLoadLen;
    if (TransProxyPackMessage(msgHead, info->authHandle, dataInfo, false, &(info->ukIdInfo)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack msg error");
        SoftBusFree(outPayLoad);
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    ret = TransProxyTransSendMsg(
        info->connId, dataInfo->outData, dataInfo->outLen, CONN_HIGH, info->appInfo.myData.pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send encrypt msg failed");
    }
    SoftBusFree(outPayLoad);
    return ret;
}

int32_t TransProxySendInnerMessage(ProxyChannelInfo *info, const char *payLoad, uint32_t payLoadLen, int32_t priority)
{
    if (info == NULL || payLoad == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    ProxyDataInfo dataInfo = { 0 };
    ProxyMessageHead msgHead = { 0 };
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;

    if ((info->appInfo.channelCapability & TRANS_CHANNEL_INNER_ENCRYPT) != 0) {
        int32_t ret = TransProxySendEncryptInnerMessage(info, payLoad, payLoadLen, &msgHead, &dataInfo);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send encrypt msg failed");
            return ret;
        }
    } else {
        dataInfo.inData = (uint8_t *)payLoad;
        dataInfo.inLen = payLoadLen;
        if (TransProxyPackMessage(&msgHead, info->authHandle, &dataInfo, false, &(info->ukIdInfo)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "pack msg error");
            return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
        }
        return TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen,
            priority, info->appInfo.myData.pid);
    }
    return SOFTBUS_OK;
}

static inline AuthLinkType ConvertConnectType2AuthLinkType(ConnectType type)
{
    if (type == CONNECT_TCP) {
        return AUTH_LINK_TYPE_WIFI;
    } else if ((type == CONNECT_BLE) || (type == CONNECT_BLE_DIRECT)) {
        return AUTH_LINK_TYPE_BLE;
    } else if (type == CONNECT_BR) {
        return AUTH_LINK_TYPE_BR;
    } else {
        return AUTH_LINK_TYPE_P2P;
    }
}

static int32_t SetCipherOfHandshakeMsg(ProxyChannelInfo *info, uint8_t *cipher)
{
    AuthGetLatestIdByUuid(info->appInfo.peerData.deviceId, ConvertConnectType2AuthLinkType(info->type),
                          false, &info->authHandle);
    if (info->authHandle.authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "get authId for cipher err");
        return SOFTBUS_TRANS_PROXY_GET_AUTH_ID_FAILED;
    }

    int32_t ret = TransProxySetAuthHandleByChanId((int32_t)info->channelId, info->authHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set authHandle fail, ret=%{public}d", ret);
        return ret;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthGetConnInfo(info->authHandle, &connInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth connInfo fail");
        return ret;
    }
    bool isAuthServer = false;
    ret = AuthGetServerSide(info->authHandle.authId, &isAuthServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth server side fail");
        return ret;
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

int32_t TransProxyHandshake(ProxyChannelInfo *info, bool isNegoUk, const UkIdInfo *ukIdInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    uint8_t type =
        IsVaildUkInfo(ukIdInfo) ? PROXYCHANNEL_MSG_TYPE_HANDSHAKE_WITHUKENCY : PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    type = isNegoUk ? PROXYCHANNEL_MSG_TYPE_HANDSHAKE_UK : type;
    (void)TransProxySetUkInfoByChanId(info->myId, ukIdInfo);
    msgHead.type = (type & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.cipher = CS_MODE;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        if (SetCipherOfHandshakeMsg(info, &msgHead.cipher) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "set cipher fail");
            return SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED;
        }
    }
    msgHead.myId = info->myId;
    msgHead.peerId = INVALID_CHANNEL_ID;
    TRANS_LOGI(TRANS_CTRL, "handshake myChannelId=%{public}d, cipher=0x%{public}02x", msgHead.myId, msgHead.cipher);
    if (isNegoUk) {
        payLoad = PackUkRequest(&info->appInfo);
    } else {
        payLoad = TransProxyPackHandshakeMsg(info);
    }
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake fail");
        return SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, info->authHandle, &dataInfo, true, ukIdInfo) != SOFTBUS_OK) {
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
    return SOFTBUS_OK;
}

int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(chan != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = {0};
    ProxyMessageHead msgHead = {0};
    uint8_t type = chan->ukIdInfo.myId != 0 ?
        PROXYCHANNEL_MSG_TYPE_HANDSHAKE_WITHUKENCY_ACK : PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    msgHead.type = (type & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (chan->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }
    msgHead.myId = chan->myId;
    msgHead.peerId = chan->peerId;

    if (retCode != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL,
            "send handshake error msg errCode=%{public}d, myChannelId=%{public}d, peerChannelId=%{public}d",
            retCode, chan->myId, chan->peerId);
        payLoad = TransProxyPackHandshakeErrMsg(retCode);
    } else {
        TRANS_LOGI(TRANS_CTRL, "send handshake ack msg myChannelId=%{public}d, peerChannelId=%{public}d",
            chan->myId, chan->peerId);
        payLoad = TransProxyPackHandshakeAckMsg(chan);
    }
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake ack fail");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    if (TransProxyPackMessage(&msgHead, chan->authHandle, &dataInfo, false, &(chan->ukIdInfo)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    cJSON_free(payLoad);
    int32_t ret = TransProxyTransSendMsg(connId, dataInfo.outData, dataInfo.outLen,
        CONN_HIGH, chan->appInfo.myData.pid);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "send handshakeack buf fail");
    return SOFTBUS_OK;
}

int32_t TransProxyAckHandshakeUk(const UkRequestNode *ukRequest, int32_t ukId, int32_t retCode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(ukRequest != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    char *payLoad = NULL;
    ProxyDataInfo dataInfo = { 0 };
    ProxyMessageHead msgHead = { 0 };

    msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE_UK_ACK & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.cipher = (msgHead.cipher | ENCRYPTED);

    msgHead.myId = -1;
    msgHead.peerId = ukRequest->channelId;
    if (retCode != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "send handshake uk error msg errCode=%{public}d, peerChannelId=%{public}d", retCode,
            ukRequest->channelId);
        payLoad = TransProxyPackHandshakeErrMsg(retCode);
    } else {
        TRANS_LOGI(TRANS_CTRL, "send handshake uk ack msg, peerChannelId=%{public}d", ukRequest->channelId);
        payLoad = PackUkReply(&ukRequest->aclInfo, ukId);
    }
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake uk ack fail");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    UkIdInfo ukIdInfo = { 0 };
    (void)TransProxyGetUkInfoByChanId(msgHead.myId, &ukIdInfo);
    if (TransProxyPackMessage(&msgHead, ukRequest->authHandle, &dataInfo, false, &ukIdInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack handshake ack head fail");
        cJSON_free(payLoad);
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }
    cJSON_free(payLoad);
    int32_t ret =
        TransProxyTransSendMsg(ukRequest->connId, dataInfo.outData, dataInfo.outLen, CONN_HIGH, ukRequest->pid);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "send handshake ack buf fail.");
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
    if (TransProxyPackMessage(&msgHead, info->authHandle, &dataInfo, false, &(info->ukIdInfo)) != SOFTBUS_OK) {
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
        return SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    int32_t ret = TransProxyPackMessage(&msgHead, info->authHandle, &dataInfo, false, &(info->ukIdInfo));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack keepalive ack head fail");
        cJSON_free(payLoad);
        return ret;
    }
    cJSON_free(payLoad);
    ret = TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen, CONN_HIGH, info->appInfo.myData.pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send keepalive ack buf fail");
        return ret;
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
    TRANS_LOGI(TRANS_CTRL, "send reset msg myChannelId=%{public}d, peerChannelId=%{public}d", info->myId, info->peerId);
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_RESET & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    if (info->appInfo.appType != APP_TYPE_AUTH) {
        msgHead.cipher = (msgHead.cipher | ENCRYPTED);
    }

    payLoad = TransProxyPackIdentity(info->identity);
    if (payLoad == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack reset fail");
        return SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED;
    }
    dataInfo.inData = (uint8_t *)payLoad;
    dataInfo.inLen = strlen(payLoad) + 1;
    int32_t ret = TransProxyPackMessage(&msgHead, info->authHandle, &dataInfo, false, &(info->ukIdInfo));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack reset head fail");
        cJSON_free(payLoad);
        return ret;
    }
    cJSON_free(payLoad);
    ret = TransProxyTransSendMsg(info->connId, dataInfo.outData, dataInfo.outLen, CONN_LOW, info->appInfo.myData.pid);
    TransEventExtra extra = {
        .socketName = info->appInfo.myData.sessionName,
        .channelId = info->channelId,
        .errcode = ret,
        .result = EVENT_STAGE_RESULT_OK
    };
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reset buf fail");
        extra.result = EVENT_STAGE_RESULT_FAILED;
        TRANS_EVENT(EVENT_SCENE_TRANS_PROXY_RESET_PEER, EVENT_STAGE_TRANS_COMMON_ONE, extra);
        return ret;
    }
    TRANS_EVENT(EVENT_SCENE_TRANS_PROXY_RESET_PEER, EVENT_STAGE_TRANS_COMMON_ONE, extra);
    return SOFTBUS_OK;
}
