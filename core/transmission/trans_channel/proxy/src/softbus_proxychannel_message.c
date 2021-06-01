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

#include "softbus_proxychannel_message.h"

#include <securec.h>

#include "auth_interface.h"
#include "base64.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"

int32_t ChiperSideProc(ProxyMessage *msg, int32_t *side)
{
    if (msg->msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE) {
        *side = ((msg->msgHead.chiper & AUTH_SERVER_SIDE) ? CLIENT_SIDE_FLAG : SERVER_SIDE_FLAG);
        return SOFTBUS_OK;
    }
    if (TransProxyGetChiperSide(msg->msgHead.myId, side) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessageHead(ProxyMessage *msg, char *data, int32_t len)
{
    char *ptr = data;
    uint8_t firstByte = *ptr;
    ptr += sizeof(int8_t);
    int8_t version = (firstByte >> VERSION_SHIFT) & FOUR_BIT_MASK;
    msg->msgHead.type = firstByte & FOUR_BIT_MASK;
    if (version != VERSION || msg->msgHead.type >= PROXYCHANNEL_MSG_TYPE_MAX) {
        LOG_ERR("parseMessage: unsupported message, version(%d), type(%d)", version, msg->msgHead.type);
        return SOFTBUS_ERR;
    }

    msg->msgHead.chiper = *ptr;
    ptr += sizeof(int8_t);
    msg->msgHead.peerId = *(int16_t *)ptr;
    ptr += sizeof(uint16_t);
    msg->msgHead.myId = *(int16_t *)ptr;
    msg->data = data + sizeof(ProxyMessageHead);
    msg->dateLen = len - sizeof(ProxyMessageHead);
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    uint8_t isEncrypted;
    int32_t isServer;
    ConnectOption option;
    OutBuf deBuf = {0};

    if (len <= PROXY_CHANNEL_HEAD_LEN) {
        LOG_ERR("parseMessage: invalid message length(%d)", len);
        return SOFTBUS_ERR;
    }
    if (TransProxyParseMessageHead(msg, data, len) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    isEncrypted = ((msg->msgHead.chiper & ENCRYPTED) != 0);
    if (isEncrypted) {
        if (ChiperSideProc(msg, &isServer) != SOFTBUS_OK) {
            LOG_ERR("get side fail chanId[%d]", msg->msgHead.myId);
            return SOFTBUS_ERR;
        }
        msg->chiperSide = isServer;
        if (TransProxyGetConnectOption(msg->connId, &option) != 0) {
            LOG_ERR("parse msg GetConnectOption fail connId[%d]", msg->connId);
            return SOFTBUS_ERR;
        }

        deBuf.buf = SoftBusCalloc(len - PROXY_CHANNEL_HEAD_LEN);
        if (deBuf.buf == NULL) {
            return SOFTBUS_ERR;
        }
        deBuf.bufLen = len - PROXY_CHANNEL_HEAD_LEN;
        if (AuthDecrypt(&option, (AuthSideFlag)isServer, (uint8_t *)(data + PROXY_CHANNEL_HEAD_LEN),
            len - PROXY_CHANNEL_HEAD_LEN, &deBuf) != 0) {
            SoftBusFree(deBuf.buf);
            LOG_ERR("pack msg decrypt fail isServer");
            return SOFTBUS_ERR;
        }
        msg->data = (char *)deBuf.buf;
        msg->dateLen = deBuf.outLen;
    }

    return SOFTBUS_OK;
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, uint32_t connId,
    char *payload, int32_t payloadLen, char **data, int32_t *dataLen)
{
    char *buf = NULL;
    int32_t bufLen;
    int32_t connHeadLen;
    connHeadLen = ConnGetHeadSize();
    AuthSideFlag isServer = CLIENT_SIDE_FLAG;

    if (msg->chiper == 0) {
        bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + payloadLen;
        buf = (char*)SoftBusCalloc(bufLen);
        if (buf == NULL) {
            return SOFTBUS_ERR;
        }
        (void)memcpy_s(buf + connHeadLen, bufLen - connHeadLen, msg, sizeof(ProxyMessageHead));
        (void)memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN,
                       bufLen - connHeadLen - PROXY_CHANNEL_HEAD_LEN, payload, payloadLen);
        *data = buf;
        *dataLen = bufLen;
    } else {
        OutBuf enBuf = {0};
        ConnectOption option;
        int ret;

        if (TransProxyGetConnectOption(connId, &option) != SOFTBUS_OK) {
            LOG_ERR("pack msg GetConnectOption fail connId[%u]", connId);
            return SOFTBUS_ERR;
        }
        bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + payloadLen + AuthGetEncryptHeadLen();
        buf = SoftBusCalloc(bufLen);
        if (buf == NULL) {
            return SOFTBUS_ERR;
        }
        enBuf.buf = (unsigned char *)(buf + PROXY_CHANNEL_HEAD_LEN + connHeadLen);
        enBuf.bufLen = bufLen - PROXY_CHANNEL_HEAD_LEN - connHeadLen;
        ret = AuthEncrypt(&option, &isServer, (uint8_t *)payload, payloadLen, &enBuf);
        if (ret != SOFTBUS_OK) {
            SoftBusFree(buf);
            LOG_ERR("pack msg encrypt fail %d", ret);
            return SOFTBUS_ERR;
        }

        if (isServer == SERVER_SIDE_FLAG) {
            msg->chiper = msg->chiper | AUTH_SERVER_SIDE;
        }

        (void)memcpy_s(buf + connHeadLen, bufLen - connHeadLen, msg, sizeof(ProxyMessageHead));
        (void)memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN,
                       bufLen - connHeadLen - PROXY_CHANNEL_HEAD_LEN, enBuf.buf, enBuf.outLen);
        *data = buf;
        *dataLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + enBuf.outLen;
    }

    return SOFTBUS_OK;
}

static int32_t PackHandshakeMsgForNormal(SessionKeyBase64 *sessionBase64, AppInfo *appInfo, cJSON *root)
{
    int32_t ret = mbedtls_base64_encode((unsigned char *)sessionBase64->sessionKeyBase64,
                                        sizeof(sessionBase64->sessionKeyBase64), &(sessionBase64->len),
                                        (unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
    if (ret != 0) {
        LOG_ERR("mbedtls_base64_encode FAIL %d", ret);
        return ret;
    }
    LOG_INFO("mbedtls_base64_encode len %d", sessionBase64->len);
    if (!AddNumberToJsonObject(root, JSON_KEY_UID, appInfo->myData.uid) ||
        !AddNumberToJsonObject(root, JSON_KEY_PID, appInfo->myData.pid) ||
        !AddStringToJsonObject(root, JSON_KEY_GROUP_ID, appInfo->groupId) ||
        !AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName) ||
        !AddStringToJsonObject(root, JSON_KEY_SESSION_KEY, sessionBase64->sessionKeyBase64)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info)
{
    cJSON *root = 0;
    SessionKeyBase64 sessionBase64;
    char *buf = 0;
    AppInfo *appInfo = &(info->appInfo);
    int32_t ret;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    (void)memset_s(&sessionBase64, sizeof(SessionKeyBase64), 0, sizeof(SessionKeyBase64));
    if (!AddNumberToJsonObject(root, JSON_KEY_TYPE, appInfo->appType) ||
        !AddStringToJsonObject(root, JSON_KEY_IDENTITY, info->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, appInfo->myData.deviceId) ||
        !AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, appInfo->myData.sessionName) ||
        !AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, appInfo->peerData.sessionName)) {
        cJSON_Delete(root);
        return NULL;
    }
    (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);

    if (appInfo->appType == APP_TYPE_NORMAL) {
        ret = PackHandshakeMsgForNormal(&sessionBase64, appInfo, root);
        if (ret != SOFTBUS_OK) {
            cJSON_Delete(root);
            return NULL;
        }
    } else if (appInfo->appType == APP_TYPE_AUTH) {
        if (!AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName)) {
            cJSON_Delete(root);
            return NULL;
        }
    } else {
        ret = mbedtls_base64_encode((uint8_t *)sessionBase64.sessionKeyBase64,
                                    sizeof(sessionBase64.sessionKeyBase64), &(sessionBase64.len),
                                    (uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
        if (ret != 0) {
            LOG_ERR("mbedtls_base64_encode FAIL %d", ret);
            cJSON_Delete(root);
            return NULL;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_SESSION_KEY, sessionBase64.sessionKeyBase64)) {
            cJSON_Delete(root);
            return NULL;
        }
    }

    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

char *TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan)
{
    cJSON *root = NULL;
    char *buf = NULL;
    AppInfo *appInfo = &(chan->appInfo);

    if (appInfo->appType == APP_TYPE_NOT_CARE) {
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddStringToJsonObject(root, JSON_KEY_IDENTITY, chan->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, appInfo->myData.deviceId)) {
        cJSON_Delete(root);
        return NULL;
    }
    (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);
    if (appInfo->appType == APP_TYPE_NORMAL) {
        if (!AddNumberToJsonObject(root, JSON_KEY_UID, appInfo->myData.uid) ||
            !AddNumberToJsonObject(root, JSON_KEY_PID, appInfo->myData.pid) ||
            !AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName)) {
            cJSON_Delete(root);
            return NULL;
        }
    } else if (appInfo->appType == APP_TYPE_AUTH) {
        if (!AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName)) {
            cJSON_Delete(root);
            return NULL;
        }
    }

    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo)
{
    cJSON *root = 0;
    AppInfo *appInfo = &(chanInfo->appInfo);

    root = cJSON_Parse(msg);
    if (root == NULL) {
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chanInfo->identity, sizeof(chanInfo->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, appInfo->peerData.deviceId,
                                 sizeof(appInfo->peerData.deviceId))) {
        LOG_ERR("fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, appInfo->peerData.pkgName,
                                 sizeof(appInfo->peerData.pkgName))) {
        LOG_INFO("no item to get pkg name");
    }
    cJSON_Delete(root);
    return SOFTBUS_OK;
}

static int32_t UnpackHandshakeMsgForNormal(cJSON *root, AppInfo *appInfo, char *sessionKey, int32_t sessionKeyLen)
{
    if (!GetJsonObjectNumberItem(root, JSON_KEY_UID, &(appInfo->peerData.uid)) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_PID, &(appInfo->peerData.pid)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, appInfo->peerData.pkgName,
                                 sizeof(appInfo->peerData.pkgName)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_SESSION_KEY, sessionKey, sessionKeyLen)) {
        LOG_ERR("Failed to get handshake msg APP_TYPE_NORMAL");
        return SOFTBUS_ERR;
    }
    size_t len = 0;
    int32_t ret = mbedtls_base64_decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
        &len, (uint8_t *)sessionKey, strlen(sessionKey));
    if (len != sizeof(appInfo->sessionKey) || ret != 0) {
        LOG_ERR("decode session fail %d ", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan)
{
    cJSON *root = cJSON_Parse(msg);
    if (root == NULL) {
        return SOFTBUS_ERR;
    }
    char sessionKey[BASE64KEY] = {0};
    AppInfo *appInfo = &(chan->appInfo);
    int32_t appType = 0;

    if (!GetJsonObjectNumberItem(root, JSON_KEY_TYPE, &(appType)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chan->identity, sizeof(chan->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, appInfo->peerData.deviceId,
                                 sizeof(appInfo->peerData.deviceId)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_SRC_BUS_NAME, appInfo->peerData.sessionName,
                                 sizeof(appInfo->peerData.sessionName)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DST_BUS_NAME, appInfo->myData.sessionName,
                                 sizeof(appInfo->myData.sessionName))) {
        LOG_ERR("Failed to get handshake msg");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }
    appInfo->appType = (AppType)appType;

    if (appInfo->appType == APP_TYPE_NORMAL) {
        int32_t ret = UnpackHandshakeMsgForNormal(root, appInfo, sessionKey, BASE64KEY);
        if (ret != SOFTBUS_OK) {
            cJSON_Delete(root);
            return ret;
        }
    } else if (appInfo->appType == APP_TYPE_AUTH) {
        if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME,
            appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName))) {
            LOG_ERR("Failed to get handshake msg");
            cJSON_Delete(root);
            return SOFTBUS_ERR;
        }
    } else {
        if (!GetJsonObjectStringItem(root, JSON_KEY_SESSION_KEY, sessionKey, sizeof(sessionKey))) {
            LOG_ERR("Failed to get handshake msg");
            cJSON_Delete(root);
            return SOFTBUS_ERR;
        }
        size_t len = 0;
        int32_t ret = mbedtls_base64_decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
            &len, (uint8_t *)sessionKey, strlen(sessionKey));
        if (len != sizeof(appInfo->sessionKey) || ret != 0) {
            LOG_ERR("decode session fail %d ", ret);
            cJSON_Delete(root);
            return SOFTBUS_ERR;
        }
    }
    cJSON_Delete(root);
    return SOFTBUS_OK;
}

char *TransProxyPackIdentity(const char *identity)
{
    cJSON *root = NULL;
    char *buf = NULL;

    if (identity == NULL) {
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddStringToJsonObject(root, JSON_KEY_IDENTITY, identity)) {
        cJSON_Delete(root);
        return NULL;
    }

    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

int32_t TransProxyUnpackIdentity(const char *msg, char *identity, int32_t identitySize)
{
    cJSON *root = NULL;

    root = cJSON_Parse(msg);
    if (root == NULL) {
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, identity, identitySize)) {
        LOG_ERR("fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}
