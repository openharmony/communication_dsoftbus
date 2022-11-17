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
#include "bus_center_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"

static int32_t TransProxyParseMessageHead(char *data, int32_t len, ProxyMessage *msg)
{
    char *ptr = data;
    uint8_t firstByte = *ptr;
    ptr += sizeof(int8_t);
    int8_t version = (firstByte >> VERSION_SHIFT) & FOUR_BIT_MASK;
    msg->msgHead.type = firstByte & FOUR_BIT_MASK;
    if (version != VERSION || msg->msgHead.type >= PROXYCHANNEL_MSG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parseMessage: unsupported message, version(%d), type(%d)",
            version, msg->msgHead.type);
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

int32_t GetRemoteUuidByBtMac(const char *peerMac, char *uuid, int32_t len)
{
    NodeBasicInfo *info = NULL;
    int32_t num = 0;

    if (LnnGetAllOnlineNodeInfo(&info, &num) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "get online node fail");
        return SOFTBUS_ERR;
    }
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "no online node");
        return SOFTBUS_NOT_FIND;
    }
    if (num == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "num is 0");
        SoftBusFree(info);
        return SOFTBUS_NOT_FIND;
    }
    for (int32_t i = 0; i < num; i++) {
        char btMac[BT_MAC_LEN] = {0};
        char *tmpNetworkId = info[i].networkId;
        if (LnnGetRemoteStrInfo(tmpNetworkId, STRING_KEY_BT_MAC, btMac, BT_MAC_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (Strnicmp(peerMac, btMac, BT_MAC_LEN) == 0) {
            if (LnnGetRemoteStrInfo(tmpNetworkId, STRING_KEY_UUID, uuid, len) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "get remote uuid fail");
                SoftBusFree(info);
                return SOFTBUS_ERR;
            }
            SoftBusFree(info);
            return SOFTBUS_OK;
        }
    }

    SoftBusFree(info);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetRemoteUuidByBtMac no find");
    return SOFTBUS_NOT_FIND;
}

static int32_t GetConnectOptionByConnId(uint32_t connId, bool isBle, bool isAuthServer, ConnectOption *option)
{
    char uuid[UUID_BUF_LEN] = {0};
    if (TransProxyGetConnectOption(connId, option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get connect option fail connId[%d]", connId);
        return SOFTBUS_ERR;
    }
    if (isBle && option->type == CONNECT_BR) {
        if (GetRemoteUuidByBtMac(option->info.brOption.brMac, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get uuid by btmac fail");
            return SOFTBUS_ERR;
        }
        if (AuthGetActiveBleConnectOption(uuid, isAuthServer, option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get ble auth connect option fail");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetChiperParam(ProxyMessage *msg, bool *isBle, bool *isAuthServer)
{
    uint8_t chiper = 0;
    if (msg->msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE) {
        *isAuthServer = !((msg->msgHead.chiper & AUTH_SERVER_SIDE) != 0);
        *isBle = ((msg->msgHead.chiper & USE_BLE_CIPHER) != 0);
        if (*isAuthServer) {
            chiper |= AUTH_SERVER_SIDE;
        }
        if (*isBle) {
            chiper |= USE_BLE_CIPHER;
        }
        msg->chiper = chiper;
        return SOFTBUS_OK;
    }

    if (TransProxyGetChiper(msg->msgHead.myId, &chiper) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get chiper fail, msgType=%d", msg->msgHead.type);
        return SOFTBUS_ERR;
    }
    *isAuthServer = ((chiper & AUTH_SERVER_SIDE) != 0);
    *isBle = ((chiper & USE_BLE_CIPHER) != 0);
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    OutBuf deBuf = {0};
    ConnectOption option = {0};
    if (len <= PROXY_CHANNEL_HEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parseMessage: invalid message length(%d)", len);
        return SOFTBUS_ERR;
    }
    if (TransProxyParseMessageHead(data, len, msg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    bool isEncrypted = ((msg->msgHead.chiper & ENCRYPTED) != 0);
    bool isBle = false;
    bool isAuthServer = false;
    if (GetChiperParam(msg, &isBle, &isAuthServer) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get chiper fail connId[%d]", msg->connId);
        return SOFTBUS_ERR;
    }

    if (isEncrypted) {
        if (GetConnectOptionByConnId(msg->connId, isBle, isAuthServer, &option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetConnectOptionByConnId fail connId[%d]", msg->connId);
            return SOFTBUS_ERR;
        }
        deBuf.buf = SoftBusCalloc((uint32_t)len - PROXY_CHANNEL_HEAD_LEN);
        if (deBuf.buf == NULL) {
            return SOFTBUS_ERR;
        }
        deBuf.bufLen = (uint32_t)len - PROXY_CHANNEL_HEAD_LEN;
        if (AuthDecrypt(&option, (isAuthServer ? CLIENT_SIDE_FLAG : SERVER_SIDE_FLAG),
            (uint8_t *)(data + PROXY_CHANNEL_HEAD_LEN), (uint32_t)len - PROXY_CHANNEL_HEAD_LEN, &deBuf) != SOFTBUS_OK) {
            SoftBusFree(deBuf.buf);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg decrypt fail isServer");
            return SOFTBUS_ERR;
        }
        msg->data = (char *)deBuf.buf;
        msg->dateLen = (int32_t)deBuf.outLen;
    }

    return SOFTBUS_OK;
}

static uint8_t *PackPlaintextMessage(ProxyMessageHead *msg, const uint8_t *payload, uint32_t payloadLen,
    uint32_t *outLen)
{
    uint32_t connHeadLen = ConnGetHeadSize();
    uint32_t size = PROXY_CHANNEL_HEAD_LEN + connHeadLen + payloadLen;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc proxy buf fail");
        return NULL;
    }
    if (memcpy_s(buf + connHeadLen, size - connHeadLen, msg, sizeof(ProxyMessageHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, size - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
        payload, payloadLen) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    *outLen = size;
    return buf;
}

static uint8_t *PackEncrypedMessage(ProxyMessageHead *msg, uint32_t connId,
    const uint8_t *payload, uint32_t payloadLen, uint32_t *outLen)
{
    OutBuf encBuf = {0};
    ConnectOption option = {0};
    uint32_t connHeadLen = ConnGetHeadSize();
    bool isAuthServer = ((msg->chiper & AUTH_SERVER_SIDE) != 0);
    bool isBle = ((msg->chiper & USE_BLE_CIPHER) != 0);
    if (GetConnectOptionByConnId(connId, isBle, isAuthServer, &option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetConnectOptionByConnId fail connId[%u]", connId);
        return NULL;
    }

    uint32_t size = PROXY_CHANNEL_HEAD_LEN + connHeadLen + payloadLen + AuthGetEncryptHeadLen();
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc enc buf fail connId[%u]", connId);
        return NULL;
    }
    encBuf.buf = buf + PROXY_CHANNEL_HEAD_LEN + connHeadLen;
    encBuf.bufLen = size - PROXY_CHANNEL_HEAD_LEN - connHeadLen;
    AuthSideFlag side = isAuthServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG;
    if (AuthEncrypt(&option, &side, (uint8_t *)payload, payloadLen, &encBuf) != SOFTBUS_OK) {
        SoftBusFree(buf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg encrypt fail");
        return NULL;
    }

    if (memcpy_s(buf + connHeadLen, size - connHeadLen, msg, sizeof(ProxyMessageHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, size - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
        encBuf.buf, encBuf.outLen) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    *outLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + encBuf.outLen;
    return buf;
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, uint32_t connId, ProxyDataInfo *dataInfo)
{
    if (msg == NULL || dataInfo == NULL || dataInfo->inData == NULL || dataInfo->inData == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (msg->chiper == 0) {
        dataInfo->outData = PackPlaintextMessage(msg, dataInfo->inData, dataInfo->inLen, &dataInfo->outLen);
    } else {
        dataInfo->outData = PackEncrypedMessage(msg, connId, dataInfo->inData, dataInfo->inLen, &dataInfo->outLen);
    }
    if (dataInfo->outData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack proxy msg fail connId[%u]", connId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PackHandshakeMsgForNormal(SessionKeyBase64 *sessionBase64, AppInfo *appInfo, cJSON *root)
{
    int32_t ret = SoftBusBase64Encode((unsigned char *)sessionBase64->sessionKeyBase64,
        sizeof(sessionBase64->sessionKeyBase64), &(sessionBase64->len),
        (unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "mbedtls_base64_encode FAIL %d", ret);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "mbedtls_base64_encode len %d", sessionBase64->len);
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
    cJSON *root = NULL;
    SessionKeyBase64 sessionBase64;
    char *buf = NULL;
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
        goto EXIT;
    }
    (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);

    if (appInfo->appType == APP_TYPE_NORMAL) {
        ret = PackHandshakeMsgForNormal(&sessionBase64, appInfo, root);
        if (ret != SOFTBUS_OK) {
            goto EXIT;
        }
    } else if (appInfo->appType == APP_TYPE_AUTH) {
        if (strlen(appInfo->reqId) == 0 && GenerateRandomStr(appInfo->reqId, REQ_ID_SIZE_MAX) != SOFTBUS_OK) {
            goto EXIT;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_REQUEST_ID, appInfo->reqId)) {
            goto EXIT;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName)) {
            goto EXIT;
        }
    } else {
        ret = SoftBusBase64Encode((uint8_t *)sessionBase64.sessionKeyBase64, sizeof(sessionBase64.sessionKeyBase64),
            &(sessionBase64.len), (uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
        if (ret != 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "mbedtls_base64_encode FAIL %d", ret);
            goto EXIT;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_SESSION_KEY, sessionBase64.sessionKeyBase64)) {
            goto EXIT;
        }
    }

    buf = cJSON_PrintUnformatted(root);
EXIT:
    cJSON_Delete(root);
    return buf;
}

char *TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan)
{
    cJSON *root = NULL;
    char *buf = NULL;
    AppInfo *appInfo = &(chan->appInfo);
    if (appInfo == NULL || appInfo->appType == APP_TYPE_NOT_CARE) {
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
    if (appInfo == NULL) {
        return SOFTBUS_ERR;
    }
    root = cJSON_Parse(msg);
    if (root == NULL) {
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chanInfo->identity, sizeof(chanInfo->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, appInfo->peerData.deviceId,
                                 sizeof(appInfo->peerData.deviceId))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, appInfo->peerData.pkgName,
                                 sizeof(appInfo->peerData.pkgName))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "no item to get pkg name");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to get handshake msg APP_TYPE_NORMAL");
        return SOFTBUS_ERR;
    }
    size_t len = 0;
    int32_t ret = SoftBusBase64Decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
        &len, (uint8_t *)sessionKey, strlen(sessionKey));
    if (len != sizeof(appInfo->sessionKey) || ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decode session fail %d ", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyUnpackAuthHandshakeMsg(cJSON *root, AppInfo *appInfo)
{
    if (!GetJsonObjectStringItem(root, JSON_KEY_REQUEST_ID, appInfo->reqId, REQ_ID_SIZE_MAX)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to get handshake msg REQUEST_ID");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME,
        appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to get handshake msg pkgName");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to get handshake msg");
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
        if (TransProxyUnpackAuthHandshakeMsg(root, appInfo) != SOFTBUS_OK) {
            cJSON_Delete(root);
            return SOFTBUS_ERR;
        }
    } else {
        if (!GetJsonObjectStringItem(root, JSON_KEY_SESSION_KEY, sessionKey, sizeof(sessionKey))) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to get handshake msg");
            cJSON_Delete(root);
            return SOFTBUS_ERR;
        }
        size_t len = 0;
        int32_t ret = SoftBusBase64Decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
            &len, (uint8_t *)sessionKey, strlen(sessionKey));
        if (len != sizeof(appInfo->sessionKey) || ret != 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decode session fail %d ", ret);
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

int32_t TransProxyUnpackIdentity(const char *msg, char *identity, uint32_t identitySize)
{
    cJSON *root = NULL;

    root = cJSON_Parse(msg);
    if (root == NULL) {
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, identity, identitySize)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}
