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

static int32_t ChiperSideProc(ProxyMessage *msg, int32_t *side)
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

static int32_t GetRemoteUuidByBtMac(const char *peerMac, char *uuid, int32_t len)
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

static int32_t TransProxyGetAuthConnectOption(uint32_t connId, ConnectOption *option)
{
    if (TransProxyGetConnectOption(connId, option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth option fail connId[%d]", connId);
        return SOFTBUS_ERR;
    }
    if (option->type == CONNECT_BR) {
        char uuid[UUID_BUF_LEN] = {0};
        if (GetRemoteUuidByBtMac(option->info.brOption.brMac, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get uuid by btmac fail");
            return SOFTBUS_ERR;
        }
        if (AuthGetActiveConnectOption(uuid, CONNECT_BLE, option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth ble connect option by uuid fail");
            if (AuthGetActiveConnectOption(uuid, CONNECT_BR, option) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth br connect option by uuid fail");
                return SOFTBUS_ERR;
            }
        }
    }
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    uint8_t isEncrypted;
    int32_t isServer;
    ConnectOption option;
    OutBuf deBuf = {0};

    if (len <= PROXY_CHANNEL_HEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parseMessage: invalid message length(%d)", len);
        return SOFTBUS_ERR;
    }
    if (TransProxyParseMessageHead(data, len, msg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    isEncrypted = ((msg->msgHead.chiper & ENCRYPTED) != 0);
    isServer = ((msg->msgHead.chiper & AUTH_SERVER_SIDE) != 0);
    bool isBle = ((msg->msgHead.chiper & USE_BLE_CIPHER) != 0);
    if (isEncrypted) {
        if (ChiperSideProc(msg, &isServer) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get side fail chanId[%d]", msg->msgHead.myId);
            return SOFTBUS_ERR;
        }
        msg->chiperSide = isServer;
        if (TransProxyGetAuthConnectOption(msg->connId, &option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parse msg GetConnectOption fail connId[%d]", msg->connId);
            return SOFTBUS_ERR;
        }
        if (isBle && option.type != CONNECT_BLE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth option fail. type[%d]", option.type);
            return SOFTBUS_ERR;
        }
        deBuf.buf = SoftBusCalloc((uint32_t)len - PROXY_CHANNEL_HEAD_LEN);
        if (deBuf.buf == NULL) {
            return SOFTBUS_ERR;
        }
        deBuf.bufLen = (uint32_t)len - PROXY_CHANNEL_HEAD_LEN;
        if (AuthDecrypt(&option, (AuthSideFlag)isServer, (uint8_t *)(data + PROXY_CHANNEL_HEAD_LEN),
            (uint32_t)len - PROXY_CHANNEL_HEAD_LEN, &deBuf) != SOFTBUS_OK) {
            SoftBusFree(deBuf.buf);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg decrypt fail isServer");
            return SOFTBUS_ERR;
        }
        msg->data = (char *)deBuf.buf;
        msg->dateLen = (int32_t)deBuf.outLen;
    }

    return SOFTBUS_OK;
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, uint32_t connId,
    const char *payload, int32_t payloadLen, char **data, int32_t *dataLen)
{
    char *buf = NULL;
    uint32_t bufLen;
    uint32_t connHeadLen;
    connHeadLen = ConnGetHeadSize();
    AuthSideFlag isServer = AUTH_SIDE_ANY;
    if (msg->type != PROXYCHANNEL_MSG_TYPE_NORMAL) {
        AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "TransProxyPackMessage, payload: ", payload, payloadLen);
    }

    if (msg->chiper == 0) {
        bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + (uint32_t)payloadLen;
        buf = (char*)SoftBusCalloc(bufLen);
        if (buf == NULL) {
            return SOFTBUS_ERR;
        }
        if (memcpy_s(buf + connHeadLen, bufLen - connHeadLen, msg, sizeof(ProxyMessageHead)) != EOK) {
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, bufLen - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
            payload, payloadLen) != EOK) {
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        *data = buf;
        *dataLen = (int32_t)bufLen;
    } else {
        OutBuf enBuf = {0};
        ConnectOption option;
        int ret;

        if (TransProxyGetAuthConnectOption(connId, &option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg GetConnectOption fail connId[%u]", connId);
            return SOFTBUS_ERR;
        }
        bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + (uint32_t)payloadLen + AuthGetEncryptHeadLen();
        buf = (char *)SoftBusCalloc(bufLen);
        if (buf == NULL) {
            return SOFTBUS_ERR;
        }
        enBuf.buf = (unsigned char *)(buf + PROXY_CHANNEL_HEAD_LEN + connHeadLen);
        enBuf.bufLen = bufLen - PROXY_CHANNEL_HEAD_LEN - connHeadLen;
        ret = AuthEncrypt(&option, &isServer, (uint8_t *)payload, (uint32_t)payloadLen, &enBuf);
        if (ret != SOFTBUS_OK) {
            SoftBusFree(buf);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg encrypt fail %d", ret);
            return SOFTBUS_ERR;
        }

        if (isServer == SERVER_SIDE_FLAG) {
            msg->chiper = msg->chiper | AUTH_SERVER_SIDE;
        }
        if (option.type == CONNECT_BLE) {
            msg->chiper = msg->chiper | USE_BLE_CIPHER;
        }

        if (memcpy_s(buf + connHeadLen, bufLen - connHeadLen, msg, sizeof(ProxyMessageHead)) != EOK) {
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, bufLen - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
            enBuf.buf, enBuf.outLen) != EOK) {
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        *data = buf;
        *dataLen = (int32_t)(PROXY_CHANNEL_HEAD_LEN + connHeadLen + enBuf.outLen);
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
    if (!AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, appInfo->encrypt) ||
        !AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, appInfo->algorithm) ||
        !AddNumberToJsonObject(root, JSON_KEY_CRC, appInfo->crc)) {
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
            !AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName) ||
            !AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, appInfo->encrypt) ||
            !AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, appInfo->algorithm) ||
            !AddNumberToJsonObject(root, JSON_KEY_CRC, appInfo->crc)) {
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &appInfo->encrypt) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &appInfo->algorithm) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &appInfo->crc)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "unpack handshake ack old version");
        appInfo->encrypt = APP_INFO_SUPPORT;
        appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
        appInfo->crc = APP_INFO_NO_SUPPORT;
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
    if (!GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &appInfo->encrypt) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &appInfo->algorithm) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &appInfo->crc)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "unpack handshake old version");
        appInfo->encrypt = APP_INFO_SUPPORT;
        appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
        appInfo->crc = APP_INFO_NO_SUPPORT;
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
