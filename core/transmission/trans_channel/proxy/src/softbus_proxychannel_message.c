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
#include "softbus_message_open_channel.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "softbus_datahead_transform.h"
#include "softbus_adapter_socket.h"

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

    msg->msgHead.cipher = *ptr;
    ptr += sizeof(int8_t);
    msg->msgHead.peerId = *(int16_t *)ptr;
    ptr += sizeof(uint16_t);
    msg->msgHead.myId = *(int16_t *)ptr;
    msg->data = data + sizeof(ProxyMessageHead);
    msg->dateLen = len - sizeof(ProxyMessageHead);
    UnpackProxyMessageHead(&msg->msgHead);

    return SOFTBUS_OK;
}

static void TransProxyPackMessageHead(ProxyMessageHead *msgHead, uint8_t *buf, uint32_t size)
{
    if (size < PROXY_CHANNEL_HEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy head not enough");
        return;
    }
    uint32_t offset = 0;
    *buf = msgHead->type;
    offset += sizeof(uint8_t);
    *(buf + offset) = msgHead->cipher;
    offset += sizeof(uint8_t);
    *(uint16_t *)(buf + offset) = SoftBusHtoLs((uint16_t)msgHead->myId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusHtoLs((uint16_t)msgHead->peerId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusHtoLs((uint16_t)msgHead->reserved);
}

static int32_t GetRemoteUdidByBtMac(const char *peerMac, char *udid, int32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByBtMac(peerMac, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "LnnGetNetworkIdByBtMac fail");
        return SOFTBUS_NOT_FIND;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "LnnGetRemoteStrInfo UDID fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyGetAuthConnInfo(uint32_t connId, AuthConnInfo *connInfo)
{
    ConnectionInfo info = {0};
    if (ConnGetConnectionInfo(connId, &info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ConnGetConnectionInfo fail, connId=%u", connId);
        return SOFTBUS_ERR;
    }
    switch (info.type) {
        case CONNECT_TCP:
            connInfo->type = AUTH_LINK_TYPE_WIFI;
            if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, info.socketInfo.addr) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy ip fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BR:
            connInfo->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, info.brInfo.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unexpected connType: %d.", info.type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int64_t GetAuthIdByHandshakeMsg(uint32_t connId, uint8_t cipher)
{
    AuthConnInfo connInfo;
    if (TransProxyGetAuthConnInfo(connId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get connInfo fail connId[%d]", connId);
        return AUTH_INVALID_ID;
    }
    bool isBle = ((cipher & USE_BLE_CIPHER) != 0);
    if (isBle && connInfo.type == AUTH_LINK_TYPE_BR) {
        char udid[UDID_BUF_LEN] = {0};
        if (GetRemoteUdidByBtMac(connInfo.info.brInfo.brMac, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udid by btmac fail");
            return AUTH_INVALID_ID;
        }
        if (SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid),
            connInfo.info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate udid hash fail");
            return AUTH_INVALID_ID;
        }
        connInfo.type = AUTH_LINK_TYPE_BLE;
    }
    bool isAuthServer = !((cipher & AUTH_SERVER_SIDE) != 0);
    return AuthGetIdByConnInfo(&connInfo, isAuthServer, false);
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    if (len <= PROXY_CHANNEL_HEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parseMessage: invalid message length(%d)", len);
        return SOFTBUS_ERR;
    }
    if (TransProxyParseMessageHead(data, len, msg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    bool isEncrypted = ((msg->msgHead.cipher & ENCRYPTED) != 0);
    if (isEncrypted) {
        if (msg->msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "prxoy recv handshake cipher: 0x%02x", msg->msgHead.cipher);
            msg->authId = GetAuthIdByHandshakeMsg(msg->connId, msg->msgHead.cipher);
        } else {
            msg->authId = TransProxyGetAuthId(msg->msgHead.myId);
        }
        if (msg->authId == AUTH_INVALID_ID) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "get authId for decrypt fail, connId[%d], myId[%d], type[%d]",
                msg->connId, msg->msgHead.myId, msg->msgHead.type);
            return SOFTBUS_ERR;
        }
        uint32_t decDataLen = AuthGetDecryptSize((uint32_t)msg->dateLen);
        uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
        if (decData == NULL) {
            return SOFTBUS_ERR;
        }
        if (AuthDecrypt(msg->authId, (uint8_t *)msg->data, (uint32_t)msg->dateLen,
            decData, &decDataLen) != SOFTBUS_OK) {
            SoftBusFree(decData);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parse msg decrypt fail");
            return SOFTBUS_ERR;
        }
        msg->data = (char *)decData;
        msg->dateLen = (int32_t)decDataLen;
    }
    return SOFTBUS_OK;
}

static int32_t PackPlaintextMessage(ProxyMessageHead *msg, ProxyDataInfo *dataInfo)
{
    uint32_t connHeadLen = ConnGetHeadSize();
    uint32_t size = PROXY_CHANNEL_HEAD_LEN + connHeadLen + dataInfo->inLen;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc proxy buf fail, myId[%d]", msg->myId);
        return SOFTBUS_MALLOC_ERR;
    }
    TransProxyPackMessageHead(msg, buf + connHeadLen, PROXY_CHANNEL_HEAD_LEN);
    if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, size - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
        dataInfo->inData, dataInfo->inLen) != EOK) {
        SoftBusFree(buf);
        return SOFTBUS_MEM_ERR;
    }
    dataInfo->outData = buf;
    dataInfo->outLen = size;
    return SOFTBUS_OK;
}

static int32_t PackEncryptedMessage(ProxyMessageHead *msg, int64_t authId, ProxyDataInfo *dataInfo)
{
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid authId, myId[%d]", msg->myId);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size = ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN + AuthGetEncryptSize(dataInfo->inLen);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc enc buf fail, myId[%d]", msg->myId);
        return SOFTBUS_MALLOC_ERR;
    }
    TransProxyPackMessageHead(msg, buf + ConnGetHeadSize(), PROXY_CHANNEL_HEAD_LEN);
    uint8_t *encData = buf + ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN;
    uint32_t encDataLen = size - ConnGetHeadSize() - PROXY_CHANNEL_HEAD_LEN;
    if (AuthEncrypt(authId, dataInfo->inData, dataInfo->inLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusFree(buf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg encrypt fail, myId[%d]", msg->myId);
        return SOFTBUS_ENCRYPT_ERR;
    }
    dataInfo->outData = buf;
    dataInfo->outLen = size;
    return SOFTBUS_OK;
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, int64_t authId, ProxyDataInfo *dataInfo)
{
    if (msg == NULL || dataInfo == NULL || dataInfo->inData == NULL || dataInfo->inData == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (msg->type != PROXYCHANNEL_MSG_TYPE_NORMAL) {
        AnonyPacketPrintout(SOFTBUS_LOG_TRAN,
            "TransProxyPackMessage, payload: ", (const char *)dataInfo->inData, dataInfo->inLen);
    }

    int32_t ret;
    if ((msg->cipher & ENCRYPTED) == 0) {
        ret = PackPlaintextMessage(msg, dataInfo);
    } else {
        ret = PackEncryptedMessage(msg, authId, dataInfo);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack proxy msg fail, myId[%d]", msg->myId);
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
    if (!AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, appInfo->encrypt) ||
        !AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, appInfo->algorithm) ||
        !AddNumberToJsonObject(root, JSON_KEY_CRC, appInfo->crc)) {
        return SOFTBUS_ERR;
    }
    (void)AddNumberToJsonObject(root, JSON_KEY_BUSINESS_TYPE, appInfo->businessType);
    return SOFTBUS_OK;
}

char *TransProxyPackHandshakeErrMsg(int32_t errCode)
{
    cJSON *root = NULL;
    char *buf = NULL;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddNumberToJsonObject(root, ERR_CODE, errCode)) {
        cJSON_Delete(root);
        return NULL;
    }

    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
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

int32_t TransProxyUnPackHandshakeErrMsg(const char *msg, int *errCode, int32_t len)
{
    cJSON *root = cJSON_ParseWithLength(msg, len);
    if ((root == NULL) || (errCode == NULL)) {
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectInt32Item(root, ERR_CODE, errCode)) {
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}


int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo, int32_t len)
{
    cJSON *root = 0;
    AppInfo *appInfo = &(chanInfo->appInfo);
    if (appInfo == NULL) {
        return SOFTBUS_ERR;
    }
    root = cJSON_ParseWithLength(msg, len);
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
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int32_t appType = TransProxyGetAppInfoType(chanInfo->myId, chanInfo->identity);
    if (appType == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to get app type");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }
    appInfo->appType = (AppType)appType;
    if (appInfo->appType == APP_TYPE_NORMAL) {
        if (!GetJsonObjectNumberItem(root, JSON_KEY_UID, &appInfo->peerData.uid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_PID, &appInfo->peerData.pid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &appInfo->encrypt) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &appInfo->algorithm) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &appInfo->crc)) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "unpack handshake ack old version");
            appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
            appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
            appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
        }
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
        appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
        appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
        appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_BUSINESS_TYPE, (int*)&appInfo->businessType)) {
        appInfo->businessType = BUSINESS_TYPE_NOT_CARE;
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

int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len)
{
    cJSON *root = cJSON_ParseWithLength(msg, len);
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

int32_t TransProxyUnpackIdentity(const char *msg, char *identity, uint32_t identitySize, int32_t len)
{
    cJSON *root = NULL;

    root = cJSON_ParseWithLength(msg, len);
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
