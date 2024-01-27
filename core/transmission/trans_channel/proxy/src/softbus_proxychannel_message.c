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

#include "softbus_proxychannel_message.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_datahead_transform.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_utils.h"
#include "trans_log.h"

static int g_proxyPktHeadSeq = 2048;

static int32_t TransProxyParseMessageHead(char *data, int32_t len, ProxyMessage *msg)
{
    char *ptr = data;
    uint8_t firstByte = *ptr;
    ptr += sizeof(int8_t);
    int8_t version = (firstByte >> VERSION_SHIFT) & FOUR_BIT_MASK;
    msg->msgHead.type = firstByte & FOUR_BIT_MASK;
    if (version != VERSION || msg->msgHead.type >= PROXYCHANNEL_MSG_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "parseMessage: unsupported message, version=%{public}d, type=%{public}d",
            version, msg->msgHead.type);
        return SOFTBUS_ERR;
    }

    msg->msgHead.cipher = *ptr;
    ptr += sizeof(int8_t);
    msg->msgHead.peerId = (int16_t)SoftBusBEtoLEs(*(uint16_t *)ptr);
    ptr += sizeof(uint16_t);
    msg->msgHead.myId = (int16_t)SoftBusBEtoLEs(*(uint16_t *)ptr);
    msg->data = data + sizeof(ProxyMessageHead);
    msg->dateLen = len - sizeof(ProxyMessageHead);
    UnpackProxyMessageHead(&msg->msgHead);

    return SOFTBUS_OK;
}

static void TransProxyPackMessageHead(ProxyMessageHead *msgHead, uint8_t *buf, uint32_t size)
{
    if (size < PROXY_CHANNEL_HEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "proxy head not enough");
        return;
    }
    uint32_t offset = 0;
    *buf = msgHead->type;
    offset += sizeof(uint8_t);
    *(buf + offset) = msgHead->cipher;
    offset += sizeof(uint8_t);
    *(uint16_t *)(buf + offset) = SoftBusBEtoLEs((uint16_t)msgHead->myId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusBEtoLEs((uint16_t)msgHead->peerId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusBEtoLEs((uint16_t)msgHead->reserved);
}

static int32_t GetRemoteUdidByBtMac(const char *peerMac, char *udid, int32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    char *tmpMac = NULL;
    Anonymize(peerMac, &tmpMac);
    TRANS_LOGI(TRANS_CTRL, "peerMac=%{public}s", tmpMac);
    AnonymizeFree(tmpMac);
    if (LnnGetNetworkIdByBtMac(peerMac, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetNetworkIdByBtMac fail");
        return SOFTBUS_NOT_FIND;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, len) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetRemoteStrInfo UDID fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetRemoteBtMacByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *brMac, int32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUdidHash(udidHash, udidHashLen, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetNetworkIdByUdidHash fail");
        return SOFTBUS_NOT_FIND;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, len) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetRemoteBtMac fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyGetAuthConnInfo(uint32_t connId, AuthConnInfo *connInfo)
{
    ConnectionInfo info = {0};
    if (ConnGetConnectionInfo(connId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ConnGetConnectionInfo fail, connId=%{public}u", connId);
        return SOFTBUS_ERR;
    }
    switch (info.type) {
        case CONNECT_TCP:
            connInfo->type = AUTH_LINK_TYPE_WIFI;
            if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, info.socketInfo.addr) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "copy ip fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BR:
            connInfo->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, info.brInfo.brMac) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BLE:
            connInfo->type = AUTH_LINK_TYPE_BLE;
            if (strcpy_s(connInfo->info.bleInfo.bleMac, BT_MAC_LEN, info.bleInfo.bleMac) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            if (memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                info.bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            connInfo->info.bleInfo.protocol = info.bleInfo.protocol;
            connInfo->info.bleInfo.psm = info.bleInfo.psm;
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "unexpected conn type=%{public}d.", info.type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertBrConnInfo2BleConnInfo(AuthConnInfo *connInfo)
{
    char udid[UDID_BUF_LEN] = {0};
    if (GetRemoteUdidByBtMac(connInfo->info.brInfo.brMac, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udid by btmac fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid),
        connInfo->info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate udid hash fail");
        return SOFTBUS_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_BLE;
    return SOFTBUS_OK;
}

static int32_t ConvertBleConnInfo2BrConnInfo(AuthConnInfo *connInfo)
{
    char brMac[BT_MAC_LEN] = {0};
    if (GetRemoteBtMacByUdidHash(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN,
        brMac, BT_MAC_LEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get btmac by udid fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, brMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy br mac fail");
        return SOFTBUS_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_BR;
    return SOFTBUS_OK;
}

static int64_t GetAuthIdByHandshakeMsg(uint32_t connId, uint8_t cipher)
{
    AuthConnInfo connInfo;
    if (TransProxyGetAuthConnInfo(connId, &connInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get connInfo fail connId=%{public}d", connId);
        return AUTH_INVALID_ID;
    }
    TRANS_LOGI(TRANS_CTRL, "cipher=%{public}d, connInfoType=%{public}d", cipher, connInfo.type);
    bool isBle = ((cipher & USE_BLE_CIPHER) != 0);
    if (isBle && connInfo.type == AUTH_LINK_TYPE_BR) {
        if (ConvertBrConnInfo2BleConnInfo(&connInfo) != SOFTBUS_OK) {
            return AUTH_INVALID_ID;
        }
    } else if (!isBle && connInfo.type == AUTH_LINK_TYPE_BLE) {
        if (ConvertBleConnInfo2BrConnInfo(&connInfo) != SOFTBUS_OK) {
            return AUTH_INVALID_ID;
        }
    }
    bool isAuthServer = !((cipher & AUTH_SERVER_SIDE) != 0);
    return AuthGetIdByConnInfo(&connInfo, isAuthServer, false);
}

int32_t GetBrMacFromConnInfo(uint32_t connId, char *peerBrMac, uint32_t len)
{
    AuthConnInfo connInfo;

    if (peerBrMac == NULL || len <= 0 || len > BT_MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (TransProxyGetAuthConnInfo(connId, &connInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get connInfo fail connId=%{public}d", connId);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(peerBrMac, len, connInfo.info.brInfo.brMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy brMac fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    if (len <= PROXY_CHANNEL_HEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "parseMessage: invalid message len=%{public}d", len);
        return SOFTBUS_ERR;
    }
    if (TransProxyParseMessageHead(data, len, msg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    bool isEncrypted = ((msg->msgHead.cipher & ENCRYPTED) != 0);
    if (isEncrypted) {
        if (msg->msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE) {
            TRANS_LOGI(TRANS_CTRL,
                "prxoy recv handshake cipher=0x%{public}02x", msg->msgHead.cipher);
            msg->authId = GetAuthIdByHandshakeMsg(msg->connId, msg->msgHead.cipher);
        } else {
            msg->authId = TransProxyGetAuthId(msg->msgHead.myId);
        }
        if (msg->authId == AUTH_INVALID_ID) {
            TRANS_LOGE(TRANS_CTRL,
                "get authId for decrypt fail, connId=%{public}d, myChannelId=%{public}d, type=%{public}d",
                msg->connId, msg->msgHead.myId, msg->msgHead.type);
            return SOFTBUS_AUTH_NOT_FOUND;
        }
        uint32_t decDataLen = AuthGetDecryptSize((uint32_t)msg->dateLen);
        uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
        if (decData == NULL) {
            return SOFTBUS_ERR;
        }
        msg->keyIndex = (int32_t)SoftBusLtoHl(*(uint32_t *)msg->data);
        if (AuthDecrypt(msg->authId, (uint8_t *)msg->data, (uint32_t)msg->dateLen,
            decData, &decDataLen) != SOFTBUS_OK) {
            SoftBusFree(decData);
            TRANS_LOGE(TRANS_CTRL, "parse msg decrypt fail");
            return SOFTBUS_DECRYPT_ERR;
        }
        msg->data = (char *)decData;
        msg->dateLen = (int32_t)decDataLen;
    } else {
        uint8_t *allocData = (uint8_t *)SoftBusCalloc((uint32_t)msg->dateLen);
        if (allocData == NULL) {
            return SOFTBUS_ERR;
        }
        if (memcpy_s(allocData, msg->dateLen, msg->data, msg->dateLen) != EOK) {
            SoftBusFree(allocData);
            return SOFTBUS_ERR;
        }
        msg->data = (char *)allocData;
    }
    return SOFTBUS_OK;
}

int32_t PackPlaintextMessage(ProxyMessageHead *msg, ProxyDataInfo *dataInfo)
{
    if (msg == NULL || dataInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t connHeadLen = ConnGetHeadSize();
    uint32_t size = PROXY_CHANNEL_HEAD_LEN + connHeadLen + dataInfo->inLen;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc proxy buf fail, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_MALLOC_ERR;
    }
    TransProxyPackMessageHead(msg, buf + connHeadLen, PROXY_CHANNEL_HEAD_LEN);
    if (memcpy_s(buf + connHeadLen + PROXY_CHANNEL_HEAD_LEN, size - connHeadLen - PROXY_CHANNEL_HEAD_LEN,
        dataInfo->inData, dataInfo->inLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "plaint ext message memcpy fail.");
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
        TRANS_LOGE(TRANS_CTRL, "invalid authId, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size = ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN + AuthGetEncryptSize(dataInfo->inLen);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc enc buf fail, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_MALLOC_ERR;
    }
    TransProxyPackMessageHead(msg, buf + ConnGetHeadSize(), PROXY_CHANNEL_HEAD_LEN);
    uint8_t *encData = buf + ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN;
    uint32_t encDataLen = size - ConnGetHeadSize() - PROXY_CHANNEL_HEAD_LEN;
    if (AuthEncrypt(authId, dataInfo->inData, dataInfo->inLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "pack msg encrypt fail, myChannelId=%{public}d", msg->myId);
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

    int32_t ret;
    if ((msg->cipher & ENCRYPTED) == 0) {
        ret = PackPlaintextMessage(msg, dataInfo);
    } else {
        ret = PackEncryptedMessage(msg, authId, dataInfo);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack proxy msg fail, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PackHandshakeMsgForFastData(AppInfo *appInfo, cJSON *root)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (appInfo->fastTransDataSize > 0) {
        if (!AddNumberToJsonObject(root, JSON_KEY_ROUTE_TYPE, appInfo->routeType)) {
            TRANS_LOGE(TRANS_CTRL, "add route type fail.");
            return SOFTBUS_ERR;
        }
        uint8_t *encodeFastData = (uint8_t *)SoftBusMalloc(BASE64_FAST_DATA_LEN);
        if (encodeFastData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc encode fast data fail.");
            return SOFTBUS_ERR;
        }
        size_t fastDataSize = 0;
        uint32_t outLen;
        char *buf = TransProxyPackFastData(appInfo, &outLen);
        if (buf == NULL) {
            TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
            SoftBusFree(encodeFastData);
            return SOFTBUS_ERR;
        }
        int32_t ret = SoftBusBase64Encode(encodeFastData, BASE64_FAST_DATA_LEN, &fastDataSize,
            (const unsigned char *)buf, outLen);
        if (ret != 0) {
            TRANS_LOGE(TRANS_CTRL, "mbedtls base64 encode failed.");
            SoftBusFree(encodeFastData);
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_FIRST_DATA, (const char *)encodeFastData)) {
            TRANS_LOGE(TRANS_CTRL, "add first data failed.");
            SoftBusFree(encodeFastData);
            SoftBusFree(buf);
            return SOFTBUS_ERR;
        }
        SoftBusFree(encodeFastData);
        SoftBusFree(buf);
    }
    if (!AddNumber16ToJsonObject(root, JSON_KEY_FIRST_DATA_SIZE, appInfo->fastTransDataSize)) {
        TRANS_LOGE(TRANS_CTRL, "add first data size failed.");
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
        TRANS_LOGE(TRANS_CTRL, "mbedtls_base64_encode FAIL ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "mbedtls_base64_encode len=%{public}zu", sessionBase64->len);
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
    if (PackHandshakeMsgForFastData(appInfo, root) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "proxy channel pack fast data failed");
        return SOFTBUS_ERR;
    }
    (void)AddNumberToJsonObject(root, JSON_KEY_BUSINESS_TYPE, appInfo->businessType);
    (void)AddNumberToJsonObject(root, JSON_KEY_TRANS_FLAGS, TRANS_FLAG_HAS_CHANNEL_AUTH);
    (void)AddNumberToJsonObject(root, JSON_KEY_MY_HANDLE_ID, appInfo->myHandleId);
    (void)AddNumberToJsonObject(root, JSON_KEY_PEER_HANDLE_ID, appInfo->peerHandleId);
    return SOFTBUS_OK;
}

char *TransProxyPackHandshakeErrMsg(int32_t errCode)
{
    cJSON *root = NULL;
    char *buf = NULL;

    root = cJSON_CreateObject();
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create json object failed.");
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
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create json object failed.");
        return NULL;
    }

    int32_t ret;
    char *buf = NULL;
    AppInfo *appInfo = &(info->appInfo);
    SessionKeyBase64 sessionBase64;
    (void)memset_s(&sessionBase64, sizeof(SessionKeyBase64), 0, sizeof(SessionKeyBase64));
    if (!AddNumberToJsonObject(root, JSON_KEY_TYPE, appInfo->appType) ||
        !AddStringToJsonObject(root, JSON_KEY_IDENTITY, info->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, appInfo->myData.deviceId) ||
        !AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, appInfo->myData.sessionName) ||
        !AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, appInfo->peerData.sessionName) ||
        !AddNumberToJsonObject(root, JSON_KEY_MTU_SIZE, appInfo->myData.dataConfig)) {
        goto EXIT;
    }
    (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);
    if (appInfo->appType == APP_TYPE_NORMAL) {
        if (PackHandshakeMsgForNormal(&sessionBase64, appInfo, root) != SOFTBUS_OK) {
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
            TRANS_LOGE(TRANS_CTRL, "mbedtls_base64_encode FAIL ret=%{public}d", ret);
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
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create json object failed.");
        return NULL;
    }

    if (!AddStringToJsonObject(root, JSON_KEY_IDENTITY, chan->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, appInfo->myData.deviceId)) {
        cJSON_Delete(root);
        return NULL;
    }
    if (appInfo->peerData.dataConfig != 0) {
        if (!AddNumberToJsonObject(root, JSON_KEY_MTU_SIZE, appInfo->myData.dataConfig)) {
            cJSON_Delete(root);
            return NULL;
        }
    }
    (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);
    if (appInfo->appType == APP_TYPE_NORMAL) {
        if (!AddNumberToJsonObject(root, JSON_KEY_UID, appInfo->myData.uid) ||
            !AddNumberToJsonObject(root, JSON_KEY_PID, appInfo->myData.pid) ||
            !AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName) ||
            !AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, appInfo->encrypt) ||
            !AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, appInfo->algorithm) ||
            !AddNumberToJsonObject(root, JSON_KEY_CRC, appInfo->crc) ||
            !AddNumber16ToJsonObject(root, JSON_KEY_FIRST_DATA_SIZE, appInfo->fastTransDataSize) ||
            !AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, appInfo->myData.sessionName) ||
            !AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, appInfo->peerData.sessionName)) {
            cJSON_Delete(root);
            return NULL;
        }
        (void)AddNumberToJsonObject(root, JSON_KEY_MY_HANDLE_ID, appInfo->myHandleId);
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
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectInt32Item(root, ERR_CODE, errCode)) {
        TRANS_LOGE(TRANS_CTRL, "get errCode failed.");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

int32_t TransProxyUnPackRestErrMsg(const char *msg, int *errCode, int32_t len)
{
    cJSON *root = cJSON_ParseWithLength(msg, len);
    if ((root == NULL) || (errCode == NULL)) {
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectInt32Item(root, ERR_CODE, errCode) && !GetJsonObjectInt32Item(root, "ERR_CODE", errCode)) {
        TRANS_LOGE(TRANS_CTRL, "get errCode failed.");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo,
    int32_t len, uint16_t *fastDataSize)
{
    cJSON *root = 0;
    AppInfo *appInfo = &(chanInfo->appInfo);
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    root = cJSON_ParseWithLength(msg, len);
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chanInfo->identity, sizeof(chanInfo->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, appInfo->peerData.deviceId,
                                 sizeof(appInfo->peerData.deviceId))) {
        TRANS_LOGE(TRANS_CTRL, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_MTU_SIZE, (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGE(TRANS_CTRL, "peer dataconfig is null.");
    }
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int32_t appType = TransProxyGetAppInfoType(chanInfo->myId, chanInfo->identity);
    if (appType == SOFTBUS_ERR || appType == SOFTBUS_LOCK_ERR) {
        TRANS_LOGE(TRANS_CTRL, "fail to get app type");
        cJSON_Delete(root);
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }
    appInfo->appType = (AppType)appType;
    if (appInfo->appType == APP_TYPE_NORMAL) {
        if (!GetJsonObjectNumberItem(root, JSON_KEY_UID, &appInfo->peerData.uid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_PID, &appInfo->peerData.pid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &appInfo->encrypt) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &appInfo->algorithm) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &appInfo->crc) ||
            !GetJsonObjectNumber16Item(root, JSON_KEY_FIRST_DATA_SIZE, fastDataSize) ||
            !GetJsonObjectStringItem(root, JSON_KEY_SRC_BUS_NAME, appInfo->peerData.sessionName,
                                 sizeof(appInfo->peerData.sessionName)) ||
            !GetJsonObjectStringItem(root, JSON_KEY_DST_BUS_NAME, appInfo->myData.sessionName,
                                 sizeof(appInfo->myData.sessionName))) {
            TRANS_LOGW(TRANS_CTRL, "unpack handshake ack old version");
        }
        if (!GetJsonObjectInt32Item(root, JSON_KEY_MY_HANDLE_ID, &(appInfo->peerHandleId))) {
                appInfo->peerHandleId = -1;
        }
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, appInfo->peerData.pkgName,
                                 sizeof(appInfo->peerData.pkgName))) {
        TRANS_LOGW(TRANS_CTRL, "no item to get pkg name");
    }
    cJSON_Delete(root);
    return SOFTBUS_OK;
}

static int32_t UnpackPackHandshakeMsgForFastData(AppInfo *appInfo, cJSON *root)
{
    if (!GetJsonObjectNumber16Item(root, JSON_KEY_FIRST_DATA_SIZE, &(appInfo->fastTransDataSize))) {
        TRANS_LOGW(TRANS_CTRL, "Failed to get handshake msg fast data size");
        appInfo->fastTransDataSize = 0;
    }
    if (appInfo->fastTransDataSize > 0 && appInfo->fastTransDataSize <= MAX_FAST_DATA_LEN) {
        if (!GetJsonObjectNumberItem(root, JSON_KEY_ROUTE_TYPE, (int32_t*)&(appInfo->routeType))) {
            TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg route type");
            return SOFTBUS_ERR;
        }
        uint8_t *encodeFastData = (uint8_t *)SoftBusMalloc(BASE64_FAST_DATA_LEN);
        if (encodeFastData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc encode fast data fail.");
            return SOFTBUS_ERR;
        }
        size_t fastDataSize = 0;
        if (!GetJsonObjectStringItem(root, JSON_KEY_FIRST_DATA, (char *)encodeFastData, BASE64_FAST_DATA_LEN)) {
            TRANS_LOGE(TRANS_CTRL, "failed to get fast data");
            SoftBusFree(encodeFastData);
            return SOFTBUS_ERR;
        }
        appInfo->fastTransData = (uint8_t *)SoftBusMalloc(appInfo->fastTransDataSize + FAST_EXT_BYTE_SIZE);
        if (appInfo->fastTransData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc fast data fail.");
            SoftBusFree(encodeFastData);
            return SOFTBUS_ERR;
        }

        int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->fastTransData, appInfo->fastTransDataSize +
            FAST_EXT_BYTE_SIZE, &fastDataSize, encodeFastData, strlen((char*)encodeFastData));
        if (ret != 0) {
            TRANS_LOGE(TRANS_CTRL, "mbedtls decode failed.");
            SoftBusFree((void *)appInfo->fastTransData);
            SoftBusFree(encodeFastData);
            return SOFTBUS_ERR;
        }
        SoftBusFree(encodeFastData);
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyUnpackNormalHandshakeMsg(cJSON *root, AppInfo *appInfo, char *sessionKey, int32_t keyLen)
{
    if (!GetJsonObjectNumberItem(root, JSON_KEY_UID, &(appInfo->peerData.uid)) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_PID, &(appInfo->peerData.pid)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, appInfo->peerData.pkgName,
                                 sizeof(appInfo->peerData.pkgName)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_SESSION_KEY, sessionKey, keyLen)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg APP_TYPE_NORMAL");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &appInfo->encrypt) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &appInfo->algorithm) ||
        !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &appInfo->crc)) {
        TRANS_LOGW(TRANS_CTRL, "unpack handshake old version");
        appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
        appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
        appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_BUSINESS_TYPE, (int*)&appInfo->businessType)) {
        appInfo->businessType = BUSINESS_TYPE_NOT_CARE;
    }

    GetJsonObjectStringItem(root, JSON_KEY_GROUP_ID, appInfo->groupId, sizeof(appInfo->groupId));
    if (!GetJsonObjectInt32Item(root, JSON_KEY_MY_HANDLE_ID, &(appInfo->peerHandleId)) ||
        !GetJsonObjectInt32Item(root, JSON_KEY_PEER_HANDLE_ID, &(appInfo->myHandleId))) {
            appInfo->myHandleId = -1;
            appInfo->peerHandleId = -1;
    }
    size_t len = 0;
    int32_t ret = SoftBusBase64Decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
        &len, (uint8_t *)sessionKey, strlen(sessionKey));
    if (len != sizeof(appInfo->sessionKey) || ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "decode session fail ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    if (UnpackPackHandshakeMsgForFastData(appInfo, root) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "unpack fast data failed");
        SoftBusFree((void *)appInfo->fastTransData);
        return SOFTBUS_TRANS_PROXY_UNPACK_FAST_DATA_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyUnpackAuthHandshakeMsg(cJSON *root, AppInfo *appInfo)
{
    if (!GetJsonObjectStringItem(root, JSON_KEY_REQUEST_ID, appInfo->reqId, REQ_ID_SIZE_MAX)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg REQUEST_ID");
        return SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_REQUEST_FAILED;
    }
    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME,
        appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName))) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg pkgName");
        return SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_PKG_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyUnpackInnerHandshakeMsg(cJSON *root, AppInfo *appInfo, char *sessionKey, int32_t keyLen)
{
    if (!GetJsonObjectStringItem(root, JSON_KEY_SESSION_KEY, sessionKey, keyLen)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg");
        return SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_SESSIONKEY_FAILED;
    }
    size_t len = 0;
    int32_t ret = SoftBusBase64Decode((uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey),
        &len, (uint8_t *)sessionKey, strlen(sessionKey));
    if (len != sizeof(appInfo->sessionKey) || ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "decode session fail ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len)
{
    cJSON *root = cJSON_ParseWithLength(msg, len);
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char sessionKey[BASE64KEY] = {0};
    AppInfo *appInfo = &(chan->appInfo);

    if (!GetJsonObjectNumberItem(root, JSON_KEY_TYPE, (int32_t*)&(appInfo->appType)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chan->identity, sizeof(chan->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, appInfo->peerData.deviceId,
                                 sizeof(appInfo->peerData.deviceId)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_SRC_BUS_NAME, appInfo->peerData.sessionName,
                                 sizeof(appInfo->peerData.sessionName)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DST_BUS_NAME, appInfo->myData.sessionName,
                                 sizeof(appInfo->myData.sessionName))) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg");
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    
    if (!GetJsonObjectNumberItem(root, JSON_KEY_MTU_SIZE, (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGE(TRANS_CTRL, "peer dataconfig is null.");
    }

    int32_t ret = SOFTBUS_ERR;
    if (appInfo->appType == APP_TYPE_NORMAL) {
        ret = TransProxyUnpackNormalHandshakeMsg(root, appInfo, sessionKey, BASE64KEY);
        if (ret != SOFTBUS_OK) {
            goto ERR_EXIT;
        }
    } else if (appInfo->appType == APP_TYPE_AUTH) {
        ret = TransProxyUnpackAuthHandshakeMsg(root, appInfo);
        if (ret != SOFTBUS_OK) {
            goto ERR_EXIT;
        }
    } else {
        ret = TransProxyUnpackInnerHandshakeMsg(root, appInfo, sessionKey, BASE64KEY);
        if (ret != SOFTBUS_OK) {
            goto ERR_EXIT;
        }
    }

    GetJsonObjectNumberItem(root, JSON_KEY_TRANS_FLAGS, &appInfo->transFlag);
    if ((appInfo->transFlag & TRANS_FLAG_HAS_CHANNEL_AUTH) != 0) {
        GetJsonObjectNumber64Item(root, JSON_KEY_AUTH_SEQ, &appInfo->authSeq);
    }

    cJSON_Delete(root);
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    return SOFTBUS_OK;
ERR_EXIT:
    cJSON_Delete(root);
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    return ret;
}

char *TransProxyPackIdentity(const char *identity)
{
    cJSON *root = NULL;
    char *buf = NULL;

    if (identity == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create json object failed.");
        return NULL;
    }

    if (!AddStringToJsonObject(root, JSON_KEY_IDENTITY, identity)) {
        TRANS_LOGE(TRANS_CTRL, "add identity to json object failed.");
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
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, identity, identitySize)) {
        TRANS_LOGE(TRANS_CTRL, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

static int32_t TransProxyEncryptFastData(const char *sessionKey, int32_t seq, const char *in, uint32_t inLen,
    char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        return SOFTBUS_ERR;
    }

    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen,
        (unsigned char*)out, outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);

    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "encrypt error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static void FastDataPackPacketHead(PacketFastHead *data)
{
    data->magicNumber = (int32_t)SoftBusHtoLl((uint32_t)data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = (int32_t)SoftBusHtoLl((uint32_t)data->flags);
    data->dataLen = (int32_t)SoftBusHtoLl((uint32_t)data->dataLen);
}

static int32_t TransProxyPackFastDataHead(ProxyDataInfo *dataInfo, const AppInfo *appInfo)
{
#define MAGIC_NUMBER 0xBABEFACE
    if (dataInfo == NULL || appInfo ==NULL) {
        TRANS_LOGE(TRANS_CTRL, "invaild param.");
        return SOFTBUS_ERR;
    }
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketFastHead);
    uint32_t cipherLength = dataInfo->inLen + OVERHEAD_LEN;
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "calloc error");
        return SOFTBUS_MEM_ERR;
    }

    int32_t seq = g_proxyPktHeadSeq++;
    if (TransProxyEncryptFastData(appInfo->sessionKey, seq, (const char*)dataInfo->inData,
        dataInfo->inLen, (char*)dataInfo->outData + sizeof(PacketFastHead), &cipherLength) != SOFTBUS_OK) {
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "TransProxyEncryptFastData err");
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }

    PacketFastHead *pktHead = (PacketFastHead*)dataInfo->outData;
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->seq = seq;
    pktHead->flags = (appInfo->businessType == BUSINESS_TYPE_BYTE) ? FLAG_BYTES : FLAG_MESSAGE;
    pktHead->dataLen = (int32_t)cipherLength;
    FastDataPackPacketHead(pktHead);

    return SOFTBUS_OK;
}

static void FastDataPackSliceHead(SliceFastHead *data)
{
    data->priority = (int32_t)SoftBusHtoLl((uint32_t)data->priority);
    data->sliceNum = (int32_t)SoftBusHtoLl((uint32_t)data->sliceNum);
    data->sliceSeq = (int32_t)SoftBusHtoLl((uint32_t)data->sliceSeq);
    data->reserved = (int32_t)SoftBusHtoLl((uint32_t)data->reserved);
}
static int32_t TransProxyMessageData(const AppInfo *appInfo, ProxyDataInfo *dataInfo)
{
    dataInfo->inData = (uint8_t *)SoftBusMalloc(appInfo->fastTransDataSize);
    if (dataInfo->inData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc error");
        return SOFTBUS_ERR;
    }
    uint16_t fastDataSize = appInfo->fastTransDataSize;
    if (memcpy_s(dataInfo->inData, fastDataSize, appInfo->fastTransData, fastDataSize) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s error");
        SoftBusFree(dataInfo->inData);
        return SOFTBUS_ERR;
    }
    dataInfo->inLen = fastDataSize;
    return SOFTBUS_OK;
}

static int32_t TransProxyByteData(const AppInfo *appInfo, ProxyDataInfo *dataInfo)
{
    dataInfo->inData = (uint8_t *)SoftBusMalloc(appInfo->fastTransDataSize + sizeof(SessionHead));
    if (dataInfo->inData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc error");
        return SOFTBUS_ERR;
    }
    uint16_t fastDataSize = appInfo->fastTransDataSize;
    SessionHead *sessionHead = (SessionHead*)dataInfo->inData;
    sessionHead->seq = g_proxyPktHeadSeq++;
    sessionHead->packetFlag = (appInfo->businessType == BUSINESS_TYPE_BYTE) ? FLAG_BYTES : FLAG_MESSAGE;
    sessionHead->shouldAck = 0;
    if (memcpy_s(dataInfo->inData + sizeof(SessionHead), fastDataSize, appInfo->fastTransData, fastDataSize) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s error");
        SoftBusFree(dataInfo->inData);
        return SOFTBUS_ERR;
    }
    dataInfo->inLen = fastDataSize + sizeof(SessionHead);
    return SOFTBUS_OK;
}

char *TransProxyPackFastData(const AppInfo *appInfo, uint32_t *outLen)
{
    ProxyDataInfo dataInfo = {0};
    if (appInfo->businessType == BUSINESS_TYPE_MESSAGE && appInfo->routeType == WIFI_STA) {
        if (TransProxyMessageData(appInfo, &dataInfo) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "TransProxyMessageData error");
            return NULL;
        }
    } else {
        if (TransProxyByteData(appInfo, &dataInfo) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "TransProxyByteData error");
            return NULL;
        }
    }
    if (TransProxyPackFastDataHead(&dataInfo, appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransProxyPackFastDataHead error");
        SoftBusFree(dataInfo.inData);
        SoftBusFree(dataInfo.outData);
        return NULL;
    }

    char *sliceData = (char *)SoftBusMalloc(dataInfo.outLen + sizeof(SliceFastHead));
    if (sliceData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc slice data error");
        SoftBusFree(dataInfo.inData);
        SoftBusFree(dataInfo.outData);
        return NULL;
    }
    SliceFastHead *slicehead = (SliceFastHead*)sliceData;
    slicehead->priority = (appInfo->businessType == BUSINESS_TYPE_BYTE) ? FLAG_BYTES : FLAG_MESSAGE;
    slicehead->sliceNum = 1;
    slicehead->sliceSeq = 0;
    FastDataPackSliceHead(slicehead);
    if (memcpy_s(sliceData + sizeof(SliceFastHead), dataInfo.outLen, dataInfo.outData, dataInfo.outLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s error");
        SoftBusFree(dataInfo.inData);
        SoftBusFree(dataInfo.outData);
        SoftBusFree(sliceData);
        return NULL;
    }
    *outLen = dataInfo.outLen + sizeof(SliceFastHead);
    SoftBusFree(dataInfo.inData);
    SoftBusFree(dataInfo.outData);
    return sliceData;
}
