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
#include <stdatomic.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_datahead_transform.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_session_account_adapter.h"


static _Atomic int32_t g_proxyPktHeadSeq = 2048;

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
        return SOFTBUS_TRANS_INVALID_MESSAGE_TYPE;
    }

    msg->msgHead.cipher = *ptr;
    ptr += sizeof(int8_t);
    msg->msgHead.peerId = (int16_t)SoftBusBEtoLEs(*(uint16_t *)ptr);
    ptr += sizeof(uint16_t);
    msg->msgHead.myId = (int16_t)SoftBusBEtoLEs(*(uint16_t *)ptr);
    ptr += sizeof(uint16_t);
    msg->msgHead.reserved = (int16_t)SoftBusBEtoLEs(*(uint16_t *)ptr);
    msg->data = data + sizeof(ProxyMessageHead);
    msg->dateLen = len - sizeof(ProxyMessageHead);

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
    *(uint16_t *)(buf + offset) = SoftBusLEtoBEs((uint16_t)msgHead->myId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusLEtoBEs((uint16_t)msgHead->peerId);
    offset += sizeof(uint16_t);
    *(uint16_t *)(buf + offset) = SoftBusLEtoBEs((uint16_t)msgHead->reserved);
}

static int32_t GetRemoteUdidByBtMac(const char *peerMac, char *udid, int32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    char *tmpMac = NULL;
    Anonymize(peerMac, &tmpMac);
    int32_t ret = LnnGetNetworkIdByBtMac(peerMac, networkId, sizeof(networkId));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetNetworkIdByBtMac fail, peerMac=%{public}s", AnonymizeWrapper(tmpMac));
        AnonymizeFree(tmpMac);
        return ret;
    }
    ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetRemoteStrInfo UDID fail, peerMac=%{public}s", tmpMac);
    }
    AnonymizeFree(tmpMac);
    return ret;
}

static int32_t GetRemoteBtMacByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *brMac, int32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUdidHash(udidHash, udidHashLen, networkId, sizeof(networkId), true);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "LnnGetNetworkIdByUdidHash fail");

    ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "GetRemoteBtMac fail");

    return SOFTBUS_OK;
}

static int32_t TransProxyGetAuthConnInfo(uint32_t connId, AuthConnInfo *connInfo)
{
    ConnectionInfo info = { 0 };
    int32_t ret = ConnGetConnectionInfo(connId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_CTRL, "ConnGetConnectionInfo fail, connId=%{public}u", connId);
    switch (info.type) {
        case CONNECT_TCP:
            connInfo->type = AUTH_LINK_TYPE_WIFI;
            if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, info.socketInfo.addr) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s ip fail.");
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case CONNECT_BR:
            connInfo->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, info.brInfo.brMac) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s brMac fail.");
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case CONNECT_BLE:
            connInfo->type = AUTH_LINK_TYPE_BLE;
            if (strcpy_s(connInfo->info.bleInfo.bleMac, BT_MAC_LEN, info.bleInfo.bleMac) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s brMac fail.");
                return SOFTBUS_STRCPY_ERR;
            }
            if (memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                info.bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            connInfo->info.bleInfo.protocol = info.bleInfo.protocol;
            connInfo->info.bleInfo.psm = (int32_t)info.bleInfo.psm;
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "unexpected conn type=%{public}d.", info.type);
            return SOFTBUS_TRANS_UNEXPECTED_CONN_TYPE;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertBrConnInfo2BleConnInfo(AuthConnInfo *connInfo)
{
    char udid[UDID_BUF_LEN] = {0};
    int32_t ret = GetRemoteUdidByBtMac(connInfo->info.brInfo.brMac, udid, UDID_BUF_LEN);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get udid by btmac fail");

    ret = SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid), connInfo->info.bleInfo.deviceIdHash);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "generate udid hash fail");

    connInfo->type = AUTH_LINK_TYPE_BLE;
    return SOFTBUS_OK;
}

static int32_t ConvertBleConnInfo2BrConnInfo(AuthConnInfo *connInfo)
{
    char brMac[BT_MAC_LEN] = {0};
    int32_t ret = GetRemoteBtMacByUdidHash(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN, brMac, BT_MAC_LEN);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get btmac by udid fail");

    if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, brMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy br mac fail");
        return SOFTBUS_STRCPY_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_BR;
    return SOFTBUS_OK;
}

static int32_t GetAuthIdByHandshakeMsg(uint32_t connId, uint8_t cipher, AuthHandle *authHandle, int32_t index)
{
    AuthConnInfo connInfo;
    int32_t ret = TransProxyGetAuthConnInfo(connId, &connInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_CTRL, "get connInfo fail connId=%{public}d", connId);
    bool isBle = ((cipher & USE_BLE_CIPHER) != 0);
    if (isBle && connInfo.type == AUTH_LINK_TYPE_BR) {
        ret = ConvertBrConnInfo2BleConnInfo(&connInfo);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
            TRANS_CTRL, "ConvertBrConnInfo2BleConnInfo fail, connInfoType=%{public}d", connInfo.type);
    } else if (!isBle && connInfo.type == AUTH_LINK_TYPE_BLE) {
        ret = ConvertBleConnInfo2BrConnInfo(&connInfo);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
            TRANS_CTRL, "ConvertBleConnInfo2BrConnInfo fail, connInfoType=%{public}d", connInfo.type);
    }
    bool isAuthServer = !((cipher & AUTH_SERVER_SIDE) != 0);
    authHandle->type = connInfo.type;
    authHandle->authId = AuthGetIdByConnInfo(&connInfo, isAuthServer, false);
    if (authHandle->authId == AUTH_INVALID_ID) {
        if (AuthGetAuthHandleByIndex(&connInfo, isAuthServer, index, authHandle) != SOFTBUS_OK &&
            AuthGetAuthHandleByIndex(&connInfo, !isAuthServer, index, authHandle) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get auth handle fail");
            return SOFTBUS_NOT_FIND;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetAuthIdReDecrypt(AuthHandle *authHandle, ProxyMessage *msg, uint8_t *decData, uint32_t *decDataLen)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = TransProxyGetAuthConnInfo(msg->connId, &connInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_CTRL, "get connInfo fail connId=%{public}d", msg->connId);
    int32_t index = (int32_t)SoftBusLtoHl(*(uint32_t *)msg->data);
    if (AuthGetAuthHandleByIndex(&connInfo, false, index, authHandle) != SOFTBUS_OK &&
        AuthGetAuthHandleByIndex(&connInfo, true, index, authHandle) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth handle fail");
        return SOFTBUS_NOT_FIND;
    }
    return AuthDecrypt(authHandle, (uint8_t *)msg->data, (uint32_t)msg->dateLen, decData, decDataLen);
}

int32_t GetBrMacFromConnInfo(uint32_t connId, char *peerBrMac, uint32_t len)
{
    AuthConnInfo connInfo;

    if (peerBrMac == NULL || len <= 0 || len > BT_MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransProxyGetAuthConnInfo(connId, &connInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_CTRL, "get connInfo fail connId=%{public}d", connId);

    if (strcpy_s(peerBrMac, len, connInfo.info.brInfo.brMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy brMac fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyParseMessageNoDecrypt(ProxyMessage *msg)
{
    uint8_t *allocData = (uint8_t *)SoftBusCalloc((uint32_t)msg->dateLen);
    if (allocData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(allocData, msg->dateLen, msg->data, msg->dateLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy data fail");
        SoftBusFree(allocData);
        return SOFTBUS_MEM_ERR;
    }
    msg->data = (char *)allocData;
    return SOFTBUS_OK;
}

int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg, AuthHandle *auth)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(len > PROXY_CHANNEL_HEAD_LEN,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "parseMessage: invalid message len, len=%{public}d", len);
    int32_t ret = TransProxyParseMessageHead(data, len, msg);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "TransProxyParseMessageHead fail!");
    if ((msg->msgHead.cipher & ENCRYPTED) != 0) {
        if (msg->dateLen <= 0 || (uint32_t)msg->dateLen < sizeof(uint32_t)) {
            TRANS_LOGE(TRANS_CTRL, "The data length of the ProxyMessage is abnormal!");
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        if (msg->msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE) {
            TRANS_LOGD(TRANS_CTRL, "prxoy recv handshake cipher=0x%{public}02x", msg->msgHead.cipher);
            ret = GetAuthIdByHandshakeMsg(msg->connId, msg->msgHead.cipher, auth,
                (int32_t)SoftBusLtoHl(*(uint32_t *)msg->data));
        } else {
            ret = TransProxyGetAuthId(msg->msgHead.myId, auth);
        }
        if (ret != SOFTBUS_OK || auth->authId == AUTH_INVALID_ID) {
            TRANS_LOGE(TRANS_CTRL, "get authId fail, connId=%{public}d, myChannelId=%{public}d, type=%{public}d",
                msg->connId, msg->msgHead.myId, msg->msgHead.type);
            return SOFTBUS_AUTH_NOT_FOUND;
        }
        msg->authHandle = (*auth);
        uint32_t decDataLen = AuthGetDecryptSize((uint32_t)msg->dateLen);
        uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
        if (decData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        msg->keyIndex = (int32_t)SoftBusLtoHl(*(uint32_t *)msg->data);
        if (AuthDecrypt(auth, (uint8_t *)msg->data, (uint32_t)msg->dateLen, decData, &decDataLen) != SOFTBUS_OK &&
            GetAuthIdReDecrypt(auth, msg, decData, &decDataLen) != SOFTBUS_OK) {
            SoftBusFree(decData);
            TRANS_LOGE(TRANS_CTRL, "parse msg decrypt fail");
            return SOFTBUS_DECRYPT_ERR;
        }
        msg->data = (char *)decData;
        msg->dateLen = (int32_t)decDataLen;
    } else {
        ret = TransProxyParseMessageNoDecrypt(msg);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "trans not need decrypt msg fail, ret=%{public}d", ret);
            return ret;
        }
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

static int32_t PackEncryptedMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo)
{
    if (authHandle.authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "invalid authId, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size = ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN +
        AuthGetEncryptSize(authHandle.authId, dataInfo->inLen);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc enc buf fail, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_MALLOC_ERR;
    }
    TransProxyPackMessageHead(msg, buf + ConnGetHeadSize(), PROXY_CHANNEL_HEAD_LEN);
    uint8_t *encData = buf + ConnGetHeadSize() + PROXY_CHANNEL_HEAD_LEN;
    uint32_t encDataLen = size - ConnGetHeadSize() - PROXY_CHANNEL_HEAD_LEN;
    if (AuthEncrypt(&authHandle, dataInfo->inData, dataInfo->inLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "pack msg encrypt fail, myChannelId=%{public}d", msg->myId);
        return SOFTBUS_ENCRYPT_ERR;
    }
    dataInfo->outData = buf;
    dataInfo->outLen = size;
    return SOFTBUS_OK;
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo)
{
    if (msg == NULL || dataInfo == NULL || dataInfo->inData == NULL || dataInfo->inLen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    if ((msg->cipher & ENCRYPTED) == 0) {
        ret = PackPlaintextMessage(msg, dataInfo);
    } else {
        ret = PackEncryptedMessage(msg, authHandle, dataInfo);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack proxy msg fail, myChannelId=%{public}d", msg->myId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t PackHandshakeMsgForFastData(AppInfo *appInfo, cJSON *root)
{
    if (appInfo->fastTransDataSize > 0) {
        TRANS_LOGI(TRANS_CTRL, "have fast data need transport");
        if (!AddNumberToJsonObject(root, JSON_KEY_ROUTE_TYPE, appInfo->routeType)) {
            TRANS_LOGE(TRANS_CTRL, "add route type fail.");
            return SOFTBUS_PARSE_JSON_ERR;
        }
        uint8_t *encodeFastData = (uint8_t *)SoftBusMalloc(BASE64_FAST_DATA_LEN);
        if (encodeFastData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc encode fast data fail.");
            return SOFTBUS_MALLOC_ERR;
        }
        size_t fastDataSize = 0;
        uint32_t outLen;
        char *buf = TransProxyPackFastData(appInfo, &outLen);
        if (buf == NULL) {
            TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
            SoftBusFree(encodeFastData);
            return SOFTBUS_TRANS_PACK_FAST_DATA_FAILED;
        }
        int32_t ret = SoftBusBase64Encode(encodeFastData, BASE64_FAST_DATA_LEN, &fastDataSize,
            (const unsigned char *)buf, outLen);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "mbedtls base64 encode failed.");
            SoftBusFree(encodeFastData);
            SoftBusFree(buf);
            return SOFTBUS_DECRYPT_ERR;
        }
        if (!AddStringToJsonObject(root, JSON_KEY_FIRST_DATA, (const char *)encodeFastData)) {
            TRANS_LOGE(TRANS_CTRL, "add first data failed.");
            SoftBusFree(encodeFastData);
            SoftBusFree(buf);
            return SOFTBUS_PARSE_JSON_ERR;
        }
        SoftBusFree(encodeFastData);
        SoftBusFree(buf);
    }
    if (!AddNumber16ToJsonObject(root, JSON_KEY_FIRST_DATA_SIZE, appInfo->fastTransDataSize)) {
        TRANS_LOGE(TRANS_CTRL, "add first data size failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

static void TransProxyCheckIsApp(AppInfo *appInfo, cJSON *root)
{
    if (!SoftBusCheckIsApp(appInfo->callingTokenId, appInfo->myData.sessionName)) {
        return;
    }

    if (GetCurrentAccount(&appInfo->myData.accountId) != SOFTBUS_OK) {
        appInfo->myData.accountId = INVALID_ACCOUNT_ID;
        TRANS_LOGE(TRANS_CTRL, "get current account failed.");
    }
    appInfo->myData.userId = TransGetForegroundUserId();
    (void)AddNumber64ToJsonObject(root, JSON_KEY_ACCOUNT_ID, appInfo->myData.accountId);
    (void)AddNumberToJsonObject(root, JSON_KEY_USER_ID, appInfo->myData.userId);
}

static int32_t PackHandshakeMsgForNormal(SessionKeyBase64 *sessionBase64, AppInfo *appInfo, cJSON *root)
{
    int32_t ret = SoftBusBase64Encode((unsigned char *)sessionBase64->sessionKeyBase64,
        sizeof(sessionBase64->sessionKeyBase64), &(sessionBase64->len),
        (unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mbedtls_base64_encode FAIL ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "mbedtls_base64_encode len=%{public}zu", sessionBase64->len);
    if (!AddNumberToJsonObject(root, JSON_KEY_UID, appInfo->myData.uid) ||
        !AddNumberToJsonObject(root, JSON_KEY_PID, appInfo->myData.pid) ||
        !AddStringToJsonObject(root, JSON_KEY_GROUP_ID, appInfo->groupId) ||
        !AddStringToJsonObject(root, JSON_KEY_PKG_NAME, appInfo->myData.pkgName) ||
        !AddStringToJsonObject(root, JSON_KEY_SESSION_KEY, sessionBase64->sessionKeyBase64)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, appInfo->encrypt) ||
        !AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, appInfo->algorithm) ||
        !AddNumberToJsonObject(root, JSON_KEY_CRC, appInfo->crc)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (PackHandshakeMsgForFastData(appInfo, root) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "proxy channel pack fast data failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    TransProxyCheckIsApp(appInfo, root);
    (void)AddNumberToJsonObject(root, JSON_KEY_BUSINESS_TYPE, appInfo->businessType);
    (void)AddNumberToJsonObject(root, JSON_KEY_TRANS_FLAGS, TRANS_FLAG_HAS_CHANNEL_AUTH);
    (void)AddNumberToJsonObject(root, JSON_KEY_MY_HANDLE_ID, appInfo->myHandleId);
    (void)AddNumberToJsonObject(root, JSON_KEY_PEER_HANDLE_ID, appInfo->peerHandleId);
    (void)AddNumber64ToJsonObject(root, JSON_KEY_CALLING_TOKEN_ID, (int64_t)appInfo->callingTokenId);
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

static bool TransProxyAddJsonObject(cJSON *root, ProxyChannelInfo *info)
{
    if (!AddNumberToJsonObject(root, JSON_KEY_TYPE, info->appInfo.appType) ||
        !AddStringToJsonObject(root, JSON_KEY_IDENTITY, info->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, info->appInfo.myData.deviceId) ||
        !AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, info->appInfo.myData.sessionName) ||
        !AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, info->appInfo.peerData.sessionName) ||
        !AddNumberToJsonObject(root, API_VERSION, info->appInfo.myData.apiVersion) ||
        !AddNumberToJsonObject(root, JSON_KEY_MTU_SIZE, info->appInfo.myData.dataConfig)) {
        return false;
    }
    if (!AddNumberToJsonObject(root, TRANS_CAPABILITY, info->appInfo.channelCapability)) {
        return false;
    }
    return true;
}

char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create json object failed.");
        return NULL;
    }
    char *buf = NULL;
    AppInfo *appInfo = &(info->appInfo);
    SessionKeyBase64 sessionBase64;
    (void)memset_s(&sessionBase64, sizeof(SessionKeyBase64), 0, sizeof(SessionKeyBase64));
    if (!TransProxyAddJsonObject(root, info)) {
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
        int32_t ret = SoftBusBase64Encode((uint8_t *)sessionBase64.sessionKeyBase64,
            sizeof(sessionBase64.sessionKeyBase64), &(sessionBase64.len),
            (uint8_t *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
        if (ret != SOFTBUS_OK) {
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
    TRANS_CHECK_AND_RETURN_RET_LOGE(chan != NULL, NULL, TRANS_CTRL, "invalid param.");
    AppInfo *appInfo = &(chan->appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(appInfo != NULL, NULL, TRANS_CTRL, "invalid param.");
    if (appInfo->appType == APP_TYPE_NOT_CARE) {
        TRANS_LOGE(TRANS_CTRL, "invalid appType.");
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    TRANS_CHECK_AND_RETURN_RET_LOGE(root != NULL, NULL, TRANS_CTRL, "create json object failed.");
    if (!AddStringToJsonObject(root, JSON_KEY_IDENTITY, chan->identity) ||
        !AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, appInfo->myData.deviceId) ||
        !AddNumberToJsonObject(root, TRANS_CAPABILITY, appInfo->channelCapability)) {
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

    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

int32_t TransProxyUnPackHandshakeErrMsg(const char *msg, int32_t *errCode, int32_t len)
{
    if (errCode == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param errCode.");
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *root = cJSON_ParseWithLength(msg, len);
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_CREATE_JSON_ERR;
    }

    if (!GetJsonObjectInt32Item(root, ERR_CODE, errCode)) {
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    TRANS_LOGE(TRANS_CTRL, "remote device is faulty, errCode=%{public}d", *errCode);

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

int32_t TransProxyUnPackRestErrMsg(const char *msg, int32_t *errCode, int32_t len)
{
    if (errCode == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param errCode.");
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *root = cJSON_ParseWithLength(msg, len);
    if (root == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parse json failed.");
        return SOFTBUS_CREATE_JSON_ERR;
    }

    if (!GetJsonObjectInt32Item(root, ERR_CODE, errCode) && !GetJsonObjectInt32Item(root, "ERROR_CODE", errCode)) {
        TRANS_LOGE(TRANS_CTRL, "get errCode failed.");
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo,
    int32_t len, uint16_t *fastDataSize)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(msg != NULL && chanInfo != NULL && fastDataSize != NULL,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "msg or chanInfo or fastDataSize is empty.");

    TRANS_CHECK_AND_RETURN_RET_LOGE(&chanInfo->appInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "appInfo is null");

    cJSON *root = cJSON_ParseWithLength(msg, len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(root != NULL, SOFTBUS_PARSE_JSON_ERR, TRANS_CTRL, "parse json failed.");

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chanInfo->identity, sizeof(chanInfo->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, chanInfo->appInfo.peerData.deviceId,
                                 sizeof(chanInfo->appInfo.peerData.deviceId))) {
        TRANS_LOGE(TRANS_CTRL, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_MTU_SIZE, (int32_t *)&(chanInfo->appInfo.peerData.dataConfig))) {
        TRANS_LOGD(TRANS_CTRL, "peer dataconfig is null.");
    }
    chanInfo->appInfo.encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    chanInfo->appInfo.algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    chanInfo->appInfo.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;

    int32_t ret = TransProxyGetAppInfoType(chanInfo->myId, chanInfo->identity, &chanInfo->appInfo.appType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "failed to get app type");
        cJSON_Delete(root);
        return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE;
    }
    if (chanInfo->appInfo.appType == APP_TYPE_NORMAL) {
        if (!GetJsonObjectNumberItem(root, JSON_KEY_UID, &chanInfo->appInfo.peerData.uid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_PID, &chanInfo->appInfo.peerData.pid) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ENCRYPT, &chanInfo->appInfo.encrypt) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_ALGORITHM, &chanInfo->appInfo.algorithm) ||
            !GetJsonObjectNumberItem(root, JSON_KEY_CRC, &chanInfo->appInfo.crc) ||
            !GetJsonObjectNumber16Item(root, JSON_KEY_FIRST_DATA_SIZE, fastDataSize) ||
            !GetJsonObjectStringItem(root, JSON_KEY_SRC_BUS_NAME, chanInfo->appInfo.peerData.sessionName,
                                     sizeof(chanInfo->appInfo.peerData.sessionName)) ||
            !GetJsonObjectStringItem(root, JSON_KEY_DST_BUS_NAME, chanInfo->appInfo.myData.sessionName,
                                     sizeof(chanInfo->appInfo.myData.sessionName))) {
            TRANS_LOGW(TRANS_CTRL, "unpack handshake ack old version");
        }
        if (!GetJsonObjectInt32Item(root, JSON_KEY_MY_HANDLE_ID, &chanInfo->appInfo.peerHandleId)) {
            chanInfo->appInfo.peerHandleId = -1;
        }
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_PKG_NAME, chanInfo->appInfo.peerData.pkgName,
                                 sizeof(chanInfo->appInfo.peerData.pkgName))) {
        TRANS_LOGW(TRANS_CTRL, "no item to get pkg name");
    }
    if (!GetJsonObjectNumberItem(root, TRANS_CAPABILITY, (int32_t *)&(chanInfo->appInfo.channelCapability))) {
        chanInfo->appInfo.channelCapability = 0;
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
            return SOFTBUS_PARSE_JSON_ERR;
        }
        uint8_t *encodeFastData = (uint8_t *)SoftBusMalloc(BASE64_FAST_DATA_LEN);
        if (encodeFastData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc encode fast data fail.");
            return SOFTBUS_MALLOC_ERR;
        }
        size_t fastDataSize = 0;
        if (!GetJsonObjectStringItem(root, JSON_KEY_FIRST_DATA, (char *)encodeFastData, BASE64_FAST_DATA_LEN)) {
            TRANS_LOGE(TRANS_CTRL, "failed to get fast data");
            SoftBusFree(encodeFastData);
            return SOFTBUS_PARSE_JSON_ERR;
        }
        appInfo->fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize + FAST_EXT_BYTE_SIZE);
        if (appInfo->fastTransData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc fast data fail.");
            SoftBusFree(encodeFastData);
            return SOFTBUS_MALLOC_ERR;
        }

        int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->fastTransData, appInfo->fastTransDataSize +
            FAST_EXT_BYTE_SIZE, &fastDataSize, encodeFastData, strlen((char*)encodeFastData));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "mbedtls decode failed.");
            SoftBusFree((void *)appInfo->fastTransData);
            appInfo->fastTransData = NULL;
            SoftBusFree(encodeFastData);
            return SOFTBUS_DECRYPT_ERR;
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
    if (len != sizeof(appInfo->sessionKey) || ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decode session fail ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    if (UnpackPackHandshakeMsgForFastData(appInfo, root) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "unpack fast data failed");
        return SOFTBUS_TRANS_PROXY_UNPACK_FAST_DATA_FAILED;
    }
    if (!GetJsonObjectNumber64Item(root, JSON_KEY_CALLING_TOKEN_ID, (int64_t *)&appInfo->callingTokenId)) {
        appInfo->callingTokenId = TOKENID_NOT_SET;
    }
    (void)GetJsonObjectSignedNumber64Item(root, JSON_KEY_ACCOUNT_ID, &(appInfo->peerData.accountId));
    if (!GetJsonObjectNumberItem(root, JSON_KEY_USER_ID, &(appInfo->peerData.userId))) {
        appInfo->peerData.userId = INVALID_USER_ID;
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
    if (len != sizeof(appInfo->sessionKey) || ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decode session fail ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyGetJsonObject(cJSON *root, const char *msg, int32_t len, ProxyChannelInfo *chan)
{
    if (!GetJsonObjectNumberItem(root, JSON_KEY_TYPE, (int32_t *)&(chan->appInfo.appType)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, chan->identity, sizeof(chan->identity)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DEVICE_ID, chan->appInfo.peerData.deviceId,
                                 sizeof(chan->appInfo.peerData.deviceId)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_SRC_BUS_NAME, chan->appInfo.peerData.sessionName,
                                 sizeof(chan->appInfo.peerData.sessionName)) ||
        !GetJsonObjectStringItem(root, JSON_KEY_DST_BUS_NAME, chan->appInfo.myData.sessionName,
                                 sizeof(chan->appInfo.myData.sessionName))) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get handshake msg");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(root, JSON_KEY_MTU_SIZE, (int32_t *)&(chan->appInfo.peerData.dataConfig))) {
        TRANS_LOGD(TRANS_CTRL, "peer dataconfig is null.");
    }
    if (!GetJsonObjectNumberItem(root, API_VERSION, (int32_t *)&(chan->appInfo.myData.apiVersion))) {
        TRANS_LOGD(TRANS_CTRL, "peer apiVersion is null.");
    }
    uint32_t remoteCapability = 0;
    (void)GetJsonObjectNumberItem(root, TRANS_CAPABILITY, (int32_t *)&remoteCapability);
    chan->appInfo.channelCapability = remoteCapability & TRANS_CHANNEL_CAPABILITY;
    return SOFTBUS_OK;
}

int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(msg != NULL && chan != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "param invalid.");
    cJSON *root = cJSON_ParseWithLength(msg, len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(root != NULL, SOFTBUS_PARSE_JSON_ERR, TRANS_CTRL, "parse json failed.");
    char sessionKey[BASE64KEY] = { 0 };
    AppInfo *appInfo = &(chan->appInfo);
    int32_t ret = TransProxyGetJsonObject(root, msg, len, chan);
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }
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
    if (((uint32_t)appInfo->transFlag & TRANS_FLAG_HAS_CHANNEL_AUTH) != 0) {
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
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!GetJsonObjectStringItem(root, JSON_KEY_IDENTITY, identity, identitySize)) {
        TRANS_LOGE(TRANS_CTRL, "fail to get json item");
        cJSON_Delete(root);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    cJSON_Delete(root);
    return SOFTBUS_OK;
}

static int32_t TransProxyEncryptFastData(const char *sessionKey, int32_t seq, const char *in, uint32_t inLen,
    char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }

    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen,
        (unsigned char*)out, outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);

    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "encrypt error, ret=%{public}d.", ret);
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
        return SOFTBUS_INVALID_PARAM;
    }
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketFastHead);
    uint32_t cipherLength = dataInfo->inLen + OVERHEAD_LEN;
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "calloc error");
        return SOFTBUS_MALLOC_ERR;
    }

    int32_t seq = atomic_fetch_add_explicit(&g_proxyPktHeadSeq, 1, memory_order_relaxed);
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
        return SOFTBUS_MALLOC_ERR;
    }
    uint16_t fastDataSize = appInfo->fastTransDataSize;
    if (memcpy_s(dataInfo->inData, fastDataSize, appInfo->fastTransData, fastDataSize) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s fastTransData error.");
        SoftBusFree(dataInfo->inData);
        return SOFTBUS_MEM_ERR;
    }
    dataInfo->inLen = fastDataSize;
    return SOFTBUS_OK;
}

static int32_t TransProxyByteData(const AppInfo *appInfo, ProxyDataInfo *dataInfo)
{
    dataInfo->inData = (uint8_t *)SoftBusMalloc(appInfo->fastTransDataSize + sizeof(SessionHead));
    if (dataInfo->inData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc error");
        return SOFTBUS_MALLOC_ERR;
    }
    uint16_t fastDataSize = appInfo->fastTransDataSize;
    SessionHead *sessionHead = (SessionHead*)dataInfo->inData;
    sessionHead->seq = atomic_fetch_add_explicit(&g_proxyPktHeadSeq, 1, memory_order_relaxed);
    sessionHead->packetFlag = (appInfo->businessType == BUSINESS_TYPE_BYTE) ? FLAG_BYTES : FLAG_MESSAGE;
    sessionHead->shouldAck = 0;
    if (memcpy_s(dataInfo->inData + sizeof(SessionHead), fastDataSize, appInfo->fastTransData, fastDataSize) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s fastTransData error.");
        SoftBusFree(dataInfo->inData);
        return SOFTBUS_MEM_ERR;
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
