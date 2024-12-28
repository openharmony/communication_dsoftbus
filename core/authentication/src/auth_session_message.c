/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "auth_session_message.h"

#include <math.h>
#include <securec.h>

#include "anonymizer.h"
#include "auth_attest_interface.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "auth_request.h"
#include "auth_session_json.h"
#include "bus_center_manager.h"
#include "lnn_common_utils.h"
#include "lnn_compress.h"
#include "lnn_event.h"
#include "lnn_extdata_config.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_config_type.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_socket.h"

#define FLAG_COMPRESS_DEVICE_INFO   1
#define FLAG_UNCOMPRESS_DEVICE_INFO 0
#define FLAG_RELAY_DEVICE_INFO      1
#define DEVICE_ID_STR_LEN           64 // for bt v1

static int32_t UnPackBtDeviceIdV1(AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    if (!info->isServer) {
        AUTH_LOGE(AUTH_FSM, "is not server");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info->udid, UDID_BUF_LEN, data, len) != EOK) { // data:StandardCharsets.UTF_8
        AUTH_LOGE(AUTH_FSM, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PostDeviceIdData(int64_t authSeq, const AuthSessionInfo *info, uint8_t *data, uint32_t len)
{
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_ID,
        .module = MODULE_TRUST_ENGINE,
        .seq = authSeq,
        .flag = info->isConnectServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = len,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post device id fail");
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t PostBtV1DevId(int64_t authSeq, const AuthSessionInfo *info)
{
    if (!info->isServer) {
        AUTH_LOGE(AUTH_FSM, "client don't send Bt-v1 devId");
        return SOFTBUS_AUTH_NOT_NEED_SEND_V1_DEV_ID;
    }
    char uuid[UUID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get uuid fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    return PostDeviceIdData(authSeq, info, (uint8_t *)uuid, strlen(uuid));
}

static int32_t PostWifiV1DevId(int64_t authSeq, const AuthSessionInfo *info)
{
    if (!info->isServer) {
        AUTH_LOGE(AUTH_FSM, "client don't send wifi-v1 devId");
        return SOFTBUS_AUTH_NOT_NEED_SEND_V1_DEV_ID;
    }
    char *msg = PackDeviceIdJson(info);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack devId fail");
        return SOFTBUS_AUTH_PACK_DEV_ID_FAIL;
    }
    if (PostDeviceIdData(authSeq, info, (uint8_t *)msg, strlen(msg) + 1) != SOFTBUS_OK) {
        JSON_Free(msg);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    JSON_Free(msg);
    return SOFTBUS_OK;
}

static int32_t PostDeviceIdV1(int64_t authSeq, const AuthSessionInfo *info)
{
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI) {
        return PostWifiV1DevId(authSeq, info);
    } else {
        AUTH_LOGI(AUTH_FSM, "process v1 bt deviceIdSync");
        return PostBtV1DevId(authSeq, info);
    }
}

static int32_t PostDeviceIdNew(int64_t authSeq, const AuthSessionInfo *info)
{
    char *msg = PackDeviceIdJson(info);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack devId fail");
        return SOFTBUS_AUTH_PACK_DEV_ID_FAIL;
    }
    if (PostDeviceIdData(authSeq, info, (uint8_t *)msg, strlen(msg) + 1) != SOFTBUS_OK) {
        JSON_Free(msg);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    JSON_Free(msg);
    return SOFTBUS_OK;
}

static void DfxRecordLnnPostDeviceIdStart(int64_t authSeq, const AuthSessionInfo *info)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    if (info != NULL) {
        extra.authRequestId = (int32_t)info->requestId;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_DEVICE_ID_POST, extra);
}

int32_t PostDeviceIdMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    DfxRecordLnnPostDeviceIdStart(authSeq, info);
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    if (info->version == SOFTBUS_OLD_V1) {
        return PostDeviceIdV1(authSeq, info);
    } else {
        return PostDeviceIdNew(authSeq, info);
    }
}

int32_t ProcessDeviceIdMessage(AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "data is NULL");
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && (len == DEVICE_ID_STR_LEN) && (info->isServer)) {
        info->version = SOFTBUS_OLD_V1;
        return UnPackBtDeviceIdV1(info, data, len);
    }
    return UnpackDeviceIdJson((const char *)data, len, info);
}

static void GetDumpSessionKeyList(int64_t authSeq, const AuthSessionInfo *info, SessionKeyList *list)
{
    ListInit(list);
    SessionKey sessionKey;
    int64_t index = authSeq;
    if (info->normalizedType == NORMALIZED_SUPPORT) {
        index = info->normalizedIndex;
    }
    if (AuthManagerGetSessionKey(index, info, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get session key fail");
        return;
    }
    if (AddSessionKey(list, TO_INT32(index), &sessionKey, info->connInfo.type, false) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "add session key fail");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (SetSessionKeyAvailable(list, TO_INT32(index)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "set session key available fail");
    }
}

static void DfxRecordLnnPostDeviceInfoStart(int64_t authSeq, const AuthSessionInfo *info)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    if (info != NULL) {
        extra.authRequestId = (int32_t)info->requestId;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_DEVICE_INFO_POST, extra);
}

static void SetCompressFlagByAuthInfo(
    const AuthSessionInfo *info, char *msg, int32_t *compressFlag, uint8_t **compressData, uint32_t *compressLen)
{
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        AUTH_LOGI(AUTH_FSM, "before compress, datalen=%{public}zu", strlen(msg) + 1);
        if (DataCompress((uint8_t *)msg, strlen(msg) + 1, compressData, compressLen) != SOFTBUS_OK) {
            *compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
        } else {
            *compressFlag = FLAG_COMPRESS_DEVICE_INFO;
            AUTH_LOGI(AUTH_FSM, "deviceInfo compress finish");
        }
        AUTH_LOGI(AUTH_FSM, "after compress, datalen=%{public}u", *compressLen);
    }
}

static void SetIndataInfo(InDataInfo *inDataInfo, uint8_t *compressData, uint32_t compressLen, char *msg)
{
    if ((compressData != NULL) && (compressLen != 0)) {
        inDataInfo->inData = compressData;
        inDataInfo->inLen = compressLen;
    } else {
        inDataInfo->inData = (uint8_t *)msg;
        inDataInfo->inLen = strlen(msg) + 1;
    }
}

int32_t PostDeviceInfoMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    DfxRecordLnnPostDeviceInfoStart(authSeq, info);
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    char *msg = PackDeviceInfoMessage(&(info->connInfo), info->version, false, info->uuid, info);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack device info fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    int32_t compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
    uint8_t *compressData = NULL;
    uint32_t compressLen = 0;
    SetCompressFlagByAuthInfo(info, msg, &compressFlag, &compressData, &compressLen);
    InDataInfo inDataInfo = { 0 };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    SetIndataInfo(&inDataInfo, compressData, compressLen, msg);
    SessionKeyList sessionKeyList;
    GetDumpSessionKeyList(authSeq, info, &sessionKeyList);
    if (EncryptInner(&sessionKeyList, info->connInfo.type, &inDataInfo, &data, &dataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encrypt device info fail");
        JSON_Free(msg);
        SoftBusFree(compressData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    JSON_Free(msg);
    SoftBusFree(compressData);
    DestroySessionKeyList(&sessionKeyList);
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && info->isServer) {
        compressFlag = FLAG_RELAY_DEVICE_INFO;
        authSeq = 0;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_INFO,
        .module = MODULE_AUTH_CONNECTION,
        .seq = authSeq,
        .flag = compressFlag,
        .len = dataLen,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post device info fail");
        SoftBusFree(data);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}

int32_t ProcessDeviceInfoMessage(int64_t authSeq, AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "data is NULL");
    uint8_t *msg = NULL;
    uint32_t msgSize = 0;
    SessionKeyList sessionKeyList;
    GetDumpSessionKeyList(authSeq, info, &sessionKeyList);
    InDataInfo inDataInfo = { .inData = data, .inLen = len };
    if (DecryptInner(&sessionKeyList, info->connInfo.type, &inDataInfo, &msg, &msgSize) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decrypt device info fail");
        return SOFTBUS_DECRYPT_ERR;
    }
    DestroySessionKeyList(&sessionKeyList);
    uint8_t *decompressData = NULL;
    uint32_t decompressLen = 0;
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        AUTH_LOGI(AUTH_FSM, "before decompress, msgSize=%{public}u", msgSize);
        if (DataDecompress((uint8_t *)msg, msgSize, &decompressData, &decompressLen) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "data decompress fail");
            SoftBusFree(msg);
            return SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL;
        } else {
            AUTH_LOGI(AUTH_FSM, "deviceInfo deCompress finish, decompress=%{public}d", decompressLen);
        }
        AUTH_LOGI(AUTH_FSM, "after decompress, datalen=%{public}d", decompressLen);
    }
    DevInfoData devInfo = { NULL, 0, info->connInfo.type, info->version };
    if ((decompressData != NULL) && (decompressLen != 0)) {
        devInfo.msg = (const char *)decompressData;
        devInfo.len = decompressLen;
    } else {
        devInfo.msg = (const char *)msg;
        devInfo.len = msgSize;
    }
    if (UnpackDeviceInfoMessage(&devInfo, &info->nodeInfo, false, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "unpack device info fail");
        SoftBusFree(msg);
        SoftBusFree(decompressData);
        return SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL;
    }
    SoftBusFree(msg);
    SoftBusFree(decompressData);
    return SOFTBUS_OK;
}

int32_t PostCloseAckMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    const char *msg = "";
    AuthDataHead head = {
        .dataType = DATA_TYPE_CLOSE_ACK,
        .module = 0,
        .seq = authSeq,
        .flag = 0,
        .len = strlen(msg) + 1,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, (uint8_t *)msg) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post close ack fail");
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t PostHichainAuthMessage(int64_t authSeq, const AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "data is NULL");
    AuthDataHead head = {
        .dataType = DATA_TYPE_AUTH,
        .module = MODULE_AUTH_SDK,
        .seq = authSeq,
        .flag = 0,
        .len = len,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post hichain data fail");
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    return SOFTBUS_OK;
}

static char *PackVerifyDeviceMessage(const char *uuid)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        AUTH_LOGE(AUTH_FSM, "create json fail");
        return NULL;
    }
    if (!JSON_AddInt32ToObject(obj, CODE, CODE_VERIFY_DEVICE) || !JSON_AddStringToObject(obj, DEVICE_ID, uuid)) {
        AUTH_LOGE(AUTH_FSM, "add uuid fail");
        JSON_Delete(obj);
        return NULL;
    }
    char *msg = JSON_PrintUnformatted(obj);
    JSON_Delete(obj);
    return msg;
}

static char *PackKeepaliveMessage(const char *uuid, ModeCycle cycle)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        AUTH_LOGE(AUTH_FSM, "create json fail");
        return NULL;
    }
    if (!JSON_AddInt32ToObject(obj, CODE, CODE_TCP_KEEPALIVE) || !JSON_AddStringToObject(obj, DEVICE_ID, uuid) ||
        !JSON_AddInt32ToObject(obj, TIME, cycle)) {
        AUTH_LOGE(AUTH_FSM, "add uuid or cycle fail");
        JSON_Delete(obj);
        return NULL;
    }
    char *msg = JSON_PrintUnformatted(obj);
    JSON_Delete(obj);
    return msg;
}

bool IsDeviceMessagePacket(const AuthConnInfo *connInfo, const AuthDataHead *head, const uint8_t *data, bool isServer,
    DeviceMessageParse *messageParse)
{
    if (connInfo->type != AUTH_LINK_TYPE_WIFI) {
        return false;
    }
    int64_t authId = AuthDeviceGetIdByConnInfo(connInfo, isServer);
    if (authId == AUTH_INVALID_ID) {
        AUTH_LOGE(AUTH_FSM, "is flush device packet not find authId");
        return false;
    }
    uint32_t decDataLen = AuthGetDecryptSize(head->len);
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        return false;
    }
    AuthHandle authHandle = { .authId = authId, .type = connInfo->type };
    if (AuthDeviceDecrypt(&authHandle, data, head->len, decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusFree(decData);
        AUTH_LOGE(AUTH_FSM, "parse device info decrypt fail");
        return false;
    }
    JsonObj *json = JSON_Parse((char *)decData, decDataLen);
    if (json == NULL) {
        AUTH_LOGE(AUTH_FSM, "parse json fail");
        SoftBusFree(decData);
        return false;
    }
    bool result = false;
    if (!JSON_GetInt32FromOject(json, CODE, &messageParse->messageType)) {
        AUTH_LOGE(AUTH_FSM, "parse messageType fail");
    }
    AUTH_LOGI(AUTH_FSM, "messageType=%{public}d", messageParse->messageType);
    if (messageParse->messageType == CODE_VERIFY_DEVICE) {
        result = true;
    }
    if (messageParse->messageType == CODE_TCP_KEEPALIVE) {
        if (JSON_GetInt32FromOject(json, TIME, (int32_t *)&messageParse->cycle)) {
            AUTH_LOGI(AUTH_FSM, "parse keepalive cycle success, cycle=%{public}d", messageParse->cycle);
            result = true;
        }
    }
    JSON_Delete(json);
    SoftBusFree(decData);
    return result;
}

static bool IsEmptyShortHashStr(char *udidHash)
{
    if (strlen(udidHash) == 0) {
        AUTH_LOGE(AUTH_FSM, "udidHash len is 0");
        return true;
    }
    uint8_t emptyHash[SHORT_HASH_LEN] = { 0 };
    char emptyHashStr[UDID_SHORT_HASH_HEX_STR + 1] = { 0 };
    if (ConvertBytesToHexString(emptyHashStr, UDID_SHORT_HASH_HEX_STR + 1, emptyHash, SHORT_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return false;
    }
    if (strncmp(emptyHashStr, udidHash, strlen(emptyHashStr)) == EOK) {
        AUTH_LOGE(AUTH_FSM, "udidHash is null");
        return true;
    }
    return false;
}

static int32_t GetLocalUdidHash(char *udid, char *udidHash, uint32_t len)
{
    if (udid == NULL || udidHash == NULL || len < UDID_HASH_LEN) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t hash[UDID_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid), (unsigned char *)hash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "restore manager fail because generate strhash");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(udidHash, len, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    return SOFTBUS_OK;
}

int32_t UpdateLocalAuthState(int64_t authSeq, AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    if (info->isServer && strlen(info->udid) == 0) {
        info->localState = AUTH_STATE_UNKNOW;
        AUTH_LOGI(AUTH_FSM, "authSeq=%{public}" PRId64 ", udid is null update local auth state=%{public}d", authSeq,
            info->localState);
        return SOFTBUS_OK;
    }
    if (info->peerState == AUTH_STATE_COMPATIBLE) {
        info->localState = AUTH_STATE_COMPATIBLE;
        AUTH_LOGI(AUTH_FSM, "authSeq=%{public}" PRId64 " local auth state=%{public}d", authSeq, info->localState);
        return SOFTBUS_OK;
    }
    if (info->peerState == AUTH_STATE_ACK || info->peerState == AUTH_STATE_START) {
        info->localState = AUTH_STATE_ACK;
        AUTH_LOGI(AUTH_FSM, "authSeq=%{public}" PRId64 " local auth state=%{public}d", authSeq, info->localState);
        return SOFTBUS_OK;
    }
    char udid[UDID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local udid fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    char localUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    char udidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (GetLocalUdidHash(udid, localUdidHash, SHA_256_HEX_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local udid hash fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (!GetUdidShortHash(info, udidHash, SHA_256_HEX_HASH_LEN) || IsEmptyShortHashStr(udidHash)) {
        AUTH_LOGI(AUTH_FSM, "unknow peer udidHash");
        info->localState = AUTH_STATE_UNKNOW;
    } else if (memcmp(localUdidHash, udidHash, SHORT_HASH_LEN) < 0) {
        info->localState = AUTH_STATE_WAIT;
    } else if (memcmp(localUdidHash, udidHash, SHORT_HASH_LEN) > 0) {
        info->localState = AUTH_STATE_START;
    } else {
        AUTH_LOGE(AUTH_FSM, "peer udidHash = local udidHash!");
        info->localState = AUTH_STATE_START;
    }
    if (strlen(udidHash) != 0 && strcpy_s(info->udidHash, SHA_256_HEX_HASH_LEN, udidHash) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy udidHash fail");
        return SOFTBUS_MEM_ERR;
    }
    AUTH_LOGI(AUTH_FSM, "authSeq=%{public}" PRId64 " local auth state=%{public}d", authSeq, info->localState);
    return SOFTBUS_OK;
}

int32_t PostDeviceMessage(
    const AuthManager *auth, int32_t flagRelay, AuthLinkType type, const DeviceMessageParse *messageParse)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(auth != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "auth is NULL");
    if (messageParse == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error, type=%{public}d", type);
        return SOFTBUS_AUTH_CONN_TYPE_INVALID;
    }
    char *msg = NULL;
    if (messageParse->messageType == CODE_VERIFY_DEVICE) {
        msg = PackVerifyDeviceMessage(auth->uuid);
    } else if (messageParse->messageType == CODE_TCP_KEEPALIVE) {
        msg = PackKeepaliveMessage(auth->uuid, messageParse->cycle);
    }
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack verify device msg fail");
        return SOFTBUS_AUTH_PACK_VERIFY_MSG_FAIL;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    InDataInfo inDataInfo = { .inData = (uint8_t *)msg, .inLen = strlen(msg) + 1 };
    if (EncryptInner(&auth->sessionKeyList, type, &inDataInfo, &data, &dataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encrypt device info fail");
        JSON_Free(msg);
        return SOFTBUS_ENCRYPT_ERR;
    }
    JSON_Free(msg);

    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_INFO,
        .module = MODULE_AUTH_CONNECTION,
        .seq = auth->authId,
        .flag = flagRelay,
        .len = dataLen,
    };
    if (PostAuthData(auth->connId[type], !auth->isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post verify device msg fail");
        SoftBusFree(data);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}