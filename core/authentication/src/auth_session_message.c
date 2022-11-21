/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"

/* DeviceId */
#define CMD_TAG "TECmd"
#define CMD_GET_AUTH_INFO "getAuthInfo"
#define CMD_RET_AUTH_INFO "retAuthInfo"
#define DATA_TAG "TEData"
#define DEVICE_ID_TAG "TEDeviceId"
#define DATA_BUF_SIZE_TAG "DataBufSize"
#define SOFTBUS_VERSION_TAG "softbusVersion"
#define CMD_TAG_LEN 30
#define PACKET_SIZE (64 * 1024)

/* DeviceInfo */
#define CODE "CODE"
#define CODE_VERIFY_IP 1
#define CODE_VERIFY_BT 5
#define DEVICE_NAME "DEVICE_NAME"
#define DEVICE_TYPE "DEVICE_TYPE"
#define DEVICE_UDID "DEVICE_UDID"
#define DEVICE_UUID "DEVICE_UUID"
#define NETWORK_ID "NETWORK_ID"
#define NODE_ADDR "NODE_ADDR"
#define VERSION_TYPE "VERSION_TYPE"
#define BT_MAC "BT_MAC"
#define BUS_MAX_VERSION "BUS_MAX_VERSION"
#define BUS_MIN_VERSION "BUS_MIN_VERSION"
#define AUTH_PORT "AUTH_PORT"
#define SESSION_PORT "SESSION_PORT"
#define PROXY_PORT "PROXY_PORT"
#define CONN_CAP "CONN_CAP"
#define SW_VERSION "SW_VERSION"
#define MASTER_UDID "MASTER_UDID"
#define MASTER_WEIGHT "MASTER_WEIGHT"
#define BLE_P2P "BLE_P2P"
#define P2P_MAC_ADDR "P2P_MAC_ADDR"
#define P2P_ROLE "P2P_ROLE"
#define TRANSPORT_PROTOCOL "TRANSPORT_PROTOCOL"
#define BLE_OFFLINE_CODE "OFFLINE_CODE"
#define DATA_CHANGE_FLAG "NODE_DATA_CHANGE_FLAG"
#define BUS_V1 1
#define BUS_V2 2

#define FLAG_COMPRESS_DEVICE_INFO 1
#define FLAG_UNCOMPRESS_DEVICE_INFO 0

/* VerifyDevice */
#define CODE_VERIFY_DEVICE 2
#define DEVICE_ID "DEVICE_ID"

static char *PackDeviceIdMessage(int32_t linkType, bool isServer, int32_t softbusVersion)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "PackDeviceId: connType = %d.", linkType);
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get uuid/udid fail.");
        cJSON_Delete(obj);
        return NULL;
    }
    if (linkType == AUTH_LINK_TYPE_WIFI && !isServer) {
        if (!AddStringToJsonObject(obj, CMD_TAG, CMD_GET_AUTH_INFO)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add CMD_GET fail.");
            cJSON_Delete(obj);
            return NULL;
        }
    } else {
        if (!AddStringToJsonObject(obj, CMD_TAG, CMD_RET_AUTH_INFO)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add CMD_RET fail.");
            cJSON_Delete(obj);
            return NULL;
        }
    }
    if (!AddStringToJsonObject(obj, DATA_TAG, uuid) ||
        !AddStringToJsonObject(obj, DEVICE_ID_TAG, udid) ||
        !AddNumberToJsonObject(obj, DATA_BUF_SIZE_TAG, PACKET_SIZE) ||
        !AddNumberToJsonObject(obj, SOFTBUS_VERSION_TAG, softbusVersion)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add msg body fail.");
        cJSON_Delete(obj);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return msg;
}

static int32_t UnpackDeviceIdMessage(const char *msg, AuthSessionInfo *info)
{
    cJSON *obj = cJSON_Parse(msg);
    if (obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "json parse fail.");
        return SOFTBUS_ERR;
    }
    char cmd[CMD_TAG_LEN] = {0};
    if (!GetJsonObjectStringItem(obj, CMD_TAG, cmd, CMD_TAG_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "CMD_TAG not found.");
        cJSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && info->isServer) {
        if (strncmp(cmd, CMD_GET_AUTH_INFO, strlen(CMD_GET_AUTH_INFO)) != 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "CMD_GET not match.");
            cJSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    } else {
        if (strncmp(cmd, CMD_RET_AUTH_INFO, strlen(CMD_RET_AUTH_INFO)) != 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "CMD_RET not match.");
            cJSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    }
    if (!GetJsonObjectStringItem(obj, DATA_TAG, info->uuid, UUID_BUF_LEN) ||
        !GetJsonObjectStringItem(obj, DEVICE_ID_TAG, info->udid, UDID_BUF_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "uuid/udid not found.");
        cJSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectNumberItem(obj, SOFTBUS_VERSION_TAG, (int32_t *)&info->version)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "set default version: SOFTBUS_OLD_V2.");
        info->version = SOFTBUS_OLD_V2;
    }
    cJSON_Delete(obj);
    return SOFTBUS_OK;
}

static int32_t PackCommon(cJSON *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!AddStringToJsonObject(json, SW_VERSION, info->softBusVersion)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add version info fail.");
            return SOFTBUS_ERR;
        }
        if (!AddStringToJsonObject(json, MASTER_UDID, info->masterUdid) ||
            !AddNumberToJsonObject(json, MASTER_WEIGHT, info->masterWeight)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add master node info fail.");
            return SOFTBUS_ERR;
        }
        if (!AddStringToJsonObject(json, NODE_ADDR, info->nodeAddress)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack node address Fail.");
            return SOFTBUS_ERR;
        }
    }

    char offlineCodeResult[OFFLINE_CODE_LEN] = {0};
    int32_t ret = ConvertBytesToHexString(offlineCodeResult, OFFLINE_CODE_LEN,
        (const unsigned char *)info->offlineCode, OFFLINE_CODE_BYTE_SIZE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert bytes to str offline fail, ret=%d", ret);
        return SOFTBUS_ERR;
    }
    if (!AddStringToJsonObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo)) ||
        !AddStringToJsonObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !AddStringToJsonObject(json, DEVICE_UDID, LnnGetDeviceUdid(info))) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddStringToJsonObject fail.");
        return SOFTBUS_ERR;
    }
    if (isMetaAuth && !AddStringToJsonObject(json, DEVICE_UUID, info->uuid)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddStringToJsonObject fail.");
        return SOFTBUS_ERR;
    }
    if (!AddStringToJsonObject(json, NETWORK_ID, info->networkId) ||
        !AddStringToJsonObject(json, VERSION_TYPE, info->versionType) ||
        !AddNumberToJsonObject(json, CONN_CAP, info->netCapacity) ||
        !AddNumberToJsonObject(json, P2P_ROLE, LnnGetP2pRole(info)) ||
        !AddNumberToJsonObject(json, DATA_CHANGE_FLAG, info->dataChangeFlag) ||
        !AddBoolToJsonObject(json, BLE_P2P, info->isBleP2p) ||
        !AddStringToJsonObject(json, P2P_MAC_ADDR, LnnGetP2pMac(info)) ||
        !AddNumber64ToJsonObject(json, TRANSPORT_PROTOCOL, (int64_t)LnnGetSupportedProtocols(info))  ||
        !AddStringToJsonObject(json, BLE_OFFLINE_CODE, offlineCodeResult)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddStringToJsonObject fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UnpackCommon(const cJSON *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        (void)GetJsonObjectStringItem(json, SW_VERSION, info->softBusVersion, VERSION_MAX_LEN);
        if (!GetJsonObjectStringItem(json, MASTER_UDID, info->masterUdid, UDID_BUF_LEN) ||
            !GetJsonObjectNumberItem(json, MASTER_WEIGHT, &info->masterWeight)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get master node info fail");
        }
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "get master weight: %d", info->masterWeight);
        if (!GetJsonObjectStringItem(json, NODE_ADDR, info->nodeAddress, sizeof(info->nodeAddress))) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN,
                "no node address packed. set to address %s", NODE_ADDR_LOOPBACK);
            (void)strcpy_s(info->nodeAddress, sizeof(info->nodeAddress), NODE_ADDR_LOOPBACK);
        }
    }

    char deviceType[DEVICE_TYPE_BUF_LEN] = {0};
    (void)GetJsonObjectStringItem(json, DEVICE_NAME, info->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN);
    if (GetJsonObjectStringItem(json, DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN)) {
        (void)LnnConvertDeviceTypeToId(deviceType, &(info->deviceInfo.deviceTypeId));
    }
    (void)GetJsonObjectStringItem(json, DEVICE_UDID, info->deviceInfo.deviceUdid, UDID_BUF_LEN);
    if (isMetaAuth) {
        (void)GetJsonObjectStringItem(json, DEVICE_UUID, info->uuid, UDID_BUF_LEN);
    }
    (void)GetJsonObjectStringItem(json, NETWORK_ID, info->networkId, NETWORK_ID_BUF_LEN);
    (void)GetJsonObjectStringItem(json, VERSION_TYPE, info->versionType, VERSION_MAX_LEN);
    (void)GetJsonObjectNumberItem(json, CONN_CAP, (int *)&info->netCapacity);

    info->isBleP2p = false;
    char getOfflineCodeResult[OFFLINE_CODE_LEN] = {0};
    (void)GetJsonObjectBoolItem(json, BLE_P2P, &info->isBleP2p);
    (void)GetJsonObjectNumberItem(json, P2P_ROLE, &info->p2pInfo.p2pRole);
    (void)GetJsonObjectNumber16Item(json, DATA_CHANGE_FLAG, &info->dataChangeFlag);
    (void)GetJsonObjectStringItem(json, P2P_MAC_ADDR, info->p2pInfo.p2pMac, MAC_LEN);
    (void)GetJsonObjectStringItem(json, BLE_OFFLINE_CODE, getOfflineCodeResult, OFFLINE_CODE_LEN);
    int32_t ret = ConvertHexStringToBytes(info->offlineCode, OFFLINE_CODE_BYTE_SIZE,
        (const char *)getOfflineCodeResult, OFFLINE_CODE_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert str to bytes offline fail, ret=%d", ret);
    }
}

static int32_t PackBt(cJSON *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (!AddNumberToJsonObject(json, CODE, CODE_VERIFY_BT) ||
        !AddStringToJsonObject(json, BT_MAC, LnnGetBtMac(info))) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add bt info fail.");
        return SOFTBUS_ERR;
    }
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "PackCommon fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackBt(const cJSON *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    (void)GetJsonObjectStringItem(json, BT_MAC, info->connectInfo.macAddr, MAC_LEN);
    if (!GetJsonObjectNumber64Item(json, TRANSPORT_PROTOCOL, (int64_t *)&info->supportedProtocols)) {
        info->supportedProtocols = LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE;
    }
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackWiFi(cJSON *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (!AddNumberToJsonObject(json, CODE, CODE_VERIFY_IP) ||
        !AddNumberToJsonObject(json, BUS_MAX_VERSION, BUS_V2) ||
        !AddNumberToJsonObject(json, BUS_MIN_VERSION, BUS_V1) ||
        !AddNumberToJsonObject(json, AUTH_PORT, LnnGetAuthPort(info)) ||
        !AddNumberToJsonObject(json, SESSION_PORT, LnnGetSessionPort(info)) ||
        !AddNumberToJsonObject(json, PROXY_PORT, LnnGetProxyPort(info))) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add wifi info fail.");
        return SOFTBUS_ERR;
    }
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "PackCommon fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackWiFi(const cJSON *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    (void)GetJsonObjectNumberItem(json, AUTH_PORT, &info->connectInfo.authPort);
    (void)GetJsonObjectNumberItem(json, SESSION_PORT, &info->connectInfo.sessionPort);
    (void)GetJsonObjectNumberItem(json, PROXY_PORT, &info->connectInfo.proxyPort);
    if (!GetJsonObjectNumber64Item(json, TRANSPORT_PROTOCOL, (int64_t *)&info->supportedProtocols)) {
        info->supportedProtocols = LNN_PROTOCOL_IP;
    }
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

char *PackDeviceInfoMessage(int32_t linkType, SoftBusVersion version, bool isMetaAuth)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "PackDeviceInfo: connType = %d.", linkType);
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "local info is null.");
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "create cjson fail.");
        return NULL;
    }
    int32_t ret;
    if (linkType == AUTH_LINK_TYPE_WIFI) {
        ret = PackWiFi(json, info, version, isMetaAuth);
    } else {
        ret = PackBt(json, info, version, isMetaAuth);
    }
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return NULL;
    }

    char *msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted fail.");
    }
    cJSON_Delete(json);
    return msg;
}

int32_t UnpackDeviceInfoMessage(const char *msg, int32_t linkType, SoftBusVersion version,
    NodeInfo *nodeInfo, bool isMetaAuth)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "UnpackDeviceInfo: connType = %d.", linkType);
    cJSON *json = cJSON_Parse(msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "parse cjson fail.");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    if (linkType == AUTH_LINK_TYPE_WIFI) {
        ret = UnpackWiFi(json, nodeInfo, version, isMetaAuth);
    } else {
        ret = UnpackBt(json, nodeInfo, version, isMetaAuth);
    }
    cJSON_Delete(json);
    return ret;
}

int32_t PostDeviceIdMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    char *msg = PackDeviceIdMessage(info->connInfo.type, info->isServer, SOFTBUS_NEW_V1);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack deviceId msg fail.");
        return SOFTBUS_ERR;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_ID,
        .module = MODULE_TRUST_ENGINE,
        .seq = authSeq,
        .flag = info->isServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = strlen(msg) + 1,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, (uint8_t *)msg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post device id fail.");
        cJSON_free(msg);
        return SOFTBUS_ERR;
    }
    cJSON_free(msg);
    return SOFTBUS_OK;
}

int32_t ProcessDeviceIdMessage(AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    CHECK_EXPRESSION_RETURN_VALUE((len == 0 || strnlen((const char *)data, len) >= len),
        SOFTBUS_INVALID_PARAM);
    return UnpackDeviceIdMessage((const char *)data, info);
}

static void GetSessionKeyList(int64_t authSeq, const AuthSessionInfo *info, SessionKeyList *list)
{
    ListInit(list);
    SessionKey sessionKey;
    if (AuthManagerGetSessionKey(authSeq, info, &sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get session key fail.");
        return;
    }
    if (AddSessionKey(list, TO_INT32(authSeq), &sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add session key fail.");
        return;
    }
}

int32_t PostDeviceInfoMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    char *msg = PackDeviceInfoMessage(info->connInfo.type, SOFTBUS_NEW_V1, false);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack device info fail.");
        return SOFTBUS_ERR;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    SessionKeyList sessionKeyList;
    GetSessionKeyList(authSeq, info, &sessionKeyList);
    if (EncryptInner(&sessionKeyList, (uint8_t *)msg, strlen(msg) + 1, &data, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "encrypt device info fail.");
        cJSON_free(msg);
        return SOFTBUS_ENCRYPT_ERR;
    }
    cJSON_free(msg);

    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_INFO,
        .module = MODULE_AUTH_CONNECTION,
        .seq = authSeq,
        .flag = FLAG_UNCOMPRESS_DEVICE_INFO,
        .len = dataLen,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, data) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post device info fail.");
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}

int32_t ProcessDeviceInfoMessage(int64_t authSeq, AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    uint8_t *msg = NULL;
    uint32_t msgSize = 0;
    SessionKeyList sessionKeyList;
    GetSessionKeyList(authSeq, info, &sessionKeyList);
    if (DecryptInner(&sessionKeyList, data, len, &msg, &msgSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "decrypt device info fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    if (UnpackDeviceInfoMessage((const char *)msg,
        info->connInfo.type, info->version, &info->nodeInfo, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unpack device info fail.");
        SoftBusFree(msg);
        return SOFTBUS_ERR;
    }
    SoftBusFree(msg);
    return SOFTBUS_OK;
}

int32_t PostCloseAckMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    const char *msg = "";
    AuthDataHead head = {
        .dataType = DATA_TYPE_CLOSE_ACK,
        .module = 0,
        .seq = authSeq,
        .flag = 0,
        .len = strlen(msg) + 1,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, (uint8_t *)msg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post close ack fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t PostHichainAuthMessage(int64_t authSeq, const AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    AuthDataHead head = {
        .dataType = DATA_TYPE_AUTH,
        .module = MODULE_AUTH_SDK,
        .seq = authSeq,
        .flag = 0,
        .len = len,
    };
    if (PostAuthData(info->connId, !info->isServer, &head, data) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post hichain data fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *PackVerifyDeviceMessage(const char *uuid)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "create json fail.");
        return NULL;
    }
    if (!AddNumberToJsonObject(obj, CODE, CODE_VERIFY_DEVICE) ||
        !AddStringToJsonObject(obj, DEVICE_ID, uuid)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add uuid fail.");
        cJSON_Delete(obj);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return msg;
}

int32_t PostVerifyDeviceMessage(const AuthManager *auth)
{
    CHECK_NULL_PTR_RETURN_VALUE(auth, SOFTBUS_INVALID_PARAM);
    char *msg = PackVerifyDeviceMessage(auth->uuid);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack verify device msg fail.");
        return SOFTBUS_ERR;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (EncryptInner(&auth->sessionKeyList, (uint8_t *)msg, strlen(msg) + 1, &data, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "encrypt device info fail.");
        cJSON_free(msg);
        return SOFTBUS_ENCRYPT_ERR;
    }
    cJSON_free(msg);

    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_INFO,
        .module = MODULE_AUTH_CONNECTION,
        .seq = GenSeq(false),
        .flag = 0,
        .len = dataLen,
    };
    if (PostAuthData(auth->connId, !auth->isServer, &head, data) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post verify device msg fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
