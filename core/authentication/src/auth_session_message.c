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
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain_adapter.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_request.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_common_utils.h"
#include "lnn_compress.h"
#include "lnn_event.h"
#include "lnn_extdata_config.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_config_type.h"
#include "softbus_def.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_socket.h"

/* DeviceId */
#define CMD_TAG "TECmd"
#define CMD_GET_AUTH_INFO "getAuthInfo"
#define CMD_RET_AUTH_INFO "retAuthInfo"
#define DATA_TAG "TEData"
#define DEVICE_ID_TAG "TEDeviceId"
#define DATA_BUF_SIZE_TAG "DataBufSize"
#define SOFTBUS_VERSION_TAG "softbusVersion"
#define SUPPORT_INFO_COMPRESS "supportInfoCompress"
#define EXCHANGE_ID_TYPE "exchangeIdType"
#define DEV_IP_HASH_TAG "DevIpHash"
#define CMD_TAG_LEN 30
#define PACKET_SIZE (64 * 1024)

/* DeviceInfo-WiFi */
#define CODE_VERIFY_IP 1
#define BUS_MAX_VERSION "BUS_MAX_VERSION"
#define BUS_MIN_VERSION "BUS_MIN_VERSION"
#define AUTH_PORT "AUTH_PORT"
#define SESSION_PORT "SESSION_PORT"
#define PROXY_PORT "PROXY_PORT"
#define DEV_IP "DEV_IP"
#define BLE_OFFLINE_CODE "OFFLINE_CODE"
#define BUS_V1 1
#define BUS_V2 2

/* DeviceInfo-BT */
#define CODE_VERIFY_BT 5
#define DISCOVERY_TYPE "DISCOVERY_TYPE"
#define UUID "UUID"
#define DEVICE_VERSION_TYPE "DEVICE_VERSION_TYPE"
#define BR_MAC_ADDR "BR_MAC_ADDR"
#define CONNECT_INFO "CONNECT_INFO"

/* DeviceInfo-common */
#define CODE "CODE"
#define DEVICE_NAME "DEVICE_NAME"
#define DEVICE_TYPE "DEVICE_TYPE"
#define DEVICE_UDID "DEVICE_UDID"
#define DEVICE_UUID "DEVICE_UUID"
#define NETWORK_ID "NETWORK_ID"
#define NODE_ADDR "NODE_ADDR"
#define VERSION_TYPE "VERSION_TYPE"
#define BT_MAC "BT_MAC"
#define BLE_MAC "BLE_MAC"
#define CONN_CAP "CONN_CAP"
#define AUTH_CAP "AUTH_CAP"
#define SW_VERSION "SW_VERSION"
#define MASTER_UDID "MASTER_UDID"
#define MASTER_WEIGHT "MASTER_WEIGHT"
#define BLE_P2P "BLE_P2P"
#define STA_FREQUENCY               "STA_FREQUENCY"
#define P2P_MAC_ADDR "P2P_MAC_ADDR"
#define P2P_ROLE "P2P_ROLE"
#define TRANSPORT_PROTOCOL "TRANSPORT_PROTOCOL"
#define DATA_CHANGE_FLAG "NODE_DATA_CHANGE_FLAG"
#define IS_CHARGING "IS_CHARGING"
#define BATTERY_LEAVEL "BATTERY_LEAVEL"
#define PKG_VERSION "PKG_VERSION"
#define WIFI_VERSION "WIFI_VERSION"
#define BLE_VERSION "BLE_VERSION"
#define HML_MAC "HML_MAC"
#define WIFI_CFG "WIFI_CFG"
#define CHAN_LIST_5G "CHAN_LIST_5G"
#define REMAIN_POWER "REMAIN_POWER"
#define IS_CHARGING "IS_CHARGING"
#define IS_SCREENON "IS_SCREENON"
#define IP_MAC "IP_MAC"
#define NODE_WEIGHT "NODE_WEIGHT"
#define ACCOUNT_ID "ACCOUNT_ID"
#define DISTRIBUTED_SWITCH "DISTRIBUTED_SWITCH"
#define TRANS_FLAGS "TRANS_FLAGS"
#define BLE_TIMESTAMP "BLE_TIMESTAMP"
#define WIFI_BUFF_SIZE "WIFI_BUFF_SIZE"
#define BR_BUFF_SIZE "BR_BUFF_SIZE"
#define FEATURE "FEATURE"
#define CONN_SUB_FEATURE "CONN_SUB_FEATURE"
#define META_NODE_INFO_OF_EAR "MetaNodeInfoOfEar"
#define NEW_CONN_CAP "NEW_CONN_CAP"
#define EXTDATA "EXTDATA"
#define STATE_VERSION "STATE_VERSION"
#define BD_KEY "BD_KEY"
#define IV "IV"
#define SETTINGS_NICK_NAME "SETTINGS_NICK_NAME"
#define UNIFIED_DISPLAY_DEVICE_NAME "UNIFIED_DISPLAY_DEVICE_NAME"
#define UNIFIED_DEFAULT_DEVICE_NAME "UNIFIED_DEFAULT_DEVICE_NAME"
#define UNIFIED_DEVICE_NAME "UNIFIED_DEVICE_NAME"
#define PTK "PTK"
#define STATIC_CAP "STATIC_CAP"
#define STATIC_CAP_LENGTH "STATIC_CAP_LEN"
#define BROADCAST_CIPHER_KEY "BROADCAST_CIPHER_KEY"
#define BROADCAST_CIPHER_IV "BROADCAST_CIPHER_IV"
#define IRK "IRK"
#define PUB_MAC "PUB_MAC"

#define FLAG_COMPRESS_DEVICE_INFO 1
#define FLAG_UNCOMPRESS_DEVICE_INFO 0
#define FLAG_RELAY_DEVICE_INFO 1

#define HAS_CTRL_CHANNEL (0x1L)
#define HAS_CHANNEL_AUTH (0x2L)
#define HAS_P2P_AUTH_V2 (0x04L)
#define HAS_SUPPRESS_STRATEGY (0x08L)
#define HAS_WAIT_TCP_TX_DONE (0x10L)
#define LOCAL_FLAGS (HAS_CTRL_CHANNEL | HAS_P2P_AUTH_V2 | HAS_SUPPRESS_STRATEGY | HAS_WAIT_TCP_TX_DONE)
#define DEVICE_ID_STR_LEN 64 // for bt v1
#define DEFAULT_BATTERY_LEVEL 100
#define DEFAULT_NODE_WEIGHT 100
#define BASE64_OFFLINE_CODE_LEN ((OFFLINE_CODE_BYTE_SIZE / 3 + 1) * 4 + 1)
#define DEFAULT_WIFI_BUFF_SIZE 32768 // 32k
#define DEFAULT_BR_BUFF_SIZE 4096 // 4k
#define DEFAULT_BLE_TIMESTAMP (roundl(pow(2, 63)) - 1)
#define BT_DISC_TYPE_MAX_LEN 7 // br, ble,...
#define BT_MAC_LEN 18
#define DEFAULT_BT_DISC_TYPE_STR "NO"
#define PARSE_UNCOMPRESS_STRING_BUFF_LEN 6 // "true" or "false"
#define TRUE_STRING_TAG "true"
#define FALSE_STRING_TAG "false"

/* fast_auth */
#define ACCOUNT_HASH "accountHash"
#define COMMON_KEY_HASH "keyHash"
#define FAST_AUTH "fastauth"
#define SOFTBUS_FAST_AUTH "support_fast_auth"

/* VerifyDevice */
#define CODE_VERIFY_DEVICE 2
#define DEVICE_ID "DEVICE_ID"
#define ENCRYPTED_FAST_AUTH_MAX_LEN 512
#define UDID_SHORT_HASH_HEX_STR 16
#define UDID_SHORT_HASH_LEN_TEMP 8

/* ble conn close delay time */
#define BLE_CONN_CLOSE_DELAY_TIME "BLE_CONN_CLOSE_DELAY_TIME"
#define BLE_MAC_REFRESH_SWITCH "BLE_MAC_REFRESH_SWITCH"
#define BLE_CONNECTION_CLOSE_DELAY (10 * 1000L)
#define BLE_MAC_AUTO_REFRESH_SWITCH 1

static void OptString(const JsonObj *json, const char * const key,
    char *target, uint32_t targetLen, const char *defaultValue)
{
    if (JSON_GetStringFromOject(json, key, target, targetLen)) {
        return;
    }
    if (strcpy_s(target, targetLen, defaultValue) != EOK) {
        AUTH_LOGI(AUTH_FSM, "set default fail");
        return;
    }
    AUTH_LOGI(AUTH_FSM, "key prase fail, use default. key=%{public}s", key);
}

static void OptInt(const JsonObj *json, const char * const key, int *target, int defaultValue)
{
    if (JSON_GetInt32FromOject(json, key, target)) {
        return;
    }
    AUTH_LOGI(AUTH_FSM, "key prase fail, use default. key=%{public}s", key);
    *target = defaultValue;
}

static void OptInt64(const JsonObj *json, const char * const key, int64_t *target, int64_t defaultValue)
{
    if (JSON_GetInt64FromOject(json, key, target)) {
        return;
    }
    AUTH_LOGI(AUTH_FSM, "key prase fail, use default. key=%{public}s", key);
    *target = defaultValue;
}

static void OptBool(const JsonObj *json, const char * const key, bool *target, bool defaultValue)
{
    if (JSON_GetBoolFromOject(json, key, target)) {
        return;
    }
    AUTH_LOGI(AUTH_FSM, "key prase fail, use default. key=%{public}s", key);
    *target = defaultValue;
}

static int32_t PackFastAuthValue(JsonObj *obj, AuthDeviceKeyInfo *deviceCommKey)
{
    uint32_t dataLen = 0;
    uint8_t *data = NULL;
    AesGcmInputParam aesParam = {0};
    aesParam.data = (uint8_t *)SOFTBUS_FAST_AUTH;
    aesParam.dataLen = strlen(SOFTBUS_FAST_AUTH);
    aesParam.key = deviceCommKey->deviceKey;
    aesParam.keyLen = deviceCommKey->keyLen;
    int32_t ret = LnnEncryptAesGcm(&aesParam, (int32_t)deviceCommKey->keyIndex, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusEncryptDataWithSeq fail=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    if (data == NULL || dataLen == 0) {
        AUTH_LOGE(AUTH_FSM, "encrypt data invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char encryptFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (ConvertBytesToUpperCaseHexString(encryptFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN - 1,
        data, dataLen) != SOFTBUS_OK) {
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    AUTH_LOGD(AUTH_FSM, "pack fastAuthTag=%{public}s", encryptFastAuth);
    JSON_AddStringToObject(obj, FAST_AUTH, encryptFastAuth);
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static bool GenerateUdidShortHash(const char *udid, char *udidHashBuf, uint32_t bufLen)
{
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash((uint8_t *)udid, strlen(udid), hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return false;
    }
    if (ConvertBytesToUpperCaseHexString(udidHashBuf, bufLen, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return false;
    }
    return true;
}

static bool GetUdidOrShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    if (!info->isServer && info->connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        AUTH_LOGD(AUTH_FSM, "client(enhance p2p), use conninfo udid");
        return GenerateUdidShortHash(info->connInfo.info.ipInfo.udid, udidBuf, bufLen);
    }
    if (strlen(info->udid) != 0) {
        AUTH_LOGI(AUTH_FSM, "use info->udid build fastAuthInfo");
        return GenerateUdidShortHash(info->udid, udidBuf, bufLen);
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE) {
        AUTH_LOGI(AUTH_FSM, "use bleInfo deviceIdHash build fastAuthInfo");
        AuthRequest request = {0};
        if (GetAuthRequestNoLock(info->requestId, &request) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "GetAuthRequest fail");
            return false;
        }
        return (memcpy_s(udidBuf, bufLen, request.connInfo.info.bleInfo.deviceIdHash, UDID_SHORT_HASH_HEX_STR) == EOK);
    }
    AUTH_LOGD(AUTH_FSM, "udidLen=%{public}zu, connInfoType=%{public}d", strlen(info->udid), info->connInfo.type);
    return false;
}

static int32_t GetEnhancedP2pAuthKey(const char *udidHash, AuthSessionInfo *info, AuthDeviceKeyInfo *deviceKey)
{
    /* first, reuse ble authKey */
    if (AuthFindDeviceKey(udidHash, AUTH_LINK_TYPE_BLE, deviceKey) == SOFTBUS_OK) {
        AUTH_LOGD(AUTH_FSM, "get ble authKey succ");
        return SOFTBUS_OK;
    }
    /* second, reuse wifi authKey */
    int64_t authId = AuthGetLatestIdByUuid(info->uuid, AUTH_LINK_TYPE_WIFI, false);
    if (authId == AUTH_INVALID_ID) {
        AUTH_LOGE(AUTH_FSM, "get wifi authKey fail");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    int32_t index;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (GetLatestSessionKey(&auth->sessionKeyList, &index, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get key fail");
        DelAuthManager(auth, false);
        return SOFTBUS_ERR;
    }
    DelAuthManager(auth, false);
    if (memcpy_s(deviceKey->deviceKey, SESSION_KEY_LENGTH,
        sessionKey.value, sizeof(sessionKey.value)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    deviceKey->keyLen = sessionKey.len;
    /* wifi authKey not enable, associated with recoveryDeviceKey */
    return SOFTBUS_ERR;
}

static int32_t GetFastAuthKey(const char *udidHash, AuthSessionInfo *info, AuthDeviceKeyInfo *deviceKey)
{
    if (info->connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        AUTH_LOGI(AUTH_FSM, "get enhanced p2p fastAuth key");
        return GetEnhancedP2pAuthKey(udidHash, info, deviceKey);
    }
    if (AuthFindDeviceKey(udidHash, info->connInfo.type, deviceKey) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "can't find common key, unsupport fastAuth");
        info->isSupportFastAuth = false;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void PackFastAuth(JsonObj *obj, AuthSessionInfo *info, const NodeInfo *localNodeInfo)
{
    AUTH_LOGD(AUTH_FSM, "pack fastAuth, isServer=%{public}d", info->isServer);
    bool isNeedPack;
    if (!info->isServer || info->isSupportFastAuth) {
        isNeedPack = true;
    } else {
        AUTH_LOGI(AUTH_FSM, "unsupport fastAuth");
        isNeedPack = false;
    }
    if (isNeedPack && info->isNeedFastAuth == false) {
        AUTH_LOGI(AUTH_FSM, "no need fastAuth");
        isNeedPack = false;
    }
    if (!isNeedPack) {
        return;
    }
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = {0};
    if (!GetUdidOrShortHash(info, udidHashHexStr, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get udid fail, bypass fastAuth");
        info->isSupportFastAuth = false;
        return;
    }
    AUTH_LOGD(AUTH_FSM, "udidHashHexStr=%{public}s", udidHashHexStr);
    if (info->connInfo.type != AUTH_LINK_TYPE_ENHANCED_P2P &&
        !IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidHashHexStr, false, false)) {
        AUTH_LOGI(AUTH_FSM, "not potential trusted realtion, bypass fastAuthProc");
        info->isSupportFastAuth = false;
        return;
    }
    AuthDeviceKeyInfo deviceCommKey = {0};
    if (GetFastAuthKey(udidHashHexStr, info, &deviceCommKey) != SOFTBUS_OK) {
        info->isSupportFastAuth = false;
        return;
    }
    if (PackFastAuthValue(obj, &deviceCommKey) != SOFTBUS_OK) {
        (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
        info->isSupportFastAuth = false;
        return;
    }
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
}

static void ParseFastAuthValue(AuthSessionInfo *info, const char *encryptedFastAuth, AuthDeviceKeyInfo *deviceKey)
{
    uint8_t fastAuthBytes[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (ConvertHexStringToBytes(fastAuthBytes, ENCRYPTED_FAST_AUTH_MAX_LEN,
        encryptedFastAuth, strlen(encryptedFastAuth)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "fastAuth data String to bytes fail");
        return;
    }
    uint32_t bytesLen = strlen(encryptedFastAuth) >> 1;
    uint32_t dataLen = 0;
    uint8_t *data = NULL;
    AesGcmInputParam aesParam = {0};
    aesParam.data = fastAuthBytes;
    aesParam.dataLen = bytesLen;
    aesParam.key = deviceKey->deviceKey;
    aesParam.keyLen = deviceKey->keyLen;
    int32_t ret = LnnDecryptAesGcm(&aesParam, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "LnnDecryptAesGcm fail, fastAuth not support. ret=%{public}d", ret);
        return;
    }
    if (data == NULL || dataLen == 0) {
        AUTH_LOGE(AUTH_FSM, "decrypt data invalid, fastAuth not support");
        return;
    }
    if (strncmp((char *)data, SOFTBUS_FAST_AUTH, strlen(SOFTBUS_FAST_AUTH)) != 0) {
        AUTH_LOGE(AUTH_FSM, "fast auth info error");
        SoftBusFree(data);
        return;
    }
    AUTH_LOGD(AUTH_FSM, "parse fastAuth succ");
    SoftBusFree(data);
    info->isSupportFastAuth = true;
}

static void UnpackFastAuth(JsonObj *obj, AuthSessionInfo *info)
{
    info->isSupportFastAuth = false;
    char encryptedFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, FAST_AUTH, encryptedFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN)) {
        AUTH_LOGI(AUTH_FSM, "old version or not support fastAuth");
        return;
    }
    AUTH_LOGE(AUTH_FSM, "unpack fastAuthTag=%{public}s", encryptedFastAuth);
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return;
    }
    char udidShortHash[UDID_SHORT_HASH_HEX_STR + 1] = {0};
    if (ConvertBytesToUpperCaseHexString(udidShortHash, UDID_SHORT_HASH_HEX_STR + 1,
        udidHash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "udid hash bytes to hexString fail");
        return;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_ENHANCED_P2P &&
        !IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidShortHash, false, false)) {
        AUTH_LOGI(AUTH_FSM, "not potential trusted realtion, fastAuth not support");
        return;
    }
    AuthDeviceKeyInfo deviceKey = {0};
    if (GetFastAuthKey(udidShortHash, info, &deviceKey) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "can't find device key, fastAuth not support");
        return;
    }
    ParseFastAuthValue(info, encryptedFastAuth, &deviceKey);
    (void)memset_s(&deviceKey, sizeof(deviceKey), 0, sizeof(deviceKey));
}

static void PackCompressInfo(JsonObj *obj, const NodeInfo *info)
{
    if (info != NULL) {
        if (IsFeatureSupport(info->feature, BIT_INFO_COMPRESS)) {
            JSON_AddStringToObject(obj, SUPPORT_INFO_COMPRESS, TRUE_STRING_TAG);
        } else {
            JSON_AddStringToObject(obj, SUPPORT_INFO_COMPRESS, FALSE_STRING_TAG);
        }
    }
}

static void PackWifiSinglePassInfo(JsonObj *obj, const AuthSessionInfo *info)
{
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGE(AUTH_FSM, "link type is not wifi");
        return;
    }
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    char localIp[MAX_ADDR_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local ip fail");
        return;
    }
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)localIp, strlen(localIp), hash);
    if (ret != SOFTBUS_OK) {
        return;
    }
    char devIpHash[SHA_256_HEX_HASH_LEN] = {0};
    if (ConvertBytesToUpperCaseHexString(devIpHash, SHA_256_HEX_HASH_LEN,
        hash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        return;
    }
    JSON_AddStringToObject(obj, DEV_IP_HASH_TAG, devIpHash);
}

static bool VerifySessionInfoIdType(const AuthSessionInfo *info, JsonObj *obj, char *networkId, char *udid)
{
    if (info->idType == EXCHANGE_NETWORKID) {
        if (!JSON_AddStringToObject(obj, DEVICE_ID_TAG, networkId)) {
            AUTH_LOGE(AUTH_FSM, "add msg body fail");
            return false;
        }
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        AUTH_LOGI(AUTH_FSM, "exchangeIdType=%{public}d, networkid=%{public}s", info->idType, anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
    } else {
        if (!JSON_AddStringToObject(obj, DEVICE_ID_TAG, udid)) {
            AUTH_LOGE(AUTH_FSM, "add msg body fail");
            return false;
        }
        char *anonyUdid = NULL;
        Anonymize(udid, &anonyUdid);
        AUTH_LOGI(AUTH_FSM, "exchangeIdType=%{public}d, udid=%{public}s", info->idType, anonyUdid);
        AnonymizeFree(anonyUdid);
    }

    AUTH_LOGI(AUTH_FSM, "session info verify succ.");
    return true;
}

static char *PackDeviceIdJson(const AuthSessionInfo *info)
{
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", info->connInfo.type);
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get uuid/udid/networkId fail");
        JSON_Delete(obj);
        return NULL;
    }
    PackWifiSinglePassInfo(obj, info);
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && !info->isServer) {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_GET_AUTH_INFO)) {
            AUTH_LOGE(AUTH_FSM, "add CMD_GET fail");
            JSON_Delete(obj);
            return NULL;
        }
    } else {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_RET_AUTH_INFO)) {
            AUTH_LOGE(AUTH_FSM, "add CMD_RET fail");
            JSON_Delete(obj);
            return NULL;
        }
    }
    if (!VerifySessionInfoIdType(info, obj, networkId, udid)) {
        JSON_Delete(obj);
        return NULL;
    }
    if (!JSON_AddStringToObject(obj, DATA_TAG, uuid) || !JSON_AddInt32ToObject(obj, DATA_BUF_SIZE_TAG, PACKET_SIZE) ||
        !JSON_AddInt32ToObject(obj, SOFTBUS_VERSION_TAG, info->version) ||
        !JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, info->idType)) {
        AUTH_LOGE(AUTH_FSM, "add msg body fail");
        JSON_Delete(obj);
        return NULL;
    }
    const NodeInfo *nodeInfo = LnnGetLocalNodeInfo();
    PackCompressInfo(obj, nodeInfo);
    PackFastAuth(obj, (AuthSessionInfo *)info, nodeInfo);
    char *msg = JSON_PrintUnformatted(obj);
    JSON_Delete(obj);
    return msg;
}

static bool UnpackWifiSinglePassInfo(JsonObj *obj, AuthSessionInfo *info)
{
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGD(AUTH_FSM, "isn't wifi link, ignore");
        return true;
    }
    char devIpHash[SHA_256_HEX_HASH_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, DEV_IP_HASH_TAG, devIpHash, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGD(AUTH_FSM, "devIpHash hash not found, ignore");
        return true;
    }
    // check devIpHash
    int32_t socketFd = GetFd(info->connId);
    SoftBusSockAddrIn addr = {0};
    SocketAddr socketAddr;
    int32_t rc = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&addr);
    if (rc != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetPerrName fd=%{public}d, rc=%{public}d", socketFd, rc);
        return true;
    }
    (void)memset_s(&socketAddr, sizeof(socketAddr), 0, sizeof(socketAddr));
    if (SoftBusInetNtoP(SOFTBUS_AF_INET, (void *)&addr.sinAddr, socketAddr.addr, sizeof(socketAddr.addr)) == NULL) {
        AUTH_LOGE(AUTH_FSM, "GetPerrName fd=%{public}d, rc=%{public}d", socketFd, rc);
        return true;
    }
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    rc = SoftBusGenerateStrHash((const unsigned char *)socketAddr.addr, strlen(socketAddr.addr), hash);
    if (rc != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate hash failed rc=%{public}d", rc);
        return true;
    }
    char socketIpHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (ConvertBytesToUpperCaseHexString(socketIpHash, SHA_256_HEX_HASH_LEN, hash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        return true;
    }
    if (strcmp(devIpHash, socketIpHash) == 0) {
        AUTH_LOGE(AUTH_FSM, "devIpHash is mismatch");
        return true;
    }
    return false;
}

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

static void SetCompressFlag(const char *compressCapa, bool *sessionSupportFlag)
{
    const NodeInfo *node = LnnGetLocalNodeInfo();
    if (node == NULL) {
        return;
    }
    bool isRemoteSupportCompress = false;
    if (strncmp(compressCapa, TRUE_STRING_TAG, strlen(compressCapa)) == 0) {
        isRemoteSupportCompress = true;
    } else {
        isRemoteSupportCompress = false;
    }
    if (IsFeatureSupport(node->feature, BIT_INFO_COMPRESS) && isRemoteSupportCompress) {
        *sessionSupportFlag = true;
        AUTH_LOGI(AUTH_FSM, "local-remote all support deviceinfo compress");
    } else {
        *sessionSupportFlag = false;
    }
}

static int32_t SetExchangeIdTypeAndValve(JsonObj *obj, AuthSessionInfo *info)
{
    int32_t idType = -1;
    char peerUdid[UDID_BUF_LEN] = {0};
    if (obj == NULL || info == NULL) {
        AUTH_LOGE(AUTH_FSM, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!JSON_GetInt32FromOject(obj, EXCHANGE_ID_TYPE, &idType)) {
        AUTH_LOGI(AUTH_FSM, "parse idType failed, ignore");
        info->idType = EXCHANHE_UDID;
        return SOFTBUS_OK;
    }
    char *anonyUdid = NULL;
    Anonymize(info->udid, &anonyUdid);
    AUTH_LOGI(AUTH_FSM,
        "oldIdType=%{public}d, exchangeIdType=%{public}d, deviceId=%{public}s", info->idType, idType, anonyUdid);
    if (idType == EXCHANHE_UDID) {
        info->idType = EXCHANHE_UDID;
        AnonymizeFree(anonyUdid);
        return SOFTBUS_OK;
    }
    if (info->isServer) {
        if (idType == EXCHANGE_NETWORKID) {
            if (GetPeerUdidByNetworkId(info->udid, peerUdid) != SOFTBUS_OK) {
                info->idType = EXCHANGE_FAIL;
            } else {
                if (memcpy_s(info->udid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
                    AUTH_LOGE(AUTH_FSM, "copy peer udid fail");
                    info->idType = EXCHANGE_FAIL;
                    AnonymizeFree(anonyUdid);
                    return SOFTBUS_MEM_ERR;
                }
                info->idType = EXCHANGE_NETWORKID;
            }
        }
        AnonymizeFree(anonyUdid);
        return SOFTBUS_OK;
    }
    if (info->idType == EXCHANGE_NETWORKID) {
        if (idType == EXCHANGE_FAIL) {
            info->idType = EXCHANGE_FAIL;
        }
        if (idType == EXCHANGE_NETWORKID) {
            if (GetPeerUdidByNetworkId(info->udid, peerUdid) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "get peer udid fail, peer networkId=%{public}s", anonyUdid);
                info->idType = EXCHANGE_FAIL;
            } else {
                if (memcpy_s(info->udid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
                    AUTH_LOGE(AUTH_FSM, "copy peer udid fail");
                    info->idType = EXCHANGE_FAIL;
                    AnonymizeFree(anonyUdid);
                    return SOFTBUS_MEM_ERR;
                }
                AUTH_LOGE(AUTH_FSM, "get peer udid success, peer udid=%{public}s", anonyUdid);
                info->idType = EXCHANGE_NETWORKID;
            }
        }
    }
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceIdJson(const char *msg, uint32_t len, AuthSessionInfo *info)
{
    JsonObj *obj = JSON_Parse(msg, len);
    if (obj == NULL) {
        AUTH_LOGE(AUTH_FSM, "json parse fail");
        return SOFTBUS_ERR;
    }
    char cmd[CMD_TAG_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, CMD_TAG, cmd, CMD_TAG_LEN)) {
        AUTH_LOGE(AUTH_FSM, "CMD_TAG not found");
        JSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (!UnpackWifiSinglePassInfo(obj, info)) {
        AUTH_LOGE(AUTH_FSM, "check ip fail, can't support auth");
        return SOFTBUS_ERR;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && info->isServer) {
        if (strncmp(cmd, CMD_GET_AUTH_INFO, strlen(CMD_GET_AUTH_INFO)) != 0) {
            AUTH_LOGE(AUTH_FSM, "CMD_GET not match");
            JSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    } else {
        if (strncmp(cmd, CMD_RET_AUTH_INFO, strlen(CMD_RET_AUTH_INFO)) != 0) {
            AUTH_LOGE(AUTH_FSM, "CMD_RET not match");
            JSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_GetStringFromOject(obj, DATA_TAG, info->uuid, UUID_BUF_LEN)) {
        AUTH_LOGE(AUTH_FSM, "uuid not found");
        JSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    int32_t maxBuffSize;
    OptString(obj, DEVICE_ID_TAG, info->udid, UDID_BUF_LEN, "");
    OptInt(obj, DATA_BUF_SIZE_TAG, &maxBuffSize, PACKET_SIZE);
    if (strlen(info->udid) != 0) {
        info->version = SOFTBUS_OLD_V2;
    } else {
        info->version = SOFTBUS_OLD_V1;
        if (strcpy_s(info->udid, UDID_BUF_LEN, info->uuid) != EOK) {
            AUTH_LOGE(AUTH_FSM, "strcpy udid fail, ignore");
        }
    }
    if (!JSON_GetInt32FromOject(obj, SOFTBUS_VERSION_TAG, (int32_t *)&info->version)) {
        // info->version = SOFTBUS_OLD_V2;
        AUTH_LOGE(AUTH_FSM, "softbusVersion is not found");
    }
    if (SetExchangeIdTypeAndValve(obj, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "set exchange id type or valve fail");
        JSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        char compressParse[PARSE_UNCOMPRESS_STRING_BUFF_LEN] = { 0 };
        OptString(obj, SUPPORT_INFO_COMPRESS, compressParse, PARSE_UNCOMPRESS_STRING_BUFF_LEN, FALSE_STRING_TAG);
        SetCompressFlag(compressParse, &info->isSupportCompress);
    }
    UnpackFastAuth(obj, info);
    JSON_Delete(obj);
    return SOFTBUS_OK;
}

static void GetAndSetLocalUnifiedName(JsonObj *json)
{
    char unified[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDeviceName(unified, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get defaultDeviceName fail");
        (void)JSON_AddStringToObject(json, UNIFIED_DEVICE_NAME, unified);
        return;
    }

    if (strlen(unified) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_UNIFIED_NAME, unified) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "set device unifiedDefaultName fail");
        }
        AUTH_LOGI(AUTH_FSM, "unifed length is not zero, unified=%{public}s", unified);
    }
    (void)JSON_AddStringToObject(json, UNIFIED_DEVICE_NAME, unified);
}

static int32_t PackCommonDevInfo(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    if (strlen(info->deviceInfo.unifiedName) == 0) {
        GetAndSetLocalUnifiedName(json);
    } else {
        (void)JSON_AddStringToObject(json, UNIFIED_DEVICE_NAME, info->deviceInfo.unifiedName);
    }
    (void)JSON_AddStringToObject(json, UNIFIED_DEFAULT_DEVICE_NAME, info->deviceInfo.unifiedDefaultName);
    (void)JSON_AddStringToObject(json, SETTINGS_NICK_NAME, info->deviceInfo.nickName);
    if (!JSON_AddStringToObject(json, NETWORK_ID, info->networkId) ||
        !JSON_AddStringToObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo)) ||
        !JSON_AddStringToObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !JSON_AddStringToObject(json, DEVICE_UDID, LnnGetDeviceUdid(info))) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_ERR;
    }
    if (isMetaAuth && !JSON_AddStringToObject(json, DEVICE_UUID, info->uuid)) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void PackCommonFastAuth(JsonObj *json, const NodeInfo *info)
{
    (void)JSON_AddInt32ToObject(json, STATE_VERSION, info->stateVersion);
    char extData[EXTDATA_LEN] = {0};
    int32_t ret = GetExtData(extData, EXTDATA_LEN);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetExtData fail");
    } else {
        AUTH_LOGI(AUTH_FSM, "GetExtData=%{public}s", extData);
        (void)JSON_AddStringToObject(json, EXTDATA, extData);
    }
}

static void PackCommP2pInfo(JsonObj *json, const NodeInfo *info)
{
    (void)JSON_AddInt32ToObject(json, P2P_ROLE, LnnGetP2pRole(info));
    (void)JSON_AddStringToObject(json, P2P_MAC_ADDR, LnnGetP2pMac(info));
    (void)JSON_AddStringToObject(json, HML_MAC, info->wifiDirectAddr);

    (void)JSON_AddStringToObject(json, WIFI_CFG, info->p2pInfo.wifiCfg);
    (void)JSON_AddStringToObject(json, CHAN_LIST_5G, info->p2pInfo.chanList5g);
    (void)JSON_AddInt32ToObject(json, STA_FREQUENCY, LnnGetStaFrequency(info));
}

static void PackWifiDirectInfo(JsonObj *json, const NodeInfo *info, const char *remoteUuid)
{
    if (json == NULL || remoteUuid == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return;
    }
    unsigned char encodePtk[PTK_ENCODE_LEN] = {0};
    char localPtk[PTK_DEFAULT_LEN] = {0};
    if (LnnGetLocalPtkByUuid(remoteUuid, localPtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get ptk by uuid fail");
        return;
    }
    size_t keyLen = 0;
    if (SoftBusBase64Encode(encodePtk, PTK_ENCODE_LEN, &keyLen, (unsigned char *)localPtk,
        PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encode ptk fail");
        return;
    }
    if (!JSON_AddStringToObject(json, PTK, (char *)encodePtk)) {
        AUTH_LOGE(AUTH_FSM, "add ptk string to json fail");
        return;
    }
    if (!JSON_AddInt32ToObject(json, STATIC_CAP_LENGTH, info->staticCapLen)) {
        AUTH_LOGE(AUTH_FSM, "add static cap len fail");
        return;
    }
    char staticCap[STATIC_CAP_STR_LEN] = {0};
    if (ConvertBytesToHexString((char *)staticCap, STATIC_CAP_STR_LEN,
        info->staticCapability, info->staticCapLen) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "convert static cap fail");
        return;
    }
    if (!JSON_AddStringToObject(json, STATIC_CAP, (char *)staticCap)) {
        AUTH_LOGW(AUTH_FSM, "add static capability fail");
        return;
    }
    return;
}

static int32_t PackCipherRpaInfo(JsonObj *json, const NodeInfo *info)
{
    char cipherKey[SESSION_KEY_STR_LEN] = {0};
    char cipherIv[BROADCAST_IV_STR_LEN] = {0};
    char peerIrk[LFINDER_IRK_STR_LEN] = {0};
    char pubMac[LFINDER_MAC_ADDR_STR_LEN] = {0};

    if (ConvertBytesToHexString(cipherKey, SESSION_KEY_STR_LEN,
        info->cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher key to string fail.");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(cipherIv, BROADCAST_IV_STR_LEN,
        info->cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher iv to string fail.");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(peerIrk, LFINDER_IRK_STR_LEN,
        info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert peerIrk to string fail.");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(pubMac, LFINDER_MAC_ADDR_STR_LEN,
        info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert publicAddress to string fail.");
        return SOFTBUS_ERR;
    }
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_KEY, cipherKey);
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_IV, cipherIv);
    (void)JSON_AddStringToObject(json, IRK, peerIrk);
    (void)JSON_AddStringToObject(json, PUB_MAC, pubMac);
    AUTH_LOGI(AUTH_FSM, "pack cipher and rpa info success!");

    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    if (memcpy_s(broadcastKey.udid, UDID_BUF_LEN, info->deviceInfo.deviceUdid, UDID_BUF_LEN) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy udid fail.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy key fail.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy iv fail.");
        return SOFTBUS_ERR;
    }
    if (LnnUpdateLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "update local broadcast key failed");
        return SOFTBUS_ERR;
    }
    AUTH_LOGI(AUTH_FSM, "update broadcast cipher key success!");
    return SOFTBUS_OK;
}

static void UnpackCipherRpaInfo(const JsonObj *json, NodeInfo *info)
{
    char cipherKey[SESSION_KEY_STR_LEN] = {0};
    char cipherIv[BROADCAST_IV_STR_LEN] = {0};
    char peerIrk[LFINDER_IRK_STR_LEN] = {0};
    char pubMac[LFINDER_MAC_ADDR_STR_LEN] = {0};

    if (!JSON_GetStringFromOject(json, BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_STR_LEN) ||
        !JSON_GetStringFromOject(json, BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_STR_LEN) ||
        !JSON_GetStringFromOject(json, IRK, peerIrk, LFINDER_IRK_STR_LEN) ||
        !JSON_GetStringFromOject(json, PUB_MAC, pubMac, LFINDER_MAC_ADDR_STR_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get json info fail.");
        return;
    }

    if (ConvertHexStringToBytes((unsigned char *)info->cipherInfo.key,
        SESSION_KEY_LENGTH, cipherKey, strlen(cipherKey)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher key to bytes fail.");
        return;
    }
    if (ConvertHexStringToBytes((unsigned char *)info->cipherInfo.iv,
        BROADCAST_IV_LEN, cipherIv, strlen(cipherIv)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher iv to bytes fail.");
        return;
    }
    if (ConvertHexStringToBytes((unsigned char *)info->rpaInfo.peerIrk,
        LFINDER_IRK_LEN, peerIrk, strlen(peerIrk)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert peerIrk to bytes fail.");
        return;
    }
    if (ConvertHexStringToBytes((unsigned char *)info->rpaInfo.publicAddress,
        LFINDER_MAC_ADDR_LEN, pubMac, strlen(pubMac)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert publicAddress to bytes fail.");
        return;
    }
    AUTH_LOGI(AUTH_FSM, "unpack cipher and rpa info success!");
}

static int32_t PackCommon(JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!JSON_AddStringToObject(json, MASTER_UDID, info->masterUdid) ||
            !JSON_AddInt32ToObject(json, MASTER_WEIGHT, info->masterWeight)) {
            AUTH_LOGE(AUTH_FSM, "add master node info fail");
            return SOFTBUS_ERR;
        }
        if (!JSON_AddStringToObject(json, NODE_ADDR, info->nodeAddress)) {
            AUTH_LOGE(AUTH_FSM, "pack node address Fail");
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_AddStringToObject(json, SW_VERSION, info->softBusVersion)) {
        AUTH_LOGE(AUTH_FSM, "add version info fail");
        return SOFTBUS_ERR;
    }
    if (PackCommonDevInfo(json, info, isMetaAuth) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!JSON_AddStringToObject(json, VERSION_TYPE, info->versionType) ||
        !JSON_AddInt32ToObject(json, CONN_CAP, info->netCapacity) ||
        !JSON_AddInt32ToObject(json, AUTH_CAP, info->authCapacity) ||
        !JSON_AddInt16ToObject(json, DATA_CHANGE_FLAG, info->dataChangeFlag) ||
        !JSON_AddBoolToObject(json, IS_CHARGING, info->batteryInfo.isCharging) ||
        !JSON_AddBoolToObject(json, BLE_P2P, info->isBleP2p) ||
        !JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, (int64_t)LnnGetSupportedProtocols(info))) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_ERR;
    }
    char btMacUpper[BT_MAC_LEN] = {0};
    if (StringToUpperCase(LnnGetBtMac(info), btMacUpper, BT_MAC_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "btMac to upperCase fail");
        if (memcpy_s(btMacUpper, BT_MAC_LEN, LnnGetBtMac(info), BT_MAC_LEN) != EOK) {
            AUTH_LOGE(AUTH_FSM, "btMac cpy fail");
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_AddStringToObject(json, PKG_VERSION, info->pkgVersion) ||
        !JSON_AddInt64ToObject(json, WIFI_VERSION, info->wifiVersion) ||
        !JSON_AddInt64ToObject(json, BLE_VERSION, info->bleVersion) ||
        !JSON_AddStringToObject(json, BT_MAC, btMacUpper) ||
        !JSON_AddStringToObject(json, BLE_MAC, info->connectInfo.bleMacAddr) ||
        !JSON_AddInt32ToObject(json, REMAIN_POWER, info->batteryInfo.batteryLevel) ||
        !JSON_AddBoolToObject(json, IS_CHARGING, info->batteryInfo.isCharging) ||
        !JSON_AddBoolToObject(json, IS_SCREENON, info->isScreenOn) ||
        !JSON_AddInt32ToObject(json, NODE_WEIGHT, info->masterWeight) ||
        !JSON_AddInt64ToObject(json, ACCOUNT_ID, info->accountId) ||
        !JSON_AddBoolToObject(json, DISTRIBUTED_SWITCH, true) ||
        !JSON_AddInt64ToObject(json, BLE_TIMESTAMP, info->bleStartTimestamp) ||
        !JSON_AddInt32ToObject(json, WIFI_BUFF_SIZE, info->wifiBuffSize) ||
        !JSON_AddInt32ToObject(json, BR_BUFF_SIZE, info->brBuffSize) ||
        !JSON_AddInt64ToObject(json, FEATURE, info->feature) ||
        !JSON_AddInt64ToObject(json, CONN_SUB_FEATURE, info->connSubFeature) ||
        !JSON_AddInt64ToObject(json, NEW_CONN_CAP, info->netCapacity)) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_ERR;
    }
    PackCommonFastAuth(json, info);
    if (!PackCipherKeySyncMsg(json)) {
        AUTH_LOGE(AUTH_FSM, "PackCipherKeySyncMsg fail");
    }
    PackCommP2pInfo(json, info);

    if (PackCipherRpaInfo(json, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "pack CipherRpaInfo of device key fail.");
    }
    return SOFTBUS_OK;
}

static void UnpackWifiDirectInfo(const JsonObj *json, NodeInfo *info)
{
    char staticCap[STATIC_CAP_STR_LEN] = {0};
    if (!JSON_GetInt32FromOject(json, STATIC_CAP_LENGTH, &info->staticCapLen)) {
        AUTH_LOGE(AUTH_FSM, "get static cap len fail");
        return;
    }
    if (!JSON_GetStringFromOject(json, STATIC_CAP, staticCap, STATIC_CAP_STR_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get static cap fail");
        return;
    }
    if (ConvertHexStringToBytes((unsigned char *)info->staticCapability, STATIC_CAP_LEN,
        staticCap, strlen(staticCap)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert static cap fail");
        return;
    }
    char encodePtk[PTK_ENCODE_LEN] = {0};
    size_t len = 0;
    if (!JSON_GetStringFromOject(json, PTK, encodePtk, PTK_ENCODE_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get encode ptk fail");
        return;
    }
    if (SoftBusBase64Decode((unsigned char *)info->remotePtk, PTK_DEFAULT_LEN,
        &len, (const unsigned char *)encodePtk, strlen((char *)encodePtk)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decode static cap fail");
        return;
    }
    if (len != PTK_DEFAULT_LEN) {
        AUTH_LOGE(AUTH_FSM, "decode data len error");
        return;
    }
}

static void UnpackCommon(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!JSON_GetStringFromOject(json, MASTER_UDID, info->masterUdid, UDID_BUF_LEN) ||
            !JSON_GetInt32FromOject(json, MASTER_WEIGHT, &info->masterWeight)) {
            AUTH_LOGE(AUTH_FSM, "get master node info fail");
        }
        AUTH_LOGE(AUTH_FSM, "get master weight=%{public}d", info->masterWeight);
        if (!JSON_GetStringFromOject(json, NODE_ADDR, info->nodeAddress, sizeof(info->nodeAddress))) {
            AUTH_LOGW(AUTH_FSM,
                "no node address packed. set to address NODE_ADDR_LOOPBACK. NODE_ADDR_LOOPBACK=%{public}s",
                NODE_ADDR_LOOPBACK);
            (void)strcpy_s(info->nodeAddress, sizeof(info->nodeAddress), NODE_ADDR_LOOPBACK);
        }
    }
    (void)JSON_GetStringFromOject(json, SW_VERSION, info->softBusVersion, VERSION_MAX_LEN);
    OptString(json, PKG_VERSION, info->pkgVersion, VERSION_MAX_LEN, "");
    OptString(json, UNIFIED_DEVICE_NAME, info->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, "");
    OptString(json, UNIFIED_DEFAULT_DEVICE_NAME, info->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, "");
    OptString(json, SETTINGS_NICK_NAME, info->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, "");
    OptInt64(json, WIFI_VERSION, &info->wifiVersion, 0);
    OptInt64(json, BLE_VERSION, &info->bleVersion, 0);
    OptString(json, BT_MAC, info->connectInfo.macAddr, MAC_LEN, "");
    OptString(json, BLE_MAC, info->connectInfo.bleMacAddr, MAC_LEN, "");
    char deviceType[DEVICE_TYPE_BUF_LEN] = {0};
    (void)JSON_GetStringFromOject(json, DEVICE_NAME, info->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN);
    if (JSON_GetStringFromOject(json, DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN)) {
        (void)LnnConvertDeviceTypeToId(deviceType, &(info->deviceInfo.deviceTypeId));
    }
    (void)JSON_GetStringFromOject(json, DEVICE_UDID, info->deviceInfo.deviceUdid, UDID_BUF_LEN);
    if (isMetaAuth) {
        (void)JSON_GetStringFromOject(json, DEVICE_UUID, info->uuid, UDID_BUF_LEN);
    }
    (void)JSON_GetStringFromOject(json, NETWORK_ID, info->networkId, NETWORK_ID_BUF_LEN);
    (void)JSON_GetStringFromOject(json, VERSION_TYPE, info->versionType, VERSION_MAX_LEN);
    (void)JSON_GetInt32FromOject(json, CONN_CAP, (int32_t *)&info->netCapacity);
    (void)JSON_GetInt32FromOject(json, AUTH_CAP, (int32_t *)&info->authCapacity);

    info->isBleP2p = false;
    (void)JSON_GetBoolFromOject(json, BLE_P2P, &info->isBleP2p);
    (void)JSON_GetInt16FromOject(json, DATA_CHANGE_FLAG, (int16_t *)&info->dataChangeFlag);
    (void)JSON_GetBoolFromOject(json, IS_CHARGING, &info->batteryInfo.isCharging);
    (void)JSON_GetInt32FromOject(json, REMAIN_POWER, &info->batteryInfo.batteryLevel);
    OptBool(json, IS_SCREENON, &info->isScreenOn, false);
    OptInt64(json, ACCOUNT_ID, &info->accountId, 0);
    OptInt(json, NODE_WEIGHT, &info->masterWeight, DEFAULT_NODE_WEIGHT);

    // IS_SUPPORT_TCP_HEARTBEAT
    OptInt(json, NEW_CONN_CAP, (int32_t *)&info->netCapacity, -1);
    if (info->netCapacity == (uint32_t)-1) {
        (void)JSON_GetInt32FromOject(json, CONN_CAP, (int32_t *)&info->netCapacity);
    }
    OptInt(json, WIFI_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_WIFI_BUFF_SIZE);
    OptInt(json, BR_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_BR_BUFF_SIZE);
    OptInt64(json, FEATURE, (int64_t *)&info->feature, 0);
    OptInt64(json, CONN_SUB_FEATURE, (int64_t *)&info->connSubFeature, 0);
    //MetaNodeInfoOfEar
    OptString(json, EXTDATA, info->extData, EXTDATA_LEN, "");
    if (version == SOFTBUS_OLD_V1) {
        if (strcpy_s(info->networkId, NETWORK_ID_BUF_LEN, info->uuid) != EOK) {
            AUTH_LOGE(AUTH_FSM, "v1 version strcpy networkid fail");
        }
    }
    ProcessCipherKeySyncInfo(json, info->deviceInfo.deviceUdid);

    // unpack p2p info
    OptInt(json, P2P_ROLE, &info->p2pInfo.p2pRole, -1);
    OptString(json, WIFI_CFG, info->p2pInfo.wifiCfg, WIFI_CFG_INFO_MAX_LEN, "");
    OptString(json, CHAN_LIST_5G, info->p2pInfo.chanList5g, CHANNEL_LIST_STR_LEN, "");
    OptInt(json, STA_FREQUENCY, &info->p2pInfo.staFrequency, -1);
    OptString(json, P2P_MAC_ADDR, info->p2pInfo.p2pMac, MAC_LEN, "");
    OptString(json, HML_MAC, info->wifiDirectAddr, MAC_LEN, "");

    UnpackCipherRpaInfo(json, info);
}

static int32_t GetBtDiscTypeString(const NodeInfo *info, char *buf, uint32_t len)
{
    uint32_t i = 0;
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)) {
        CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_ERR);
        buf[i++] = DISCOVERY_TYPE_BLE + '0';
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        if (i != 0) {
            CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_ERR);
            buf[i++] = ',';
        }
        CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_ERR);
        buf[i++] = DISCOVERY_TYPE_BR + '0';
    }
    return SOFTBUS_OK;
}

static void AddDiscoveryType(JsonObj *json, const char *remoteUuid)
{
    if (remoteUuid == NULL) {
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUuid(remoteUuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "networkId not found by uuid, maybe first online");
        return;
    }
    uint32_t discoveryType = 0;
    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_DISCOVERY_TYPE, (int32_t *)&discoveryType) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get discoveryType fail");
        return;
    }
    NodeInfo nodeInfo; // only for discType calc
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    nodeInfo.discoveryType = discoveryType;
    char discTypeStr[BT_DISC_TYPE_MAX_LEN] = {0};
    if (GetBtDiscTypeString(&nodeInfo, discTypeStr, BT_DISC_TYPE_MAX_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "disc Type calc fail");
        return;
    }
    AUTH_LOGD(AUTH_FSM, "discTypeStr=%{public}s", discTypeStr);
    JSON_AddStringToObject(json, DISCOVERY_TYPE, discTypeStr);
}

static int32_t PackBt(JsonObj *json, const NodeInfo *info, SoftBusVersion version,
    bool isMetaAuth, const char *remoteUuid)
{
    if (!JSON_AddInt32ToObject(json, CODE, CODE_VERIFY_BT)) {
        AUTH_LOGE(AUTH_FSM, "add bt info fail");
        return SOFTBUS_ERR;
    }
    AddDiscoveryType(json, remoteUuid);
    int32_t delayTime = BLE_CONNECTION_CLOSE_DELAY;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BLE_CLOSE_DELAY_TIME,
        (unsigned char *)(&delayTime), sizeof(delayTime)) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "get ble conn close delay time from config file fail");
    }
    int32_t bleMacRefreshSwitch = BLE_MAC_AUTO_REFRESH_SWITCH;
    if (SoftbusGetConfig(SOFTBUS_INT_BLE_MAC_AUTO_REFRESH_SWITCH,
        (unsigned char *)(&bleMacRefreshSwitch), sizeof(bleMacRefreshSwitch)) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "get ble mac refresh switch from config file fail");
    }
    if (!JSON_AddInt32ToObject(json, BLE_CONN_CLOSE_DELAY_TIME, delayTime) ||
        !JSON_AddInt32ToObject(json, BLE_MAC_REFRESH_SWITCH, bleMacRefreshSwitch)) {
        AUTH_LOGI(AUTH_FSM, "add ble conn close delay time or refresh switch fail");
    }
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "PackCommon fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetDiscType(uint32_t *discType, const char *discStr)
{
    if (strcmp(discStr, DEFAULT_BT_DISC_TYPE_STR) == 0) {
        AUTH_LOGE(AUTH_FSM, "disc type can't parse");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackBt(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    char discTypeStr[BT_DISC_TYPE_MAX_LEN] = {0};
    if (!JSON_GetInt64FromOject(json, TRANSPORT_PROTOCOL, (int64_t *)&info->supportedProtocols)) {
        info->supportedProtocols = LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE;
    }
    OptString(json, DISCOVERY_TYPE, discTypeStr, BT_DISC_TYPE_MAX_LEN, DEFAULT_BT_DISC_TYPE_STR);
    (void)SetDiscType(&info->discoveryType, discTypeStr);
    OptInt64(json, BLE_TIMESTAMP, &info->bleStartTimestamp, DEFAULT_BLE_TIMESTAMP);
    OptInt(json, STATE_VERSION, &info->stateVersion, 0);
    OptInt(json, BLE_CONN_CLOSE_DELAY_TIME, &info->bleConnCloseDelayTime, BLE_CONNECTION_CLOSE_DELAY);
    OptInt(json, BLE_MAC_REFRESH_SWITCH, &info->bleMacRefreshSwitch, BLE_MAC_AUTO_REFRESH_SWITCH);
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackWiFi(JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    AUTH_LOGD(AUTH_FSM, "devIp=%{public}zu", strlen(info->connectInfo.deviceIp));
    if (!JSON_AddInt32ToObject(json, CODE, CODE_VERIFY_IP) || !JSON_AddInt32ToObject(json, BUS_MAX_VERSION, BUS_V2) ||
        !JSON_AddInt32ToObject(json, BUS_MIN_VERSION, BUS_V1) ||
        !JSON_AddInt32ToObject(json, AUTH_PORT, LnnGetAuthPort(info)) ||
        !JSON_AddInt32ToObject(json, SESSION_PORT, LnnGetSessionPort(info)) ||
        !JSON_AddInt32ToObject(json, PROXY_PORT, LnnGetProxyPort(info)) ||
        !JSON_AddStringToObject(json, DEV_IP, info->connectInfo.deviceIp)) {
        AUTH_LOGE(AUTH_FSM, "add wifi info fail");
        return SOFTBUS_ERR;
    }
    char offlineCode[BASE64_OFFLINE_CODE_LEN] = {0};
    size_t len = 0;
    AUTH_LOGE(AUTH_FSM, "offlineCodeLen=%{public}zu, offlineCodeSize=%{public}zu",
        strlen(offlineCode), sizeof(info->offlineCode));
    int32_t ret = SoftBusBase64Encode((unsigned char*)offlineCode, BASE64_OFFLINE_CODE_LEN, &len,
        (unsigned char*)info->offlineCode, sizeof(info->offlineCode));
    if (ret != 0) {
        AUTH_LOGE(AUTH_FSM, "mbedtls base64 encode failed");
        return SOFTBUS_ERR;
    }
    (void)JSON_AddStringToObject(json, BLE_OFFLINE_CODE, offlineCode);
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "PackCommon fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CheckBusVersion(const JsonObj *json)
{
    int32_t maxVersion;
    int32_t minVersion;
    OptInt(json, BUS_MAX_VERSION, &maxVersion, -1);
    OptInt(json, BUS_MIN_VERSION, &minVersion, -1);
    if (maxVersion > BUS_V2) {
        maxVersion = BUS_V2;
    }
    if (minVersion < BUS_V1) {
        minVersion = BUS_V1;
    }
    if (maxVersion < 0 || maxVersion < minVersion) {
        AUTH_LOGE(AUTH_FSM, "no common version");
        return SOFTBUS_ERR;
    }
    return maxVersion;
}

static int32_t UnpackWiFi(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (CheckBusVersion(json) < 0) {
        return SOFTBUS_ERR;
    }
    (void)JSON_GetInt32FromOject(json, AUTH_PORT, &info->connectInfo.authPort);
    (void)JSON_GetInt32FromOject(json, SESSION_PORT, &info->connectInfo.sessionPort);
    (void)JSON_GetInt32FromOject(json, PROXY_PORT, &info->connectInfo.proxyPort);
    if (!JSON_GetInt64FromOject(json, TRANSPORT_PROTOCOL, (int64_t *)&info->supportedProtocols)) {
        info->supportedProtocols = LNN_PROTOCOL_IP;
    }
    char offlineCode[BASE64_OFFLINE_CODE_LEN] = {0};
    OptString(json, DEV_IP, info->connectInfo.deviceIp, MAX_ADDR_LEN, ""); // check ip available
    OptString(json, BLE_OFFLINE_CODE, offlineCode, BASE64_OFFLINE_CODE_LEN, "");
    size_t len;
    if (SoftBusBase64Decode(info->offlineCode, OFFLINE_CODE_BYTE_SIZE,
        &len, (const unsigned char *)offlineCode, strlen(offlineCode)) != 0) {
        AUTH_LOGE(AUTH_FSM, "base64Decode fail");
    }
    if (len != OFFLINE_CODE_BYTE_SIZE) {
        AUTH_LOGE(AUTH_FSM, "base64Decode data err");
    }
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackDeviceInfoBtV1(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    AUTH_LOGI(AUTH_FSM, "pack deviceInfo bt-v1");
    if (!JSON_AddStringToObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo)) ||
        !JSON_AddStringToObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !JSON_AddStringToObject(json, DEVICE_VERSION_TYPE, info->versionType) ||
        !JSON_AddStringToObject(json, BR_MAC_ADDR, LnnGetBtMac(info)) ||
        !JSON_AddStringToObject(json, P2P_MAC_ADDR, LnnGetP2pMac(info)) ||
        !JSON_AddStringToObject(json, UUID, info->uuid) ||
        !JSON_AddStringToObject(json, SW_VERSION, info->softBusVersion) ||
        !JSON_AddStringToObject(json, DEVICE_UDID, info->deviceInfo.deviceUdid) ||
        !JSON_AddInt64ToObject(json, WIFI_VERSION, info->wifiVersion) ||
        !JSON_AddInt64ToObject(json, BLE_VERSION, info->bleVersion) ||
        !JSON_AddInt64ToObject(json, CONN_CAP, info->netCapacity) ||
        !JSON_AddInt64ToObject(json, NEW_CONN_CAP, info->netCapacity) ||
        !JSON_AddStringToObject(json, BT_MAC, info->connectInfo.macAddr) ||
        !JSON_AddStringToObject(json, HML_MAC, info->wifiDirectAddr) ||
        !JSON_AddInt32ToObject(json, REMAIN_POWER, info->batteryInfo.batteryLevel) ||
        !JSON_AddBoolToObject(json, IS_CHARGING, info->batteryInfo.isCharging) ||
        !JSON_AddBoolToObject(json, IS_SCREENON, info->isScreenOn) ||
        !JSON_AddInt32ToObject(json, P2P_ROLE, info->p2pInfo.p2pRole) ||
        !JSON_AddInt64ToObject(json, ACCOUNT_ID, info->accountId) ||
        !JSON_AddInt32ToObject(json, NODE_WEIGHT, info->masterWeight)) {
        AUTH_LOGE(AUTH_FSM, "add wifi info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceInfoBtV1(const JsonObj *json, NodeInfo *info)
{
    char deviceType[DEVICE_TYPE_BUF_LEN] = { 0 };
    if (!JSON_GetStringFromOject(json, DEVICE_NAME, info->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN) ||
        !JSON_GetStringFromOject(json, DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN) ||
        !JSON_GetStringFromOject(json, DEVICE_UDID, info->deviceInfo.deviceUdid, UDID_BUF_LEN) ||
        !JSON_GetStringFromOject(json, UUID, info->uuid, UUID_BUF_LEN) ||
        !JSON_GetStringFromOject(json, BR_MAC_ADDR, info->connectInfo.macAddr, MAC_LEN)) {
        AUTH_LOGE(AUTH_FSM, "prase devinfo fail, invalid msg");
        return SOFTBUS_ERR;
    }
    (void)LnnConvertDeviceTypeToId(deviceType, &(info->deviceInfo.deviceTypeId));
    OptString(json, HML_MAC, info->wifiDirectAddr, MAC_LEN, "");
    OptString(json, P2P_MAC_ADDR, info->p2pInfo.p2pMac, MAC_LEN, "");
    OptString(json, SW_VERSION, info->softBusVersion, VERSION_MAX_LEN, "");
    OptString(json, DEVICE_VERSION_TYPE, info->versionType, VERSION_MAX_LEN, "");
    OptInt64(json, WIFI_VERSION, &info->wifiVersion, 0);
    OptInt64(json, BLE_VERSION, &info->bleVersion, 0);
    OptInt(json, REMAIN_POWER, &info->batteryInfo.batteryLevel, DEFAULT_BATTERY_LEVEL);
    OptBool(json, IS_CHARGING, &info->batteryInfo.isCharging, false);
    OptBool(json, IS_SCREENON, &info->isScreenOn, false);
    OptInt(json, P2P_ROLE, &info->p2pInfo.p2pRole, 0);
    OptInt64(json, ACCOUNT_ID, &info->accountId, 0);
    OptInt(json, NODE_WEIGHT, &info->masterWeight, DEFAULT_NODE_WEIGHT);
    OptInt64(json, FEATURE, (int64_t *)&info->feature, 0);
    OptInt64(json, NEW_CONN_CAP, (int64_t *)&info->netCapacity, -1);
    if (info->netCapacity == (uint32_t)-1) {
        OptInt64(json, CONN_CAP, (int64_t *)&info->netCapacity, 0);
    }
    if (strcpy_s(info->networkId, NETWORK_ID_BUF_LEN, info->uuid) != EOK) {
        AUTH_LOGE(AUTH_FSM, "strcpy networkId fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

char *PackDeviceInfoMessage(int32_t linkType, SoftBusVersion version, bool isMetaAuth, const char *remoteUuid)
{
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", linkType);
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        AUTH_LOGE(AUTH_FSM, "local info is null");
        return NULL;
    }
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        AUTH_LOGE(AUTH_FSM, "create cjson fail");
        return NULL;
    }
    int32_t ret;
    if (linkType == AUTH_LINK_TYPE_WIFI) {
        ret = PackWiFi(json, info, version, isMetaAuth);
    } else if (version == SOFTBUS_OLD_V1) {
        ret = PackDeviceInfoBtV1(json, info, isMetaAuth);
    } else {
        ret = PackBt(json, info, version, isMetaAuth, remoteUuid);
    }
    if (ret != SOFTBUS_OK) {
        JSON_Delete(json);
        return NULL;
    }
    PackWifiDirectInfo(json, info, remoteUuid);

    char *msg = JSON_PrintUnformatted(json);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "JSON_PrintUnformatted fail");
    }
    JSON_Delete(json);
    return msg;
}

static void UpdatePeerDeviceName(NodeInfo *peerNodeInfo)
{
    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        AUTH_LOGE(AUTH_FSM, "localInfo is null");
        return;
    }
    int32_t ret = EOK;
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    if (strlen(peerNodeInfo->deviceInfo.unifiedName) != 0 &&
        strcmp(peerNodeInfo->deviceInfo.unifiedName, peerNodeInfo->deviceInfo.unifiedDefaultName) != 0) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedName);
    } else if (strlen(peerNodeInfo->deviceInfo.nickName) == 0 || localInfo->accountId == peerNodeInfo->accountId) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedDefaultName);
    } else {
        LnnGetDeviceDisplayName(peerNodeInfo->deviceInfo.nickName,
            peerNodeInfo->deviceInfo.unifiedDefaultName, deviceName, DEVICE_NAME_BUF_LEN);
    }
    AUTH_LOGD(AUTH_FSM,
        "peer tmpDeviceName=%{public}s, deviceName=%{public}s, unifiedName=%{public}s, "
        "unifiedDefaultName=%{public}s, nickName=%{public}s",
        deviceName, peerNodeInfo->deviceInfo.deviceName, peerNodeInfo->deviceInfo.unifiedName,
        peerNodeInfo->deviceInfo.unifiedDefaultName, peerNodeInfo->deviceInfo.nickName);
    if (strlen(deviceName) != 0) {
        ret = strcpy_s(peerNodeInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, deviceName);
    }
    if (ret != EOK) {
        AUTH_LOGW(AUTH_FSM, "strcpy_s fail, use default name");
    }
}

int32_t UnpackDeviceInfoMessage(const DevInfoData *devInfo, NodeInfo *nodeInfo, bool isMetaAuth)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(devInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "devInfo is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(nodeInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "nodeInfo is NULL");
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", devInfo->linkType);
    JsonObj *json = JSON_Parse(devInfo->msg, devInfo->len);
    if (json == NULL) {
        AUTH_LOGE(AUTH_FSM, "parse cjson fail");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    if (devInfo->linkType == AUTH_LINK_TYPE_WIFI) {
        ret = UnpackWiFi(json, nodeInfo, devInfo->version, isMetaAuth);
    } else if (devInfo->version == SOFTBUS_OLD_V1) {
        ret = UnpackDeviceInfoBtV1(json, nodeInfo);
    } else {
        ret = UnpackBt(json, nodeInfo, devInfo->version, isMetaAuth);
    }
    UnpackWifiDirectInfo(json, nodeInfo);
    JSON_Delete(json);
    int32_t stateVersion;
    if (LnnGetLocalNumInfo(NUM_KEY_STATE_VERSION, &stateVersion) == SOFTBUS_OK) {
        nodeInfo->localStateVersion = stateVersion;
    }
    if (IsFeatureSupport(nodeInfo->feature, BIT_SUPPORT_UNIFORM_NAME_CAPABILITY)) {
        UpdatePeerDeviceName(nodeInfo);
    }
    return ret;
}

static int32_t PostDeviceIdData(int64_t authSeq, const AuthSessionInfo *info, uint8_t *data, uint32_t len)
{
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_ID,
        .module = MODULE_TRUST_ENGINE,
        .seq = authSeq,
        .flag = info->isServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
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
        return SOFTBUS_ERR;
    }
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get uuid fail");
        return SOFTBUS_ERR;
    }
    return PostDeviceIdData(authSeq, info, (uint8_t *)uuid, strlen(uuid));
}

static int32_t PostWifiV1DevId(int64_t authSeq, const AuthSessionInfo *info)
{
    if (!info->isServer) {
        AUTH_LOGE(AUTH_FSM, "client don't send wifi-v1 devId");
        return SOFTBUS_ERR;
    }
    char *msg = PackDeviceIdJson(info);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack devId fail");
        return SOFTBUS_ERR;
    }
    if (PostDeviceIdData(authSeq, info, (uint8_t *)msg, strlen(msg) + 1) != SOFTBUS_OK) {
        JSON_Free(msg);
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    if (PostDeviceIdData(authSeq, info, (uint8_t *)msg, strlen(msg) + 1) != SOFTBUS_OK) {
        JSON_Free(msg);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    JSON_Free(msg);
    return SOFTBUS_OK;
}

static void DfxRecordLnnPostDeviceIdStart(int64_t authSeq)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_DEVICE_ID_POST, extra);
}

int32_t PostDeviceIdMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    DfxRecordLnnPostDeviceIdStart(authSeq);
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

static void GetSessionKeyList(int64_t authSeq, const AuthSessionInfo *info, SessionKeyList *list)
{
    ListInit(list);
    SessionKey sessionKey;
    if (AuthManagerGetSessionKey(authSeq, info, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get session key fail");
        return;
    }
    if (AddSessionKey(list, TO_INT32(authSeq), &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "add session key fail");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
}

static void DfxRecordLnnPostDeviceInfoStart(int64_t authSeq)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_DEVICE_INFO_POST, extra);
}

int32_t PostDeviceInfoMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    DfxRecordLnnPostDeviceInfoStart(authSeq);
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    char *msg = PackDeviceInfoMessage(info->connInfo.type, info->version, false, info->uuid);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack device info fail");
        return SOFTBUS_ERR;
    }
    int32_t compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
    uint8_t *compressData = NULL;
    uint32_t compressLen = 0;
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        AUTH_LOGI(AUTH_FSM, "before compress, datalen=%{public}zu", strlen(msg) + 1);
        if (DataCompress((uint8_t *)msg, strlen(msg) + 1, &compressData, &compressLen) != SOFTBUS_OK) {
            compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
        } else {
            compressFlag = FLAG_COMPRESS_DEVICE_INFO;
            AUTH_LOGI(AUTH_FSM, "deviceInfo compress finish");
        }
        AUTH_LOGI(AUTH_FSM, "after compress, datalen=%{public}u", compressLen);
    }
    uint8_t *inputData = NULL;
    uint32_t inputLen;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if ((compressData != NULL) && (compressLen != 0)) {
        inputData = compressData;
        inputLen = compressLen;
    } else {
        inputData = (uint8_t *)msg;
        inputLen = strlen(msg) + 1;
    }
    SessionKeyList sessionKeyList;
    GetSessionKeyList(authSeq, info, &sessionKeyList);
    if (EncryptInner(&sessionKeyList, inputData, inputLen, &data, &dataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encrypt device info fail");
        JSON_Free(msg);
        SoftBusFree(compressData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    JSON_Free(msg);
    SoftBusFree(compressData);
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
    GetSessionKeyList(authSeq, info, &sessionKeyList);
    if (DecryptInner(&sessionKeyList, data, len, &msg, &msgSize) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decrypt device info fail");
        return SOFTBUS_DECRYPT_ERR;
    }
    uint8_t *decompressData = NULL;
    uint32_t decompressLen = 0;
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        AUTH_LOGI(AUTH_FSM, "before decompress, msgSize=%{public}u", msgSize);
        if (DataDecompress((uint8_t *)msg, msgSize, &decompressData, &decompressLen) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "data decompress fail");
            SoftBusFree(msg);
            return SOFTBUS_ERR;
        } else {
            AUTH_LOGI(AUTH_FSM, "deviceInfo deCompress finish, decompress=%{public}d", decompressLen);
        }
        AUTH_LOGI(AUTH_FSM, "after decompress, datalen=%{public}d", decompressLen);
    }
    DevInfoData devInfo = {NULL, 0, info->connInfo.type, info->version};
    if ((decompressData != NULL) && (decompressLen != 0)) {
        devInfo.msg = (const char *)decompressData;
        devInfo.len = decompressLen;
    } else {
        devInfo.msg = (const char *)msg;
        devInfo.len = msgSize;
    }
    if (UnpackDeviceInfoMessage(&devInfo, &info->nodeInfo, false) != SOFTBUS_OK) {
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

bool IsFlushDevicePacket(const AuthConnInfo *connInfo, const AuthDataHead *head, const uint8_t *data, bool isServer)
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
    if (AuthDeviceDecrypt(authId, data, head->len, decData, &decDataLen) != SOFTBUS_OK) {
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
    int32_t verifyDevice = 0;
    if (!JSON_GetInt32FromOject(json, CODE, &verifyDevice)) {
        AUTH_LOGE(AUTH_FSM, "parse device info fail");
    }
    if (verifyDevice == CODE_VERIFY_DEVICE) {
        result = true;
    }
    JSON_Delete(json);
    SoftBusFree(decData);
    return result;
}

int32_t PostVerifyDeviceMessage(const AuthManager *auth, int32_t flagRelay)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(auth != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "auth is NULL");
    char *msg = PackVerifyDeviceMessage(auth->uuid);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_FSM, "pack verify device msg fail");
        return SOFTBUS_ERR;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (EncryptInner(&auth->sessionKeyList, (uint8_t *)msg, strlen(msg) + 1, &data, &dataLen) != SOFTBUS_OK) {
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
    if (PostAuthData(auth->connId, !auth->isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post verify device msg fail");
        SoftBusFree(data);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}