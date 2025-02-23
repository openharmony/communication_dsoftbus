/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "auth_session_json.h"

#include <math.h>
#include <securec.h>

#include "anonymizer.h"
#include "auth_attest_interface.h"
#include "auth_connection.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_common_utils.h"
#include "lnn_extdata_config.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"

/* DeviceId */
#define CMD_TAG               "TECmd"
#define CMD_GET_AUTH_INFO     "getAuthInfo"
#define CMD_RET_AUTH_INFO     "retAuthInfo"
#define DATA_TAG              "TEData"
#define DEVICE_ID_TAG         "TEDeviceId"
#define DATA_BUF_SIZE_TAG     "DataBufSize"
#define SOFTBUS_VERSION_TAG   "softbusVersion"
#define SUPPORT_INFO_COMPRESS "supportInfoCompress"
#define IS_NORMALIZED         "isNormalized"
#define NORMALIZED_DATA       "normalizedData"
#define EXCHANGE_ID_TYPE      "exchangeIdType"
#define DEV_IP_HASH_TAG       "DevIpHash"
#define AUTH_MODULE           "AuthModule"
#define CMD_TAG_LEN           30
#define PACKET_SIZE           (64 * 1024)

/* DeviceInfo-WiFi */
#define CODE_VERIFY_IP   1
#define BUS_MAX_VERSION  "BUS_MAX_VERSION"
#define BUS_MIN_VERSION  "BUS_MIN_VERSION"
#define AUTH_PORT        "AUTH_PORT"
#define SESSION_PORT     "SESSION_PORT"
#define PROXY_PORT       "PROXY_PORT"
#define DEV_IP           "DEV_IP"
#define BLE_OFFLINE_CODE "OFFLINE_CODE"
#define BUS_V1           1
#define BUS_V2           2

/* DeviceInfo-BT */
#define CODE_VERIFY_BT      5
#define DISCOVERY_TYPE      "DISCOVERY_TYPE"
#define UUID                "UUID"
#define DEVICE_VERSION_TYPE "DEVICE_VERSION_TYPE"
#define BR_MAC_ADDR         "BR_MAC_ADDR"
#define CONNECT_INFO        "CONNECT_INFO"

/* DeviceInfo-common */
#define DEVICE_NAME                 "DEVICE_NAME"
#define DEVICE_TYPE                 "DEVICE_TYPE"
#define DEVICE_UDID                 "DEVICE_UDID"
#define DEVICE_UUID                 "DEVICE_UUID"
#define NETWORK_ID                  "NETWORK_ID"
#define NODE_ADDR                   "NODE_ADDR"
#define VERSION_TYPE                "VERSION_TYPE"
#define BT_MAC                      "BT_MAC"
#define BLE_MAC                     "BLE_MAC"
#define CONN_CAP                    "CONN_CAP"
#define AUTH_CAP                    "AUTH_CAP"
#define HB_CAP                      "HB_CAP"
#define SW_VERSION                  "SW_VERSION"
#define MASTER_UDID                 "MASTER_UDID"
#define MASTER_WEIGHT               "MASTER_WEIGHT"
#define BLE_P2P                     "BLE_P2P"
#define STA_FREQUENCY               "STA_FREQUENCY"
#define P2P_MAC_ADDR                "P2P_MAC_ADDR"
#define P2P_ROLE                    "P2P_ROLE"
#define TRANSPORT_PROTOCOL          "TRANSPORT_PROTOCOL"
#define DATA_CHANGE_FLAG            "NODE_DATA_CHANGE_FLAG"
#define IS_CHARGING                 "IS_CHARGING"
#define BATTERY_LEAVEL              "BATTERY_LEAVEL"
#define PKG_VERSION                 "PKG_VERSION"
#define OS_TYPE                     "OS_TYPE"
#define OS_VERSION                  "OS_VERSION"
#define DEVICE_VERSION              "DEVICE_VERSION"
#define WIFI_VERSION                "WIFI_VERSION"
#define BLE_VERSION                 "BLE_VERSION"
#define HML_MAC                     "HML_MAC"
#define WIFI_CFG                    "WIFI_CFG"
#define CHAN_LIST_5G                "CHAN_LIST_5G"
#define REMAIN_POWER                "REMAIN_POWER"
#define IS_CHARGING                 "IS_CHARGING"
#define IS_SCREENON                 "IS_SCREENON"
#define IP_MAC                      "IP_MAC"
#define NODE_WEIGHT                 "NODE_WEIGHT"
#define ACCOUNT_ID                  "ACCOUNT_ID"
#define DISTRIBUTED_SWITCH          "DISTRIBUTED_SWITCH"
#define TRANS_FLAGS                 "TRANS_FLAGS"
#define BLE_TIMESTAMP               "BLE_TIMESTAMP"
#define WIFI_BUFF_SIZE              "WIFI_BUFF_SIZE"
#define BR_BUFF_SIZE                "BR_BUFF_SIZE"
#define FEATURE                     "FEATURE"
#define CONN_SUB_FEATURE            "CONN_SUB_FEATURE"
#define META_NODE_INFO_OF_EAR       "MetaNodeInfoOfEar"
#define NEW_CONN_CAP                "NEW_CONN_CAP"
#define EXTDATA                     "EXTDATA"
#define STATE_VERSION               "STATE_VERSION"
#define STATE_VERSION_CHANGE_REASON "STATE_VERSION_CHANGE_REASON"
#define BD_KEY                      "BD_KEY"
#define IV                          "IV"
#define SETTINGS_NICK_NAME          "SETTINGS_NICK_NAME"
#define UNIFIED_DISPLAY_DEVICE_NAME "UNIFIED_DISPLAY_DEVICE_NAME"
#define UNIFIED_DEFAULT_DEVICE_NAME "UNIFIED_DEFAULT_DEVICE_NAME"
#define UNIFIED_DEVICE_NAME         "UNIFIED_DEVICE_NAME"
#define PTK                         "PTK"
#define STATIC_CAP                  "STATIC_CAP"
#define STATIC_CAP_LENGTH           "STATIC_CAP_LEN"
#define BROADCAST_CIPHER_KEY        "BROADCAST_CIPHER_KEY"
#define BROADCAST_CIPHER_IV         "BROADCAST_CIPHER_IV"
#define IRK                         "IRK"
#define PUB_MAC                     "PUB_MAC"
#define DEVICE_SECURITY_LEVEL       "DEVICE_SECURITY_LEVEL"
#define AUTH_START_STATE            "AUTH_START_STATE"

#define HAS_CTRL_CHANNEL                 (0x1L)
#define HAS_CHANNEL_AUTH                 (0x2L)
#define HAS_P2P_AUTH_V2                  (0x04L)
#define HAS_SUPPRESS_STRATEGY            (0x08L)
#define HAS_WAIT_TCP_TX_DONE             (0x10L)
#define LOCAL_FLAGS (HAS_CTRL_CHANNEL | HAS_P2P_AUTH_V2 | HAS_SUPPRESS_STRATEGY | HAS_WAIT_TCP_TX_DONE)
#define DEFAULT_BATTERY_LEVEL            100
#define DEFAULT_NODE_WEIGHT              100
#define BASE64_OFFLINE_CODE_LEN          16
#define DEFAULT_WIFI_BUFF_SIZE           32768 // 32k
#define DEFAULT_BR_BUFF_SIZE             4096  // 4k
#define DEFAULT_BLE_TIMESTAMP            (roundl(pow(2, 63)) - 1)
#define BT_DISC_TYPE_MAX_LEN             7 // br, ble,...
#define BT_MAC_LEN                       18
#define DEFAULT_BT_DISC_TYPE_STR         "NO"
#define PARSE_UNCOMPRESS_STRING_BUFF_LEN 6 // "true" or "false"
#define TRUE_STRING_TAG                  "true"
#define FALSE_STRING_TAG                 "false"

/* fast_auth */
#define ACCOUNT_HASH      "accountHash"
#define COMMON_KEY_HASH   "keyHash"
#define FAST_AUTH         "fastauth"
#define SOFTBUS_FAST_AUTH "support_fast_auth"

#define ENCRYPTED_FAST_AUTH_MAX_LEN      512
#define ENCRYPTED_NORMALIZED_KEY_MAX_LEN 512

/* UDID abatement*/
#define ATTEST_CERTS      "ATTEST_CERTS"
#define DEVICE_CERTS      "DEVICE_CERTS"
#define MANUFACTURE_CERTS "MANUFACTURE_CERTS"
#define ROOT_CERTS        "ROOT_CERTS"
#define IS_NEED_PACK_CERT "IS_NEED_PACK_CERT"

/* ble conn close delay time */
#define BLE_CONN_CLOSE_DELAY_TIME   "BLE_CONN_CLOSE_DELAY_TIME"
#define BLE_MAC_REFRESH_SWITCH      "BLE_MAC_REFRESH_SWITCH"
#define BLE_CONNECTION_CLOSE_DELAY  (10 * 1000L)
#define BLE_MAC_AUTO_REFRESH_SWITCH 1

#define INVALID_BR_MAC_ADDR "00:00:00:00:00:00"

/* userId */
#define USERID_CHECKSUM "USERID_CHECKSUM"
#define USERID          "USERID"

static void OptString(
    const JsonObj *json, const char * const key, char *target, uint32_t targetLen, const char *defaultValue)
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
    AesGcmInputParam aesParam = { 0 };
    aesParam.data = (uint8_t *)SOFTBUS_FAST_AUTH;
    aesParam.dataLen = strlen(SOFTBUS_FAST_AUTH);
    aesParam.key = deviceCommKey->deviceKey;
    aesParam.keyLen = deviceCommKey->keyLen;
    int32_t ret = LnnEncryptAesGcm(&aesParam, (int32_t)deviceCommKey->keyIndex, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusEncryptDataWithSeq fail=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (data == NULL || dataLen == 0) {
        AUTH_LOGE(AUTH_FSM, "encrypt data invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char encryptFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = { 0 };
    if (ConvertBytesToUpperCaseHexString(encryptFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN - 1, data, dataLen) !=
        SOFTBUS_OK) {
        SoftBusFree(data);
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    AUTH_LOGD(AUTH_FSM, "pack fastAuthTag=%{public}s", encryptFastAuth);
    JSON_AddStringToObject(obj, FAST_AUTH, encryptFastAuth);
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static bool GenerateUdidShortHash(const char *udid, char *udidHashBuf, uint32_t bufLen)
{
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    int ret = SoftBusGenerateStrHash((uint8_t *)udid, strlen(udid), hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return false;
    }
    if (ConvertBytesToHexString(udidHashBuf, bufLen, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return false;
    }
    return true;
}

static bool GetUdidOrShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    if (!info->isServer) {
        AUTH_LOGI(AUTH_FSM, "client generate udid, connType is %{public}d", info->connInfo.type);
        if (info->connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
            return GenerateUdidShortHash(info->connInfo.info.ipInfo.udid, udidBuf, bufLen);
        } else if (info->connInfo.type == AUTH_LINK_TYPE_SESSION) {
            return GenerateUdidShortHash(info->connInfo.info.sessionInfo.udid, udidBuf, bufLen);
        }
    }
    if (strlen(info->udid) != 0) {
        AUTH_LOGI(AUTH_FSM, "use info->udid build fastAuthInfo");
        return GenerateUdidShortHash(info->udid, udidBuf, bufLen);
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE) {
        AUTH_LOGI(AUTH_FSM, "use bleInfo deviceIdHash build fastAuthInfo");
        return (ConvertBytesToHexString(
            udidBuf, bufLen, info->connInfo.info.bleInfo.deviceIdHash, UDID_SHORT_HASH_LEN_TEMP) == SOFTBUS_OK);
    }
    AUTH_LOGD(AUTH_FSM, "udidLen=%{public}zu, connInfoType=%{public}d", strlen(info->udid), info->connInfo.type);
    return false;
}

bool GetUdidShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    if (info == NULL || udidBuf == NULL || bufLen <= UDID_SHORT_HASH_HEX_STR) {
        AUTH_LOGE(AUTH_FSM, "param error");
        return false;
    }
    if (strlen(info->udid) != 0) {
        AUTH_LOGI(AUTH_FSM, "use info->udid build normalize auth");
        return GenerateUdidShortHash(info->udid, udidBuf, bufLen);
    }
    char udid[UDID_BUF_LEN] = { 0 };
    switch (info->connInfo.type) {
        case AUTH_LINK_TYPE_BR:
            if (LnnGetUdidByBrMac(info->connInfo.info.brInfo.brMac, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "get udid by brMac fail.");
                return false;
            }
            return GenerateUdidShortHash(udid, udidBuf, bufLen);
        case AUTH_LINK_TYPE_WIFI:
            return (memcpy_s(udidBuf, bufLen, info->connInfo.info.ipInfo.deviceIdHash, UDID_SHORT_HASH_HEX_STR) == EOK);
        case AUTH_LINK_TYPE_BLE:
            return (ConvertBytesToHexString(udidBuf, bufLen, info->connInfo.info.bleInfo.deviceIdHash,
                UDID_SHORT_HASH_LEN_TEMP) == SOFTBUS_OK);
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            if (!info->isServer) {
                AUTH_LOGD(AUTH_FSM, "client(enhance p2p), use conninfo udid");
                return GenerateUdidShortHash(info->connInfo.info.ipInfo.udid, udidBuf, bufLen);
            }
            return false;
        case AUTH_LINK_TYPE_SESSION:
            AUTH_LOGD(AUTH_FSM, "client(session), use conninfo.sessionInfo udid");
            return GenerateUdidShortHash(info->connInfo.info.sessionInfo.udid, udidBuf, bufLen);
        default:
            AUTH_LOGE(AUTH_CONN, "unknown connType. type=%{public}d", info->connInfo.type);
    }
    return false;
}

static int32_t GetEnhancedP2pAuthKey(const char *udidHash, AuthSessionInfo *info, AuthDeviceKeyInfo *deviceKey)
{
    /* first, reuse ble authKey */
    if (AuthFindLatestNormalizeKey(udidHash, deviceKey, true) == SOFTBUS_OK ||
        AuthFindDeviceKey(udidHash, AUTH_LINK_TYPE_BLE, deviceKey) == SOFTBUS_OK) {
        AUTH_LOGD(AUTH_FSM, "get ble authKey succ");
        return SOFTBUS_OK;
    }
    /* second, reuse wifi authKey */
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    AuthGetLatestIdByUuid(info->uuid, AUTH_LINK_TYPE_WIFI, false, &authHandle);
    if (authHandle.authId == AUTH_INVALID_ID) {
        AUTH_LOGE(AUTH_FSM, "get wifi authKey fail");
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "get AuthManager fail");
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    int32_t index;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (GetLatestSessionKey(&auth->sessionKeyList, (AuthLinkType)authHandle.type, &index, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get key fail");
        DelDupAuthManager(auth);
        return SOFTBUS_AUTH_GET_SESSION_KEY_FAIL;
    }
    DelDupAuthManager(auth);
    if (memcpy_s(deviceKey->deviceKey, SESSION_KEY_LENGTH, sessionKey.value, sizeof(sessionKey.value)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    deviceKey->keyLen = sessionKey.len;
    /* wifi authKey not enable, associated with recoveryFastAuthKey */
    return SOFTBUS_AUTH_GET_SESSION_KEY_FAIL;
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
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    return SOFTBUS_OK;
}

static void PackFastAuth(JsonObj *obj, AuthSessionInfo *info)
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
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    if (!GetUdidOrShortHash(info, udidHashHexStr, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get udid fail, bypass fastAuth");
        info->isSupportFastAuth = false;
        return;
    }
    char *anonyUdidHash = NULL;
    Anonymize(udidHashHexStr, &anonyUdidHash);
    AUTH_LOGI(AUTH_FSM, "udidHashHexStr=%{public}s", AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyUdidHash);
    if (info->connInfo.type != AUTH_LINK_TYPE_ENHANCED_P2P &&
        !IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidHashHexStr, false, false)) {
        AUTH_LOGI(AUTH_FSM, "not potential trusted realtion, bypass fastAuthProc");
        info->isSupportFastAuth = false;
        return;
    }
    AuthDeviceKeyInfo deviceCommKey = { 0 };
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

static int32_t PackNormalizedKeyValue(JsonObj *obj, SessionKey *sessionKey)
{
    uint32_t dataLen = 0;
    uint8_t *data = NULL;
    AesGcmInputParam aesParam = { 0 };
    aesParam.data = (uint8_t *)TRUE_STRING_TAG;
    aesParam.dataLen = strlen(TRUE_STRING_TAG);
    aesParam.key = sessionKey->value;
    aesParam.keyLen = sessionKey->len;
    int32_t ret = LnnEncryptAesGcm(&aesParam, 0, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encrypt aes gcm fail=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (data == NULL || dataLen == 0) {
        AUTH_LOGE(AUTH_FSM, "encrypt data invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char encNormalizedKey[ENCRYPTED_NORMALIZED_KEY_MAX_LEN] = { 0 };
    if (ConvertBytesToUpperCaseHexString(encNormalizedKey, ENCRYPTED_NORMALIZED_KEY_MAX_LEN - 1, data, dataLen) !=
        SOFTBUS_OK) {
        SoftBusFree(data);
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    (void)JSON_AddStringToObject(obj, NORMALIZED_DATA, encNormalizedKey);
    AUTH_LOGI(AUTH_FSM, "pack normalize value succ");
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static void PackNormalizedKey(JsonObj *obj, AuthSessionInfo *info)
{
    if (!info->isNeedFastAuth && !info->isServer) {
        AUTH_LOGE(AUTH_FSM, "force auth.");
        return;
    }
    if (info->isServer && info->normalizedType == NORMALIZED_KEY_ERROR) {
        AUTH_LOGE(AUTH_FSM, "peer not support normalize or key error.");
        return;
    }
    if (info->localState != AUTH_STATE_START && info->localState != AUTH_STATE_ACK &&
        info->localState != AUTH_STATE_COMPATIBLE) {
        AUTH_LOGI(AUTH_FSM, "nego state, not send normalize data.");
        return;
    }
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    if (!GetUdidShortHash(info, udidHashHexStr, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get udid fail, bypass normalizedAuth");
        return;
    }
    if (info->normalizedKey != NULL) {
        if (PackNormalizedKeyValue(obj, info->normalizedKey) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "pack normalized key fail");
        }
        return;
    }
    info->normalizedKey = (SessionKey *)SoftBusCalloc(sizeof(SessionKey));
    if (info->normalizedKey == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc fail");
        return;
    }
    AuthDeviceKeyInfo deviceKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    if (AuthFindLatestNormalizeKey((char *)udidHashHexStr, &deviceKey, true) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "can't find device key");
        return;
    }
    info->normalizedIndex = deviceKey.keyIndex;
    info->normalizedKey->len = deviceKey.keyLen;
    if (memcpy_s(info->normalizedKey->value, sizeof(info->normalizedKey->value), deviceKey.deviceKey,
        sizeof(deviceKey.deviceKey)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        return;
    }
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    if (PackNormalizedKeyValue(obj, info->normalizedKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "pack normalized key fail");
        return;
    }
}

static void ParseFastAuthValue(AuthSessionInfo *info, const char *encryptedFastAuth, AuthDeviceKeyInfo *deviceKey)
{
    uint8_t fastAuthBytes[ENCRYPTED_FAST_AUTH_MAX_LEN] = { 0 };
    if (ConvertHexStringToBytes(
        fastAuthBytes, ENCRYPTED_FAST_AUTH_MAX_LEN, encryptedFastAuth, strlen(encryptedFastAuth)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "fastAuth data String to bytes fail");
        return;
    }
    uint32_t bytesLen = strlen(encryptedFastAuth) >> 1;
    uint32_t dataLen = 0;
    uint8_t *data = NULL;
    AesGcmInputParam aesParam = { 0 };
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

static int32_t ParseNormalizedKeyValue(AuthSessionInfo *info, const char *encNormalizedKey, SessionKey *sessionKey)
{
    uint8_t normalizedKeyBytes[ENCRYPTED_NORMALIZED_KEY_MAX_LEN] = { 0 };
    if (ConvertHexStringToBytes(normalizedKeyBytes, ENCRYPTED_NORMALIZED_KEY_MAX_LEN, encNormalizedKey,
        strlen(encNormalizedKey)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "normalizedType String to bytes fail");
        return SOFTBUS_AUTH_HEX_STR_TO_BYTES_FAIL;
    }
    uint32_t bytesLen = strlen(encNormalizedKey) >> 1;
    uint32_t dataLen = 0;
    uint8_t *data = NULL;
    AesGcmInputParam aesParam = { 0 };
    aesParam.data = normalizedKeyBytes;
    aesParam.dataLen = bytesLen;
    aesParam.key = sessionKey->value;
    aesParam.keyLen = sessionKey->len;
    int32_t ret = LnnDecryptAesGcm(&aesParam, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "LnnDecryptAesGcm fail=%{public}d, key error", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    if (data == NULL || dataLen == 0) {
        AUTH_LOGE(AUTH_FSM, "decrypt data invalid");
        return SOFTBUS_DECRYPT_ERR;
    }
    if (strncmp((char *)data, TRUE_STRING_TAG, strlen(TRUE_STRING_TAG)) != 0) {
        AUTH_LOGE(AUTH_FSM, "normalized key error");
        SoftBusFree(data);
        return SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR;
    }
    AUTH_LOGI(AUTH_FSM, "parse normalized key succ");
    SoftBusFree(data);
    info->normalizedType = NORMALIZED_SUPPORT;
    return SOFTBUS_OK;
}

static int32_t ParseNormalizeData(AuthSessionInfo *info, char *encNormalizedKey, AuthDeviceKeyInfo *deviceKey)
{
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    char hashHexStr[UDID_SHORT_HASH_HEX_STR + 1] = { 0 };
    if (ConvertBytesToUpperCaseHexString(hashHexStr, UDID_SHORT_HASH_HEX_STR + 1, udidHash, UDID_SHORT_HASH_LEN_TEMP) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "udid hash bytes to hexString fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    // First: use latest normalizedKey
    if (AuthFindLatestNormalizeKey(hashHexStr, deviceKey, true) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "can't find common key, parse normalize data fail");
        return SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR;
    }
    sessionKey.len = deviceKey->keyLen;
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), deviceKey->deviceKey, sizeof(deviceKey->deviceKey)) !=
        EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ParseNormalizedKeyValue(info, encNormalizedKey, &sessionKey) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    // Second: decrypt fail, use another side normalizedKey
    AUTH_LOGI(AUTH_FSM, "find another key");
    if (AuthFindNormalizeKeyByServerSide(hashHexStr, !deviceKey->isServerSide, deviceKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "can't find another key, parse normalize data fail");
        return SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR;
    }
    sessionKey.len = deviceKey->keyLen;
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), deviceKey->deviceKey, sizeof(deviceKey->deviceKey)) !=
        EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ParseNormalizedKeyValue(info, encNormalizedKey, &sessionKey) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR;
    }
    (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    AuthUpdateCreateTime(hashHexStr, AUTH_LINK_TYPE_NORMALIZED, deviceKey->isServerSide);
    return SOFTBUS_OK;
}

static void UnpackNormalizedKey(JsonObj *obj, AuthSessionInfo *info, bool isSupportNormalizedKey)
{
    if (isSupportNormalizedKey == NORMALIZED_NOT_SUPPORT) {
        AUTH_LOGI(AUTH_FSM, "peer old version or not support normalizedType");
        info->normalizedType = NORMALIZED_NOT_SUPPORT;
        return;
    }
    info->normalizedType = NORMALIZED_KEY_ERROR;
    char encNormalizedKey[ENCRYPTED_NORMALIZED_KEY_MAX_LEN] = { 0 };
    if (!JSON_GetStringFromOject(obj, NORMALIZED_DATA, encNormalizedKey, ENCRYPTED_NORMALIZED_KEY_MAX_LEN)) {
        AUTH_LOGI(AUTH_FSM, "peer not send normalizedKey");
        return;
    }
    if (!info->isServer && info->normalizedKey != NULL) {
        AUTH_LOGI(AUTH_FSM, "client already exit normalizedKey");
        (void)ParseNormalizedKeyValue(info, encNormalizedKey, info->normalizedKey);
        info->normalizedType = NORMALIZED_SUPPORT;
        return;
    }
    info->normalizedKey = (SessionKey *)SoftBusCalloc(sizeof(SessionKey));
    if (info->normalizedKey == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc fail");
        return;
    }
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return;
    }
    char hashHexStr[UDID_SHORT_HASH_HEX_STR + 1] = { 0 };
    if (ConvertBytesToUpperCaseHexString(hashHexStr, UDID_SHORT_HASH_HEX_STR + 1, udidHash, UDID_SHORT_HASH_LEN_TEMP) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "udid hash bytes to hexString fail");
        return;
    }
    AuthDeviceKeyInfo deviceKey = { 0 };
    if (ParseNormalizeData(info, encNormalizedKey, &deviceKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "normalize decrypt fail.");
        return;
    }
    info->normalizedIndex = deviceKey.keyIndex;
    info->normalizedType = NORMALIZED_SUPPORT;
    info->normalizedKey->len = deviceKey.keyLen;
    if (memcpy_s(info->normalizedKey->value, sizeof(info->normalizedKey->value), deviceKey.deviceKey,
        sizeof(deviceKey.deviceKey)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        return;
    }
    (void)memset_s(&deviceKey, sizeof(deviceKey), 0, sizeof(deviceKey));
}

static void UnpackFastAuth(JsonObj *obj, AuthSessionInfo *info)
{
    info->isSupportFastAuth = false;
    char encryptedFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = { 0 };
    if (!JSON_GetStringFromOject(obj, FAST_AUTH, encryptedFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN)) {
        AUTH_LOGI(AUTH_FSM, "old version or not support fastAuth");
        return;
    }
    AUTH_LOGE(AUTH_FSM, "unpack fastAuthTag=%{public}s", encryptedFastAuth);
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return;
    }
    char udidShortHash[UDID_SHORT_HASH_HEX_STR + 1] = { 0 };
    if (ConvertBytesToHexString(udidShortHash, UDID_SHORT_HASH_HEX_STR + 1, udidHash, UDID_SHORT_HASH_LEN_TEMP) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "udid hash bytes to hexString fail");
        return;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_ENHANCED_P2P &&
        !IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidShortHash, false, false)) {
        AUTH_LOGI(AUTH_FSM, "not potential trusted realtion, fastAuth not support");
        return;
    }
    AuthDeviceKeyInfo deviceKey = { 0 };
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
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    char localIp[MAX_ADDR_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local ip fail");
        return;
    }
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)localIp, strlen(localIp), hash);
    if (ret != SOFTBUS_OK) {
        return;
    }
    char devIpHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (ConvertBytesToUpperCaseHexString(devIpHash, SHA_256_HEX_HASH_LEN, hash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
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
        AUTH_LOGI(AUTH_FSM, "exchangeIdType=%{public}d, networkid=%{public}s", info->idType,
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
    } else {
        if (!JSON_AddStringToObject(obj, DEVICE_ID_TAG, udid)) {
            AUTH_LOGE(AUTH_FSM, "add msg body fail");
            return false;
        }
        char *anonyUdid = NULL;
        Anonymize(udid, &anonyUdid);
        AUTH_LOGI(AUTH_FSM, "exchangeIdType=%{public}d, udid=%{public}s", info->idType, AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
    }

    AUTH_LOGI(AUTH_FSM, "session info verify succ.");
    return true;
}

static void PackUDIDAbatementFlag(JsonObj *obj, const AuthSessionInfo *info)
{
    if (IsSupportUDIDAbatement() && !JSON_AddBoolToObject(obj, IS_NEED_PACK_CERT, IsNeedUDIDAbatement(info))) {
        AUTH_LOGE(AUTH_FSM, "add pack cert flag fail.");
    }
}

static int32_t PackDeviceJsonInfo(const AuthSessionInfo *info, JsonObj *obj)
{
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && !info->isConnectServer) {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_GET_AUTH_INFO)) {
            AUTH_LOGE(AUTH_FSM, "add CMD_GET fail");
            return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
        }
    } else {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_RET_AUTH_INFO)) {
            AUTH_LOGE(AUTH_FSM, "add CMD_RET fail");
            return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
        }
    }
    if (!JSON_AddInt32ToObject(obj, AUTH_START_STATE, info->localState)) {
        AUTH_LOGE(AUTH_FSM, "add local auth state fail.");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t PackNormalizedData(const AuthSessionInfo *info, JsonObj *obj, const NodeInfo *nodeInfo)
{
    bool isSupportNormalizedKey = IsSupportFeatureByCapaBit(nodeInfo->authCapacity, BIT_SUPPORT_NORMALIZED_LINK);
    if (!JSON_AddBoolToObject(obj, IS_NORMALIZED, isSupportNormalizedKey)) {
        AUTH_LOGE(AUTH_FSM, "add normalizedType fail");
        return SOFTBUS_AUTH_PACK_NORMALIZED_DATA_FAIL;
    }
    if (isSupportNormalizedKey) {
        PackNormalizedKey(obj, (AuthSessionInfo *)info);
    }
    if (info->isServer && info->connInfo.type == AUTH_LINK_TYPE_WIFI) {
        GenerateUdidShortHash(info->udid, (char *)info->connInfo.info.ipInfo.deviceIdHash, UDID_HASH_LEN);
    }
    return SOFTBUS_OK;
}

static void PackUserId(JsonObj *json, int32_t userId)
{
    if (!JSON_AddInt32ToObject(json, USERID, userId)) {
        AUTH_LOGW(AUTH_FSM, "pack userId fail");
    }
}

char *PackDeviceIdJson(const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, NULL, AUTH_FSM, "info is NULL");
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", info->connInfo.type);
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }
    char uuid[UUID_BUF_LEN] = { 0 };
    char udid[UDID_BUF_LEN] = { 0 };
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get uuid/udid/networkId fail");
        JSON_Delete(obj);
        return NULL;
    }
    PackWifiSinglePassInfo(obj, info);
    if (PackDeviceJsonInfo(info, obj) != SOFTBUS_OK || !VerifySessionInfoIdType(info, obj, networkId, udid)) {
        JSON_Delete(obj);
        return NULL;
    }
    if (!JSON_AddStringToObject(obj, DATA_TAG, uuid) || !JSON_AddInt32ToObject(obj, DATA_BUF_SIZE_TAG, PACKET_SIZE) ||
        !JSON_AddInt32ToObject(obj, SOFTBUS_VERSION_TAG, info->version) ||
        !JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, info->idType) ||
        !JSON_AddInt32ToObject(obj, AUTH_MODULE, info->module)) {
        AUTH_LOGE(AUTH_FSM, "add msg body fail");
        JSON_Delete(obj);
        return NULL;
    }
    const NodeInfo *nodeInfo = LnnGetLocalNodeInfo();
    if (nodeInfo == NULL) {
        AUTH_LOGE(AUTH_FSM, "nodeInfo is null!");
        JSON_Delete(obj);
        return NULL;
    }
    PackCompressInfo(obj, nodeInfo);
    PackFastAuth(obj, (AuthSessionInfo *)info);
    PackUserId(obj, nodeInfo->userId);
    if (PackNormalizedData(info, obj, nodeInfo) != SOFTBUS_OK) {
        JSON_Delete(obj);
        return NULL;
    }
    PackUDIDAbatementFlag(obj, info);
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
    char devIpHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (!JSON_GetStringFromOject(obj, DEV_IP_HASH_TAG, devIpHash, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGD(AUTH_FSM, "devIpHash hash not found, ignore");
        return true;
    }
    // check devIpHash
    int32_t socketFd = GetFd(info->connId);
    SoftBusSockAddrIn addr = { 0 };
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
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
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

static int32_t VerifyExchangeIdTypeAndInfo(AuthSessionInfo *info, int32_t idType, char *anonyUdid)
{
    char peerUdid[UDID_BUF_LEN] = { 0 };
    bool isExchangeUdid = true;
    if (idType == EXCHANGE_NETWORKID) {
        if (GetPeerUdidByNetworkId(info->udid, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get peer udid fail, peer networkId=%{public}s", anonyUdid);
            info->idType = EXCHANGE_FAIL;
            (void)memset_s(info->udid, sizeof(info->udid), 0, sizeof(info->udid));
        } else {
            if (GetIsExchangeUdidByNetworkId(info->udid, &isExchangeUdid) == SOFTBUS_OK && isExchangeUdid) {
                AUTH_LOGE(AUTH_FSM, "need exchange udid, peer udid=%{public}s", anonyUdid);
                info->idType = EXCHANGE_UDID;
            } else {
                AUTH_LOGE(AUTH_FSM, "get peer udid success, peer udid=%{public}s", anonyUdid);
                info->idType = EXCHANGE_NETWORKID;
            }
            if (memcpy_s(info->udid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
                AUTH_LOGE(AUTH_FSM, "copy peer udid fail");
                info->idType = EXCHANGE_FAIL;
                return SOFTBUS_MEM_ERR;
            }
        }
    }
    AUTH_LOGI(AUTH_FSM, "idType verify and get info succ.");
    return SOFTBUS_OK;
}

static int32_t SetExchangeIdTypeAndValue(JsonObj *obj, AuthSessionInfo *info)
{
    if (obj == NULL || info == NULL) {
        AUTH_LOGE(AUTH_FSM, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t idType = -1;
    if (!JSON_GetInt32FromOject(obj, EXCHANGE_ID_TYPE, &idType)) {
        AUTH_LOGI(AUTH_FSM, "parse idType failed, ignore");
        info->idType = EXCHANGE_UDID;
        return SOFTBUS_OK;
    }
    char *anonyUdid = NULL;
    Anonymize(info->udid, &anonyUdid);
    AUTH_LOGI(AUTH_FSM, "oldIdType=%{public}d, exchangeIdType=%{public}d, deviceId=%{public}s", info->idType, idType,
        AnonymizeWrapper(anonyUdid));
    if (idType == EXCHANGE_UDID) {
        info->idType = EXCHANGE_UDID;
        AnonymizeFree(anonyUdid);
        return SOFTBUS_OK;
    }
    if (info->isServer) {
        if (VerifyExchangeIdTypeAndInfo(info, idType, anonyUdid) != SOFTBUS_OK) {
            AnonymizeFree(anonyUdid);
            return SOFTBUS_AUTH_SET_EXCHANGE_INFO_FAIL;
        }
        AUTH_LOGI(AUTH_FSM, "isServer is true in authSessionInfo.");
        AnonymizeFree(anonyUdid);
        return SOFTBUS_OK;
    }
    if (info->idType == EXCHANGE_NETWORKID) {
        if (idType == EXCHANGE_FAIL) {
            info->idType = EXCHANGE_FAIL;
        }
        if (VerifyExchangeIdTypeAndInfo(info, idType, anonyUdid) != SOFTBUS_OK) {
            AnonymizeFree(anonyUdid);
            return SOFTBUS_AUTH_SET_EXCHANGE_INFO_FAIL;
        }
    }
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

static void UnPackVersionByDeviceId(JsonObj *obj, AuthSessionInfo *info)
{
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
        AUTH_LOGE(AUTH_FSM, "softbusVersion is not found");
    }
    OptInt(obj, AUTH_START_STATE, (int32_t *)&info->peerState, AUTH_STATE_COMPATIBLE);
}

static int32_t IsCmdMatchByDeviceId(JsonObj *obj, AuthSessionInfo *info)
{
    char cmd[CMD_TAG_LEN] = { 0 };
    if (!JSON_GetStringFromOject(obj, CMD_TAG, cmd, CMD_TAG_LEN)) {
        AUTH_LOGE(AUTH_FSM, "CMD_TAG not found");
        return SOFTBUS_NOT_FIND;
    }
    if (!UnpackWifiSinglePassInfo(obj, info)) {
        AUTH_LOGE(AUTH_FSM, "check ip fail, can't support auth");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && info->isConnectServer) {
        if (strncmp(cmd, CMD_GET_AUTH_INFO, strlen(CMD_GET_AUTH_INFO)) != 0) {
            AUTH_LOGE(AUTH_FSM, "CMD_GET not match");
            return SOFTBUS_CMP_FAIL;
        }
    } else {
        if (strncmp(cmd, CMD_RET_AUTH_INFO, strlen(CMD_RET_AUTH_INFO)) != 0) {
            AUTH_LOGE(AUTH_FSM, "CMD_RET not match");
            return SOFTBUS_CMP_FAIL;
        }
    }
    return SOFTBUS_OK;
}

int32_t UnpackDeviceIdJson(const char *msg, uint32_t len, AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(msg != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "msg is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    JsonObj *obj = JSON_Parse(msg, len);
    if (obj == NULL) {
        AUTH_LOGE(AUTH_FSM, "json parse fail");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = IsCmdMatchByDeviceId(obj, info);
    if (ret != SOFTBUS_OK) {
        JSON_Delete(obj);
        return ret;
    }
    if (!JSON_GetStringFromOject(obj, DATA_TAG, info->uuid, UUID_BUF_LEN)) {
        AUTH_LOGE(AUTH_FSM, "uuid not found");
        JSON_Delete(obj);
        return SOFTBUS_AUTH_UNPACK_DEV_ID_FAIL;
    }
    UnPackVersionByDeviceId(obj, info);
    if (SetExchangeIdTypeAndValue(obj, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "set exchange id type or value fail");
        JSON_Delete(obj);
        return SOFTBUS_AUTH_SET_EXCHANGE_INFO_FAIL;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        char compressParse[PARSE_UNCOMPRESS_STRING_BUFF_LEN] = { 0 };
        OptString(obj, SUPPORT_INFO_COMPRESS, compressParse, PARSE_UNCOMPRESS_STRING_BUFF_LEN, FALSE_STRING_TAG);
        SetCompressFlag(compressParse, &info->isSupportCompress);
    }
    OptInt(obj, AUTH_MODULE, (int32_t *)&info->module, AUTH_MODULE_LNN);
    bool isSupportNormalizedKey = false;
    OptBool(obj, IS_NORMALIZED, &isSupportNormalizedKey, false);
    UnpackFastAuth(obj, info);
    UnpackNormalizedKey(obj, info, isSupportNormalizedKey);
    OptBool(obj, IS_NEED_PACK_CERT, &info->isNeedPackCert, false);
    OptInt(obj, USERID, &info->userId, 0);
    JSON_Delete(obj);
    return SOFTBUS_OK;
}

static void GetAndSetLocalUnifiedName(JsonObj *json)
{
    char unified[DEVICE_NAME_BUF_LEN] = { 0 };
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
    char localDevName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    if (ret == SOFTBUS_OK) {
        (void)JSON_AddStringToObject(json, DEVICE_NAME, localDevName);
    } else {
        (void)JSON_AddStringToObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo));
    }

    if (strlen(info->deviceInfo.unifiedName) == 0) {
        GetAndSetLocalUnifiedName(json);
    } else {
        (void)JSON_AddStringToObject(json, UNIFIED_DEVICE_NAME, info->deviceInfo.unifiedName);
    }
    (void)JSON_AddStringToObject(json, UNIFIED_DEFAULT_DEVICE_NAME, info->deviceInfo.unifiedDefaultName);
    (void)JSON_AddStringToObject(json, SETTINGS_NICK_NAME, info->deviceInfo.nickName);
    if (!JSON_AddStringToObject(json, NETWORK_ID, info->networkId) ||
        !JSON_AddStringToObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !JSON_AddStringToObject(json, DEVICE_UDID, LnnGetDeviceUdid(info))) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    if (isMetaAuth && !JSON_AddStringToObject(json, DEVICE_UUID, info->uuid)) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    return SOFTBUS_OK;
}

static void PackCommonFastAuth(JsonObj *json, const NodeInfo *info)
{
    (void)JSON_AddInt32ToObject(json, STATE_VERSION, info->stateVersion);
    char extData[EXTDATA_LEN] = { 0 };
    int32_t ret = GetExtData(extData, EXTDATA_LEN);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetExtData fail");
    } else {
        AUTH_LOGI(AUTH_FSM, "GetExtData=%{public}s", extData);
        (void)JSON_AddStringToObject(json, EXTDATA, extData);
    }
}

static void PackOsInfo(JsonObj *json, const NodeInfo *info)
{
    (void)JSON_AddInt32ToObject(json, OS_TYPE, info->deviceInfo.osType);
    (void)JSON_AddStringToObject(json, OS_VERSION, info->deviceInfo.osVersion);
}

static void PackDeviceVersion(JsonObj *json, const NodeInfo *info)
{
    (void)JSON_AddStringToObject(json, DEVICE_VERSION, info->deviceInfo.deviceVersion);
    (void)JSON_AddInt32ToObject(json, STATE_VERSION_CHANGE_REASON, info->stateVersionReason);
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

static void AuthPrintBase64Ptk(const char *ptk)
{
    char *anonyPtk = NULL;
    Anonymize(ptk, &anonyPtk);
    AUTH_LOGD(AUTH_FSM, "base Ptk=%{public}s", AnonymizeWrapper(anonyPtk));
    AnonymizeFree(anonyPtk);
}

static void PackWifiDirectInfo(
    const AuthConnInfo *connInfo, JsonObj *json, const NodeInfo *info, const char *remoteUuid, bool isMetaAuth)
{
    unsigned char encodePtk[PTK_ENCODE_LEN] = { 0 };
    char localPtk[PTK_DEFAULT_LEN] = { 0 };
    if (isMetaAuth || remoteUuid == NULL) {
        uint32_t connId;
        AuthMetaGetConnIdByInfo(connInfo, &connId);
        if (LnnGetMetaPtk(connId, localPtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get meta ptk fail");
            return;
        }
    } else {
        if (LnnGetLocalPtkByUuid(remoteUuid, localPtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get ptk by uuid fail");
            return;
        }
    }
    LnnDumpRemotePtk(NULL, localPtk, "pack wifi direct info");
    size_t keyLen = 0;
    if (SoftBusBase64Encode(encodePtk, PTK_ENCODE_LEN, &keyLen, (unsigned char *)localPtk, PTK_DEFAULT_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encode ptk fail");
        (void)memset_s(localPtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
        return;
    }
    (void)memset_s(localPtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
    AuthPrintBase64Ptk((const char *)encodePtk);
    if (!JSON_AddStringToObject(json, PTK, (char *)encodePtk)) {
        AUTH_LOGE(AUTH_FSM, "add ptk string to json fail");
        (void)memset_s(encodePtk, PTK_ENCODE_LEN, 0, PTK_ENCODE_LEN);
        return;
    }
    (void)memset_s(encodePtk, PTK_ENCODE_LEN, 0, PTK_ENCODE_LEN);
    if (!JSON_AddInt32ToObject(json, STATIC_CAP_LENGTH, info->staticCapLen)) {
        AUTH_LOGE(AUTH_FSM, "add static cap len fail");
        return;
    }
    char staticCap[STATIC_CAP_STR_LEN] = { 0 };
    if (ConvertBytesToHexString((char *)staticCap, STATIC_CAP_STR_LEN, info->staticCapability, info->staticCapLen) !=
        SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "convert static cap fail");
        return;
    }
    if (!JSON_AddStringToObject(json, STATIC_CAP, (char *)staticCap)) {
        AUTH_LOGW(AUTH_FSM, "add static capability fail");
        return;
    }
}

static int32_t FillBroadcastCipherKey(BroadcastCipherKey *broadcastKey, const NodeInfo *info)
{
    if (memcpy_s(broadcastKey->udid, UDID_BUF_LEN, info->deviceInfo.deviceUdid, UDID_BUF_LEN) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy udid fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(broadcastKey->cipherInfo.key, SESSION_KEY_LENGTH, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy key fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(broadcastKey->cipherInfo.iv, BROADCAST_IV_LEN, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memcpy iv fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void DumpRpaCipherKey(char *cipherKey, char *cipherIv, const char *peerIrk, const char *log)
{
    char *anonyIrk = NULL;
    char *anonyCipherKey = NULL;
    char *anonyCipherIv = NULL;
    Anonymize(cipherKey, &anonyCipherKey);
    Anonymize(cipherIv, &anonyCipherIv);
    Anonymize(peerIrk, &anonyIrk);
    AUTH_LOGI(AUTH_FSM, "log=%{public}s, cipherKey=%{public}s, cipherIv=%{public}s, peerIrk=%{public}s", log,
        AnonymizeWrapper(anonyCipherKey), AnonymizeWrapper(anonyCipherIv), AnonymizeWrapper(anonyIrk));
    AnonymizeFree(anonyCipherKey);
    AnonymizeFree(anonyCipherIv);
    AnonymizeFree(anonyIrk);
}

static int32_t UpdateBroadcastCipherKey(const NodeInfo *info)
{
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    if (FillBroadcastCipherKey(&broadcastKey, info) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        return SOFTBUS_AUTH_CIPHER_KEY_PROC_ERR;
    }
    if (LnnUpdateLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "update local broadcast key failed");
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        return SOFTBUS_AUTH_CIPHER_KEY_PROC_ERR;
    }
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    return SOFTBUS_OK;
}

static int32_t PackCipherRpaInfo(JsonObj *json, const NodeInfo *info)
{
    char cipherKey[SESSION_KEY_STR_LEN] = { 0 };
    char cipherIv[BROADCAST_IV_STR_LEN] = { 0 };
    char peerIrk[LFINDER_IRK_STR_LEN] = { 0 };
    char pubMac[LFINDER_MAC_ADDR_STR_LEN] = { 0 };

    if (ConvertBytesToHexString(cipherKey, SESSION_KEY_STR_LEN, info->cipherInfo.key, SESSION_KEY_LENGTH) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher key to string fail.");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (ConvertBytesToHexString(cipherIv, BROADCAST_IV_STR_LEN, info->cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert cipher iv to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (ConvertBytesToHexString(peerIrk, LFINDER_IRK_STR_LEN, info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert peerIrk to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (ConvertBytesToHexString(pubMac, LFINDER_MAC_ADDR_STR_LEN, info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert publicAddress to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
        (void)memset_s(peerIrk, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_KEY, cipherKey);
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_IV, cipherIv);
    (void)JSON_AddStringToObject(json, IRK, peerIrk);
    (void)JSON_AddStringToObject(json, PUB_MAC, pubMac);
    DumpRpaCipherKey(cipherKey, cipherIv, peerIrk, "pack broadcast cipher key");
    (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
    (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
    (void)memset_s(peerIrk, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
    int32_t ret = UpdateBroadcastCipherKey(info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

static void UnpackCipherRpaInfo(const JsonObj *json, NodeInfo *info)
{
    char cipherKey[SESSION_KEY_STR_LEN] = { 0 };
    char cipherIv[BROADCAST_IV_STR_LEN] = { 0 };
    char peerIrk[LFINDER_IRK_STR_LEN] = { 0 };
    char pubMac[LFINDER_MAC_ADDR_STR_LEN] = { 0 };

    do {
        if (!JSON_GetStringFromOject(json, BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_STR_LEN) ||
            !JSON_GetStringFromOject(json, BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_STR_LEN) ||
            !JSON_GetStringFromOject(json, IRK, peerIrk, LFINDER_IRK_STR_LEN) ||
            !JSON_GetStringFromOject(json, PUB_MAC, pubMac, LFINDER_MAC_ADDR_STR_LEN)) {
            AUTH_LOGE(AUTH_FSM, "get json info fail.");
            break;
        }
        if (ConvertHexStringToBytes((unsigned char *)info->cipherInfo.key, SESSION_KEY_LENGTH, cipherKey,
            strlen(cipherKey)) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert cipher key to bytes fail.");
            break;
        }
        if (ConvertHexStringToBytes(
            (unsigned char *)info->cipherInfo.iv, BROADCAST_IV_LEN, cipherIv, strlen(cipherIv)) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert cipher iv to bytes fail.");
            break;
        }
        if (ConvertHexStringToBytes(
            (unsigned char *)info->rpaInfo.peerIrk, LFINDER_IRK_LEN, peerIrk, strlen(peerIrk)) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert peerIrk to bytes fail.");
            break;
        }
        if (ConvertHexStringToBytes((unsigned char *)info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, pubMac,
            strlen(pubMac)) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert publicAddress to bytes fail.");
            break;
        }
        DumpRpaCipherKey(cipherKey, cipherIv, peerIrk, "unpack broadcast cipher key");
    } while (0);
    (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
    (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
    (void)memset_s(peerIrk, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
}

static int32_t PackCommonEx(JsonObj *json, const NodeInfo *info)
{
    bool isFalse = (!JSON_AddStringToObject(json, VERSION_TYPE, info->versionType) ||
        !JSON_AddInt32ToObject(json, CONN_CAP, info->netCapacity) ||
        !JSON_AddInt32ToObject(json, AUTH_CAP, info->authCapacity) ||
        !JSON_AddInt32ToObject(json, HB_CAP, info->heartbeatCapacity) ||
        !JSON_AddInt16ToObject(json, DATA_CHANGE_FLAG, info->dataChangeFlag) ||
        !JSON_AddBoolToObject(json, IS_CHARGING, info->batteryInfo.isCharging) ||
        !JSON_AddBoolToObject(json, BLE_P2P, info->isBleP2p) ||
        !JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, (int64_t)LnnGetSupportedProtocols(info)) ||
        !JSON_AddBoolToObject(json, IS_SUPPORT_IPV6, true));
    if (isFalse) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject failed.");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }

    char btMacUpper[BT_MAC_LEN] = { 0 };
    if (StringToUpperCase(LnnGetBtMac(info), btMacUpper, BT_MAC_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "btMac to upperCase failed.");
        if (memcpy_s(btMacUpper, BT_MAC_LEN, LnnGetBtMac(info), BT_MAC_LEN) != EOK) {
            AUTH_LOGE(AUTH_FSM, "btMac cpy failed.");
            return SOFTBUS_MEM_ERR;
        }
    }
    isFalse = (!JSON_AddStringToObject(json, PKG_VERSION, info->pkgVersion) ||
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
        !JSON_AddInt64ToObject(json, NEW_CONN_CAP, info->netCapacity));
    if (isFalse) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject failed.");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    AUTH_LOGI(AUTH_FSM, "pack common succ.");
    return SOFTBUS_OK;
}

static int32_t PackCommon(JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!JSON_AddStringToObject(json, MASTER_UDID, info->masterUdid) ||
            !JSON_AddInt32ToObject(json, MASTER_WEIGHT, info->masterWeight)) {
            AUTH_LOGE(AUTH_FSM, "add master node info fail");
            return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
        }
        if (!JSON_AddStringToObject(json, NODE_ADDR, info->nodeAddress)) {
            AUTH_LOGE(AUTH_FSM, "pack node address Fail");
            return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
        }
    }
    if (!JSON_AddStringToObject(json, SW_VERSION, info->softBusVersion)) {
        AUTH_LOGE(AUTH_FSM, "add version info fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    if (PackCommonDevInfo(json, info, isMetaAuth) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    if (PackCommonEx(json, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "data pack failed.");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    PackOsInfo(json, info);
    PackDeviceVersion(json, info);
    PackCommonFastAuth(json, info);
    if (!PackCipherKeySyncMsg(json)) {
        AUTH_LOGE(AUTH_FSM, "PackCipherKeySyncMsg failed.");
    }
    PackCommP2pInfo(json, info);

    if (PackCipherRpaInfo(json, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "pack CipherRpaInfo of device key failed.");
    }

    if (!JSON_AddInt32ToObject(json, DEVICE_SECURITY_LEVEL, info->deviceSecurityLevel)) {
        AUTH_LOGE(AUTH_FSM, "pack deviceSecurityLevel fail.");
    }
    return SOFTBUS_OK;
}

static void UnpackMetaPtk(char *remoteMetaPtk, char *decodePtk)
{
    size_t len = 0;
    if (SoftBusBase64Decode((unsigned char *)remoteMetaPtk, PTK_DEFAULT_LEN, &len, (const unsigned char *)decodePtk,
        strlen((char *)decodePtk)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decode remote meta ptk fail");
        return;
    }
    LnnDumpRemotePtk(NULL, remoteMetaPtk, "unpack meta wifi direct info");
    if (len != PTK_DEFAULT_LEN) {
        AUTH_LOGE(AUTH_FSM, "decode data len error");
        return;
    }
    return;
}

static void UnpackPtk(char *remotePtk, char *decodePtk)
{
    size_t len = 0;
    if (SoftBusBase64Decode((unsigned char *)remotePtk, PTK_DEFAULT_LEN, &len, (const unsigned char *)decodePtk,
        strlen((char *)decodePtk)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decode remote ptk fail");
        return;
    }
    LnnDumpRemotePtk(NULL, remotePtk, "unpack wifi direct info");
    if (len != PTK_DEFAULT_LEN) {
        AUTH_LOGE(AUTH_FSM, "decode data len error");
        return;
    }
    return;
}

static void UnpackWifiDirectInfo(const JsonObj *json, NodeInfo *info, bool isMetaAuth)
{
    char staticCap[STATIC_CAP_STR_LEN] = { 0 };
    if (!JSON_GetInt32FromOject(json, STATIC_CAP_LENGTH, &info->staticCapLen)) {
        AUTH_LOGE(AUTH_FSM, "get static cap len fail");
        return;
    }
    if (!JSON_GetStringFromOject(json, STATIC_CAP, staticCap, STATIC_CAP_STR_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get static cap fail");
        return;
    }
    if (ConvertHexStringToBytes(
        (unsigned char *)info->staticCapability, STATIC_CAP_LEN, staticCap, strlen(staticCap)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert static cap fail");
        return;
    }
    char encodePtk[PTK_ENCODE_LEN] = { 0 };
    if (!JSON_GetStringFromOject(json, PTK, encodePtk, PTK_ENCODE_LEN)) {
        AUTH_LOGE(AUTH_FSM, "get encode ptk fail");
        return;
    }
    AuthPrintBase64Ptk((const char *)encodePtk);
    if (isMetaAuth) {
        UnpackMetaPtk(info->remoteMetaPtk, encodePtk);
    } else {
        UnpackPtk(info->remotePtk, encodePtk);
    }
    (void)memset_s(encodePtk, PTK_ENCODE_LEN, 0, PTK_ENCODE_LEN);
}

static void ParseCommonJsonInfo(const JsonObj *json, NodeInfo *info, bool isMetaAuth)
{
    (void)JSON_GetStringFromOject(json, SW_VERSION, info->softBusVersion, VERSION_MAX_LEN);
    OptString(json, PKG_VERSION, info->pkgVersion, VERSION_MAX_LEN, "");
    OptString(json, UNIFIED_DEVICE_NAME, info->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, "");
    OptString(json, UNIFIED_DEFAULT_DEVICE_NAME, info->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, "");
    OptString(json, SETTINGS_NICK_NAME, info->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, "");
    OptInt64(json, WIFI_VERSION, &info->wifiVersion, 0);
    OptInt64(json, BLE_VERSION, &info->bleVersion, 0);
    OptString(json, BT_MAC, info->connectInfo.macAddr, MAC_LEN, "");
    OptString(json, BLE_MAC, info->connectInfo.bleMacAddr, MAC_LEN, "");
    char deviceType[DEVICE_TYPE_BUF_LEN] = { 0 };
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
    (void)JSON_GetInt32FromOject(json, HB_CAP, (int32_t *)&info->heartbeatCapacity);
    info->isBleP2p = false;
    (void)JSON_GetBoolFromOject(json, BLE_P2P, &info->isBleP2p);
    (void)JSON_GetInt16FromOject(json, DATA_CHANGE_FLAG, (int16_t *)&info->dataChangeFlag);
    (void)JSON_GetBoolFromOject(json, IS_CHARGING, &info->batteryInfo.isCharging);
    (void)JSON_GetInt32FromOject(json, REMAIN_POWER, &info->batteryInfo.batteryLevel);
    (void)JSON_GetBoolFromOject(json, IS_SUPPORT_IPV6, &info->isSupportIpv6);
    OptBool(json, IS_SCREENON, &info->isScreenOn, false);
    OptInt64(json, ACCOUNT_ID, &info->accountId, 0);
    OptInt(json, NODE_WEIGHT, &info->masterWeight, DEFAULT_NODE_WEIGHT);
    OptInt(json, OS_TYPE, &info->deviceInfo.osType, -1);
    if ((info->deviceInfo.osType == -1) && info->authCapacity != 0) {
        info->deviceInfo.osType = OH_OS_TYPE;
        AUTH_LOGD(AUTH_FSM, "info->deviceInfo.osType: %{public}d", info->deviceInfo.osType);
    }
    OptString(json, OS_VERSION, info->deviceInfo.osVersion, OS_VERSION_BUF_LEN, "");
    OptString(json, DEVICE_VERSION, info->deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, "");
    // IS_SUPPORT_TCP_HEARTBEAT
    OptInt(json, NEW_CONN_CAP, (int32_t *)&info->netCapacity, -1);
    if (info->netCapacity == (uint32_t)-1) {
        (void)JSON_GetInt32FromOject(json, CONN_CAP, (int32_t *)&info->netCapacity);
    }
    OptInt(json, WIFI_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_WIFI_BUFF_SIZE);
    OptInt(json, BR_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_BR_BUFF_SIZE);
    OptInt64(json, FEATURE, (int64_t *)&info->feature, 0);
    OptInt64(json, CONN_SUB_FEATURE, (int64_t *)&info->connSubFeature, 0);
    OptInt(json, STATE_VERSION_CHANGE_REASON, (int32_t *)&info->stateVersionReason, 0);
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
    ParseCommonJsonInfo(json, info, isMetaAuth);
    // MetaNodeInfoOfEar
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
    OptInt(json, DEVICE_SECURITY_LEVEL, &info->deviceSecurityLevel, 0);
}

static int32_t GetBtDiscTypeString(const NodeInfo *info, char *buf, uint32_t len)
{
    uint32_t i = 0;
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)) {
        CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_INVALID_NUM);
        buf[i++] = DISCOVERY_TYPE_BLE + '0';
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        if (i != 0) {
            CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_INVALID_NUM);
            buf[i++] = ',';
        }
        CHECK_EXPRESSION_RETURN_VALUE((i >= len), SOFTBUS_INVALID_NUM);
        buf[i++] = DISCOVERY_TYPE_BR + '0';
    }
    return SOFTBUS_OK;
}

static void AddDiscoveryType(JsonObj *json, const char *remoteUuid)
{
    if (remoteUuid == NULL) {
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
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
    char discTypeStr[BT_DISC_TYPE_MAX_LEN] = { 0 };
    if (GetBtDiscTypeString(&nodeInfo, discTypeStr, BT_DISC_TYPE_MAX_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "disc Type calc fail");
        return;
    }
    AUTH_LOGD(AUTH_FSM, "discTypeStr=%{public}s", discTypeStr);
    JSON_AddStringToObject(json, DISCOVERY_TYPE, discTypeStr);
}

static int32_t PackBt(
    JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth, const char *remoteUuid)
{
    if (!JSON_AddInt32ToObject(json, CODE, CODE_VERIFY_BT)) {
        AUTH_LOGE(AUTH_FSM, "add bt info fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    AddDiscoveryType(json, remoteUuid);
    int32_t delayTime = BLE_CONNECTION_CLOSE_DELAY;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BLE_CLOSE_DELAY_TIME, (unsigned char *)(&delayTime), sizeof(delayTime)) !=
        SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "get ble conn close delay time from config file fail");
    }
    int32_t bleMacRefreshSwitch = BLE_MAC_AUTO_REFRESH_SWITCH;
    if (SoftbusGetConfig(SOFTBUS_INT_BLE_MAC_AUTO_REFRESH_SWITCH, (unsigned char *)(&bleMacRefreshSwitch),
        sizeof(bleMacRefreshSwitch)) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "get ble mac refresh switch from config file fail");
    }
    if (!JSON_AddInt32ToObject(json, BLE_CONN_CLOSE_DELAY_TIME, delayTime) ||
        !JSON_AddInt32ToObject(json, BLE_MAC_REFRESH_SWITCH, bleMacRefreshSwitch)) {
        AUTH_LOGI(AUTH_FSM, "add ble conn close delay time or refresh switch fail");
    }
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "PackCommon fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t SetDiscType(uint32_t *discType, const char *discStr)
{
    if (strcmp(discStr, DEFAULT_BT_DISC_TYPE_STR) == 0) {
        AUTH_LOGE(AUTH_FSM, "disc type can't parse");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackBt(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    char discTypeStr[BT_DISC_TYPE_MAX_LEN] = { 0 };
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
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    char offlineCode[BASE64_OFFLINE_CODE_LEN] = { 0 };
    size_t len = 0;
    AUTH_LOGE(AUTH_FSM, "offlineCodeLen=%{public}zu, offlineCodeSize=%{public}zu", strlen(offlineCode),
        sizeof(info->offlineCode));
    int32_t ret = SoftBusBase64Encode((unsigned char *)offlineCode, BASE64_OFFLINE_CODE_LEN, &len,
        (unsigned char *)info->offlineCode, sizeof(info->offlineCode));
    if (ret != 0) {
        AUTH_LOGE(AUTH_FSM, "mbedtls base64 encode failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    (void)JSON_AddStringToObject(json, BLE_OFFLINE_CODE, offlineCode);
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "PackCommon fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
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
        return SOFTBUS_INVALID_NUM;
    }
    return maxVersion;
}

static int32_t UnpackWiFi(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (CheckBusVersion(json) < 0) {
        return SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL;
    }
    (void)JSON_GetInt32FromOject(json, AUTH_PORT, &info->connectInfo.authPort);
    (void)JSON_GetInt32FromOject(json, SESSION_PORT, &info->connectInfo.sessionPort);
    (void)JSON_GetInt32FromOject(json, PROXY_PORT, &info->connectInfo.proxyPort);
    if (!JSON_GetInt64FromOject(json, TRANSPORT_PROTOCOL, (int64_t *)&info->supportedProtocols)) {
        info->supportedProtocols = LNN_PROTOCOL_IP;
    }
    char offlineCode[BASE64_OFFLINE_CODE_LEN] = { 0 };
    OptString(json, DEV_IP, info->connectInfo.deviceIp, MAX_ADDR_LEN, ""); // check ip available
    OptString(json, BLE_OFFLINE_CODE, offlineCode, BASE64_OFFLINE_CODE_LEN, "");
    size_t len;
    if (SoftBusBase64Decode(info->offlineCode, OFFLINE_CODE_BYTE_SIZE, &len, (const unsigned char *)offlineCode,
        strlen(offlineCode)) != 0) {
        AUTH_LOGE(AUTH_FSM, "base64Decode fail");
    }
    if (len != OFFLINE_CODE_BYTE_SIZE) {
        AUTH_LOGE(AUTH_FSM, "base64Decode data err");
    }
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackDeviceInfoMac(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    AUTH_LOGI(AUTH_FSM, "pack deviceInfo mac");
    if (!JSON_AddStringToObject(json, BR_MAC_ADDR, LnnGetBtMac(info)) ||
        !JSON_AddStringToObject(json, P2P_MAC_ADDR, LnnGetP2pMac(info)) ||
        !JSON_AddStringToObject(json, BT_MAC, info->connectInfo.macAddr) ||
        !JSON_AddStringToObject(json, HML_MAC, info->wifiDirectAddr)) {
        AUTH_LOGE(AUTH_FSM, "add mac info fail");
        return SOFTBUS_AUTH_REG_DATA_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t PackDeviceInfoBtV1(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    AUTH_LOGI(AUTH_FSM, "pack deviceInfo bt-v1");
    if (PackDeviceInfoMac(json, info, isMetaAuth) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "add packdevice mac info fail ");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
    }
    char localDevName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    if (ret == SOFTBUS_OK) {
        (void)JSON_AddStringToObject(json, DEVICE_NAME, localDevName);
    } else {
        (void)JSON_AddStringToObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo));
    }
    if (!JSON_AddStringToObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !JSON_AddStringToObject(json, DEVICE_VERSION_TYPE, info->versionType) ||
        !JSON_AddStringToObject(json, UUID, info->uuid) ||
        !JSON_AddStringToObject(json, SW_VERSION, info->softBusVersion) ||
        !JSON_AddStringToObject(json, DEVICE_UDID, info->deviceInfo.deviceUdid) ||
        !JSON_AddInt64ToObject(json, WIFI_VERSION, info->wifiVersion) ||
        !JSON_AddInt64ToObject(json, BLE_VERSION, info->bleVersion) ||
        !JSON_AddInt64ToObject(json, CONN_CAP, info->netCapacity) ||
        !JSON_AddInt64ToObject(json, NEW_CONN_CAP, info->netCapacity) ||
        !JSON_AddInt32ToObject(json, REMAIN_POWER, info->batteryInfo.batteryLevel) ||
        !JSON_AddBoolToObject(json, IS_CHARGING, info->batteryInfo.isCharging) ||
        !JSON_AddBoolToObject(json, IS_SCREENON, info->isScreenOn) ||
        !JSON_AddInt32ToObject(json, P2P_ROLE, info->p2pInfo.p2pRole) ||
        !JSON_AddInt64ToObject(json, ACCOUNT_ID, info->accountId) ||
        !JSON_AddInt32ToObject(json, NODE_WEIGHT, info->masterWeight) ||
        !JSON_AddInt32ToObject(json, STATE_VERSION_CHANGE_REASON, info->stateVersionReason)) {
        AUTH_LOGE(AUTH_FSM, "add wifi info fail");
        return SOFTBUS_AUTH_PACK_DEVINFO_FAIL;
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
        return SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL;
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
    OptInt(json, STATE_VERSION_CHANGE_REASON, (int32_t *)&info->stateVersionReason, 0);
    OptInt64(json, NEW_CONN_CAP, (int64_t *)&info->netCapacity, -1);
    if (info->netCapacity == (uint32_t)-1) {
        OptInt64(json, CONN_CAP, (int64_t *)&info->netCapacity, 0);
    }
    if (strcpy_s(info->networkId, NETWORK_ID_BUF_LEN, info->uuid) != EOK) {
        AUTH_LOGE(AUTH_FSM, "strcpy networkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PackCertificateInfo(JsonObj *json, const AuthSessionInfo *info)
{
    if (info == NULL || !IsSupportUDIDAbatement() || !info->isNeedPackCert) {
        AUTH_LOGI(AUTH_FSM, "device not support udid abatement or no need");
        return SOFTBUS_OK;
    }

    SoftbusCertChain softbusCertChain;
    (void)memset_s(&softbusCertChain, sizeof(SoftbusCertChain), 0, sizeof(SoftbusCertChain));
    if (GenerateCertificate(&softbusCertChain, info) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "GenerateCertificate fail");
        return SOFTBUS_OK;
    }
    if (!JSON_AddBytesToObject(json, ATTEST_CERTS, softbusCertChain.cert[ATTEST_CERTS_INDEX].data,
        softbusCertChain.cert[ATTEST_CERTS_INDEX].size) ||
        !JSON_AddBytesToObject(json, DEVICE_CERTS, softbusCertChain.cert[DEVICE_CERTS_INDEX].data,
        softbusCertChain.cert[DEVICE_CERTS_INDEX].size) ||
        !JSON_AddBytesToObject(json, MANUFACTURE_CERTS, softbusCertChain.cert[MANUFACTURE_CERTS_INDEX].data,
        softbusCertChain.cert[MANUFACTURE_CERTS_INDEX].size) ||
        !JSON_AddBytesToObject(json, ROOT_CERTS, softbusCertChain.cert[ROOT_CERTS_INDEX].data,
        softbusCertChain.cert[ROOT_CERTS_INDEX].size)) {
        FreeSoftbusChain(&softbusCertChain);
        AUTH_LOGE(AUTH_FSM, "pack certChain fail.");
        return SOFTBUS_AUTH_INNER_ERR;
    }
    FreeSoftbusChain(&softbusCertChain);
    return SOFTBUS_OK;
}

static int32_t UnpackCertificateInfo(JsonObj *json, NodeInfo *nodeInfo, const AuthSessionInfo *info)
{
    if (info == NULL || !IsSupportUDIDAbatement() || !IsNeedUDIDAbatement(info)) {
        AUTH_LOGI(AUTH_FSM, "device not support udid abatement or no need");
        return SOFTBUS_OK;
    }
    SoftbusCertChain softbusCertChain;
    (void)memset_s(&softbusCertChain, sizeof(SoftbusCertChain), 0, sizeof(SoftbusCertChain));
    if (InitSoftbusChain(&softbusCertChain) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_FSM, "malloc fail.");
        return SOFTBUS_OK;
    }
    if (!JSON_GetBytesFromObject(json, ATTEST_CERTS, softbusCertChain.cert[ATTEST_CERTS_INDEX].data,
        SOFTBUS_CERTIFICATE_SIZE, &softbusCertChain.cert[ATTEST_CERTS_INDEX].size) ||
        !JSON_GetBytesFromObject(json, DEVICE_CERTS, softbusCertChain.cert[DEVICE_CERTS_INDEX].data,
        SOFTBUS_CERTIFICATE_SIZE, &softbusCertChain.cert[DEVICE_CERTS_INDEX].size) ||
        !JSON_GetBytesFromObject(json, MANUFACTURE_CERTS, softbusCertChain.cert[MANUFACTURE_CERTS_INDEX].data,
        SOFTBUS_CERTIFICATE_SIZE, &softbusCertChain.cert[MANUFACTURE_CERTS_INDEX].size) ||
        !JSON_GetBytesFromObject(json, ROOT_CERTS, softbusCertChain.cert[ROOT_CERTS_INDEX].data,
        SOFTBUS_CERTIFICATE_SIZE, &softbusCertChain.cert[ROOT_CERTS_INDEX].size)) {
        FreeSoftbusChain(&softbusCertChain);
        nodeInfo->deviceSecurityLevel = 0;
        AUTH_LOGE(AUTH_FSM, "unpack certChain fail.");
        return SOFTBUS_OK;
    }
    if (VerifyCertificate(&softbusCertChain, nodeInfo, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "attest cert fail.");
        FreeSoftbusChain(&softbusCertChain);
        return SOFTBUS_AUTH_ATTEST_CERT_FAIL;
    }
    FreeSoftbusChain(&softbusCertChain);
    return SOFTBUS_OK;
}

static void UpdateLocalNetBrMac(void)
{
    NodeInfo info;
    if (memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "memset_s fail");
        return;
    }
    if (LnnGetLocalNodeInfoSafe(&info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local node info fail");
        return;
    }
    const char *brMacTemp = LnnGetBtMac(&info);
    int32_t lenBrMac = strlen(brMacTemp);
    if ((lenBrMac == 0 || (strncmp(brMacTemp, INVALID_BR_MAC_ADDR, BT_MAC_LEN) == 0)) &&
        SoftBusGetBtState() == BLE_ENABLE) {
        char brMac[BT_MAC_LEN] = { 0 };
        SoftBusBtAddr mac = { 0 };
        int32_t ret = SoftBusGetBtMacAddr(&mac);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get bt mac addr fail, do not update local brmac");
            return;
        }
        ret = ConvertBtMacToStr(brMac, BT_MAC_LEN, mac.addr, sizeof(mac.addr));
        if (ret != SOFTBUS_OK || strlen(brMac) == 0) {
            AUTH_LOGE(AUTH_FSM, "convert bt mac to str fail, do not update local brmac");
            return;
        }
        if (LnnSetLocalStrInfo(STRING_KEY_BT_MAC, brMac) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "set local brmac fail, do not update local brmac");
            return;
        }
        char *anonyMac = NULL;
        Anonymize(brMac, &anonyMac);
        AUTH_LOGI(AUTH_FSM, "update local brmac=%{public}s", AnonymizeWrapper(anonyMac));
        AnonymizeFree(anonyMac);
    }
}

#define USERID_CHECKSUM_HEXSTRING_LEN 9
static int32_t PackUserIdCheckSum(JsonObj *json, const NodeInfo *nodeInfo)
{
    if (!JSON_AddInt32ToObject(json, USERID, nodeInfo->userId)) {
        AUTH_LOGW(AUTH_FSM, "pack userId fail");
    }
    char userIdCheckSumHexStr[USERID_CHECKSUM_HEXSTRING_LEN] = { 0 };
    int32_t ret = ConvertBytesToHexString(userIdCheckSumHexStr, USERID_CHECKSUM_HEXSTRING_LEN, nodeInfo->userIdCheckSum,
        sizeof(nodeInfo->userIdCheckSum));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "ConvertBytesToHexString failed.");
        return ret;
    }
    if (!JSON_AddStringToObject(json, USERID_CHECKSUM, userIdCheckSumHexStr)) {
        AUTH_LOGE(AUTH_FSM, "JSON_AddStringToObject failed.");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

char *PackDeviceInfoMessage(const AuthConnInfo *connInfo, SoftBusVersion version, bool isMetaAuth,
    const char *remoteUuid, const AuthSessionInfo *info)
{
    // uuid and info is null in meta, no need check param
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_FSM, "conninfo is null");
        return NULL;
    }
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", connInfo->type);
    UpdateLocalNetBrMac();
    const NodeInfo *nodeInfo = LnnGetLocalNodeInfo();
    if (nodeInfo == NULL) {
        AUTH_LOGE(AUTH_FSM, "local info is null");
        return NULL;
    }
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        AUTH_LOGE(AUTH_FSM, "create cjson fail");
        return NULL;
    }
    int32_t ret;
    if (connInfo->type == AUTH_LINK_TYPE_WIFI) {
        ret = PackWiFi(json, nodeInfo, version, isMetaAuth);
    } else if (version == SOFTBUS_OLD_V1) {
        ret = PackDeviceInfoBtV1(json, nodeInfo, isMetaAuth);
    } else {
        ret = PackBt(json, nodeInfo, version, isMetaAuth, remoteUuid);
    }
    if (ret != SOFTBUS_OK) {
        JSON_Delete(json);
        return NULL;
    }
    PackWifiDirectInfo(connInfo, json, nodeInfo, remoteUuid, isMetaAuth);

    if (PackCertificateInfo(json, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "packCertificateInfo fail");
        JSON_Delete(json);
        return NULL;
    }
    ret = PackUserIdCheckSum(json, nodeInfo);
    if (ret != SOFTBUS_OK) {
        JSON_Delete(json);
        return NULL;
    }
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
    char deviceName[DEVICE_NAME_BUF_LEN] = { 0 };
    if (strlen(peerNodeInfo->deviceInfo.unifiedName) != 0 &&
        strcmp(peerNodeInfo->deviceInfo.unifiedName, peerNodeInfo->deviceInfo.unifiedDefaultName) != 0) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedName);
    } else if (strlen(peerNodeInfo->deviceInfo.nickName) == 0 || localInfo->accountId == peerNodeInfo->accountId) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedDefaultName);
    } else {
        LnnGetDeviceDisplayName(peerNodeInfo->deviceInfo.nickName, peerNodeInfo->deviceInfo.unifiedDefaultName,
            deviceName, DEVICE_NAME_BUF_LEN);
    }
    char *anonyDeviceName = NULL;
    Anonymize(deviceName, &anonyDeviceName);
    char *anonyPeerDeviceName = NULL;
    Anonymize(peerNodeInfo->deviceInfo.deviceName, &anonyPeerDeviceName);
    char *anonyUnifiedName = NULL;
    Anonymize(peerNodeInfo->deviceInfo.unifiedName, &anonyUnifiedName);
    char *anonyUnifiedDefaultName = NULL;
    Anonymize(peerNodeInfo->deviceInfo.unifiedDefaultName, &anonyUnifiedDefaultName);
    char *anonyNickName = NULL;
    Anonymize(peerNodeInfo->deviceInfo.nickName, &anonyNickName);
    AUTH_LOGD(AUTH_FSM,
        "peer tmpDeviceName=%{public}s, deviceName=%{public}s, unifiedName=%{public}s, "
        "unifiedDefaultName=%{public}s, nickName=%{public}s",
        AnonymizeWrapper(anonyDeviceName), AnonymizeWrapper(anonyPeerDeviceName), AnonymizeWrapper(anonyUnifiedName),
        AnonymizeWrapper(anonyUnifiedDefaultName), AnonymizeWrapper(anonyNickName));
    AnonymizeFree(anonyDeviceName);
    AnonymizeFree(anonyPeerDeviceName);
    AnonymizeFree(anonyUnifiedName);
    AnonymizeFree(anonyUnifiedDefaultName);
    AnonymizeFree(anonyNickName);
    if (strlen(deviceName) != 0) {
        ret = strcpy_s(peerNodeInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, deviceName);
    }
    if (ret != EOK) {
        AUTH_LOGW(AUTH_FSM, "strcpy_s fail, use default name");
    }
}

static void UnpackUserIdCheckSum(JsonObj *json, NodeInfo *nodeInfo)
{
    char userIdCheckSumHexStr[USERID_CHECKSUM_HEXSTRING_LEN] = { 0 };
    OptInt(json, USERID, &nodeInfo->userId, 0);
    if (!JSON_GetStringFromOject(json, USERID_CHECKSUM, userIdCheckSumHexStr, sizeof(userIdCheckSumHexStr))) {
        AUTH_LOGE(AUTH_FSM, "JSON_GetStringFromOject failed!");
        return;
    }
    int32_t ret = ConvertHexStringToBytes(
        nodeInfo->userIdCheckSum, USERID_CHECKSUM_LEN, userIdCheckSumHexStr, strlen(userIdCheckSumHexStr));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "ConvertHexStringToBytes failed! ret:%{public}d", ret);
    }
}

int32_t UnpackDeviceInfoMessage(
    const DevInfoData *devInfo, NodeInfo *nodeInfo, bool isMetaAuth, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(devInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "devInfo is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(nodeInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "nodeInfo is NULL");
    AUTH_LOGI(AUTH_FSM, "connType=%{public}d", devInfo->linkType);
    JsonObj *json = JSON_Parse(devInfo->msg, devInfo->len);
    if (json == NULL) {
        AUTH_LOGE(AUTH_FSM, "parse cjson fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    int32_t ret;
    int32_t target = 0;
    if (devInfo->linkType == AUTH_LINK_TYPE_WIFI) {
        ret = UnpackWiFi(json, nodeInfo, devInfo->version, isMetaAuth);
    } else if (devInfo->version == SOFTBUS_OLD_V1) {
        ret = UnpackDeviceInfoBtV1(json, nodeInfo);
    } else {
        ret = UnpackBt(json, nodeInfo, devInfo->version, isMetaAuth);
    }
    UnpackWifiDirectInfo(json, nodeInfo, isMetaAuth);
    nodeInfo->isSupportSv = false;
    if (JSON_GetInt32FromOject(json, STATE_VERSION, &target)) {
        nodeInfo->isSupportSv = true;
    }
    if (UnpackCertificateInfo(json, nodeInfo, info) != SOFTBUS_OK) {
        JSON_Delete(json);
        return SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL;
    }
    UnpackUserIdCheckSum(json, nodeInfo);
    JSON_Delete(json);
    int32_t stateVersion;
    if (LnnGetLocalNumInfo(NUM_KEY_STATE_VERSION, &stateVersion) == SOFTBUS_OK) {
        nodeInfo->localStateVersion = stateVersion;
    }
    if (IsFeatureSupport(nodeInfo->feature, BIT_SUPPORT_UNIFORM_NAME_CAPABILITY) &&
        nodeInfo->deviceInfo.osType != OH_OS_TYPE) {
        UpdatePeerDeviceName(nodeInfo);
    }
    nodeInfo->updateTimestamp = SoftBusGetSysTimeMs();
    return ret;
}
