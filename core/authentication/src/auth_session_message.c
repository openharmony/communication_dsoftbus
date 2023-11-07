/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "auth_common.h"
#include "auth_request.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain_adapter.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_common_utils.h"
#include "lnn_extdata_config.h"
#include "lnn_local_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_network_manager.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_common.h"
#include "softbus_json_utils.h"
#include "lnn_compress.h"
#include "softbus_adapter_json.h"
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

static void OptString(const JsonObj *json, const char * const key,
    char *target, uint32_t targetLen, const char *defaultValue)
{
    if (JSON_GetStringFromOject(json, key, target, targetLen)) {
        return;
    }
    if (strcpy_s(target, targetLen, defaultValue) != EOK) {
        ALOGI("set default fail");
        return;
    }
    ALOGI("(%s) prase fail, use default", key);
}

static void OptInt(const JsonObj *json, const char * const key, int *target, int defaultValue)
{
    if (JSON_GetInt32FromOject(json, key, target)) {
        return;
    }
    ALOGI("(%s) prase fail, use default", key);
    *target = defaultValue;
}

static void OptInt64(const JsonObj *json, const char * const key,
    int64_t *target, int64_t defaultValue)
{
    if (JSON_GetInt64FromOject(json, key, target)) {
        return;
    }
    ALOGI("(%s) prase fail, use default", key);
    *target = defaultValue;
}

static void OptBool(const JsonObj *json, const char * const key, bool *target, bool defaultValue)
{
    if (JSON_GetBoolFromOject(json, key, target)) {
        return;
    }
    ALOGI("(%s) prase fail, use default", key);
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
        ALOGE("SoftBusEncryptDataWithSeq fail(=%d).", ret);
        return SOFTBUS_ERR;
    }
    if (data == NULL || dataLen == 0) {
        ALOGE("encrypt data invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char encryptFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (ConvertBytesToUpperCaseHexString(encryptFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN - 1,
        data, dataLen) != SOFTBUS_OK) {
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    ALOGD("pack fastAuthTag:%s", encryptFastAuth);
    JSON_AddStringToObject(obj, FAST_AUTH, encryptFastAuth);
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static bool GetUdidOrShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    if (strlen(info->udid) != 0) {
        ALOGI("use info->udid build fastAuthInfo");
        uint8_t hash[SHA_256_HASH_LEN] = {0};
        int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), hash);
        if (ret != SOFTBUS_OK) {
            ALOGE("generate udidHash fail");
            return false;
        }
        if (ConvertBytesToUpperCaseHexString(udidBuf, bufLen, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
            ALOGE("convert bytes to string fail");
            return false;
        }
        return true;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE) {
        ALOGI("use bleInfo deviceIdHash build fastAuthInfo");
        AuthRequest request = {0};
        if (GetAuthRequestNoLock(info->requestId, &request) != SOFTBUS_OK) {
            LLOGE("GetAuthRequest fail");
            return false;
        }
        return (memcpy_s(udidBuf, bufLen, request.connInfo.info.bleInfo.deviceIdHash,
            UDID_SHORT_HASH_HEX_STR) == EOK);
    }
    ALOGD("udid len:%d, connInfo type:%d", strlen(info->udid), info->connInfo.type);
    return false;
}

static void PackFastAuth(JsonObj *obj, AuthSessionInfo *info, const NodeInfo *localNodeInfo)
{
    ALOGD("pack fastAuth, isServer:%d", info->isServer);
    bool isNeedPack;
    if (!info->isServer || info->isSupportFastAuth) {
        isNeedPack = true;
    } else {
        ALOGI("unsupport fastAuth");
        isNeedPack = false;
    }
    if (isNeedPack && info->isNeedFastAuth == false) {
        ALOGI("no need fastAuth");
        isNeedPack = false;
    }
    if (!isNeedPack) {
        return;
    }
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = {0};
    if (!GetUdidOrShortHash(info, udidHashHexStr, SHA_256_HEX_HASH_LEN)) {
        ALOGE("get udid fail, bypass fastAuth");
        info->isSupportFastAuth = false;
        return;
    }
    ALOGD("udidHashHexStr:%s", udidHashHexStr);
    if (!IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidHashHexStr, false, true)) {
        ALOGI("not potential trusted realtion, bypass fastAuthProc");
        info->isSupportFastAuth = false;
        return;
    }
    AuthDeviceKeyInfo deviceCommKey = {0};
    if (AuthFindDeviceKey(udidHashHexStr, info->connInfo.type, &deviceCommKey) != SOFTBUS_OK) {
        ALOGW("can't find common key, unsupport fastAuth");
        info->isSupportFastAuth = false;
        return;
    }
    if (PackFastAuthValue(obj, &deviceCommKey) != SOFTBUS_OK) {
        info->isSupportFastAuth = false;
        return;
    }
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
}

static void ParseFastAuthValue(AuthSessionInfo *info, const char *encryptedFastAuth,
    AuthDeviceKeyInfo *deviceKey)
{
    uint8_t fastAuthBytes[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (ConvertHexStringToBytes(fastAuthBytes, ENCRYPTED_FAST_AUTH_MAX_LEN,
        encryptedFastAuth, strlen(encryptedFastAuth)) != SOFTBUS_OK) {
        ALOGE("fastAuth data String to bytes fail");
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
        ALOGE("LnnDecryptAesGcm fail(=%d), fastAuth not support", ret);
        return;
    }
    if (data == NULL || dataLen == 0) {
        ALOGE("decrypt data invalid, fastAuth not support");
        return;
    }
    if (strncmp((char *)data, SOFTBUS_FAST_AUTH, strlen(SOFTBUS_FAST_AUTH)) != 0) {
        ALOGE("fast auth info error");
        SoftBusFree(data);
        return;
    }
    ALOGD("parse fastAuth succ");
    SoftBusFree(data);
    info->isSupportFastAuth = true;
}

static void UnpackFastAuth(JsonObj *obj, AuthSessionInfo *info)
{
    info->isSupportFastAuth = false;
    char encryptedFastAuth[ENCRYPTED_FAST_AUTH_MAX_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, FAST_AUTH, encryptedFastAuth, ENCRYPTED_FAST_AUTH_MAX_LEN)) {
        ALOGI("old version or not support fastAuth");
        return;
    }
    ALOGE("unpack fastAuthTag:%s", encryptedFastAuth);
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash((uint8_t *)info->udid, strlen(info->udid), udidHash);
    if (ret != SOFTBUS_OK) {
        ALOGE("generate udidHash fail");
        return;
    }
    char udidShortHash[UDID_SHORT_HASH_HEX_STR + 1] = {0};
    if (ConvertBytesToUpperCaseHexString(udidShortHash, UDID_SHORT_HASH_HEX_STR + 1,
        udidHash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        ALOGE("udid hash bytes to hexString fail");
        return;
    }
    if (!IsPotentialTrustedDevice(ID_TYPE_DEVID, (const char *)udidShortHash, false, true)) {
        ALOGI("not potential trusted realtion, fastAuth not support");
        return;
    }
    AuthDeviceKeyInfo deviceKey = {0};
    /* find comm key use udid or udidShortHash */
    if (AuthFindDeviceKey(udidShortHash, info->connInfo.type, &deviceKey) != SOFTBUS_OK) {
        ALOGW("can't find common key, fastAuth not support");
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
        return;
    }
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    char localIp[MAX_ADDR_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        ALOGE("get local ip fail");
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

static char *PackDeviceIdJson(const AuthSessionInfo *info)
{
    ALOGI("PackDeviceId: connType = %d.", info->connInfo.type);
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
        ALOGE("get uuid/udid/networkId fail.");
        JSON_Delete(obj);
        return NULL;
    }
    PackWifiSinglePassInfo(obj, info);
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && !info->isServer) {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_GET_AUTH_INFO)) {
            ALOGE("add CMD_GET fail.");
            JSON_Delete(obj);
            return NULL;
        }
    } else {
        if (!JSON_AddStringToObject(obj, CMD_TAG, CMD_RET_AUTH_INFO)) {
            ALOGE("add CMD_RET fail.");
            JSON_Delete(obj);
            return NULL;
        }
    }
    if (info->idType == EXCHANGE_NETWORKID) {
        if (!JSON_AddStringToObject(obj, DEVICE_ID_TAG, networkId)) {
            ALOGE("add msg body fail.");
            JSON_Delete(obj);
            return NULL;
        }
        ALOGI("exchangeIdType=[%d], networkid=[%s]", info->idType, AnonymizesNetworkID(networkId));
    } else {
        if (!JSON_AddStringToObject(obj, DEVICE_ID_TAG, udid)) {
            ALOGE("add msg body fail.");
            JSON_Delete(obj);
            return NULL;
        }
        ALOGI("exchangeIdType=[%d], udid=[%s]", info->idType, AnonymizesUDID(udid));
    }
    if (!JSON_AddStringToObject(obj, DATA_TAG, uuid) ||
        !JSON_AddInt32ToObject(obj, DATA_BUF_SIZE_TAG, PACKET_SIZE) ||
        !JSON_AddInt32ToObject(obj, SOFTBUS_VERSION_TAG, info->version) ||
        !JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, info->idType)) {
        ALOGE("add msg body fail.");
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
        ALOGD("isn't wifi link, ignore");
        return true;
    }
    char devIpHash[SHA_256_HEX_HASH_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, DEV_IP_HASH_TAG, devIpHash, SHA_256_HEX_HASH_LEN)) {
        ALOGD("devIpHash hash not found, ignore");
        return true;
    }
    // check devIpHash
    int32_t socketFd = GetFd(info->connId);
    SoftBusSockAddrIn addr = {0};
    SocketAddr socketAddr;
    int32_t rc = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&addr);
    if (rc != 0) {
        ALOGE("fd=%d, GetPerrName rc=%d", socketFd, rc);
        return true;
    }
    (void)memset_s(&socketAddr, sizeof(socketAddr), 0, sizeof(socketAddr));
    if (SoftBusInetNtoP(SOFTBUS_AF_INET, (void *)&addr.sinAddr, socketAddr.addr, sizeof(socketAddr.addr)) == NULL) {
        ALOGE("fd=%d, GetPerrName rc=%d", socketFd, rc);
        return true;
    }
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    rc = SoftBusGenerateStrHash((const unsigned char *)socketAddr.addr, strlen(socketAddr.addr), hash);
    if (rc != SOFTBUS_OK) {
        return true;
    }
    char socketIpHash[SHA_256_HEX_HASH_LEN] = {0};
    if (ConvertBytesToUpperCaseHexString(socketIpHash, SHA_256_HEX_HASH_LEN,
        hash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        return true;
    }
    if (strcmp(devIpHash, socketIpHash) == 0) {
        ALOGE("devIpHash is mismatch");
        return true;
    }
    return false;
}

static int32_t UnPackBtDeviceIdV1(AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    if (!info->isServer) {
        ALOGE("invalid bt deviceId msg");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info->udid, UDID_BUF_LEN, data, len) != EOK) { // data:StandardCharsets.UTF_8
        ALOGE("memcpy fail");
        return SOFTBUS_ERR;
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
        ALOGI("local-remote all support deviceinfo compress");
    } else {
        *sessionSupportFlag = false;
    }
}

static int32_t SetExchangeIdTypeAndValve(JsonObj *obj, AuthSessionInfo *info)
{
    int32_t idType = -1;
    char peerUdid[UDID_BUF_LEN] = {0};
    if (obj == NULL || info == NULL) {
        ALOGE("param invalid");
        return SOFTBUS_ERR;
    }
    if (!JSON_GetInt32FromOject(obj, EXCHANGE_ID_TYPE, &idType)) {
        ALOGI("parse idType failed, ignore");
        info->idType = EXCHANHE_UDID;
        return SOFTBUS_OK;
    }
    ALOGI("old idType=[%d] exchangeIdType=[%d] deviceId=[%s]", info->idType, idType, AnonymizesUDID(info->udid));
    if (idType == EXCHANHE_UDID) {
        info->idType = EXCHANHE_UDID;
        return SOFTBUS_OK;
    }
    if (info->isServer) {
        if (idType == EXCHANGE_NETWORKID) {
            if (GetPeerUdidByNetworkId(info->udid, peerUdid) != SOFTBUS_OK) {
                info->idType = EXCHANGE_FAIL;
            } else {
                if (memcpy_s(info->udid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
                    ALOGE("copy peer udid fail");
                    info->idType = EXCHANGE_FAIL;
                    return SOFTBUS_ERR;
                }
                info->idType = EXCHANGE_NETWORKID;
            }
        }
        return SOFTBUS_OK;
    }
    if (info->idType == EXCHANGE_NETWORKID) {
        if (idType == EXCHANGE_FAIL) {
            info->idType = EXCHANGE_FAIL;
        }
        if (idType == EXCHANGE_NETWORKID) {
            if (GetPeerUdidByNetworkId(info->udid, peerUdid) != SOFTBUS_OK) {
                ALOGE("get peer udid fail, peer networkId=[%s]", AnonymizesUDID(info->udid));
                info->idType = EXCHANGE_FAIL;
            } else {
                if (memcpy_s(info->udid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
                    ALOGE("copy peer udid fail");
                    info->idType = EXCHANGE_FAIL;
                    return SOFTBUS_ERR;
                }
                ALOGE("get peer udid success, peer udid=[%s]", AnonymizesUDID(info->udid));
                info->idType = EXCHANGE_NETWORKID;
            }
        }
    }
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceIdJson(const char *msg, uint32_t len, AuthSessionInfo *info)
{
    JsonObj *obj = JSON_Parse(msg, len);
    if (obj == NULL) {
        ALOGE("json parse fail.");
        return SOFTBUS_ERR;
    }
    char cmd[CMD_TAG_LEN] = {0};
    if (!JSON_GetStringFromOject(obj, CMD_TAG, cmd, CMD_TAG_LEN)) {
        ALOGE("CMD_TAG not found");
        JSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (!UnpackWifiSinglePassInfo(obj, info)) {
        ALOGE("check ip fail, can't support auth");
        return SOFTBUS_ERR;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && info->isServer) {
        if (strncmp(cmd, CMD_GET_AUTH_INFO, strlen(CMD_GET_AUTH_INFO)) != 0) {
            ALOGE("CMD_GET not match.");
            JSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    } else {
        if (strncmp(cmd, CMD_RET_AUTH_INFO, strlen(CMD_RET_AUTH_INFO)) != 0) {
            ALOGE("CMD_RET not match.");
            JSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_GetStringFromOject(obj, DATA_TAG, info->uuid, UUID_BUF_LEN)) {
        ALOGE("uuid not found");
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
            ALOGE("strcpy udid fail, ignore");
        }
    }
    if (!JSON_GetInt32FromOject(obj, SOFTBUS_VERSION_TAG, (int32_t *)&info->version)) {
        // info->version = SOFTBUS_OLD_V2;
        ALOGE("softbusVersion is not found");
    }
    if (SetExchangeIdTypeAndValve(obj, info) != SOFTBUS_OK) {
        ALOGE("set exchange id type or valve fail.");
        JSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        char compressParse[PARSE_UNCOMPRESS_STRING_BUFF_LEN] = {0};
        OptString(obj, SUPPORT_INFO_COMPRESS, compressParse,
            PARSE_UNCOMPRESS_STRING_BUFF_LEN, FALSE_STRING_TAG);
        SetCompressFlag(compressParse, &info->isSupportCompress);
    }
    UnpackFastAuth(obj, info);
    JSON_Delete(obj);
    return SOFTBUS_OK;
}

static int32_t PackCommonDevInfo(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    (void)JSON_AddStringToObject(json, UNIFIED_DEVICE_NAME, info->deviceInfo.unifiedName);
    (void)JSON_AddStringToObject(json, SETTINGS_NICK_NAME, info->deviceInfo.nickName);
    (void)JSON_AddStringToObject(json, UNIFIED_DEFAULT_DEVICE_NAME, info->deviceInfo.unifiedDefaultName);
    if (!JSON_AddStringToObject(json, NETWORK_ID, info->networkId) ||
        !JSON_AddStringToObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo)) ||
        !JSON_AddStringToObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !JSON_AddStringToObject(json, DEVICE_UDID, LnnGetDeviceUdid(info))) {
        ALOGE("JSON_AddStringToObject fail.");
        return SOFTBUS_ERR;
    }
    if (isMetaAuth && !JSON_AddStringToObject(json, DEVICE_UUID, info->uuid)) {
        ALOGE("JSON_AddStringToObject fail.");
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
        ALOGE("GetExtData fail.");
    } else {
        ALOGI("GetExtData : %s", extData);
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

static int32_t PackCommon(JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!JSON_AddStringToObject(json, MASTER_UDID, info->masterUdid) ||
            !JSON_AddInt32ToObject(json, MASTER_WEIGHT, info->masterWeight)) {
            ALOGE("add master node info fail.");
            return SOFTBUS_ERR;
        }
        if (!JSON_AddStringToObject(json, NODE_ADDR, info->nodeAddress)) {
            ALOGE("pack node address Fail.");
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_AddStringToObject(json, SW_VERSION, info->softBusVersion)) {
        ALOGE("add version info fail.");
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
        ALOGE("JSON_AddStringToObject fail.");
        return SOFTBUS_ERR;
    }
    char btMacUpper[BT_MAC_LEN] = {0};
    if (StringToUpperCase(LnnGetBtMac(info), btMacUpper, BT_MAC_LEN) != SOFTBUS_OK) {
        LLOGE("btMac to upperCase fail.");
        if (memcpy_s(btMacUpper, BT_MAC_LEN, LnnGetBtMac(info), BT_MAC_LEN) != EOK) {
            LLOGE("btMac cpy fail.");
            return SOFTBUS_ERR;
        }
    }
    if (!JSON_AddStringToObject(json, PKG_VERSION, info->pkgVersion) ||
        !JSON_AddInt64ToObject(json, WIFI_VERSION, info->wifiVersion) ||
        !JSON_AddInt64ToObject(json, BLE_VERSION, info->bleVersion) ||
        !JSON_AddStringToObject(json, BT_MAC, btMacUpper) ||
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
        !JSON_AddInt64ToObject(json, NEW_CONN_CAP, info->netCapacity)) {
        ALOGE("JSON_AddStringToObject fail.");
        return SOFTBUS_ERR;
    }
    PackCommonFastAuth(json, info);
    if (!PackCipherKeySyncMsg(json)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "PackCipherKeySyncMsg fail.");
    }
    PackCommP2pInfo(json, info);
    return SOFTBUS_OK;
}

static void UnpackCommon(const JsonObj *json, NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    if (version >= SOFTBUS_NEW_V1) {
        if (!JSON_GetStringFromOject(json, MASTER_UDID, info->masterUdid, UDID_BUF_LEN) ||
            !JSON_GetInt32FromOject(json, MASTER_WEIGHT, &info->masterWeight)) {
            ALOGE("get master node info fail");
        }
        ALOGE("get master weight: %d", info->masterWeight);
        if (!JSON_GetStringFromOject(json, NODE_ADDR, info->nodeAddress, sizeof(info->nodeAddress))) {
            ALOGW("no node address packed. set to address %s", NODE_ADDR_LOOPBACK);
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

    //IS_SUPPORT_TCP_HEARTBEAT
    OptInt64(json, NEW_CONN_CAP, (int64_t *)&info->netCapacity, -1);
    if (info->netCapacity == (uint32_t)-1) {
        (void)JSON_GetInt64FromOject(json, CONN_CAP, (int64_t *)&info->netCapacity);
    }
    OptInt(json, WIFI_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_WIFI_BUFF_SIZE);
    OptInt(json, BR_BUFF_SIZE, &info->wifiBuffSize, DEFAULT_BR_BUFF_SIZE);
    OptInt64(json, FEATURE, (int64_t *)&info->feature, 0);
    //MetaNodeInfoOfEar
    OptString(json, EXTDATA, info->extData, EXTDATA_LEN, "");
    if (version == SOFTBUS_OLD_V1) {
        if (strcpy_s(info->networkId, NETWORK_ID_BUF_LEN, info->uuid) != EOK) {
            ALOGE("v1 version strcpy networkid fail");
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
        ALOGI("networkId not found by uuid, maybe first online!");
        return;
    }
    uint32_t discoveryType = 0;
    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_DISCOVERY_TYPE, (int32_t *)&discoveryType) != SOFTBUS_OK) {
        ALOGE("get discoveryType fail!");
        return;
    }
    NodeInfo nodeInfo; // only for discType calc
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    nodeInfo.discoveryType = discoveryType;
    char discTypeStr[BT_DISC_TYPE_MAX_LEN] = {0};
    if (GetBtDiscTypeString(&nodeInfo, discTypeStr, BT_DISC_TYPE_MAX_LEN) != SOFTBUS_OK) {
        ALOGE("disc Type calc fail");
        return;
    }
    ALOGD("pack discType is:%s", discTypeStr);
    JSON_AddStringToObject(json, DISCOVERY_TYPE, discTypeStr);
}

static int32_t PackBt(JsonObj *json, const NodeInfo *info, SoftBusVersion version,
    bool isMetaAuth, const char *remoteUuid)
{
    if (!JSON_AddInt32ToObject(json, CODE, CODE_VERIFY_BT)) {
        ALOGE("add bt info fail");
        return SOFTBUS_ERR;
    }
    AddDiscoveryType(json, remoteUuid);
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        ALOGE("PackCommon fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetDiscType(uint32_t *discType, const char *discStr)
{
    if (strcmp(discStr, DEFAULT_BT_DISC_TYPE_STR) == 0) {
        ALOGE("disc type can't parse");
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
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackWiFi(JsonObj *json, const NodeInfo *info, SoftBusVersion version, bool isMetaAuth)
{
    ALOGD("devIp %d", strlen(info->connectInfo.deviceIp));
    if (!JSON_AddInt32ToObject(json, CODE, CODE_VERIFY_IP) ||
        !JSON_AddInt32ToObject(json, BUS_MAX_VERSION, BUS_V2) ||
        !JSON_AddInt32ToObject(json, BUS_MIN_VERSION, BUS_V1) ||
        !JSON_AddInt32ToObject(json, AUTH_PORT, LnnGetAuthPort(info)) ||
        !JSON_AddInt32ToObject(json, SESSION_PORT, LnnGetSessionPort(info)) ||
        !JSON_AddInt32ToObject(json, PROXY_PORT, LnnGetProxyPort(info)) ||
        !JSON_AddStringToObject(json, DEV_IP, info->connectInfo.deviceIp)) {
        ALOGE("add wifi info fail.");
        return SOFTBUS_ERR;
    }
    char offlineCode[BASE64_OFFLINE_CODE_LEN] = {0};
    size_t len = 0;
    ALOGE("offlineCode %d, %d", strlen(offlineCode), sizeof(info->offlineCode));
    int32_t ret = SoftBusBase64Encode((unsigned char*)offlineCode, BASE64_OFFLINE_CODE_LEN, &len,
        (unsigned char*)info->offlineCode, sizeof(info->offlineCode));
    if (ret != 0) {
        ALOGE("mbedtls base64 encode failed.");
        return SOFTBUS_ERR;
    }
    (void)JSON_AddStringToObject(json, BLE_OFFLINE_CODE, offlineCode);
    if (PackCommon(json, info, version, isMetaAuth) != SOFTBUS_OK) {
        ALOGE("PackCommon fail");
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
        ALOGE("no common version");
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
        ALOGE("base64Decode fail");
    }
    if (len != OFFLINE_CODE_BYTE_SIZE) {
        ALOGE("base64Decode data err");
    }
    UnpackCommon(json, info, version, isMetaAuth);
    return SOFTBUS_OK;
}

static int32_t PackDeviceInfoBtV1(JsonObj *json, const NodeInfo *info, bool isMetaAuth)
{
    ALOGI("pack deviceInfo bt-v1");
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
        ALOGE("add wifi info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceInfoBtV1(const JsonObj *json, NodeInfo *info)
{
    char deviceType[DEVICE_TYPE_BUF_LEN] = {0};
    if (!JSON_GetStringFromOject(json, DEVICE_NAME, info->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN) ||
        !JSON_GetStringFromOject(json, DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN) ||
        !JSON_GetStringFromOject(json, DEVICE_UDID, info->deviceInfo.deviceUdid, UDID_BUF_LEN) ||
        !JSON_GetStringFromOject(json, UUID, info->uuid, UUID_BUF_LEN) ||
        !JSON_GetStringFromOject(json, BR_MAC_ADDR, info->connectInfo.macAddr, MAC_LEN)) {
        ALOGE("prase devinfo fail, invalid msg");
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
        ALOGE("strcpy networkId fail");
    }
    return SOFTBUS_OK;
}

char *PackDeviceInfoMessage(int32_t linkType, SoftBusVersion version, bool isMetaAuth, const char *remoteUuid)
{
    ALOGI("PackDeviceInfo: connType = %d.", linkType);
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        ALOGE("local info is null.");
        return NULL;
    }
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        ALOGE("create cjson fail.");
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

    char *msg = JSON_PrintUnformatted(json);
    if (msg == NULL) {
        ALOGE("JSON_PrintUnformatted fail.");
    }
    JSON_Delete(json);
    return msg;
}

static void UpdatePeerDeviceName(NodeInfo *peerNodeInfo)
{
    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        ALOGE("localInfo is null");
        return;
    }
    int32_t ret = EOK;
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    if (strlen(peerNodeInfo->deviceInfo.unifiedName) != 0 &&
        strcmp(peerNodeInfo->deviceInfo.unifiedName, peerNodeInfo->deviceInfo.unifiedDefaultName) != 0) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedName);
    } else if (strlen(peerNodeInfo->deviceInfo.nickName) == 0 ||
        localInfo->accountId == peerNodeInfo->accountId) {
        ret = strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedDefaultName);
    } else {
        LnnGetDeviceDisplayName(peerNodeInfo->deviceInfo.nickName,
            peerNodeInfo->deviceInfo.unifiedDefaultName, deviceName, DEVICE_NAME_BUF_LEN);
    }
    if (strlen(deviceName) != 0) {
        ret = strcpy_s(peerNodeInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, deviceName);
    }
    LLOGD("peer deviceName:%s", peerNodeInfo->deviceInfo.deviceName);
    if (ret != EOK) {
        ALOGW("strcpy_s fail, use default name");
    }
}

int32_t UnpackDeviceInfoMessage(const DevInfoData *devInfo, NodeInfo *nodeInfo, bool isMetaAuth)
{
    CHECK_NULL_PTR_RETURN_VALUE(devInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(nodeInfo, SOFTBUS_INVALID_PARAM);
    ALOGI("UnpackDeviceInfo: connType = %d.", devInfo->linkType);
    JsonObj *json = JSON_Parse(devInfo->msg, devInfo->len);
    if (json == NULL) {
        ALOGE("parse cjson fail.");
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
        ALOGE("post device id fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PostBtV1DevId(int64_t authSeq, const AuthSessionInfo *info)
{
    if (!info->isServer) {
        ALOGE("client don't send Bt-v1 devId");
        return SOFTBUS_ERR;
    }
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        ALOGE("get uuid fail");
        return SOFTBUS_ERR;
    }
    return PostDeviceIdData(authSeq, info, (uint8_t *)uuid, strlen(uuid));
}

static int32_t PostWifiV1DevId(int64_t authSeq, const AuthSessionInfo *info)
{
    if (!info->isServer) {
        ALOGE("client don't send wifi-v1 devId");
        return SOFTBUS_ERR;
    }
    char *msg = PackDeviceIdJson(info);
    if (msg == NULL) {
        ALOGE("pack devId fail");
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
        ALOGI("process v1 bt deviceIdSync");
        return PostBtV1DevId(authSeq, info);
    }
}

static int32_t PostDeviceIdNew(int64_t authSeq, const AuthSessionInfo *info)
{
    char *msg = PackDeviceIdJson(info);
    if (msg == NULL) {
        ALOGE("pack devId fail");
        return SOFTBUS_ERR;
    }
    if (PostDeviceIdData(authSeq, info, (uint8_t *)msg, strlen(msg) + 1) != SOFTBUS_OK) {
        JSON_Free(msg);
        return SOFTBUS_ERR;
    }
    JSON_Free(msg);
    return SOFTBUS_OK;
}

int32_t PostDeviceIdMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    if (info->version == SOFTBUS_OLD_V1) {
        return PostDeviceIdV1(authSeq, info);
    } else {
        return PostDeviceIdNew(authSeq, info);
    }
}

int32_t ProcessDeviceIdMessage(AuthSessionInfo *info, const uint8_t *data, uint32_t len)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) &&
        (len == DEVICE_ID_STR_LEN) &&
        (info->isServer)) {
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
        ALOGE("get session key fail.");
        return;
    }
    if (AddSessionKey(list, TO_INT32(authSeq), &sessionKey) != SOFTBUS_OK) {
        ALOGE("add session key fail.");
        return;
    }
}

int32_t PostDeviceInfoMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    char *msg = PackDeviceInfoMessage(info->connInfo.type, info->version, false, info->uuid);
    if (msg == NULL) {
        ALOGE("pack device info fail.");
        return SOFTBUS_ERR;
    }
    int32_t compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
    uint8_t *compressData = NULL;
    uint32_t compressLen = 0;
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        ALOGI("before compress, datalen:%d", strlen(msg) + 1);
        if (DataCompress((uint8_t *)msg, strlen(msg) + 1, &compressData, &compressLen) != SOFTBUS_OK) {
            compressFlag = FLAG_UNCOMPRESS_DEVICE_INFO;
        } else {
            compressFlag = FLAG_COMPRESS_DEVICE_INFO;
            ALOGI("deviceInfo compress finish");
        }
        ALOGI("after compress, datalen:%d", compressLen);
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
        ALOGE("encrypt device info fail.");
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
        ALOGE("post device info fail.");
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
        ALOGE("decrypt device info fail");
        return SOFTBUS_DECRYPT_ERR;
    }
    uint8_t *decompressData = NULL;
    uint32_t decompressLen = 0;
    if ((info->connInfo.type != AUTH_LINK_TYPE_WIFI) && info->isSupportCompress) {
        ALOGI("before decompress, msgSize:%d", msgSize);
        if (DataDecompress((uint8_t *)msg, msgSize, &decompressData, &decompressLen) != SOFTBUS_OK) {
            ALOGE("data decompress fail");
            SoftBusFree(msg);
            return SOFTBUS_ERR;
        } else {
            ALOGI("deviceInfo deCompress finish, decompress:%d", decompressLen);
        }
        ALOGI("after decompress, datalen:%d", decompressLen);
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
        ALOGE("unpack device info fail");
        SoftBusFree(msg);
        SoftBusFree(decompressData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(msg);
    SoftBusFree(decompressData);
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
        ALOGE("post close ack fail.");
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
        ALOGE("post hichain data fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *PackVerifyDeviceMessage(const char *uuid)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        ALOGE("create json fail.");
        return NULL;
    }
    if (!JSON_AddInt32ToObject(obj, CODE, CODE_VERIFY_DEVICE) ||
        !JSON_AddStringToObject(obj, DEVICE_ID, uuid)) {
        ALOGE("add uuid fail.");
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "is flush device packet not find authId");
        return false;
    }
    uint32_t decDataLen = AuthGetDecryptSize(head->len);
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        return false;
    }
    if (AuthDeviceDecrypt(authId, data, head->len, decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusFree(decData);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "parse device info decrypt fail");
        return false;
    }
    JsonObj *json = JSON_Parse((char *)decData, decDataLen);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "parse json fail.");
        SoftBusFree(decData);
        return false;
    }
    bool result = false;
    int32_t verifyDevice = 0;
    if (!JSON_GetInt32FromOject(json, CODE, &verifyDevice)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "parse device info fail");
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
    CHECK_NULL_PTR_RETURN_VALUE(auth, SOFTBUS_INVALID_PARAM);
    char *msg = PackVerifyDeviceMessage(auth->uuid);
    if (msg == NULL) {
        ALOGE("pack verify device msg fail.");
        return SOFTBUS_ERR;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (EncryptInner(&auth->sessionKeyList, (uint8_t *)msg, strlen(msg) + 1, &data, &dataLen) != SOFTBUS_OK) {
        ALOGE("encrypt device info fail.");
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
        ALOGE("post verify device msg fail.");
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}
