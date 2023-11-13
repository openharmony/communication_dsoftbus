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

#include "lnn_heartbeat_utils.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_device_info.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_log.h"
#include "wifi_direct_manager.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType)
{
    switch (addrType) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
            return HEARTBEAT_TYPE_UDP;
        case CONNECTION_ADDR_BR:
        case CONNECTION_ADDR_BLE:
            return HEARTBEAT_TYPE_BLE_V1;
        default:
            break;
    }
    return HEARTBEAT_TYPE_MAX;
}

ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type)
{
    switch (type) {
        case HEARTBEAT_TYPE_UDP:
        case HEARTBEAT_TYPE_TCP_FLUSH:
            return CONNECTION_ADDR_WLAN;
        case HEARTBEAT_TYPE_BLE_V1:
        case HEARTBEAT_TYPE_BLE_V0:
            return CONNECTION_ADDR_BLE;
        default:
            break;
    }
    return CONNECTION_ADDR_MAX;
}

int32_t LnnConvertHbTypeToId(LnnHeartbeatType type)
{
    int32_t cnt = -1;

    if (type < HEARTBEAT_TYPE_MIN || type >= HEARTBEAT_TYPE_MAX) {
        return HB_INVALID_TYPE_ID;
    }
    do {
        type >>= 1;
        ++cnt;
    } while (type >= HEARTBEAT_TYPE_MIN);
    if (cnt < 0 || cnt > HB_MAX_TYPE_COUNT) {
        return HB_INVALID_TYPE_ID;
    }
    return cnt;
}

static bool HbHasActiveBrConnection(const char *networkId)
{
    bool ret = false;
    ConnectOption option = {0};
    char brMac[BT_MAC_LEN] = {0};

    uint8_t binaryAddr[BT_ADDR_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, sizeof(brMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get bt mac err");
        return false;
    }
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, brMac) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB strcpy_s bt mac err");
        return false;
    }
    if (ConvertBtMacToBinary(brMac, BT_ADDR_LEN, binaryAddr, BT_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB convert bt mac err");
        return false;
    }
    ret = CheckActiveConnection(&option);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active bt connection=%s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveBleConnection(const char *networkId)
{
    bool ret = false;
    ConnectOption option = {0};
    char udid[UDID_BUF_LEN] = {0};
    char udidHash[UDID_HASH_LEN] = {0};

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get udid err");
        return false;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid),
        (unsigned char *)udidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get udid hash err");
        return false;
    }
    option.type = CONNECT_BLE;
    if (memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udidHash, sizeof(udidHash)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB memcpy_s udid hash err");
        return false;
    }
    ret = CheckActiveConnection(&option);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active ble connection=%s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveP2pConnection(const char *networkId)
{
    char peerMac[MAC_ADDR_STR_LEN] = {0};

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, peerMac, sizeof(peerMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get peer p2p mac err");
        return false;
    }
    bool isOnline = GetWifiDirectManager()->isDeviceOnline(peerMac);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active p2p connection=%s", isOnline ? "true" : "false");
    return isOnline;
}

bool LnnHasActiveConnection(const char *networkId, ConnectionAddrType addrType)
{
    bool ret = false;

    if (networkId == NULL || addrType >= CONNECTION_ADDR_MAX) {
        LNN_LOGE(LNN_HEART_BEAT, "HB check active connection get invalid param");
        return ret;
    }

    switch (addrType) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
        case CONNECTION_ADDR_BR:
            break;
        case CONNECTION_ADDR_BLE:
            ret = HbHasActiveBrConnection(networkId) || HbHasActiveBleConnection(networkId) ||
                HbHasActiveP2pConnection(networkId);
            char *anonyNetworkId = NULL;
            Anonymize(networkId, &anonyNetworkId);
            LNN_LOGI(LNN_HEART_BEAT, "HB networkId=%s has active BT/BLE/P2P connection=%s",
                anonyNetworkId, ret ? "true" : "false");
            AnonymizeFree(anonyNetworkId);
            return ret;
        default:
            break;
    }
    return false;
}

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data)
{
    bool isFinish = false;
    LnnHeartbeatType i;

    if (typeSet == NULL || *typeSet < HEARTBEAT_TYPE_MIN || *typeSet >= HEARTBEAT_TYPE_MAX) {
        LNN_LOGE(LNN_HEART_BEAT, "HB visit typeSet get invalid param");
        return false;
    }
    for (i = HEARTBEAT_TYPE_MIN; i < HEARTBEAT_TYPE_MAX; i <<= 1) {
        if ((i & *typeSet) == 0) {
            continue;
        }
        isFinish = callback(typeSet, i, data);
        if (!isFinish) {
            return false;
        }
    }
    return true;
}

static bool VisitCheckSupportedHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    LnnHeartbeatType *dstType = (LnnHeartbeatType *)data;

    if ((eachType & *dstType) == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB not support hbType=%d completely", *dstType);
        return false;
    }
    return true;
}

bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType)
{
    if (srcType == NULL || dstType == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB check supported hbType get invalid param");
        return false;
    }
    return LnnVisitHbTypeSet(VisitCheckSupportedHbType, srcType, dstType);
}

int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len)
{
    int32_t ret;
    uint8_t hashResult[SHA_256_HASH_LEN] = {0};

    if (str == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB generate str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB generate str hash fail, ret=%d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, len + 1, hashResult, len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB convert bytes to str hash fail ret=%d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetShortAccountHash(uint8_t *accountHash, uint32_t len)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};

    if (accountHash == NULL || len < HB_SHORT_ACCOUNT_HASH_LEN || len > SHA_256_HASH_LEN) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get accountHash get invaild param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get local accountHash fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(accountHash, len, localAccountHash, len) != EOK) {
        LNN_LOGI(LNN_HEART_BEAT, "HB get accountHash memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGD(LNN_HEART_BEAT, "HB get accountHash [%02x %02x]", accountHash[0], accountHash[1]);
    return SOFTBUS_OK;
}

int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen)
{
    if (btMac == NULL || brMacHash == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "null point");
        return SOFTBUS_ERR;
    }
    if (brMacLen != BT_MAC_LEN || hashLen != BT_MAC_HASH_STR_LEN) {
        LNN_LOGE(LNN_HEART_BEAT, "invaild len");
        return SOFTBUS_ERR;
    }
    uint8_t btMacBin[BT_ADDR_LEN] = {0};
    char btMacStr[BT_MAC_NO_COLON_LEN] = {0};
    char hashLower[BT_MAC_HASH_STR_LEN] = {0};
    char hash[BT_MAC_HASH_LEN] = {0};
    if (ConvertBtMacToBinary(btMac, BT_MAC_LEN, btMacBin, BT_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "convert br mac to bin fail");
        return SOFTBUS_ERR;
    }
    if (ConvertBtMacToStrNoColon(btMacStr, BT_MAC_NO_COLON_LEN, btMacBin, BT_ADDR_LEN)) {
        LNN_LOGE(LNN_HEART_BEAT, "convert br mac to str fail");
        return SOFTBUS_ERR;
    }
    char brMacUpper[BT_MAC_NO_COLON_LEN] = {0};
    if (StringToUpperCase(btMacStr, brMacUpper, BT_MAC_NO_COLON_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "bt mac to upperCase fail");
        return SOFTBUS_ERR;
    }
    char *anonyMac = NULL;
    Anonymize(brMacUpper, &anonyMac);
    LNN_LOGI(LNN_HEART_BEAT, "upper BrMac=**:**:**:**:%s", anonyMac);
    AnonymizeFree(anonyMac);
    if (SoftBusGenerateStrHash((const unsigned char *)brMacUpper, strlen(brMacUpper), (unsigned char *)hash)) {
        LNN_LOGE(LNN_HEART_BEAT, "Generate brMac hash fail");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(hashLower, BT_MAC_HASH_STR_LEN, (const uint8_t *)hash,
        BT_MAC_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ConvertBytesToHexString failed");
        return SOFTBUS_ERR;
    }
    if (StringToUpperCase(hashLower, brMacHash, BT_MAC_HASH_STR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "bt mac to upperCase fail");
        return SOFTBUS_ERR;
    }
    char *anonyUdid = NULL;
    Anonymize(brMacHash, &anonyUdid);
    LNN_LOGI(LNN_HEART_BEAT, "brmacHash=%s", anonyUdid);
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

void LnnDumpLocalBasicInfo(void)
{
    char *anonyIp = NULL;
    char *anonyBtMac = NULL;
    char *anonyNetworkId = NULL;
    char *anonyP2pMac = NULL;
    char localIp[IP_LEN] = {0};
    char localP2PMac[MAC_LEN] = {0};
    char localBtMac[BT_MAC_LEN] = {0};
    int32_t onlineNodeNum = 0;
    NodeBasicInfo localInfo = {0};
    Anonymize(localInfo.networkId, &anonyNetworkId);
    (void)LnnGetLocalDeviceInfo(&localInfo);
    LNN_LOGI(LNN_HEART_BEAT, "local DeviceInfo [networkId=%s]", anonyNetworkId);
    const char *devTypeStr = LnnConvertIdToDeviceType(localInfo.deviceTypeId);
    (void)LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_P2P_MAC, localP2PMac, MAC_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_BT_MAC, localBtMac, BT_MAC_LEN);
    (void)LnnGetAllOnlineNodeNum(&onlineNodeNum);
    Anonymize(localBtMac, &anonyBtMac);
    Anonymize(localIp, &anonyIp);
    Anonymize(localP2PMac, &anonyP2pMac);
    LNN_LOGI(LNN_HEART_BEAT, "devType=%s, deviceTypeId=%hu, deviceName=%s, ip=..*%s, brMac=::%s, p2pMac=::%s, "
        "onlineNodeNum=%d]", devTypeStr, localInfo.deviceTypeId, localInfo.deviceName,
        anonyIp, anonyBtMac, anonyP2pMac, onlineNodeNum);
    AnonymizeFree(anonyIp);
    AnonymizeFree(anonyBtMac);
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyP2pMac);
}
