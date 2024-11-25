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
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "wifi_direct_manager.h"

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
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    char brMac[BT_MAC_LEN] = { 0 };
    uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, sizeof(brMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get bt mac err");
        return false;
    }
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, brMac) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB strcpy_s bt mac err");
        return false;
    }
    if (ConvertBtMacToBinary(brMac, sizeof(brMac), binaryAddr, BT_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB convert bt mac err");
        return false;
    }
    ret = CheckActiveConnection(&option, false);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active bt connection=%{public}s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveBleConnection(const char *networkId)
{
    bool ret = false;
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    char udid[UDID_BUF_LEN] = { 0 };
    char udidHash[UDID_HASH_LEN] = { 0 };

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get udid err");
        return false;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), (unsigned char *)udidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get udid hash err");
        return false;
    }
    option.type = CONNECT_BLE;
    if (memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udidHash, sizeof(udidHash)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB memcpy_s udid hash err");
        return false;
    }
    ret = CheckActiveConnection(&option, false);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active ble connection=%{public}s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveP2pConnection(const char *networkId)
{
    char peerMac[MAC_ADDR_STR_LEN] = { 0 };
    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB not support wifi direct");
        return false;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, peerMac, sizeof(peerMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get peer p2p mac err");
        return false;
    }
    bool isOnline = pManager->isDeviceOnline(peerMac);
    LNN_LOGD(LNN_HEART_BEAT, "HB has active p2p connection=%{public}s", isOnline ? "true" : "false");
    return isOnline;
}

static bool HbHasActiveHmlConnection(const char *networkId)
{
    NodeInfo info;
    char myIp[IP_LEN] = { 0 };
    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB not support wifi direct");
        return false;
    }
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get node info fail");
        return false;
    }
    if (pManager->getLocalIpByUuid(info.uuid, myIp, sizeof(myIp)) == SOFTBUS_OK) {
        LNN_LOGI(LNN_HEART_BEAT, "HB get HML ip success");
        return true;
    }
    return false;
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
                HbHasActiveP2pConnection(networkId) || HbHasActiveHmlConnection(networkId);
            char *anonyNetworkId = NULL;
            Anonymize(networkId, &anonyNetworkId);
            LNN_LOGI(LNN_HEART_BEAT, "HB has active BT/BLE/P2P/HML connection. networkId=%{public}s, ret=%{public}s",
                AnonymizeWrapper(anonyNetworkId), ret ? "true" : "false");
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
    LnnHeartbeatType tmp = *typeSet;
    for (i = HEARTBEAT_TYPE_MIN; i < HEARTBEAT_TYPE_MAX; i <<= 1) {
        if ((i & tmp) == 0) {
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
        LNN_LOGE(LNN_HEART_BEAT, "HB not support hbType=%{public}d completely", *dstType);
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
    uint8_t hashResult[SHA_256_HASH_LEN] = { 0 };

    if (str == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB generate str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB generate str hash fail, ret=%{public}d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, len + 1, hashResult, len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB convert bytes to str hash fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetShortAccountHash(uint8_t *accountHash, uint32_t len)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };

    if (accountHash == NULL || len < HB_SHORT_ACCOUNT_HASH_LEN || len > SHA_256_HASH_LEN) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get accountHash get invaild param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get local accountHash fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (memcpy_s(accountHash, len, localAccountHash, len) != EOK) {
        LNN_LOGI(LNN_HEART_BEAT, "HB get accountHash memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGD(LNN_HEART_BEAT, "HB get accountHash=[%{public}02x, %{public}02x]", accountHash[0], accountHash[1]);
    return SOFTBUS_OK;
}

int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen)
{
    if (btMac == NULL || brMacHash == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "null point");
        return SOFTBUS_INVALID_PARAM;
    }
    if (brMacLen != BT_MAC_LEN || hashLen != BT_MAC_HASH_STR_LEN) {
        LNN_LOGE(LNN_HEART_BEAT, "invaild len");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t btMacBin[BT_ADDR_LEN] = { 0 };
    char btMacStr[BT_MAC_NO_COLON_LEN] = { 0 };
    char hashLower[BT_MAC_HASH_STR_LEN] = { 0 };
    char hash[SHA_256_HASH_LEN] = { 0 };
    if (ConvertBtMacToBinary(btMac, BT_MAC_LEN, btMacBin, BT_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "convert br mac to bin fail");
        return SOFTBUS_NETWORK_MAC_TO_BIN_ERR;
    }
    if (ConvertBtMacToStrNoColon(btMacStr, BT_MAC_NO_COLON_LEN, btMacBin, BT_ADDR_LEN)) {
        LNN_LOGE(LNN_HEART_BEAT, "convert br mac to str fail");
        return SOFTBUS_NETWORK_MAC_TO_STR_ERR;
    }
    char brMacUpper[BT_MAC_NO_COLON_LEN] = { 0 };
    if (StringToUpperCase(btMacStr, brMacUpper, BT_MAC_NO_COLON_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "bt mac to upperCase fail");
        return SOFTBUS_NETWORK_STR_TO_UPPER_ERR;
    }
    char *anonyMac = NULL;
    Anonymize(brMacUpper, &anonyMac);
    LNN_LOGI(LNN_HEART_BEAT, "upper BrMac=**:**:**:**:%{public}s", AnonymizeWrapper(anonyMac));
    AnonymizeFree(anonyMac);
    if (SoftBusGenerateStrHash((const unsigned char *)brMacUpper, strlen(brMacUpper), (unsigned char *)hash)) {
        LNN_LOGE(LNN_HEART_BEAT, "Generate brMac hash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(hashLower, BT_MAC_HASH_STR_LEN, (const uint8_t *)hash, BT_MAC_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ConvertBytesToHexString failed");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (StringToUpperCase(hashLower, brMacHash, BT_MAC_HASH_STR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "bt mac to upperCase fail");
        return SOFTBUS_NETWORK_STR_TO_UPPER_ERR;
    }
    char *anonyUdid = NULL;
    Anonymize(brMacHash, &anonyUdid);
    LNN_LOGI(LNN_HEART_BEAT, "brmacHash=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

bool LnnIsSupportBurstFeature(const char *networkId)
{
    uint64_t localFeature;
    uint64_t peerFeature;

    if (networkId == NULL) {
        return false;
    }
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature) != SOFTBUS_OK ||
        LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, &peerFeature) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get local or remote feature fail");
        return false;
    }
    return IsFeatureSupport(localFeature, BIT_BLE_SUPPORT_LP_HEARTBEAT) &&
        IsFeatureSupport(peerFeature, BIT_BLE_SUPPORT_LP_HEARTBEAT);
}

bool LnnIsLocalSupportBurstFeature(void)
{
    uint64_t localFeature;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get local feature fail");
        return false;
    }
    return IsFeatureSupport(localFeature, BIT_BLE_SUPPORT_LP_HEARTBEAT);
}

void LnnDumpLocalBasicInfo(void)
{
    char *anonyIp = NULL;
    char *anonyBtMac = NULL;
    char *anonyUdidHash = NULL;
    char *anonyNetworkId = NULL;
    char *anonyP2pMac = NULL;
    char *anonyUdid = NULL;
    char *anonyUuid = NULL;
    char *anonyDeviceName = NULL;
    char localIp[IP_LEN] = { 0 };
    char localP2PMac[MAC_LEN] = { 0 };
    char localBtMac[BT_MAC_LEN] = { 0 };
    char localUdid[UDID_BUF_LEN] = { 0 };
    char localUuid[UUID_BUF_LEN] = { 0 };
    char udidShortHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t onlineNodeNum = 0;
    NodeBasicInfo localInfo = { 0 };

    (void)LnnGetLocalDeviceInfo(&localInfo);
    (void)LnnGetLocalStrInfo(STRING_KEY_UUID, localUuid, UUID_BUF_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    (void)LnnGenerateHexStringHash((const unsigned char *)localUdid, udidShortHash, HB_SHORT_UDID_HASH_HEX_LEN);
    Anonymize(udidShortHash, &anonyUdidHash);
    Anonymize(localUuid, &anonyUuid);
    Anonymize(localUdid, &anonyUdid);
    Anonymize(localInfo.networkId, &anonyNetworkId);
    LNN_LOGW(LNN_HEART_BEAT, "local DeviceInfo, uuid=%{public}s, udid=%{public}s, udidShortHash=%{public}s, "
        "networkId=%{public}s", AnonymizeWrapper(anonyUuid), AnonymizeWrapper(anonyUdid),
        AnonymizeWrapper(anonyUdidHash), AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyUuid);
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyUdidHash);
    AnonymizeFree(anonyNetworkId);
    const char *devTypeStr = LnnConvertIdToDeviceType(localInfo.deviceTypeId);
    (void)LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_P2P_MAC, localP2PMac, MAC_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_BT_MAC, localBtMac, BT_MAC_LEN);
    (void)LnnGetAllOnlineNodeNum(&onlineNodeNum);
    Anonymize(localIp, &anonyIp);
    Anonymize(localBtMac, &anonyBtMac);
    Anonymize(localP2PMac, &anonyP2pMac);
    Anonymize(localInfo.deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_HEART_BEAT, "devType=%{public}s, deviceTypeId=%{public}hu, deviceName=%{public}s, ip=%{public}s, "
        "brMac=%{public}s, p2pMac=%{public}s, onlineNodeNum=%{public}d", devTypeStr, localInfo.deviceTypeId,
        AnonymizeWrapper(anonyDeviceName), AnonymizeWrapper(anonyIp), AnonymizeWrapper(anonyBtMac),
        AnonymizeWrapper(anonyP2pMac), onlineNodeNum);
    AnonymizeFree(anonyDeviceName);
    AnonymizeFree(anonyIp);
    AnonymizeFree(anonyBtMac);
    AnonymizeFree(anonyP2pMac);
}

static int32_t LnnDumpPrintUdid(const char *networkId)
{
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get udid failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    char *tmpUdid = NULL;
    Anonymize(udid, &tmpUdid);
    LNN_LOGI(LNN_HEART_BEAT, "Udid=%{public}s", AnonymizeWrapper(tmpUdid));
    AnonymizeFree(tmpUdid);
    return SOFTBUS_OK;
}

static int32_t LnnDumpPrintUuid(const char *networkId)
{
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get uuid failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    char *tmpUuid = NULL;
    Anonymize(uuid, &tmpUuid);
    LNN_LOGI(LNN_HEART_BEAT, "Uuid=%{public}s", AnonymizeWrapper(tmpUuid));
    AnonymizeFree(tmpUuid);
    return SOFTBUS_OK;
}

static int32_t LnnDumpPrintMac(const char *networkId)
{
    char brMac[BT_MAC_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, BT_MAC_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get brMac failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    char *tmpBrMac = NULL;
    Anonymize(brMac, &tmpBrMac);
    LNN_LOGI(LNN_HEART_BEAT, "BrMac=%{public}s", AnonymizeWrapper(tmpBrMac));
    AnonymizeFree(tmpBrMac);
    return SOFTBUS_OK;
}

static int32_t LnnDumpPrintIp(const char *networkId)
{
    char ipAddr[IP_STR_MAX_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_WLAN_IP, ipAddr, IP_STR_MAX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get ipAddr failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    char *tmpIpAddr = NULL;
    Anonymize(ipAddr, &tmpIpAddr);
    LNN_LOGI(LNN_HEART_BEAT, "IpAddr=%{public}s", AnonymizeWrapper(tmpIpAddr));
    AnonymizeFree(tmpIpAddr);
    return SOFTBUS_OK;
}

static int32_t LnnDumpPrintNetCapacity(const char *networkId)
{
    uint32_t netCapacity = 0;
    if (LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, &netCapacity) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get netCapacity failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LNN_LOGI(LNN_HEART_BEAT, "NetCapacity=%{public}u", netCapacity);
    return SOFTBUS_OK;
}

static int32_t LnnDumpPrintNetType(const char *networkId)
{
    int32_t netType = 0;
    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_DISCOVERY_TYPE, &netType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get netType fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LNN_LOGI(LNN_HEART_BEAT, "NetType=%{public}d", netType);
    return SOFTBUS_OK;
}

static void LnnDumpOnlinePrintInfo(NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "param is null");
        return;
    }
    char *anonyDeviceName = NULL;
    Anonymize(nodeInfo->deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_HEART_BEAT, "DeviceName=%{public}s", AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyDeviceName);
    char *tmpNetWorkId = NULL;
    Anonymize(nodeInfo->networkId, &tmpNetWorkId);
    LNN_LOGI(LNN_HEART_BEAT, "NetworkId=%{public}s", AnonymizeWrapper(tmpNetWorkId));
    AnonymizeFree(tmpNetWorkId);
    if (LnnDumpPrintUdid(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintUdid failed");
        return;
    }
    if (LnnDumpPrintUuid(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintUuid failed");
        return;
    }
    if (LnnDumpPrintMac(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintMac failed");
        return;
    }
    if (LnnDumpPrintIp(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintMac failed");
        return;
    }
    if (LnnDumpPrintNetCapacity(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintNetCapacity failed");
        return;
    }
    if (LnnDumpPrintNetType(nodeInfo->networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LnnDumpPrintNetType failed");
        return;
    }
}

void LnnDumpOnlineDeviceInfo(void)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "Lnn get online node fail");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "online count is zero");
        return;
    }
    LNN_LOGI(LNN_HEART_BEAT, "online device num=%{public}d", infoNum);
    for (int32_t i = 0; i < infoNum; i++) {
        LNN_LOGI(LNN_HEART_BEAT, "[NO.%{public}d]", i + 1);
        LnnDumpOnlinePrintInfo(info + i);
    }
    SoftBusFree(info);
}

uint32_t GenerateRandomNumForHb(uint32_t randMin, uint32_t randMax)
{
    if (randMin >= randMax) {
        return randMin - randMax;
    }

    time_t currTime = time(NULL);
    if (currTime == 0) {
        LNN_LOGI(LNN_HEART_BEAT, "seed is 0, just ignore");
    }
    srand(currTime);
    uint32_t random = (uint32_t)rand() % (randMax - randMin);
    return randMin + random;
}

static int32_t GetOnlineInfoNum(int32_t *nums)
{
    int32_t infoNum = 0;
    NodeBasicInfo *netInfo = NULL;
    if (LnnGetAllOnlineNodeInfo(&netInfo, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get all online node info fail.");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    }
    if (netInfo == NULL || infoNum == 0) {
        LNN_LOGI(LNN_BUILDER, "online device num is 0, not need to send network info");
        return SOFTBUS_NO_ONLINE_DEVICE;
    }
    *nums = infoNum;
    LNN_LOGD(LNN_HEART_BEAT, "online nums=%{public}d", infoNum);
    SoftBusFree(netInfo);
    return SOFTBUS_OK;
}

bool LnnIsMultiDeviceOnline(void)
{
    int32_t onlineNum = 0;

    return GetOnlineInfoNum(&onlineNum) == SOFTBUS_OK && onlineNum >= HB_MULTI_DEVICE_THRESHOLD;
}

bool LnnIsSupportHeartbeatCap(uint32_t hbCapacity, HeartbeatCapability capaBit)
{
    return ((hbCapacity & (1 << (uint32_t) capaBit)) != 0);
}