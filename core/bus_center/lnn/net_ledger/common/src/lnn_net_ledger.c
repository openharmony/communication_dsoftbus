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

#include "lnn_net_ledger.h"

#include <string.h>
#include <securec.h>

#include "anonymizer.h"
#include "auth_device_common_key.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_decision_db.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_feature_capability.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_interface.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_p2p_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_mem.h"
#include "lnn_oobe_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

static bool g_isRestore = false;

int32_t LnnInitNetLedger(void)
{
    if (LnnInitHuksInterface() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init huks interface fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitLocalLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local net ledger fail!");
        return SOFTBUS_ERR;
    }
    if (LnnInitDistributedLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init distributed net ledger fail!");
        return SOFTBUS_ERR;
    }
    if (LnnInitMetaNodeLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init meta node ledger fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitMetaNodeExtLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init meta node ext ledger fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsBleDirectlyOnlineFactorChange(NodeInfo *info)
{
    char softBusVersion[VERSION_MAX_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, softBusVersion, sizeof(softBusVersion)) == SOFTBUS_OK) {
        if (strcmp(softBusVersion, info->softBusVersion) != 0) {
            LNN_LOGW(LNN_LEDGER, "softbus version=%{public}s->%{public}s", softBusVersion, info->softBusVersion);
            return true;
        }
    }
    uint64_t softbusFeature = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &softbusFeature) == SOFTBUS_OK) {
        if (softbusFeature != info->feature) {
            LNN_LOGW(LNN_LEDGER, "feature=%{public}" PRIu64 "->%{public}" PRIu64, info->feature, softbusFeature);
            return true;
        }
    }
    char *anonyNewUuid = NULL;
    char uuid[UUID_BUF_LEN] = { 0 };
    if ((LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) == SOFTBUS_OK) && (strcmp(uuid, info->uuid) != 0)) {
        Anonymize(info->uuid, &anonyNewUuid);
        LNN_LOGW(LNN_LEDGER, "uuid change, new=%{public}s", anonyNewUuid);
        AnonymizeFree(anonyNewUuid);
        return true;
    }
    int32_t osType = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_OS_TYPE, &osType) == SOFTBUS_OK) {
        if (osType != info->deviceInfo.osType) {
            LNN_LOGW(LNN_LEDGER, "osType=%{public}d->%{public}d", info->deviceInfo.osType, osType);
            return true;
        }
    }
    uint32_t authCapacity = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_AUTH_CAP, &authCapacity) == SOFTBUS_OK) {
        if (authCapacity != info->authCapacity) {
            LNN_LOGW(LNN_LEDGER, "authCapacity=%{public}d->%{public}d", info->authCapacity, authCapacity);
            return true;
        }
    }
    int32_t level = 0;
    if ((LnnGetLocalNumInfo(NUM_KEY_DEVICE_SECURITY_LEVEL, &level) == SOFTBUS_OK) &&
        (level != info->deviceSecurityLevel)) {
        LNN_LOGW(LNN_LEDGER, "deviceSecurityLevel=%{public}d->%{public}d", info->deviceSecurityLevel, level);
        return true;
    }
    return false;
}

static void LnnSetLocalFeature(void)
{
    if (IsSupportLpFeature()) {
        uint64_t feature = 1 << BIT_BLE_SUPPORT_SENSORHUB_HEARTBEAT;
        if (LnnSetLocalNum64Info(NUM_KEY_FEATURE_CAPA, feature) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set feature fail");
        }
    } else {
        LNN_LOGE(LNN_LEDGER, "not support mlps");
    }
}

static void ProcessLocalDeviceInfo(void)
{
    g_isRestore = true;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)LnnGetLocalDevInfo(&info);
    LnnDumpNodeInfo(&info, "load local deviceInfo success");
    if (IsBleDirectlyOnlineFactorChange(&info)) {
        info.stateVersion++;
        LnnSaveLocalDeviceInfo(&info);
    }
    LNN_LOGI(LNN_LEDGER, "load local deviceInfo stateVersion=%{public}d", info.stateVersion);
    if (LnnSetLocalNumInfo(NUM_KEY_STATE_VERSION, info.stateVersion) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set state version fail");
    }
    if (LnnUpdateLocalNetworkId(info.networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set networkId fail");
    }
    LnnNotifyNetworkIdChangeEvent(info.networkId);
    LnnNotifyLocalNetworkIdChanged();
    if (info.networkIdTimestamp != 0) {
        LnnUpdateLocalNetworkIdTime(info.networkIdTimestamp);
        LNN_LOGD(LNN_LEDGER, "update networkIdTimestamp=%" PRId64, info.networkIdTimestamp);
    }
}

void RestoreLocalDeviceInfo(void)
{
    LNN_LOGI(LNN_LEDGER, "restore local device info enter");
    LnnSetLocalFeature();
    if (g_isRestore) {
        LNN_LOGI(LNN_LEDGER, "aready init");
        return;
    }
    if (LnnLoadLocalDeviceInfo() != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "get local device info fail");
        const NodeInfo *temp = LnnGetLocalNodeInfo();
        if (LnnSaveLocalDeviceInfo(temp) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "save local device info fail");
        } else {
            LNN_LOGI(LNN_LEDGER, "save local device info success");
        }
    } else {
        ProcessLocalDeviceInfo();
    }
    AuthLoadDeviceKey();
    LnnLoadPtkInfo();
    if (LnnLoadRemoteDeviceInfo() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "load remote deviceInfo fail");
        return;
    }
    LoadBleBroadcastKey();
    LnnLoadLocalBroadcastCipherKey();
}

int32_t LnnInitNetLedgerDelay(void)
{
    LnnLoadLocalDeviceAccountIdInfo();
    RestoreLocalDeviceInfo();
    if (LnnInitLocalLedgerDelay() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init local ledger fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitDecisionDbDelay() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init decision db fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitEventMoniterDelay(void)
{
    if (LnnInitCommonEventMonitorImpl() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init LnnInitCommonEventMonitorImpl fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitDeviceNameMonitorImpl() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init LnnInitDeviceNameMonitorImpl fail");
        return SOFTBUS_ERR;
    }
    LnnInitOOBEStateMonitorImpl();
    return SOFTBUS_OK;
}

void LnnDeinitNetLedger(void)
{
    LnnDeinitMetaNodeLedger();
    LnnDeinitDistributedLedger();
    LnnDeinitLocalLedger();
    LnnDeinitHuksInterface();
    LnnDeinitMetaNodeExtLedger();
    LnnDeInitCloudSyncModule();
}

static int32_t LnnGetNodeKeyInfoLocal(const char *networkId, int key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_ERR;
    }
    switch (key) {
        case NODE_KEY_UDID:
            return LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, (char *)info, infoLen);
        case NODE_KEY_UUID:
            return LnnGetLocalStrInfo(STRING_KEY_UUID, (char *)info, infoLen);
        case NODE_KEY_MASTER_UDID:
            return LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, (char *)info, infoLen);
        case NODE_KEY_BR_MAC:
            return LnnGetLocalStrInfo(STRING_KEY_BT_MAC, (char *)info, infoLen);
        case NODE_KEY_IP_ADDRESS:
            return LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, (char *)info, infoLen);
        case NODE_KEY_DEV_NAME:
            return LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, (char *)info, infoLen);
        case NODE_KEY_BLE_OFFLINE_CODE:
            return LnnGetLocalStrInfo(STRING_KEY_OFFLINE_CODE, (char *)info, infoLen);
        case NODE_KEY_NETWORK_CAPABILITY:
            return LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, (uint32_t *)info);
        case NODE_KEY_NETWORK_TYPE:
            return LnnGetLocalNumInfo(NUM_KEY_DISCOVERY_TYPE, (int32_t *)info);
        case NODE_KEY_DATA_CHANGE_FLAG:
            return LnnGetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, (int16_t *)info);
        case NODE_KEY_NODE_ADDRESS:
            return LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, (char *)info, infoLen);
        case NODE_KEY_P2P_IP_ADDRESS:
            return LnnGetLocalStrInfo(STRING_KEY_P2P_IP, (char *)info, infoLen);
        case NODE_KEY_DEVICE_SECURITY_LEVEL:
            return LnnGetLocalNumInfo(NUM_KEY_DEVICE_SECURITY_LEVEL, (int32_t *)info);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_ERR;
    }
}

static int32_t LnnGetNodeKeyInfoRemote(const char *networkId, int key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_ERR;
    }
    switch (key) {
        case NODE_KEY_UDID:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, (char *)info, infoLen);
        case NODE_KEY_UUID:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, (char *)info, infoLen);
        case NODE_KEY_BR_MAC:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, (char *)info, infoLen);
        case NODE_KEY_IP_ADDRESS:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_WLAN_IP, (char *)info, infoLen);
        case NODE_KEY_DEV_NAME:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_NAME, (char *)info, infoLen);
        case NODE_KEY_BLE_OFFLINE_CODE:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_OFFLINE_CODE, (char *)info, infoLen);
        case NODE_KEY_NETWORK_CAPABILITY:
            return LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, (uint32_t *)info);
        case NODE_KEY_NETWORK_TYPE:
            return LnnGetRemoteNumInfo(networkId, NUM_KEY_DISCOVERY_TYPE, (int32_t *)info);
        case NODE_KEY_DATA_CHANGE_FLAG:
            return LnnGetRemoteNum16Info(networkId, NUM_KEY_DATA_CHANGE_FLAG, (int16_t *)info);
        case NODE_KEY_NODE_ADDRESS:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_NODE_ADDR, (char *)info, infoLen);
        case NODE_KEY_P2P_IP_ADDRESS:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_IP, (char *)info, infoLen);
        case NODE_KEY_DEVICE_SECURITY_LEVEL:
            return LnnGetRemoteNumInfo(networkId, NUM_KEY_DEVICE_SECURITY_LEVEL, (int32_t *)info);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_ERR;
    }
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int key, uint8_t *info, uint32_t infoLen)
{
    bool isLocalNetworkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id fail");
        return SOFTBUS_ERR;
    }
    if (strncmp(localNetworkId, networkId, NETWORK_ID_BUF_LEN) == 0) {
        isLocalNetworkId = true;
    }
    if (isLocalNetworkId) {
        return LnnGetNodeKeyInfoLocal(networkId, key, info, infoLen);
    } else {
        return LnnGetNodeKeyInfoRemote(networkId, key, info, infoLen);
    }
}

int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag)
{
    bool isLocalNetworkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (networkId == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id fail");
        return SOFTBUS_ERR;
    }
    if (strncmp(localNetworkId, networkId, NETWORK_ID_BUF_LEN) == 0) {
        isLocalNetworkId = true;
    }
    if (isLocalNetworkId) {
        return LnnSetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, (int16_t)dataChangeFlag);
    }
    LNN_LOGE(LNN_LEDGER, "remote networkId");
    return SOFTBUS_ERR;
}

int32_t LnnSetDataLevel(const DataLevel *dataLevel, bool *isSwitchLevelChanged)
{
    if (dataLevel == NULL || isSwitchLevelChanged == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnSetDataLevel data level or switch level change flag is null");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "LnnSetDataLevel, dynamic: %{public}hu, static: %{public}hu, "
        "switch: %{public}u, switchLen: %{public}hu", dataLevel->dynamicLevel, dataLevel->staticLevel,
        dataLevel->switchLevel, dataLevel->switchLength);
    uint16_t dynamicLevel = dataLevel->dynamicLevel;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, dynamicLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data dynamic level failed");
        return SOFTBUS_ERR;
    }
    uint16_t staticLevel = dataLevel->staticLevel;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_STATIC_LEVEL, staticLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data static level failed");
        return SOFTBUS_ERR;
    }
    uint32_t curSwitchLevel = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, &curSwitchLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Get current data switch level faield");
        return SOFTBUS_ERR;
    }
    uint32_t switchLevel = dataLevel->switchLevel;
    if (LnnSetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, switchLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data switch level faield");
        return SOFTBUS_ERR;
    }
    uint16_t switchLength = dataLevel->switchLength;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_SWITCH_LENGTH, switchLength) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data switch length failed");
        return SOFTBUS_ERR;
    }
    *isSwitchLevelChanged = (curSwitchLevel != switchLevel);
    return SOFTBUS_OK;
}

int32_t LnnGetNodeKeyInfoLen(int32_t key)
{
    switch (key) {
        case NODE_KEY_UDID:
            return UDID_BUF_LEN;
        case NODE_KEY_UUID:
            return UUID_BUF_LEN;
        case NODE_KEY_MASTER_UDID:
            return UDID_BUF_LEN;
        case NODE_KEY_BR_MAC:
            return MAC_LEN;
        case NODE_KEY_IP_ADDRESS:
            return IP_LEN;
        case NODE_KEY_DEV_NAME:
            return DEVICE_NAME_BUF_LEN;
        case NODE_KEY_NETWORK_CAPABILITY:
            return LNN_COMMON_LEN;
        case NODE_KEY_NETWORK_TYPE:
            return LNN_COMMON_LEN;
        case NODE_KEY_DATA_CHANGE_FLAG:
            return DATA_CHANGE_FLAG_BUF_LEN;
        case NODE_KEY_NODE_ADDRESS:
            return SHORT_ADDRESS_MAX_LEN;
        case NODE_KEY_P2P_IP_ADDRESS:
            return IP_LEN;
        case NODE_KEY_DEVICE_SECURITY_LEVEL:
            return LNN_COMMON_LEN;
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_ERR;
    }
}

int32_t SoftbusDumpPrintUdid(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_UDID;
    unsigned char udid[UDID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, udid, UDID_BUF_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Udid failed");
        return SOFTBUS_ERR;
    }
    char *anonyUdid = NULL;
    Anonymize((char *)udid, &anonyUdid);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "Udid", anonyUdid);
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintUuid(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_UUID;
    unsigned char uuid[UUID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, uuid, UUID_BUF_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Uuid failed");
        return SOFTBUS_ERR;
    }
    char *anonyUuid = NULL;
    Anonymize((char *)uuid, &anonyUuid);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "Udid", anonyUuid);
    AnonymizeFree(anonyUuid);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintMac(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_BR_MAC;
    unsigned char brMac[BT_MAC_LEN] = {0};
    char newBrMac[BT_MAC_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, brMac, BT_MAC_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo brMac failed");
        return SOFTBUS_ERR;
    }
    DataMasking((char *)brMac, BT_MAC_LEN, MAC_DELIMITER, newBrMac);
    SOFTBUS_DPRINTF(fd, "BrMac = %s\n", newBrMac);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintIp(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_IP_ADDRESS;
    char ipAddr[IP_STR_MAX_LEN] = {0};
    char newIpAddr[IP_STR_MAX_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)ipAddr, IP_STR_MAX_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo ipAddr failed");
        return SOFTBUS_ERR;
    }
    DataMasking((char *)ipAddr, IP_STR_MAX_LEN, IP_DELIMITER, newIpAddr);
    SOFTBUS_DPRINTF(fd, "IpAddr = %s\n", newIpAddr);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintNetCapacity(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_NETWORK_CAPABILITY;
    int32_t netCapacity = 0;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)&netCapacity, LNN_COMMON_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo netCapacity failed");
        return SOFTBUS_ERR;
    }
    SOFTBUS_DPRINTF(fd, "NetCapacity = %d\n", netCapacity);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintNetType(int fd, NodeBasicInfo *nodeInfo)
{
    NodeDeviceInfoKey key;
    key = NODE_KEY_NETWORK_TYPE;
    int32_t netType = 0;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)&netType, LNN_COMMON_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo netType failed");
        return SOFTBUS_ERR;
    }
    SOFTBUS_DPRINTF(fd, "NetType = %d\n", netType);
    return SOFTBUS_OK;
}

void SoftBusDumpBusCenterPrintInfo(int fd, NodeBasicInfo *nodeInfo)
{
    if (fd <= 0 || nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param is null");
        return;
    }
    char *anonyDeviceName = NULL;
    Anonymize(nodeInfo->deviceName, &anonyDeviceName);
    SOFTBUS_DPRINTF(fd, "DeviceName = %s\n", anonyDeviceName);
    AnonymizeFree(anonyDeviceName);
    char *anonyNetworkId = NULL;
    Anonymize(nodeInfo->networkId, &anonyNetworkId);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "NetworkId", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    if (SoftbusDumpPrintUdid(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintUdid failed");
        return;
    }
    if (SoftbusDumpPrintUuid(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintUuid failed");
        return;
    }
    if (SoftbusDumpPrintMac(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintMac failed");
        return;
    }
    if (SoftbusDumpPrintIp(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintIp failed");
        return;
    }
    if (SoftbusDumpPrintNetCapacity(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintNetCapacity failed");
        return;
    }
    if (SoftbusDumpPrintNetType(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintNetType failed");
        return;
    }
}
