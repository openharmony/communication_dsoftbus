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
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static bool g_isRestore = false;

int32_t LnnInitNetLedger(void)
{
    if (LnnInitHuksInterface() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init huks interface fail");
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    if (LnnInitLocalLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local net ledger fail!");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitDistributedLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init distributed net ledger fail!");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitMetaNodeLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init meta node ledger fail");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitMetaNodeExtLedger() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init meta node ext ledger fail");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    return SOFTBUS_OK;
}

static bool IsCapacityChange(NodeInfo *info)
{
    uint64_t softbusFeature = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &softbusFeature) == SOFTBUS_OK) {
        if (softbusFeature != info->feature) {
            LNN_LOGW(LNN_LEDGER, "feature=%{public}" PRIu64 "->%{public}" PRIu64, info->feature, softbusFeature);
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
    uint32_t heartbeatCapacity = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_HB_CAP, &heartbeatCapacity) == SOFTBUS_OK) {
        if (heartbeatCapacity != info->heartbeatCapacity) {
            LNN_LOGW(LNN_LEDGER, "hbCapacity=%{public}d->%{public}d", info->heartbeatCapacity, heartbeatCapacity);
            return true;
        }
    }
    return false;
}

static bool IsLocalIrkInfoChange(NodeInfo *info)
{
    unsigned char localIrk[LFINDER_IRK_LEN] = { 0 };
    if (LnnGetLocalByteInfo(BYTE_KEY_IRK, localIrk, LFINDER_IRK_LEN) == SOFTBUS_OK) {
        if (memcmp(info->rpaInfo.peerIrk, localIrk, LFINDER_IRK_LEN) != 0) {
            LNN_LOGI(LNN_LEDGER, "local irk change");
            if (memcpy_s(info->rpaInfo.peerIrk, LFINDER_IRK_LEN, localIrk, LFINDER_IRK_LEN) != EOK) {
                LNN_LOGE(LNN_LEDGER, "memcpy local irk fail");
                (void)memset_s(localIrk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
                return true;
            }
            (void)memset_s(localIrk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
            return true;
        }
        LNN_LOGI(LNN_LEDGER, "local irk same");
        (void)memset_s(localIrk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
        return false;
    }
    LNN_LOGI(LNN_LEDGER, "get local irk fail, ignore");
    (void)memset_s(localIrk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
    return false;
}

static bool IsLocalBroadcastLinKeyChange(NodeInfo *info)
{
    BroadcastCipherInfo linkKey;
    (void)memset_s(&linkKey, sizeof(BroadcastCipherInfo), 0, sizeof(BroadcastCipherInfo));
    if (LnnGetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY, linkKey.key, SESSION_KEY_LENGTH) == SOFTBUS_OK &&
        LnnGetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV, linkKey.iv, BROADCAST_IV_LEN) == SOFTBUS_OK) {
        if (memcmp(info->cipherInfo.key, linkKey.key, SESSION_KEY_LENGTH) != 0 ||
            memcmp(info->cipherInfo.iv, linkKey.iv, BROADCAST_IV_LEN) != 0) {
            LNN_LOGI(LNN_LEDGER, "local link key change");
            if (memcpy_s(info->cipherInfo.key, SESSION_KEY_LENGTH, linkKey.key, SESSION_KEY_LENGTH) != EOK ||
                memcpy_s(info->cipherInfo.iv, BROADCAST_IV_LEN, linkKey.iv, BROADCAST_IV_LEN) != EOK) {
                LNN_LOGE(LNN_LEDGER, "memcpy local link key fail");
                (void)memset_s(&linkKey, sizeof(BroadcastCipherInfo), 0, sizeof(BroadcastCipherInfo));
                return true;
            }
            (void)memset_s(&linkKey, sizeof(BroadcastCipherInfo), 0, sizeof(BroadcastCipherInfo));
            return true;
        }
        LNN_LOGI(LNN_LEDGER, "local link key same");
        (void)memset_s(&linkKey, sizeof(BroadcastCipherInfo), 0, sizeof(BroadcastCipherInfo));
        return false;
    }
    LNN_LOGI(LNN_LEDGER, "get local link key fail, ignore");
    (void)memset_s(&linkKey, sizeof(BroadcastCipherInfo), 0, sizeof(BroadcastCipherInfo));
    return false;
}

static bool IsBleDirectlyOnlineFactorChange(NodeInfo *info)
{
    if (IsCapacityChange(info)) {
        return true;
    }
    char softBusVersion[VERSION_MAX_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, softBusVersion, sizeof(softBusVersion)) == SOFTBUS_OK) {
        if (strcmp(softBusVersion, info->softBusVersion) != 0) {
            LNN_LOGW(LNN_LEDGER, "softbus version=%{public}s->%{public}s", softBusVersion, info->softBusVersion);
            return true;
        }
    }
    char *anonyNewUuid = NULL;
    char uuid[UUID_BUF_LEN] = { 0 };
    if ((LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) == SOFTBUS_OK) && (strcmp(uuid, info->uuid) != 0)) {
        Anonymize(info->uuid, &anonyNewUuid);
        LNN_LOGW(LNN_LEDGER, "uuid change, new=%{public}s", AnonymizeWrapper(anonyNewUuid));
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
    int32_t level = 0;
    if ((LnnGetLocalNumInfo(NUM_KEY_DEVICE_SECURITY_LEVEL, &level) == SOFTBUS_OK) &&
        (level != info->deviceSecurityLevel)) {
        LNN_LOGW(LNN_LEDGER, "deviceSecurityLevel=%{public}d->%{public}d", info->deviceSecurityLevel, level);
        return true;
    }
    if (IsLocalIrkInfoChange(info)) {
        return true;
    }
    if (IsLocalBroadcastLinKeyChange(info)) {
        return true;
    }
    return false;
}

static void LnnSetLocalFeature(void)
{
    if (IsSupportLpFeature()) {
        uint64_t feature = 1 << BIT_BLE_SUPPORT_LP_HEARTBEAT;
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
    if (LnnUpdateLocalDeviceName(&info.deviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set deviceName fail");
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
    int32_t ret = LnnInitLocalLedgerDelay();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init local ledger fail");
        return ret;
    }
    ret = LnnInitDecisionDbDelay();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init decision db fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitEventMoniterDelay(void)
{
    int32_t ret = LnnInitCommonEventMonitorImpl();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init LnnInitCommonEventMonitorImpl fail");
        return ret;
    }
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
        return SOFTBUS_INVALID_PARAM;
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
        case NODE_KEY_DEVICE_SCREEN_STATUS:
            return LnnGetLocalBoolInfo(BOOL_KEY_SCREEN_STATUS, (bool *)info, NODE_SCREEN_STATUS_LEN);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_INVALID_NUM;
    }
}

static int32_t LnnGetNodeKeyInfoRemote(const char *networkId, int key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
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
        case NODE_KEY_DEVICE_SCREEN_STATUS:
            return LnnGetRemoteBoolInfo(networkId, BOOL_KEY_SCREEN_STATUS, (bool*)info);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_INVALID_NUM;
    }
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int key, uint8_t *info, uint32_t infoLen)
{
    bool isLocalNetworkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
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

static int32_t LnnGetPrivateNodeKeyInfoLocal(const char *networkId, InfoKey key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case BYTE_KEY_IRK:
            return LnnGetLocalByteInfo(BYTE_KEY_IRK, info, infoLen);
        case BYTE_KEY_BROADCAST_CIPHER_KEY:
            return LnnGetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY, info, infoLen);
        case BYTE_KEY_ACCOUNT_HASH:
            return LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, info, infoLen);
        case BYTE_KEY_REMOTE_PTK:
            return LnnGetLocalByteInfo(BYTE_KEY_REMOTE_PTK, info, infoLen);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t LnnGetPrivateNodeKeyInfoRemote(const char *networkId, InfoKey key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case BYTE_KEY_IRK:
            return LnnGetRemoteByteInfo(networkId, BYTE_KEY_IRK, info, infoLen);
        case BYTE_KEY_BROADCAST_CIPHER_KEY:
            return LnnGetRemoteByteInfo(networkId, BYTE_KEY_BROADCAST_CIPHER_KEY, info, infoLen);
        case BYTE_KEY_ACCOUNT_HASH:
            return LnnGetRemoteByteInfo(networkId, BYTE_KEY_ACCOUNT_HASH, info, infoLen);
        case BYTE_KEY_REMOTE_PTK:
            return LnnGetRemoteByteInfo(networkId, BYTE_KEY_REMOTE_PTK, info, infoLen);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t LnnGetPrivateNodeKeyInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t infoLen)
{
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    bool isLocalNetworkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id fail");
        return SOFTBUS_NOT_FIND;
    }
    if (strncmp(localNetworkId, networkId, NETWORK_ID_BUF_LEN) == 0) {
        isLocalNetworkId = true;
    }
    if (isLocalNetworkId) {
        return LnnGetPrivateNodeKeyInfoLocal(networkId, key, info, infoLen);
    } else {
        return LnnGetPrivateNodeKeyInfoRemote(networkId, key, info, infoLen);
    }
}

int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag)
{
    bool isLocalNetworkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (networkId == NULL) {
        LNN_LOGE(LNN_LEDGER, "params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (strncmp(localNetworkId, networkId, NETWORK_ID_BUF_LEN) == 0) {
        isLocalNetworkId = true;
    }
    if (isLocalNetworkId) {
        return LnnSetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, (int16_t)dataChangeFlag);
    }
    LNN_LOGE(LNN_LEDGER, "remote networkId");
    return SOFTBUS_NETWORK_INVALID_DEV_INFO;
}

int32_t LnnSetDataLevel(const DataLevel *dataLevel, bool *isSwitchLevelChanged)
{
    if (dataLevel == NULL || isSwitchLevelChanged == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnSetDataLevel data level or switch level change flag is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_LEDGER, "LnnSetDataLevel, dynamic: %{public}hu, static: %{public}hu, "
        "switch: %{public}u, switchLen: %{public}hu", dataLevel->dynamicLevel, dataLevel->staticLevel,
        dataLevel->switchLevel, dataLevel->switchLength);
    uint16_t dynamicLevel = dataLevel->dynamicLevel;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, dynamicLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data dynamic level failed");
        return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
    }
    uint16_t staticLevel = dataLevel->staticLevel;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_STATIC_LEVEL, staticLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data static level failed");
        return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
    }
    uint32_t curSwitchLevel = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, &curSwitchLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Get current data switch level faield");
        return SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR;
    }
    uint32_t switchLevel = dataLevel->switchLevel;
    if (LnnSetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, switchLevel) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data switch level faield");
        return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
    }
    uint16_t switchLength = dataLevel->switchLength;
    if (LnnSetLocalNumU16Info(NUM_KEY_DATA_SWITCH_LENGTH, switchLength) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Set data switch length failed");
        return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
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
        case NODE_KEY_DEVICE_SCREEN_STATUS:
            return DATA_DEVICE_SCREEN_STATUS_LEN;
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_INVALID_NUM;
    }
}

static int32_t SoftbusDumpPrintAccountId(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    char accountHash[SHA_256_HASH_LEN] = {0};
    if (LnnGetPrivateNodeKeyInfo(nodeInfo->networkId, BYTE_KEY_ACCOUNT_HASH,
        (uint8_t *)&accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo account hash failed");
        return SOFTBUS_NOT_FIND;
    }
    char accountHashStr[SHA_256_HEX_HASH_LEN] = {0};
    if (ConvertBytesToHexString(accountHashStr, SHA_256_HEX_HASH_LEN,
        (unsigned char *)accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert account to string fail.");
        return SOFTBUS_BYTE_CONVERT_FAIL;
    }
    char *anonyAccountHash = NULL;
    Anonymize(accountHashStr, &anonyAccountHash);
    SOFTBUS_DPRINTF(fd, "AccountHash->%s\n", AnonymizeWrapper(anonyAccountHash));
    AnonymizeFree(anonyAccountHash);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintUdid(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_UDID;
    unsigned char udid[UDID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Udid failed");
        return SOFTBUS_NOT_FIND;
    }
    char *anonyUdid = NULL;
    Anonymize((char *)udid, &anonyUdid);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "Udid", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintUuid(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_UUID;
    unsigned char uuid[UUID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Uuid failed");
        return SOFTBUS_NOT_FIND;
    }
    char *anonyUuid = NULL;
    Anonymize((char *)uuid, &anonyUuid);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "Uuid", AnonymizeWrapper(anonyUuid));
    AnonymizeFree(anonyUuid);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintMac(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_BR_MAC;
    unsigned char brMac[BT_MAC_LEN] = {0};
    char newBrMac[BT_MAC_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, brMac, BT_MAC_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo brMac failed");
        return SOFTBUS_NOT_FIND;
    }
    DataMasking((char *)brMac, BT_MAC_LEN, MAC_DELIMITER, newBrMac);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "BrMac", newBrMac);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintIp(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_IP_ADDRESS;
    char ipAddr[IP_STR_MAX_LEN] = {0};
    char newIpAddr[IP_STR_MAX_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)ipAddr, IP_STR_MAX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo ipAddr failed");
        return SOFTBUS_NOT_FIND;
    }
    DataMasking((char *)ipAddr, IP_STR_MAX_LEN, IP_DELIMITER, newIpAddr);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "IpAddr", newIpAddr);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintNetCapacity(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_NETWORK_CAPABILITY;
    int32_t netCapacity = 0;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)&netCapacity, sizeof(netCapacity)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo netCapacity failed");
        return SOFTBUS_NOT_FIND;
    }
    SOFTBUS_DPRINTF(fd, "  %-15s->%d\n", "NetCapacity", netCapacity);
    return SOFTBUS_OK;
}

int32_t SoftbusDumpPrintNetType(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_NETWORK_TYPE;
    int32_t netType = 0;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)&netType, sizeof(netType)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo netType failed");
        return SOFTBUS_NOT_FIND;
    }
    SOFTBUS_DPRINTF(fd, "  %-15s->%d\n", "NetType", netType);
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintDeviceLevel(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeDeviceInfoKey key;
    key = NODE_KEY_DEVICE_SECURITY_LEVEL;
    int32_t securityLevel = 0;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, (uint8_t *)&securityLevel, sizeof(securityLevel)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo securityLevel failed");
        return SOFTBUS_NOT_FIND;
    }
    SOFTBUS_DPRINTF(fd, "  %-15s->%d\n", "SecurityLevel", securityLevel);
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintScreenStatus(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    bool isScreenOn = false;
    if (LnnGetNodeKeyInfo(nodeInfo->networkId, NODE_KEY_DEVICE_SCREEN_STATUS, (uint8_t *)&isScreenOn,
        DATA_DEVICE_SCREEN_STATUS_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo isScreenOn failed");
        return SOFTBUS_NOT_FIND;
    }
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "isScreenOn", isScreenOn ? "on" : "off");
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintIrk(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t irk[LFINDER_IRK_LEN] = {0};
    if (LnnGetPrivateNodeKeyInfo(nodeInfo->networkId, BYTE_KEY_IRK,
        (uint8_t *)&irk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetPrivateNodeKeyInfo irk failed");
        return SOFTBUS_NOT_FIND;
    }
    char peerIrkStr[LFINDER_IRK_STR_LEN] = {0};
    if (ConvertBytesToHexString(peerIrkStr, LFINDER_IRK_STR_LEN, irk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert irk to string fail.");
        (void)memset_s(irk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
        return SOFTBUS_BYTE_CONVERT_FAIL;
    }
    char *anonyIrk = NULL;
    Anonymize(peerIrkStr, &anonyIrk);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "IRK", AnonymizeWrapper(anonyIrk));
    AnonymizeFree(anonyIrk);
    (void)memset_s(irk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
    (void)memset_s(peerIrkStr, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintBroadcastCipher(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    unsigned char broadcastCipher[SESSION_KEY_LENGTH] = {0};
    if (LnnGetPrivateNodeKeyInfo(nodeInfo->networkId, BYTE_KEY_BROADCAST_CIPHER_KEY,
        (uint8_t *)&broadcastCipher, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetPrivateNodeKeyInfo broadcastCipher failed");
        return SOFTBUS_NOT_FIND;
    }
    char broadcastCipherStr[SESSION_KEY_STR_LEN] = {0};
    if (ConvertBytesToHexString(broadcastCipherStr, SESSION_KEY_STR_LEN,
        broadcastCipher, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert broadcastCipher to string fail.");
        (void)memset_s(broadcastCipher, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        return SOFTBUS_BYTE_CONVERT_FAIL;
    }
    char *anonyBroadcastCipher = NULL;
    Anonymize((char *)broadcastCipherStr, &anonyBroadcastCipher);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "BroadcastCipher", AnonymizeWrapper(anonyBroadcastCipher));
    AnonymizeFree(anonyBroadcastCipher);
    (void)memset_s(broadcastCipher, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    (void)memset_s(broadcastCipherStr, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintRemotePtk(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    char remotePtk[PTK_DEFAULT_LEN] = {0};
    if (LnnGetPrivateNodeKeyInfo(nodeInfo->networkId, BYTE_KEY_REMOTE_PTK,
        (uint8_t *)&remotePtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetPrivateNodeKeyInfo ptk failed");
        return SOFTBUS_NOT_FIND;
    }
    char remotePtkStr[PTK_STR_LEN] = {0};
    if (ConvertBytesToHexString(remotePtkStr, PTK_STR_LEN,
        (unsigned char *)remotePtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert remotePtk to string fail.");
        (void)memset_s(remotePtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
        return SOFTBUS_BYTE_CONVERT_FAIL;
    }
    char *anonyRemotePtk = NULL;
    Anonymize(remotePtkStr, &anonyRemotePtk);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "RemotePtk", AnonymizeWrapper(anonyRemotePtk));
    AnonymizeFree(anonyRemotePtk);
    (void)memset_s(remotePtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
    (void)memset_s(remotePtkStr, PTK_STR_LEN, 0, PTK_STR_LEN);
    return SOFTBUS_OK;
}

static int32_t SoftbusDumpPrintLocalPtk(int fd, NodeBasicInfo *nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(nodeInfo->networkId, STRING_KEY_UUID, peerUuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "gey peerUuid failed");
        return SOFTBUS_NOT_FIND;
    }
    char localPtk[PTK_DEFAULT_LEN] = {0};
    if (LnnGetLocalPtkByUuid(peerUuid, localPtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetLocalPtkByUuid failed");
        return SOFTBUS_NOT_FIND;
    }
    char localPtkStr[PTK_STR_LEN] = {0};
    if (ConvertBytesToHexString(localPtkStr, PTK_STR_LEN,
        (unsigned char *)localPtk, PTK_DEFAULT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert localPtk to string fail.");
        (void)memset_s(localPtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
        return SOFTBUS_BYTE_CONVERT_FAIL;
    }
    char *anonyLocalPtk = NULL;
    Anonymize(localPtkStr, &anonyLocalPtk);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "LocalPtk", AnonymizeWrapper(anonyLocalPtk));
    AnonymizeFree(anonyLocalPtk);
    (void)memset_s(localPtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
    (void)memset_s(localPtkStr, PTK_STR_LEN, 0, PTK_STR_LEN);
    return SOFTBUS_OK;
}

static void SoftbusDumpDeviceInfo(int fd, NodeBasicInfo *nodeInfo)
{
    SOFTBUS_DPRINTF(fd, "DeviceInfo:\n");
    if (fd <= 0 || nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(nodeInfo->networkId, &anonyNetworkId);
    SOFTBUS_DPRINTF(fd, "  %-15s->%s\n", "NetworkId", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    if (SoftbusDumpPrintUdid(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintUdid failed");
    }
    if (SoftbusDumpPrintUuid(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintUuid failed");
    }
    if (SoftbusDumpPrintNetCapacity(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintNetCapacity failed");
    }
    if (SoftbusDumpPrintNetType(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintNetType failed");
    }
    if (SoftbusDumpPrintDeviceLevel(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintDeviceLevel failed");
    }
    if (SoftbusDumpPrintScreenStatus(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintScreenStatus failed");
    }
}

static void SoftbusDumpDeviceAddr(int fd, NodeBasicInfo *nodeInfo)
{
    SOFTBUS_DPRINTF(fd, "DeviceAddr:\n");
    if (fd <= 0 || nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return;
    }
    if (SoftbusDumpPrintMac(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintMac failed");
    }
    if (SoftbusDumpPrintIp(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintIp failed");
    }
}

static void SoftbusDumpDeviceCipher(int fd, NodeBasicInfo *nodeInfo)
{
    SOFTBUS_DPRINTF(fd, "DeviceCipher:\n");
    if (fd <= 0 || nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return;
    }
    if (SoftbusDumpPrintIrk(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintIrk failed");
    }
    if (SoftbusDumpPrintBroadcastCipher(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintBroadcastCipher failed");
    }
    if (SoftbusDumpPrintRemotePtk(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintRemotePtk failed");
    }
    if (SoftbusDumpPrintLocalPtk(fd, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftbusDumpPrintLocalPtk failed");
    }
}

void SoftBusDumpBusCenterPrintInfo(int fd, NodeBasicInfo *nodeInfo)
{
    if (fd <= 0 || nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param is null");
        return;
    }
    char *anonyDeviceName = NULL;
    Anonymize(nodeInfo->deviceName, &anonyDeviceName);
    SOFTBUS_DPRINTF(fd, "DeviceName->%s\n", AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyDeviceName);
    SoftbusDumpPrintAccountId(fd, nodeInfo);
    SoftbusDumpDeviceInfo(fd, nodeInfo);
    SoftbusDumpDeviceAddr(fd, nodeInfo);
    SoftbusDumpDeviceCipher(fd, nodeInfo);
}
