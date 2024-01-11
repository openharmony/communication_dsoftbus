/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_decision_db.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_meta_node_interface.h"
#include "lnn_p2p_info.h"
#include "lnn_device_info_recovery.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

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

static void LnnRestoreLocalDeviceInfo()
{
    LNN_LOGI(LNN_LEDGER, "restore local device info enter");
    if (LnnLoadLocalDeviceInfo() != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "get local device info fail");
        const NodeInfo *temp = LnnGetLocalNodeInfo();
        if (LnnSaveLocalDeviceInfo(temp) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "save local device info fail");
        }
        LNN_LOGI(LNN_LEDGER, "save local device info success");
    } else {
        NodeInfo info;
        (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        (void)LnnGetLocalDevInfo(&info);
        char *anonyNetworkId = NULL;
        Anonymize(info.networkId, &anonyNetworkId);
        LNN_LOGI(LNN_LEDGER, "load local deviceInfo success, networkId=%{public}s", anonyNetworkId);
        int64_t accountId = 0;
        AnonymizeFree(anonyNetworkId);
        if (LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId) == SOFTBUS_OK) {
            if (accountId != info.accountId) {
                info.stateVersion++;
            }
        }
        LNN_LOGI(LNN_LEDGER, "load local deviceInfo stateVersion=%{public}d", info.stateVersion);
        if (LnnSetLocalNumInfo(NUM_KEY_STATE_VERSION, info.stateVersion) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set state version fail");
        }
        if (LnnUpdateLocalNetworkId(info.networkId) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set networkId fail");
        }
        LnnNotifyNetworkIdChangeEvent(info.networkId);
    }
    AuthLoadDeviceKey();
    if (LnnLoadRemoteDeviceInfo() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "load remote deviceInfo fail");
        return;
    }
    LoadBleBroadcastKey();
    LnnLoadPtkInfo();
    LnnLoadLocalBroadcastCipherKey();
    LNN_LOGI(LNN_LEDGER, "load remote deviceInfo devicekey success");
}

int32_t LnnInitNetLedgerDelay(void)
{
    if (LnnInitLocalLedgerDelay() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init local ledger fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitDecisionDbDelay() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delay init decision db fail");
        return SOFTBUS_ERR;
    }
    LnnRestoreLocalDeviceInfo();
    return SOFTBUS_OK;
}

void LnnDeinitNetLedger(void)
{
    LnnDeinitMetaNodeLedger();
    LnnDeinitDistributedLedger();
    LnnDeinitLocalLedger();
    LnnDeinitHuksInterface();
    LnnDeinitMetaNodeExtLedger();
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
            return LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)info);
        case NODE_KEY_NETWORK_TYPE:
            return LnnGetLocalNumInfo(NUM_KEY_DISCOVERY_TYPE, (int32_t *)info);
        case NODE_KEY_DATA_CHANGE_FLAG:
            return LnnGetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, (int16_t *)info);
        case NODE_KEY_NODE_ADDRESS:
            return LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, (char *)info, infoLen);
        case NODE_KEY_P2P_IP_ADDRESS:
            return LnnGetLocalStrInfo(STRING_KEY_P2P_IP, (char *)info, infoLen);
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_ERR;
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
            return LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, (int32_t *)info);
        case NODE_KEY_NETWORK_TYPE:
            return LnnGetRemoteNumInfo(networkId, NUM_KEY_DISCOVERY_TYPE, (int32_t *)info);
        case NODE_KEY_DATA_CHANGE_FLAG:
            return LnnGetRemoteNum16Info(networkId, NUM_KEY_DATA_CHANGE_FLAG, (int16_t *)info);
        case NODE_KEY_NODE_ADDRESS:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_NODE_ADDR, (char *)info, infoLen);
        case NODE_KEY_P2P_IP_ADDRESS:
            return LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_IP, (char *)info, infoLen);
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
        return SOFTBUS_INVALID_PARAM;
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
        return SOFTBUS_INVALID_PARAM;
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
        default:
            LNN_LOGE(LNN_LEDGER, "invalid node key type=%{public}d", key);
            return SOFTBUS_ERR;
    }
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
    char newUdid[UDID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, udid, UDID_BUF_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Udid failed");
        return SOFTBUS_ERR;
    }
    DataMasking((char *)udid, UDID_BUF_LEN, ID_DELIMITER, newUdid);
    SOFTBUS_DPRINTF(fd, "Udid = %s\n", newUdid);
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
    char newUuid[UUID_BUF_LEN] = {0};

    if (LnnGetNodeKeyInfo(nodeInfo->networkId, key, uuid, UUID_BUF_LEN) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetNodeKeyInfo Uuid failed");
        return SOFTBUS_ERR;
    }
    DataMasking((char *)uuid, UUID_BUF_LEN, ID_DELIMITER, newUuid);
    SOFTBUS_DPRINTF(fd, "Uuid = %s\n", newUuid);
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
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
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
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
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
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "Invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
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
    SOFTBUS_DPRINTF(fd, "DeviceName = %s\n", nodeInfo->deviceName);
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    DataMasking(nodeInfo->networkId, NETWORK_ID_BUF_LEN, ID_DELIMITER, networkId);
    SOFTBUS_DPRINTF(fd, "NetworkId = %s\n", networkId);
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
