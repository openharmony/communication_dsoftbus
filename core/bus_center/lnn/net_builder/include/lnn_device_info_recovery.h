/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LNN_DEVICE_INFO_RECOVERY_H
#define LNN_DEVICE_INFO_RECOVERY_H

#include "cJSON.h"
#include <stdint.h>
#include "lnn_node_info.h"
#include "lnn_map.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_json.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICE_INFO_P2P_MAC_ADDR "P2P_MAC_ADDR"
#define DEVICE_INFO_DEVICE_NAME "DEVICE_NAME"
#define DEVICE_INFO_SETTINGS_NICK_NAME "SETTINGS_NICK_NAME"
#define DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME "UNIFIED_DEFAULT_DEVICE_NAME"
#define DEVICE_INFO_UNIFIED_DEVICE_NAME "UNIFIED_DEVICE_NAME"
#define DEVICE_INFO_DEVICE_TYPE "DEVICE_TYPE"
#define DEVICE_INFO_VERSION_TYPE "VERSION_TYPE"
#define DEVICE_INFO_SW_VERSION "SW_VERSION"
#define DEVICE_INFO_PKG_VERSION "PKG_VERSION"
#define DEVICE_INFO_DEVICE_UDID "DEVICE_UDID"
#define DEVICE_INFO_DEVICE_UUID "DEVICE_UUID"
#define DEVICE_INFO_OS_TYPE "OS_TYPE"
#define DEVICE_INFO_OS_VERSION "OS_VERSION"
#define DEVICE_INFO_DEVICE_VERSION "DEVICE_VERSION"
#define DEVICE_INFO_WIFI_VERSION "WIFI_VERSION"
#define DEVICE_INFO_BLE_VERSION "BLE_VERSION"
#define DEVICE_INFO_CONNECT_INFO "CONNECT_INFO"
#define DEVICE_INFO_BT_MAC "BT_MAC"
#define DEVICE_INFO_BR_MAC_ADDR "BR_MAC_ADDR"
#define DEVICE_INFO_HML_MAC "HML_MAC"
#define DEVICE_INFO_REMAIN_POWER "REMAIN_POWER"
#define DEVICE_INFO_IS_CHARGING "IS_CHARGING"
#define DEVICE_INFO_IS_SCREENON "IS_SCREENON"
#define DEVICE_INFO_IP_MAC "IP_MAC"
#define DEVICE_INFO_P2P_ROLE "P2P_ROLE"
#define DEVICE_INFO_NETWORK_ID "NETWORK_ID"
#define DEVICE_INFO_NODE_WEIGHT "NODE_WEIGHT"
#define DEVICE_INFO_ACCOUNT_ID "ACCOUNT_ID"
#define DEVICE_INFO_DISTRIBUTED_SWITCH "DISTRIBUTED_SWITCH"
#define DEVICE_INFO_TRANSPORT_PROTOCOL "TRANSPORT_PROTOCOL"
#define DEVICE_INFO_TRANS_FLAGS "TRANS_FLAGS"
#define DEVICE_INFO_BLE_P2P "BLE_P2P"
#define DEVICE_INFO_BLE_TIMESTAMP "BLE_TIMESTAMP"
#define DEVICE_INFO_WIFI_BUFF_SIZE "WIFI_BUFF_SIZE"
#define DEVICE_INFO_BR_BUFF_SIZE "BR_BUFF_SIZE"
#define DEVICE_INFO_FEATURE "FEATURE"
#define DEVICE_INFO_CONN_SUB_FEATURE "CONN_SUB_FEATURE"
#define DEVICE_INFO_META_INFO_JSON_TAG "MetaNodeInfoOfEar"
#define DEVICE_INFO_CONN_CAP "CONN_CAP"
#define DEVICE_INFO_NEW_CONN_CAP "NEW_CONN_CAP"
#define DEVICE_INFO_AUTH_CAP "AUTH_CAP"
#define DEVICE_INFO_HB_CAP "HB_CAP"
#define DEVICE_INFO_EXTDATA "EXTDATA"
#define DEVICE_INFO_STATE_VERSION "STATE_VERSION"
#define DEVICE_INFO_LOCAL_STATE_VERSION "LOCAL_STATE_VERSION"
#define DEVICE_INFO_STATE_VERSION_CHANGE_REASON "STATE_VERSION_CHANGE_REASON"
#define DEVICE_INFO_BD_KEY "BD_KEY"
#define DEVICE_INFO_BDKEY_TIME "BDKEY_TIME"
#define DEVICE_INFO_IV "IV"
#define DEVICE_INFO_IV_TIME "IV_TIME"
#define DEVICE_INFO_NETWORK_ID_TIMESTAMP "NETWORK_ID_TIMESTAMP"
#define DEVICE_INFO_DEVICE_IRK "IRK"
#define DEVICE_INFO_DEVICE_PUB_MAC "PUB_MAC"
#define DEVICE_INFO_BROADCAST_CIPHER_KEY "BROADCAST_CIPHER_KEY"
#define DEVICE_INFO_BROADCAST_CIPHER_IV "BROADCAST_CIPHER_IV"
#define DEVICE_INFO_DEVICE_SECURITY_LEVEL "DEVICE_SECURITY_LEVEL"
#define DEVICE_INFO_PTK "PTK"
#define DEVICE_INFO_STATIC_CAP "STATIC_CAP"
#define DEVICE_INFO_STATIC_CAP_LEN "STATIC_CAP_LEN"
#define DEVICE_INFO_JSON_BROADCAST_KEY_TABLE "JSON_KEY_TABLE_MIAN"
#define DEVICE_INFO_JSON_KEY_TOTAL_LIFE "JSON_KEY_TOTAL_LIFE"
#define DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN "JSON_KEY_TIMESTAMP_BEGIN"
#define DEVICE_INFO_JSON_KEY_CURRENT_INDEX "JSON_KEY_CURRENT_INDEX"
#define DEVICE_INFO_TIMESTAMP "TIMESTAMP"
#define DEVICE_INFO_LAST_AUTH_SEQ "LAST_AUTH_SEQ"
#define DEVICE_INFO_USERID_CHECKSUM "USERID_CHECKSUM"
#define IS_SUPPORT_IPV6 "IS_SUPPORT_IPV6"
#define IS_AUTH_EXCHANGE_UDID "IS_AUTH_EXCHANGE_UDID"

int32_t LnnLoadLocalDeviceInfo(void);
int32_t LnnLoadRemoteDeviceInfo(void);
int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo);
int32_t LnnGetAllRemoteDevInfo(NodeInfo **info, int32_t *nums);
int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnRetrieveDeviceInfo(const char *udidHash, NodeInfo *deviceInfo);
int32_t LnnRetrieveDeviceInfoByUdid(const char *udid, NodeInfo *deviceInfo);
int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info);
void LnnDeleteDeviceInfo(const char *udid);
void ClearDeviceInfo(void);
int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen);
int32_t LnnGetLocalCacheNodeInfo(NodeInfo *info);
int32_t LnnLoadLocalDeviceAccountIdInfo(void);
int32_t LnnGetAccountIdFromLocalCache(int64_t *buf);
int32_t LnnPackCloudSyncDeviceInfo(cJSON *json, const NodeInfo *cloudSyncInfo);
int32_t LnnUnPackCloudSyncDeviceInfo(cJSON *json, NodeInfo *cloudSyncInfo);
void LnnUpdateAuthExchangeUdid(void);
void LnnClearAuthExchangeUdid(const char *networkId);
#ifdef __cplusplus
}
#endif

#endif /* LNN_DEVICE_INFO_RECOVERY_H */
