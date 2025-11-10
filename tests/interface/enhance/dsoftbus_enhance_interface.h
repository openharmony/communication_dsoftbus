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
#ifndef DSOFTBUS_ENHANCE_INTERFACE_H
#define DSOFTBUS_ENHANCE_INTERFACE_H

#include "auth_device_common_key_struct.h"
#include "cJSON.h"
#include "lnn_node_info_struct.h"
#include "lnn_data_cloud_sync_struct.h"
#include "lnn_fast_offline_struct.h"
#include "lnn_sync_info_manager_struct.h"
#include "stdint.h"
#include "stdbool.h"
#include "lnn_lane_power_control_struct.h"
#include "lnn_cipherkey_manager_struct.h"
#include "auth_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo);
bool IsCipherManagerFindKey(const char *udid);
int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey);
int32_t AuthFindLatestNormalizeKey(
    const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey);
int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnRegistBleHeartbeatMediumMgr(void);
bool IsCloudSyncEnabled(void);
int32_t LnnGetLocalCacheNodeInfo(NodeInfo *info);
int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo);
int32_t LnnUnPackCloudSyncDeviceInfo(cJSON *json, NodeInfo *cloudSyncInfo);
int32_t LnnGetLocalBroadcastCipherInfo(CloudSyncInfo *info);
int32_t LnnPackCloudSyncDeviceInfo(cJSON *json, const NodeInfo *cloudSyncInfo);
int32_t LnnRegisterBleLpDeviceMediumMgr(void);
int32_t LnnInitQos(void);
int32_t LnnInitFastOffline(void);
int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete);
int32_t LnnInitMetaNode(void);
int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len);
int32_t EnablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo);
int32_t LnnGetLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey);
int32_t LnnLoadLocalBroadcastCipherKey(void);
int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo);
int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer);
int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
int32_t AuthMetaGetConnectionTypeByMetaNodeId(const char *metaNodeId, NetworkConnectionType *connectionType);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif