/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef LNN_NODE_INFO_H
#define LNN_NODE_INFO_H

#include "lnn_connect_info.h"
#include "lnn_device_info.h"
#include "lnn_net_capability.h"
#include "lnn_node_info_struct.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *LnnGetDeviceUdid(const NodeInfo *info);
int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid);
const char *LnnGetDeviceUuid(const NodeInfo *info);
bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type);
int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type);
bool LnnIsNodeOnline(const NodeInfo *info);
void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status);
const char *LnnGetBtMac(const NodeInfo *info);
void LnnSetBtMac(NodeInfo *info, const char *mac);
const char *LnnGetBleMac(const NodeInfo *info);
void LnnSetBleMac(NodeInfo *info, const char *mac);
const char *LnnGetWiFiIp(const NodeInfo *info, int32_t ifnameIdx);
void LnnSetWiFiIp(NodeInfo *info, const char *ip, int32_t ifnameIdx);
const char *LnnGetNetIfName(const NodeInfo *info, int32_t ifnameIdx);
void LnnSetNetIfName(NodeInfo *info, const char *netIfName, int32_t ifnameIdx);
const char *LnnGetMasterUdid(const NodeInfo *info);
int32_t LnnSetMasterUdid(NodeInfo *info, const char *udid);
int32_t LnnGetAuthPort(const NodeInfo *info, int32_t ifnameIdx);
int32_t LnnSetAuthPort(NodeInfo *info, int32_t port, int32_t ifnameIdx);
int32_t LnnGetSessionPort(const NodeInfo *info, int32_t ifnameIdx);
int32_t LnnSetSessionPort(NodeInfo *info, int32_t port, int32_t ifnameIdx);
int32_t LnnGetProxyPort(const NodeInfo *info, int32_t ifnameIdx);
int32_t LnnSetProxyPort(NodeInfo *info, int32_t port, int32_t ifnameIdx);
int32_t LnnSetP2pRole(NodeInfo *info, int32_t role);
int32_t LnnGetP2pRole(const NodeInfo *info);
int32_t LnnSetWifiCfg(NodeInfo *info, const char *wifiCfg);
const char *LnnGetWifiCfg(const NodeInfo *info);
int32_t LnnSetChanList5g(NodeInfo *info, const char *chanList5g);
const char *LnnGetChanList5g(const NodeInfo *info);
int32_t LnnSetStaFrequency(NodeInfo *info, int32_t staFrequency);
int32_t LnnGetStaFrequency(const NodeInfo *info);
int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac);
uint16_t LnnGetDataChangeFlag(const NodeInfo *info);
int32_t LnnSetDataChangeFlag(NodeInfo *info, uint16_t dataChangeFlag);
uint16_t LnnGetDataDynamicLevel(const NodeInfo *info);
int32_t LnnSetDataDynamicLevel(NodeInfo *info, uint16_t dataDynamicLevel);
uint16_t LnnGetDataStaticLevel(const NodeInfo *info);
int32_t LnnSetDataStaticLevel(NodeInfo *info, uint16_t dataStaticLvel);
uint32_t LnnGetDataSwitchLevel(const NodeInfo *info);
int32_t LnnSetDataSwitchLevel(NodeInfo *info, uint32_t dataSwitchLevel);
uint16_t LnnGetDataSwitchLength(const NodeInfo *info);
int32_t LnnSetDataSwitchLength(NodeInfo *info, uint16_t dataSwitchLevel);
const char *LnnGetP2pMac(const NodeInfo *info);
int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac);
const char *LnnGetP2pGoMac(const NodeInfo *info);
uint64_t LnnGetSupportedProtocols(const NodeInfo *info);
int32_t LnnSetSupportedProtocols(NodeInfo *info, uint64_t protocols);
int32_t LnnSetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len);
int32_t LnnGetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len);
int32_t LnnSetUserIdCheckSum(NodeInfo *info, uint8_t *data, uint32_t len);
int32_t LnnGetUserIdCheckSum(NodeInfo *info, uint8_t *data, uint32_t len);
int32_t LnnSetPtk(NodeInfo *info, const char *remotePtk);
void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log);
int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr);
const char *LnnGetWifiDirectAddr(const NodeInfo *info);
void LnnDumpNodeInfo(const NodeInfo *deviceInfo, const char *log);
int32_t LnnSetScreenStatus(NodeInfo *info, bool isScreenOn);
void LnnAnonymizeDeviceStr(const char *deviceStr, uint32_t strLen, uint32_t defaultLen, char **anonymizedStr);
bool isIfnameIdxInvalid(int32_t ifnameIdx);
void LnnDumpSparkCheck(const unsigned char *sparkCheck, const char *log);
#ifdef __cplusplus
}
#endif

#endif // LNN_NODE_INFO_H
