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

#ifndef SOFTBUS_WIFI_API_ADAPTER_H
#define SOFTBUS_WIFI_API_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>
#include "softbus_wifi_api_adapter_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num);
int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig);
int32_t SoftBusDisconnectDevice(void);
int32_t SoftBusStartWifiScan(void);
int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb);
/* parameter *result is released by the caller. */
int32_t SoftBusGetWifiScanList(SoftBusWifiScanInfo **result, uint32_t *size);
int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb);
int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num);
SoftBusBand SoftBusGetLinkBand(void);
int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info);
int32_t SoftBusGetCurrentGroup(SoftBusWifiP2pGroupInfo *groupInfo);
bool SoftBusHasWifiDirectCapability(void);
bool SoftBusIsWifiTripleMode(void);
char* SoftBusGetWifiInterfaceCoexistCap(void);
bool SoftBusIsWifiActive(void);
bool SoftBusIsHotspotActive(void);
SoftBusWifiDetailState SoftBusGetWifiState(void);
bool SoftBusIsWifiP2pEnabled(void);
int32_t SoftBusGetHotspotConfig(int32_t *apChannel);

#ifdef __cplusplus
}
#endif
#endif // SOFTBUS_WIFI_API_ADAPTER_H
