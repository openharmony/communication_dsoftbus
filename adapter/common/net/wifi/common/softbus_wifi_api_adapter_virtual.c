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

#include <stdlib.h>
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num)
{
    (void)configList;
    (void)num;
    return SOFTBUS_OK;
}

int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig)
{
    (void)wifiConfig;
    return SOFTBUS_OK;
}

int32_t SoftBusDisconnectDevice(void)
{
    return SOFTBUS_OK;
}

int32_t SoftBusStartWifiScan(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb)
{
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusGetWifiScanList(SoftBusWifiScanInfo **result, uint32_t *size)
{
    (void)result;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb)
{
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num)
{
    (void)channelList;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}

SoftBusBand SoftBusGetLinkBand(void)
{
    return BAND_UNKNOWN;
}

int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

int32_t SoftBusGetCurrentGroup(SoftBusWifiP2pGroupInfo *groupInfo)
{
    (void)groupInfo;
    return SOFTBUS_OK;
}

bool SoftBusHasWifiDirectCapability(void)
{
    return true;
}

bool SoftBusIsWifiTripleMode(void)
{
    return false;
}

char* SoftBusGetWifiInterfaceCoexistCap(void)
{
    return NULL;
}

bool SoftBusIsWifiActive(void)
{
    return true;
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return SOFTBUS_WIFI_STATE_ACTIVED;
}

bool SoftBusIsWifiP2pEnabled(void)
{
    return true;
}

bool SoftBusIsHotspotActive(void)
{
    return false;
}
