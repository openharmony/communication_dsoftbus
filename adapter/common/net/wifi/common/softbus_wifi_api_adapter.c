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

#include "softbus_wifi_api_adapter.h"

#include <string.h>

#include "lnn_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "kits/c/wifi_device.h"
#include "kits/c/wifi_hid2d.h"
#include "kits/c/wifi_hotspot.h"
#include "kits/c/wifi_p2p.h"
#include "kits/c/wifi_state.h"

static int32_t ConvertSoftBusWifiConfFromWifiDev(const WifiDeviceConfig *sourceWifiConf, SoftBusWifiDevConf *wifiConf)
{
    if (strcpy_s(wifiConf->ssid, sizeof(wifiConf->ssid), sourceWifiConf->ssid) != EOK) {
        LNN_LOGE(LNN_STATE, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(wifiConf->bssid, sizeof(wifiConf->bssid), sourceWifiConf->bssid,
        sizeof(sourceWifiConf->bssid)) != EOK) {
        LNN_LOGE(LNN_STATE, "mem copy bssid fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(wifiConf->preSharedKey, sizeof(wifiConf->preSharedKey),
        sourceWifiConf->preSharedKey) != EOK) {
        LNN_LOGE(LNN_STATE, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    wifiConf->securityType = sourceWifiConf->securityType;
    wifiConf->isHiddenSsid = sourceWifiConf->isHiddenSsid;

    return SOFTBUS_OK;
}

static int32_t ConvertWifiDevConfFromSoftBusWifiConf(const SoftBusWifiDevConf *result, WifiDeviceConfig *wifiConf)
{
    if (strcpy_s(wifiConf->ssid, sizeof(wifiConf->ssid), result->ssid) != EOK) {
        LNN_LOGE(LNN_STATE, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(wifiConf->bssid, sizeof(wifiConf->bssid),
        result->bssid, sizeof(result->bssid)) != EOK) {
        LNN_LOGE(LNN_STATE, "mem copy bssid fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(wifiConf->preSharedKey, sizeof(wifiConf->preSharedKey),
        result->preSharedKey) != EOK) {
        LNN_LOGE(LNN_STATE, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    wifiConf->securityType = result->securityType;
    wifiConf->isHiddenSsid = result->isHiddenSsid;

    return SOFTBUS_OK;
}

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num)
{
    WifiDeviceConfig *result = NULL;
    uint32_t wifiConfigSize;
    int32_t retVal;
    uint32_t i;

    if (configList == NULL) {
        LNN_LOGW(LNN_STATE, "para configList is NULL");
        return SOFTBUS_ERR;
    }
    result = SoftBusMalloc(sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
    if (result == NULL) {
        LNN_LOGE(LNN_STATE, "malloc wifi device config fail");
        return SOFTBUS_ERR;
    }
    (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                   sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
    retVal = GetDeviceConfigs(result, &wifiConfigSize);
    if (retVal != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "malloc wifi device config fail");
        (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                       sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }

    if (wifiConfigSize > WIFI_MAX_CONFIG_SIZE) {
        LNN_LOGE(LNN_STATE, "wifi device config size is invalid");
        (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                       sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }

    for (i = 0; i < wifiConfigSize; i++) {
        if (ConvertSoftBusWifiConfFromWifiDev(result, configList) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "convert wifi config failed");
            (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                           sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
            SoftBusFree(result);
            return SOFTBUS_ERR;
        }
        result++;
        configList++;
    }
    *num = wifiConfigSize;
    (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                   sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
    SoftBusFree(result);
    return SOFTBUS_OK;
}

int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig)
{
    if (wifiConfig == NULL) {
        LNN_LOGE(LNN_STATE, "para wifiConfig is NULL");
        return SOFTBUS_ERR;
    }
    WifiDeviceConfig wifiDevConfig;
    (void)memset_s(&wifiDevConfig, sizeof(WifiDeviceConfig), 0, sizeof(WifiDeviceConfig));
    if (ConvertWifiDevConfFromSoftBusWifiConf(wifiConfig, &wifiDevConfig) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "convert wifi config failed");
        return SOFTBUS_ERR;
    }

    if (ConnectToDevice(&wifiDevConfig) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "connect to wifi failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusDisconnectDevice(void)
{
    return Disconnect();
}

static ISoftBusScanResult *g_scanResultCb[MAX_CALLBACK_NUM] = {NULL};
static bool g_registerFlag = true;

int32_t SoftBusStartWifiScan(void)
{
    if (Scan() != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "softbus start wifi scan failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void SoftBusWifiScanStateChanged(int state, int size)
{
    for (int i = 0; i < MAX_CALLBACK_NUM; i++) {
        if (g_scanResultCb[i] != NULL) {
            g_scanResultCb[i]->onSoftBusWifiScanResult(state, size);
        }
    }
}

static WifiEvent g_event = {
    .OnWifiConnectionChanged = NULL,
    .OnWifiScanStateChanged = SoftBusWifiScanStateChanged,
    .OnHotspotStateChanged = NULL,
    .OnHotspotStaJoin = NULL,
    .OnHotspotStaLeave = NULL,
};

static int32_t FindFreeCallbackIndex(void)
{
    int i;
    for (i = 0; i < MAX_CALLBACK_NUM; i++) {
        if (g_scanResultCb[i] == NULL) {
            break;
        }
    }
    return i;
}

int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb)
{
    if (cb == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    int index = FindFreeCallbackIndex();
    if (index == MAX_CALLBACK_NUM) {
        LNN_LOGE(LNN_STATE, "register callback index invalid");
        return SOFTBUS_ERR;
    }
    g_scanResultCb[index] = cb;

    int32_t ret = 0;
    if (g_registerFlag) {
        ret = RegisterWifiEvent(&g_event);
        if (ret == WIFI_SUCCESS) {
            g_registerFlag = false;
        } else {
            LNN_LOGE(LNN_STATE, "softbus register wifi event failed");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t ConvertSoftBusWifiScanInfoFromWifi(WifiScanInfo *info, SoftBusWifiScanInfo *result, const uint32_t *size)
{
    if (info == NULL || result == NULL || size == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < (*size); i++) {
        if (strcpy_s(result->ssid, WIFI_MAX_SSID_LEN, info->ssid) != EOK) {
            LNN_LOGE(LNN_STATE, "strcpy ssid fail");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(result->bssid, WIFI_MAC_LEN, info->bssid, sizeof(info->bssid)) != EOK) {
            LNN_LOGE(LNN_STATE, "memcpy bssid fail");
            return SOFTBUS_ERR;
        }
        result->securityType =  (int32_t)(info->securityType);
        result->rssi = (int32_t)(info->rssi);
        result->band = (int32_t)(info->band);
        result->frequency = (int32_t)(info->frequency);
        result->channelWidth = (int32_t)(info->channelWidth);
        result->centerFrequency0 = (int32_t)(info->centerFrequency0);
        result->centerFrequency1 = (int32_t)(info->centerFrequency1);
        result->timestamp = info->timestamp;
        ++result;
        ++info;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGetWifiScanList(SoftBusWifiScanInfo **result, uint32_t *size)
{
    if (size == NULL || result == NULL) {
        LNN_LOGW(LNN_STATE, "para size or result is NULL");
        return SOFTBUS_ERR;
    }
    WifiScanInfo *info = (WifiScanInfo *)SoftBusMalloc(sizeof(WifiScanInfo) * WIFI_MAX_SCAN_HOTSPOT_LIMIT);
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "malloc wifi scan information failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(info, sizeof(WifiScanInfo)*WIFI_MAX_SCAN_HOTSPOT_LIMIT, 0,
        sizeof(WifiScanInfo)*WIFI_MAX_SCAN_HOTSPOT_LIMIT);
    *size = WIFI_MAX_SCAN_HOTSPOT_LIMIT;
    int32_t ret = GetScanInfoList(info, (unsigned int *)size);
    if (ret != WIFI_SUCCESS || *size == 0) {
        LNN_LOGE(LNN_STATE, "softbus get wifi scan list failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    *result = (SoftBusWifiScanInfo *)SoftBusMalloc(sizeof(SoftBusWifiScanInfo) * (*size));
    if (*result == NULL) {
        LNN_LOGE(LNN_STATE, "malloc softbus wifi scan information failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    (void)memset_s(*result, sizeof(SoftBusWifiScanInfo)* (*size), 0, sizeof(SoftBusWifiScanInfo)* (*size));
    if (ConvertSoftBusWifiScanInfoFromWifi(info, *result, size) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ConvertSoftBusWifiScaninfoFromWifi failed");
        SoftBusFree(*result);
        *result = NULL;
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

static bool IsScanResultCbEmpty(void)
{
    for (int i = 0; i < MAX_CALLBACK_NUM; i++) {
        if (g_scanResultCb[i] != NULL) {
            return false;
        }
    }
    return true;
}

int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb)
{
    if (cb == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    for (int i = 0; i < MAX_CALLBACK_NUM; i++) {
        if (g_scanResultCb[i] == cb) {
            g_scanResultCb[i] = NULL;
        }
    }

    int32_t ret = 0;
    if (IsScanResultCbEmpty()) {
        ret = UnRegisterWifiEvent(&g_event);
        if (ret == WIFI_SUCCESS) {
            g_registerFlag = true;
        } else {
            LNN_LOGE(LNN_STATE, "softBus unRegister wifi event failed");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num)
{
    if (channelList == NULL) {
        LNN_LOGW(LNN_STATE, "para channelList is NULL");
        return SOFTBUS_ERR;
    }
    int32_t ret = Hid2dGetChannelListFor5G(channelList, num);
    if (ret != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "get channel 5G list failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

SoftBusBand SoftBusGetLinkBand(void)
{
    WifiLinkedInfo result;
    if (GetLinkedInfo(&result) != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "get SoftBusGetLinkBand failed");
        return BAND_UNKNOWN;
    }
    if (result.band == BAND_24G) {
        return BAND_24G;
    } else if (result.band == BAND_5G) {
        return BAND_5G;
    } else {
        LNN_LOGE(LNN_STATE, "band unknown");
        return BAND_UNKNOWN;
    }
}

int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    WifiLinkedInfo result;
    if (GetLinkedInfo(&result) != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "get SoftBusGetLinkedInfo failed");
        return SOFTBUS_ERR;
    }
    info->frequency = result.frequency;
    info->band = result.band;
    info->connState = SOFTBUS_API_WIFI_DISCONNECTED;
    if (result.connState == WIFI_CONNECTED) {
        info->connState = SOFTBUS_API_WIFI_CONNECTED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGetCurrentGroup(SoftBusWifiP2pGroupInfo *groupInfo)
{
    if (groupInfo == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    WifiP2pGroupInfo result;
    if (GetCurrentGroup(&result) != WIFI_SUCCESS) {
        LNN_LOGD(LNN_STATE, "get SoftBusGetCurrentGroup failed");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(groupInfo, sizeof(SoftBusWifiP2pGroupInfo), &result, sizeof(WifiP2pGroupInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
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
    int wifiState = IsWifiActive();
    LNN_LOGI(LNN_STATE, "wifiState=%{public}d", wifiState);
    if (wifiState == WIFI_STA_ACTIVE) {
        return true;
    }
    return false;
}

bool SoftBusIsHotspotActive(void)
{
    int hotspotState = IsHotspotActive();
    LNN_LOGI(LNN_STATE, "hotspotState=%{public}d", hotspotState);
    if (hotspotState == WIFI_HOTSPOT_ACTIVE) {
        return true;
    }
    return false;
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    WifiDetailState wifiState;
    if (GetWifiDetailState(&wifiState) != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetWifiDetailState failed");
        return SOFTBUS_WIFI_STATE_UNKNOWN;
    }
    LNN_LOGI(LNN_STATE, "wifiState=%{public}d", wifiState);
    switch (wifiState) {
        case STATE_INACTIVE:
            return SOFTBUS_WIFI_STATE_INACTIVE;
        case STATE_ACTIVATED:
            return SOFTBUS_WIFI_STATE_ACTIVED;
        case STATE_ACTIVATING:
            return SOFTBUS_WIFI_STATE_ACTIVATING;
        case STATE_DEACTIVATING:
            return SOFTBUS_WIFI_STATE_DEACTIVATING;
        case STATE_SEMI_ACTIVATING:
            return SOFTBUS_WIFI_STATE_SEMIACTIVATING;
        case STATE_SEMI_ACTIVE:
            return SOFTBUS_WIFI_STATE_SEMIACTIVE;
        default:
            break;
    }
    return SOFTBUS_WIFI_STATE_UNKNOWN;
}

bool SoftBusIsWifiP2pEnabled(void)
{
    enum P2pState state;
    if (GetP2pEnableStatus(&state) != WIFI_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetP2pEnableStatus failed");
        return false;
    }
    LNN_LOGI(LNN_STATE, "P2pState=%{public}d", state);

    return state == P2P_STATE_STARTED;
}
