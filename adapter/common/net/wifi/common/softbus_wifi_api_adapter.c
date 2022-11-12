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

#include <stdlib.h>
#include <string.h>

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "wifi_device.h"
#include "wifi_hid2d.h"
#include "wifi_p2p.h"

static int32_t ConvertSoftBusWifiConfFromWifiDev(const WifiDeviceConfig *sourceWifiConf, SoftBusWifiDevConf *wifiConf)
{
    if (strcpy_s(wifiConf->ssid, sizeof(wifiConf->ssid), sourceWifiConf->ssid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(wifiConf->bssid, sizeof(wifiConf->bssid), sourceWifiConf->bssid,
        sizeof(sourceWifiConf->bssid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mem copy bssid fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(wifiConf->preSharedKey, sizeof(wifiConf->preSharedKey),
        sourceWifiConf->preSharedKey) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    wifiConf->securityType = sourceWifiConf->securityType;
    wifiConf->isHiddenSsid = sourceWifiConf->isHiddenSsid;

    return SOFTBUS_OK;
}

static int32_t ConvertWifiDevConfFromSoftBusWifiConf(const SoftBusWifiDevConf *result, WifiDeviceConfig *wifiConf)
{
    if (strcpy_s(wifiConf->ssid, sizeof(wifiConf->ssid), result->ssid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy ssid fail");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(wifiConf->bssid, sizeof(wifiConf->bssid),
        result->bssid, sizeof(result->bssid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mem copy bssid fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(wifiConf->preSharedKey, sizeof(wifiConf->preSharedKey),
        result->preSharedKey) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy ssid fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para configList is NULL");
        return SOFTBUS_ERR;
    }
    result = SoftBusMalloc(sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
    if (result == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc wifi device config fail");
        return SOFTBUS_ERR;
    }
    (void)memset_s(result, sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE, 0,
                   sizeof(WifiDeviceConfig) * WIFI_MAX_CONFIG_SIZE);
    retVal = GetDeviceConfigs(result, &wifiConfigSize);
    if (retVal != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc wifi device config fail");
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }

    if (wifiConfigSize > WIFI_MAX_CONFIG_SIZE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wifi device config size is invalid.");
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }

    for (i = 0; i < wifiConfigSize; i++) {
        if (ConvertSoftBusWifiConfFromWifiDev(result, configList) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert wifi config failed.");
            SoftBusFree(result);
            return SOFTBUS_ERR;
        }
        result++;
        configList++;
    }
    *num = wifiConfigSize;
    SoftBusFree(result);
    return SOFTBUS_OK;
}

int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig)
{
    WifiDeviceConfig wifiDevConfig;

    if (wifiConfig == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para wifiConfig is NULL");
        return SOFTBUS_ERR;
    }
    (void)memset_s(&wifiDevConfig, sizeof(WifiDeviceConfig), 0, sizeof(WifiDeviceConfig));
    if (ConvertWifiDevConfFromSoftBusWifiConf(wifiConfig, &wifiDevConfig) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert wifi config failed.");
        return SOFTBUS_ERR;
    }

    if (ConnectToDevice(&wifiDevConfig) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connect to wifi failed.");
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
    int32_t ret;

    ret = Scan();
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "softbus start wifi scan failed.");
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
    int32_t ret;

    int index = FindFreeCallbackIndex();
    if (index == MAX_CALLBACK_NUM) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register callback index invalid.");
        return SOFTBUS_ERR;
    }
    g_scanResultCb[index] = cb;

    if (g_registerFlag) {
        ret = RegisterWifiEvent(&g_event);
        if (ret == WIFI_SUCCESS) {
            g_registerFlag = false;
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "softbus register wifi event failed.");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t ConvertSoftBusWifiScanInfoFromWifi(WifiScanInfo *info, SoftBusWifiScanInfo *result, uint32_t *size)
{
    if (info == NULL || result == NULL || size == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < (*size); i++) {
        if (strcpy_s(result->ssid, WIFI_MAX_SSID_LEN, info->ssid) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy ssid fail");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(result->bssid, WIFI_MAC_LEN, info->bssid, sizeof(info->bssid)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy bssid fail");
            return SOFTBUS_ERR;
        }
        result->securityType =  (int32_t)(info->securityType);
        result->rssi = (int32_t)(info->rssi);
        result->band = (int32_t)(info->band);
        result->frequency = (int32_t)(info->frequency);
        result->channelWidth = (int32_t)(info->channelWidth);
        result->centerFrequency0 =(int32_t)(info->centerFrequency0);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para size or result is NULL.");
        return SOFTBUS_ERR;
    }
    WifiScanInfo *info = (WifiScanInfo *)SoftBusMalloc(sizeof(WifiScanInfo) * WIFI_MAX_SCAN_HOTSPOT_LIMIT);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc wifi scan information failed.");
        return SOFTBUS_ERR;
    }
    (void)memset_s(info, sizeof(WifiScanInfo)*WIFI_MAX_SCAN_HOTSPOT_LIMIT, 0,
        sizeof(WifiScanInfo)*WIFI_MAX_SCAN_HOTSPOT_LIMIT);
    *size = WIFI_MAX_SCAN_HOTSPOT_LIMIT;
    int32_t ret = GetScanInfoList(info, (unsigned int *)size);
    if (ret != WIFI_SUCCESS || size == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "softbus get wifi scan list failed.");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    *result = (SoftBusWifiScanInfo *)SoftBusMalloc(sizeof(SoftBusWifiScanInfo) * (*size));
    if (*result == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc softbus wifi scan information failed.");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    (void)memset_s(*result, sizeof(SoftBusWifiScanInfo)* (*size), 0, sizeof(SoftBusWifiScanInfo)* (*size));
    if (ConvertSoftBusWifiScanInfoFromWifi(info, *result, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ConvertSoftBusWifiScaninfoFromWifi failed.");
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
    int32_t ret;

    for (int i = 0; i < MAX_CALLBACK_NUM; i++) {
        if (g_scanResultCb[i] == cb) {
            g_scanResultCb[i] = NULL;
        }
    }

    if (IsScanResultCbEmpty()) {
        ret = UnRegisterWifiEvent(&g_event);
        if (ret == WIFI_SUCCESS) {
            g_registerFlag = true;
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "softBus unRegister wifi event failed.");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num)
{
    if (channelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para channelList is NULL.");
        return SOFTBUS_ERR;
    }
    int32_t ret = Hid2dGetChannelListFor5G(channelList, num);
    if (ret != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get channel 5G list failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

SoftBusBand SoftBusGetLinkBand(void)
{
    WifiLinkedInfo result;
    GetLinkedInfo(&result);
    if (GetLinkedInfo(&result) != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get SoftBusGetLinkBand failed.");
        return BAND_UNKNOWN;
    }
    if (result.band == BAND_24G) {
        return BAND_24G;
    } else if (result.band == BAND_5G) {
        return BAND_5G;
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get SoftBusGetLinkBand success.");
        return BAND_UNKNOWN;
    }
}

int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    WifiLinkedInfo result;
    if (GetLinkedInfo(&result) != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get SoftBusGetLinkedInfo failed.");
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
    WifiP2pGroupInfo result;
    if (GetCurrentGroup(&result) != WIFI_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get SoftBusGetCurrentGroup failed.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(groupInfo, sizeof(SoftBusWifiP2pGroupInfo), &result, sizeof(WifiP2pGroupInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}