/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "wifi_statistic.h"

#include "inner_api/wifi_device.h"
#include "inner_api/wifi_hotspot.h"
#include "inner_api/wifi_p2p.h"
#include "comm_log.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "anonymizer.h"

using namespace OHOS::Wifi;

namespace Communication {
namespace Softbus {

WifiStatistic& WifiStatistic::GetInstance()
{
    static WifiStatistic instance;
    return instance;
}

int32_t WifiStatistic::GetWifiStatisticInfo(cJSON *json)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetStaInfo(json) != SOFTBUS_OK || GetSoftApInfo(json) != SOFTBUS_OK || GetP2PInfo(json) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static std::string AnonymizeStr(const std::string &data)
{
    if (data.empty()) {
        return "";
    }
    char *temp = nullptr;
    Anonymize(data.c_str(), &temp);
    std::string result = AnonymizeWrapper(temp);
    AnonymizeFree(temp);
    return result;
}

int32_t WifiStatistic::GetStaInfo(cJSON *json)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return SOFTBUS_INVALID_PARAM;
    }
    std::shared_ptr<WifiDevice> wifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiStaPtr == nullptr) {
        COMM_LOGW(COMM_DFX, "Get wifi device fail");
        return SOFTBUS_OK;
    }
    cJSON *staJson = cJSON_CreateObject();
    WifiLinkedInfo wifiLinkedInfo;
    if (wifiStaPtr->GetLinkedInfo(wifiLinkedInfo) != 0) {
        (void)AddNumberToJsonObject(staJson, "IsStaExist", 0);
        (void)cJSON_AddItemToObject(json, "StaInfo", staJson);
        return SOFTBUS_OK;
    }
    (void)AddNumberToJsonObject(staJson, "IsStaExist", 1);
    (void)AddStringToJsonObject(staJson, "Name", wifiLinkedInfo.ssid.c_str());
    (void)AddStringToJsonObject(staJson, "Mac", AnonymizeStr(wifiLinkedInfo.bssid).c_str());
    (void)AddNumberToJsonObject(staJson, "Freq", wifiLinkedInfo.frequency);
    (void)AddNumberToJsonObject(staJson, "chload", wifiLinkedInfo.chload);

    (void)cJSON_AddItemToObject(json, "StaInfo", staJson);
    return SOFTBUS_OK;
}

int32_t WifiStatistic::GetSoftApInfo(cJSON *json)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return SOFTBUS_INVALID_PARAM;
    }
    std::shared_ptr<WifiHotspot> wifiSoftApPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
    if (wifiSoftApPtr == nullptr) {
        COMM_LOGW(COMM_DFX, "Get wifi soft ap fail");
        return SOFTBUS_OK;
    }
    cJSON *softApJson = cJSON_CreateObject();
    bool isHotspotActive = false;
    wifiSoftApPtr->IsHotspotActive(isHotspotActive);
    if (!isHotspotActive) {
        (void)AddNumberToJsonObject(softApJson, "IsSoftApExist", 0);
        (void)cJSON_AddItemToObject(json, "SoftApInfo", softApJson);
        return SOFTBUS_OK;
    }
    (void)AddNumberToJsonObject(softApJson, "IsSoftApExist", 1);
    HotspotConfig config;
    wifiSoftApPtr->GetHotspotConfig(config);
    (void)AddNumberToJsonObject(softApJson, "channel", config.GetChannel());
    std::vector<StationInfo> stationList;
    if (wifiSoftApPtr->GetStationList(stationList) != 0 || stationList.size() == 0) {
        (void)AddNumberToJsonObject(softApJson, "StaNum", 0);
        (void)cJSON_AddItemToObject(json, "SoftApInfo", softApJson);
        return SOFTBUS_OK;
    }
    (void)AddNumberToJsonObject(softApJson, "StaNum", stationList.size());
    cJSON *stationArray = cJSON_CreateArray();
    for (size_t i = 0; i < stationList.size(); i++) {
        cJSON *stationJson = cJSON_CreateObject();
        (void)AddStringToJsonObject(stationJson, "Name", stationList[i].deviceName.c_str());
        (void)AddStringToJsonObject(stationJson, "Mac", AnonymizeStr(stationList[i].bssid).c_str());
        (void)cJSON_AddItemToArray(stationArray, stationJson);
    }
    (void)cJSON_AddItemToObject(softApJson, "StaDevList", stationArray);
    (void)cJSON_AddItemToObject(json, "SoftApInfo", softApJson);
    return SOFTBUS_OK;
}

int32_t WifiStatistic::GetP2PInfo(cJSON *json)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return SOFTBUS_INVALID_PARAM;
    }
    std::shared_ptr<WifiP2p> wifiP2PPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
    if (wifiP2PPtr == nullptr) {
        COMM_LOGW(COMM_DFX, "Get wifi p2p fail");
        return SOFTBUS_OK;
    }
    cJSON *p2pJson = cJSON_CreateObject();
    WifiP2pGroupInfo groupInfo;
    if (wifiP2PPtr->GetCurrentGroup(groupInfo) != 0) {
        (void)AddNumberToJsonObject(p2pJson, "IsP2PExist", 0);
        (void)cJSON_AddItemToObject(json, "P2PInfo", p2pJson);
        return SOFTBUS_OK;
    }
    (void)AddNumberToJsonObject(p2pJson, "IsP2PExist", 1);
    (void)AddBoolToJsonObject(p2pJson, "IsP2POwner", groupInfo.IsGroupOwner());
    (void)AddNumberToJsonObject(p2pJson, "Freq", groupInfo.GetFrequency());
    if (!groupInfo.IsGroupOwner()) {
        cJSON *goJson = cJSON_CreateObject();
        (void)AddStringToJsonObject(goJson, "Name", groupInfo.GetOwner().GetDeviceName().c_str());
        (void)AddStringToJsonObject(goJson, "Mac",
            AnonymizeStr(groupInfo.GetOwner().GetRandomDeviceAddress()).c_str());
        (void)cJSON_AddItemToObject(p2pJson, "GOInfo", goJson);
        (void)cJSON_AddItemToObject(json, "P2PInfo", p2pJson);
        return SOFTBUS_OK;
    }
    std::vector<WifiP2pDevice> gcList = groupInfo.GetClientDevices();
    (void)AddNumberToJsonObject(p2pJson, "GCNum", gcList.size());
    cJSON *gcArray = cJSON_CreateArray();
    for (size_t i = 0; i < gcList.size(); i++) {
        cJSON *gcJson = cJSON_CreateObject();
        (void)AddStringToJsonObject(gcJson, "Name", gcList[i].GetDeviceName().c_str());
        (void)AddStringToJsonObject(gcJson, "Mac",
            AnonymizeStr(gcList[i].GetRandomDeviceAddress()).c_str());
        (void)cJSON_AddItemToArray(gcArray, gcJson);
    }
    (void)cJSON_AddItemToObject(p2pJson, "GCInfo", gcArray);
    (void)cJSON_AddItemToObject(json, "P2PInfo", p2pJson);
    return SOFTBUS_OK;
}

} // namespace SoftBus
} // namespace Communication