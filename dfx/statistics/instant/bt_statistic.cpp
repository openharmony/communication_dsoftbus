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

#include "bt_statistic.h"

#include "bluetooth_a2dp_snk.h"
#include "bluetooth_a2dp_src.h"
#include "bluetooth_avrcp_ct.h"
#include "bluetooth_avrcp_tg.h"
#include "bluetooth_hfp_ag.h"
#include "bluetooth_hfp_hf.h"
#include "bluetooth_hid_host.h"
#include "bluetooth_host.h"
#include "bluetooth_map_mse.h"
#include "bluetooth_opp.h"
#include "bluetooth_pan.h"
#include "bluetooth_pbap_pse.h"
#include "bluetooth_gatt_manager.h"
#include "comm_log.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "anonymizer.h"

using namespace OHOS::Bluetooth;

namespace Communication {
namespace Softbus {

BtStatistic::BtStatistic()
{
    connectState_ = { static_cast<int32_t>(BTConnectState::CONNECTED) };
    getProfileDeviceInfoMap_ = {
        {PROFILE_ID_GATT_CLIENT, &BtStatistic::GetGattClientDeviceInfo},
        {PROFILE_ID_GATT_SERVER, &BtStatistic::GetGattServerDeviceInfo},
        {PROFILE_ID_A2DP_SRC, &BtStatistic::GetA2dpSrcDeviceInfo},
        {PROFILE_ID_A2DP_SINK, &BtStatistic::GetA2dpSinkDeviceInfo},
        {PROFILE_ID_AVRCP_CT, &BtStatistic::GetAvrCTDeviceInfo},
        {PROFILE_ID_AVRCP_TG, &BtStatistic::GetAvrTGDeviceInfo},
        {PROFILE_ID_HFP_AG, &BtStatistic::GetHfpAGDeviceInfo},
        {PROFILE_ID_HFP_HF, &BtStatistic::GetHfpHFDeviceInfo},
        {PROFILE_ID_MAP_MCE, nullptr},
        {PROFILE_ID_MAP_MSE, &BtStatistic::GetMapMseDeviceInfo},
        {PROFILE_ID_PBAP_PCE, nullptr},
        {PROFILE_ID_PBAP_PSE, &BtStatistic::GetPbapPseDeviceInfo},
        {PROFILE_ID_SPP, nullptr},
        {PROFILE_ID_DI, nullptr},
        {PROFILE_ID_BLE_ADVERTISER, &BtStatistic::GetBleAdvertiserDeviceInfo},
        {PROFILE_ID_BLE_CENTRAL_MANAGER_SERVER, &BtStatistic::GetBleCentralDeviceInfo},
        {PROFILE_ID_BLE_GATT_MANAGER, &BtStatistic::GetBleGattDeviceInfo},
        {PROFILE_ID_HID_HOST, &BtStatistic::GetHidHostDeviceInfo},
        {PROFILE_ID_OPP, &BtStatistic::GetOppDeviceInfo},
        {PROFILE_ID_PAN, &BtStatistic::GetPanDeviceInfo},
        {PROFILE_ID_HOST, nullptr},
    };
}

BtStatistic& BtStatistic::GetInstance()
{
    static BtStatistic instance;
    return instance;
}

int32_t BtStatistic::GetBtStatisticInfo(cJSON *json)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *btDeviceArray = cJSON_CreateArray();
    std::vector<uint32_t> profileList = BluetoothHost::GetDefaultHost().GetProfileList();
    for (size_t i = 0; i < profileList.size(); i++) {
        if (getProfileDeviceInfoMap_.find(profileList[i]) == getProfileDeviceInfoMap_.end()) {
            continue;
        }
        GetProfileDeviceInfo func = getProfileDeviceInfoMap_[profileList[i]];
        if (func != nullptr) {
            (this->*func)(btDeviceArray);
        }
    }
    (void)cJSON_AddItemToObject(json, "BtDeviceList", btDeviceArray);
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

static void AddDevicesToArray(
    cJSON *json, const std::vector<OHOS::Bluetooth::BluetoothRemoteDevice>& devices, uint32_t profileId)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return;
    }
    for (size_t i = 0; i < devices.size(); i++) {
        cJSON *deviceJson = cJSON_CreateObject();
        (void)AddStringToJsonObject(deviceJson, "Name", devices[i].GetDeviceName().c_str());
        (void)AddStringToJsonObject(deviceJson, "Mac", AnonymizeStr(devices[i].GetDeviceAddr()).c_str());
        (void)AddNumberToJsonObject(deviceJson, "Profile", static_cast<int32_t>(profileId));
        if (profileId == PROFILE_ID_A2DP_SRC) {
            (void)AddStringToJsonObject(deviceJson, "IsPlaying",
                std::to_string(A2dpSource::GetProfile()->GetPlayingState(devices[i])).c_str());
        } else if (profileId == PROFILE_ID_A2DP_SINK) {
            (void)AddStringToJsonObject(deviceJson, "IsPlaying",
                std::to_string(A2dpSink::GetProfile()->GetPlayingState(devices[i])).c_str());
        } else if (profileId == PROFILE_ID_HFP_HF) {
            (void)AddStringToJsonObject(deviceJson, "ScoState",
                std::to_string(HandsFreeUnit::GetProfile()->GetScoState(devices[i])).c_str());
        } else if (profileId == PROFILE_ID_HFP_AG) {
            (void)AddStringToJsonObject(deviceJson, "ScoState",
                std::to_string(HandsFreeAudioGateway::GetProfile()->GetScoState(devices[i])).c_str());
        }
        (void)cJSON_AddItemToArray(json, deviceJson);
    }
}

void BtStatistic::GetGattDeviceInfo(cJSON *json, uint32_t gattId)
{
    if (json == nullptr) {
        COMM_LOGE(COMM_DFX, "param json is null");
        return;
    }
    std::vector<BluetoothRemoteDevice> devices;
    GattManager gattManager;
    devices = gattManager.GetConnectedDevices();
    AddDevicesToArray(json, devices, gattId);
}

void BtStatistic::GetGattClientDeviceInfo(cJSON *json)
{
    GetGattDeviceInfo(json, PROFILE_ID_GATT_CLIENT);
}

void BtStatistic::GetGattServerDeviceInfo(cJSON *json)
{
    GetGattDeviceInfo(json, PROFILE_ID_GATT_SERVER);
}

void BtStatistic::GetBleAdvertiserDeviceInfo(cJSON *json)
{
    GetGattDeviceInfo(json, PROFILE_ID_BLE_ADVERTISER);
}

void BtStatistic::GetBleCentralDeviceInfo(cJSON *json)
{
    GetGattDeviceInfo(json, PROFILE_ID_BLE_CENTRAL_MANAGER_SERVER);
}

void BtStatistic::GetBleGattDeviceInfo(cJSON *json)
{
    GetGattDeviceInfo(json, PROFILE_ID_BLE_GATT_MANAGER);
}

void BtStatistic::GetA2dpSrcDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    A2dpSource::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_A2DP_SRC);
}

void BtStatistic::GetA2dpSinkDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    devices = A2dpSink::GetProfile()->GetDevicesByStates(connectState_);
    AddDevicesToArray(json, devices, PROFILE_ID_A2DP_SINK);
}

void BtStatistic::GetAvrCTDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    devices = AvrcpController::GetProfile()->GetDevicesByStates(connectState_);
    AddDevicesToArray(json, devices, PROFILE_ID_AVRCP_CT);
}

void BtStatistic::GetAvrTGDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    devices = AvrcpTarget::GetProfile()->GetDevicesByStates(connectState_);
    AddDevicesToArray(json, devices, PROFILE_ID_AVRCP_TG);
}

void BtStatistic::GetHfpAGDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    devices = HandsFreeAudioGateway::GetProfile()->GetDevicesByStates(connectState_);
    AddDevicesToArray(json, devices, PROFILE_ID_HFP_AG);
}

void BtStatistic::GetHfpHFDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    devices = HandsFreeUnit::GetProfile()->GetDevicesByStates(connectState_);
    AddDevicesToArray(json, devices, PROFILE_ID_HFP_HF);
}

void BtStatistic::GetMapMseDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    MapMse::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_MAP_MSE);
}

void BtStatistic::GetPbapPseDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    PbapPse::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_PBAP_PSE);
}

void BtStatistic::GetHidHostDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    HidHost::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_HID_HOST);
}

void BtStatistic::GetOppDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    Opp::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_OPP);
}

void BtStatistic::GetPanDeviceInfo(cJSON *json)
{
    std::vector<BluetoothRemoteDevice> devices;
    Pan::GetProfile()->GetDevicesByStates(connectState_, devices);
    AddDevicesToArray(json, devices, PROFILE_ID_PAN);
}

} // namespace SoftBus
} // namespace Communication