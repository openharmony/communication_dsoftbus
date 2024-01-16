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

#include "lnn_settingdata_event_monitor.h"

#include <securec.h>

#include "data_ability_observer_stub.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "lnn_async_callback_utils.h"
#include "lnn_devicename_info.h"
#include "lnn_log.h"
#include "iservice_registry.h"
#include "message_handler.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "system_ability_definition.h"
#include "uri.h"

static const int32_t DELAY_LEN = 1000;
static LnnDeviceNameHandler g_eventHandler = nullptr;

namespace OHOS {
namespace BusCenter {
static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static constexpr const char *SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static constexpr const char *SETTINGS_DATA_FIELD_VALUE = "VALUE";
static constexpr const char *PREDICATES_STRING = "settings.general.device_name";
std::shared_ptr<DataShare::DataShareHelper> g_dataShareHelper;
static const uint32_t SOFTBUS_SA_ID = 4700;

class LnnSettingDataEventMonitor : public AAFwk::DataAbilityObserverStub {
public:
    void OnChange() override;
};

void LnnSettingDataEventMonitor::OnChange()
{
    LNN_LOGI(LNN_STATE, "device name change");
    if (g_eventHandler != nullptr) {
        g_eventHandler(DEVICE_NAME_TYPE_DEV_NAME, nullptr);
    }
}

static void CreateDataShareHelperInstance(void)
{
    if (g_dataShareHelper != nullptr) {
        LNN_LOGE(LNN_STATE, "already inited");
        return;
    }

    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        LNN_LOGE(LNN_STATE, "saManager NULL");
        return;
    }

    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    if (remoteObject == nullptr) {
        LNN_LOGE(LNN_STATE, "remoteObject NULL");
        return;
    }
    g_dataShareHelper =  DataShare::DataShareHelper::Creator(remoteObject, SETTINGS_DATA_BASE_URI,
        SETTINGS_DATA_EXT_URI);
    if (g_dataShareHelper == nullptr) {
        LNN_LOGE(LNN_STATE, "create fail.");
        return;
    }
    LNN_LOGI(LNN_STATE, "exit success.");
}

static int32_t GetDeviceNameFromDataShareHelper(char *deviceName, uint32_t len)
{
    if (g_dataShareHelper == nullptr) {
        LNN_LOGI(LNN_STATE, "retry to create datashare intance.");
        OHOS::BusCenter::CreateDataShareHelperInstance();
        if (g_dataShareHelper == nullptr) {
            LNN_LOGE(LNN_STATE, "GetDeviceNameFromDataShareHelper NULL.");
            return SOFTBUS_ERR;
        }
    }

    LNN_LOGI(LNN_STATE, "GetDeviceNameFromDataShareHelper enter.");
    int32_t numRows = 0;
    std::string val;

    std::shared_ptr<Uri> uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI);
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, PREDICATES_STRING);

    auto resultSet = g_dataShareHelper->Query(*uri, predicates, columns);
    if (resultSet == nullptr) {
        LNN_LOGE(LNN_STATE, "GetDeviceNameFromDataShareHelper query fail.");
        return SOFTBUS_ERR;
    }
    resultSet->GetRowCount(numRows);
    if (numRows <= 0) {
        LNN_LOGE(LNN_STATE, "GetDeviceNameFromDataShareHelper row zero.");
        return SOFTBUS_ERR;
    }

    int columnIndex;
    resultSet->GoToFirstRow();
    resultSet->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultSet->GetString(columnIndex, val);
    if (strncpy_s(deviceName, len, val.c_str(), strlen(val.c_str())) != EOK) {
        LNN_LOGE(LNN_STATE, "strncpy_s fail.");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_STATE, "GetDeviceNameFromDataShareHelper, deviceName=%{public}s.", deviceName);
    return SOFTBUS_OK;
}

static void RegisterNameMonitorHelper(void)
{
    if (g_dataShareHelper == nullptr) {
        LNN_LOGE(LNN_STATE, "g_dataShareHelper == NULL");
        return;
    }
    auto uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI + "&key=" + PREDICATES_STRING);
    sptr<LnnSettingDataEventMonitor> settingDataObserver = std::make_unique<LnnSettingDataEventMonitor>().release();
    g_dataShareHelper->RegisterObserver(*uri, settingDataObserver);
    LNN_LOGI(LNN_STATE, "success");
}
}
}

int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    if (deviceName == NULL) {
        LNN_LOGE(LNN_STATE, "invalid para");
        return SOFTBUS_ERR;
    }
    if (OHOS::BusCenter::GetDeviceNameFromDataShareHelper(deviceName, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetDeviceNameFromDataShareHelper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler)
{
    if (handler == NULL) {
        LNN_LOGE(LNN_INIT, "handler is null");
        return SOFTBUS_ERR;
    }
    g_eventHandler = handler;
    OHOS::BusCenter::CreateDataShareHelperInstance();
    return SOFTBUS_OK;
}

int32_t LnnInitDeviceNameMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (looper == NULL) {
        LNN_LOGE(LNN_INIT, "looper is null");
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, UpdateDeviceName, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackDelayHelper fail");
    }
    return ret;
}

void RegisterNameMonitor(void)
{
    OHOS::BusCenter::RegisterNameMonitorHelper();
}

int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len)
{
    (void)unifiedName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetUnifiedDefaultDeviceName(char *unifiedDefaultName, uint32_t len)
{
    (void)unifiedDefaultName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetSettingNickName(const char *defaultName, const char *unifiedName, char *nickName, uint32_t len)
{
    (void)defaultName;
    (void)unifiedName;
    (void)nickName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName, uint32_t len)
{
    (void)nickName;
    (void)defaultName;
    (void)deviceName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}