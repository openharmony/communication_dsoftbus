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

#include "abs_shared_result_set.h"
#include "data_ability_helper.h"
#include "data_ability_predicates.h"
#include "data_ability_observer_stub.h"
#include "lnn_devicename_info.h"
#include "lnn_async_callback_utils.h"
#include "iservice_registry.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "system_ability_definition.h"

static const int32_t DELAY_LEN = 100000;
static LnnDeviceNameHandler g_eventHandler = nullptr;

namespace OHOS {
namespace BusCenter {
static const std::string SETTINGS_DATA_BASE_URI = "dataability:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
static const std::string PREDICATES_STRING = "settings.general.device_name";
static const std::string SETTINGS_DATA_DEVICE_NAME_URI =
    "dataability:///com.ohos.settingsdata.DataAbility/settings.general.device_name";
std::shared_ptr<AppExecFwk::DataAbilityHelper> g_dataAbilityHelper;
static const uint32_t SOFTBUS_SA_ID = 4700;

class LnnSettingDataEventMonitor : public AAFwk::DataAbilityObserverStub {
public:
    void OnChange() override;
};

void LnnSettingDataEventMonitor::OnChange()
{
    if (g_eventHandler != nullptr) {
        g_eventHandler();
    }
}

static void CreateDataAbilityHelperInstance(void)
{
    if (g_dataAbilityHelper != nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateDataAbilityHelperInstance already inited.");
        return;
    }

    auto uri = std::make_shared<Uri>(SETTINGS_DATA_DEVICE_NAME_URI);
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateDataAbilityHelperInstance saManager NULL");
        return;
    }

    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    if (remoteObject == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateDataAbilityHelperInstance remoteObject NULL");
        return;
    }
    g_dataAbilityHelper = AppExecFwk::DataAbilityHelper::Creator(remoteObject);
    if (g_dataAbilityHelper == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateDataAbilityHelperInstance create fail.");
        return;
    }

    sptr<LnnSettingDataEventMonitor> settingDataObserver = std::make_unique<LnnSettingDataEventMonitor>().release();
    g_dataAbilityHelper->RegisterObserver(*uri, settingDataObserver);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "CreateDataAbilityHelperInstance exit success.");
}

static int32_t GetDeviceNameFromDataAbilityHelper(char *deviceName, uint32_t len)
{
    if (g_dataAbilityHelper == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetDeviceNameFromDataAbilityHelper NULL.");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetDeviceNameFromDataAbilityHelper enter.");
    int32_t numRows = 0;
    std::string val;

    std::shared_ptr<Uri> uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI);
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, PREDICATES_STRING);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultset =
        g_dataAbilityHelper->Query(*uri, columns, predicates);
    if (resultset == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetDeviceNameFromDataAbilityHelper query fail.");
        return SOFTBUS_ERR;
    }
    resultset->GetRowCount(numRows);
    if (numRows <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetDeviceNameFromDataAbilityHelper row zero.");
        return SOFTBUS_ERR;
    }

    int columnIndex;
    resultset->GoToFirstRow();
    resultset->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultset->GetString(columnIndex, val);
    resultset->Close();
    if (strncpy_s(deviceName, len, val.c_str(), strlen(val.c_str())) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s fail.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetDeviceNameFromDataAbilityHelper, deviceName=%s.", deviceName);
    return SOFTBUS_OK;
}
}
}

int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    if (deviceName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    if (OHOS::BusCenter::GetDeviceNameFromDataAbilityHelper(deviceName, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetSettingDeviceName fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler)
{
    if (handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "handler is null");
        return SOFTBUS_ERR;
    }
    g_eventHandler = handler;
    OHOS::BusCenter::CreateDataAbilityHelperInstance();
    return SOFTBUS_OK;
}

int32_t LnnInitDeviceNameMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, UpdateDeviceName, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init DeviceName LnnAsyncCallbackDelayHelper fail");
    }
    return ret;
}