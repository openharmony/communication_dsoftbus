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

#include "anonymizer.h"
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
#include "lnn_ohos_account_adapter.h"

static LnnDeviceNameHandler g_eventHandler = nullptr;

namespace OHOS {
namespace BusCenter {
static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
static constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static constexpr const char *SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static constexpr const char *SETTINGS_DATA_FIELD_VALUE = "VALUE";
static constexpr const char *PREDICATES_STRING = "settings.general.device_name";
static constexpr const char *USER_DEFINED_STRING = "settings.general.user_defined_device_name";
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

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelperInstance(void)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        LNN_LOGE(LNN_STATE, "saManager NULL");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    if (remoteObject == nullptr) {
        LNN_LOGE(LNN_STATE, "remoteObject NULL");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObject, SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
}

static int32_t GetDeviceNameFromDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    std::shared_ptr<Uri> &uri, const char *key, char *deviceName, uint32_t len)
{
    int32_t numRows = 0;
    std::string val;
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);

    auto resultSet = dataShareHelper->Query(*uri, predicates, columns);
    if (resultSet == nullptr) {
        LNN_LOGE(LNN_STATE, "query fail.");
        return SOFTBUS_ERR;
    }
    resultSet->GetRowCount(numRows);
    if (numRows <= 0) {
        LNN_LOGE(LNN_STATE, "row zero.");
        resultSet->Close();
        return SOFTBUS_ERR;
    }

    int columnIndex;
    resultSet->GoToFirstRow();
    resultSet->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    if (resultSet->GetString(columnIndex, val) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetString val fail");
        resultSet->Close();
        return SOFTBUS_ERR;
    }
    if (strncpy_s(deviceName, len, val.c_str(), strlen(val.c_str())) != EOK) {
        LNN_LOGE(LNN_STATE, "strncpy_s fail.");
        resultSet->Close();
        return SOFTBUS_ERR;
    }
    char *anonyDeviceName = NULL;
    Anonymize(deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_STATE, "deviceName=%{public}s.", AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyDeviceName);
    resultSet->Close();
    return SOFTBUS_OK;
}

static int32_t GetDefaultDeviceName(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    char *deviceName, uint32_t len)
{
    std::shared_ptr<Uri> uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI + "&key=" + PREDICATES_STRING);
    LNN_LOGI(LNN_STATE, "get default deviceName");
    return GetDeviceNameFromDataShareHelper(dataShareHelper, uri, PREDICATES_STRING, deviceName, len);
}

static int32_t GetUserDefinedDeviceName(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    char *deviceName, uint32_t len)
{
    int32_t osAccountId = GetActiveOsAccountIds();
    if (osAccountId == SOFTBUS_ERR) {
        return SOFTBUS_NO_INIT;
    }
    std::string accountIdStr = std::to_string(osAccountId);
    std::shared_ptr<Uri> uri = std::make_shared<Uri>(SETTINGS_DATA_SECURE_URI + accountIdStr + "?Proxy=true&key=" +
        USER_DEFINED_STRING);
    LNN_LOGI(LNN_STATE, "get user defined deviceName, accountIdStr=%{public}s", accountIdStr.c_str());
    return GetDeviceNameFromDataShareHelper(dataShareHelper, uri, USER_DEFINED_STRING, deviceName, len);
}

static void RegisterNameMonitorHelper(void)
{
    auto dataShareHelper = OHOS::BusCenter::CreateDataShareHelperInstance();
    if (dataShareHelper == nullptr) {
        LNN_LOGE(LNN_STATE, "CreateDataShareHelperInstance fail.");
        return;
    }
    auto uri = std::make_shared<Uri>(SETTINGS_DATA_BASE_URI + "&key=" + PREDICATES_STRING);
    sptr<LnnSettingDataEventMonitor> settingDataObserver = std::make_unique<LnnSettingDataEventMonitor>().release();
    dataShareHelper->RegisterObserver(*uri, settingDataObserver);

    int32_t osAccountId = GetActiveOsAccountIds();
    if (osAccountId == SOFTBUS_ERR) {
        return;
    }
    std::string accountIdStr = std::to_string(osAccountId);
    uri = std::make_shared<Uri>(SETTINGS_DATA_SECURE_URI + accountIdStr + "?Proxy=true&key=" + USER_DEFINED_STRING);
    dataShareHelper->RegisterObserver(*uri, settingDataObserver);

    dataShareHelper->Release();
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
    auto dataShareHelper = OHOS::BusCenter::CreateDataShareHelperInstance();
    if (dataShareHelper == nullptr) {
        LNN_LOGE(LNN_STATE, "CreateDataShareHelperInstance fail.");
        return SOFTBUS_NO_INIT;
    }

    int32_t ret = OHOS::BusCenter::GetUserDefinedDeviceName(dataShareHelper, deviceName, len);
    if (ret == SOFTBUS_NO_INIT) {
        LNN_LOGI(LNN_STATE, "account not ready, try again");
        dataShareHelper->Release();
        return ret;
    }
    if (ret == SOFTBUS_OK) {
        char *anonyDeviceName = NULL;
        Anonymize(deviceName, &anonyDeviceName);
        LNN_LOGI(LNN_STATE, "get user defined deviceName=%{public}s", AnonymizeWrapper(anonyDeviceName));
        AnonymizeFree(anonyDeviceName);
        dataShareHelper->Release();
        return SOFTBUS_OK;
    }
    ret = OHOS::BusCenter::GetDefaultDeviceName(dataShareHelper, deviceName, len);
    char *anonyDeviceName = NULL;
    Anonymize(deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_STATE, "get default deviceName=%{public}s, ret=%{public}d", AnonymizeWrapper(anonyDeviceName), ret);
    AnonymizeFree(anonyDeviceName);
    dataShareHelper->Release();
    return ret;
}

int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler)
{
    if (handler == NULL) {
        LNN_LOGE(LNN_INIT, "handler is null");
        return SOFTBUS_ERR;
    }
    g_eventHandler = handler;
    return SOFTBUS_OK;
}

int32_t LnnInitDeviceNameMonitorImpl(void)
{
    UpdateDeviceName(NULL);
    return SOFTBUS_OK;
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