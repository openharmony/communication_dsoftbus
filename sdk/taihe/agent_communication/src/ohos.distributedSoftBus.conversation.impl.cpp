/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ohos.distributedSoftBus.conversation.proj.hpp"
#include "ohos.distributedSoftBus.conversation.impl.hpp"
#include "taihe/runtime.hpp"
#include "agent_communication_utils_taihe.h"
#include "anonymizer.h"
#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "napi_agent_communication_error_code.h"
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace Communication {
namespace OHOS::Softbus {

using DataCallback = ::taihe::callback<
    void(::taihe::string_view networkId, ::taihe::array_view<uint8_t> msg)>;

static std::mutex g_callbackMutex;
static std::map<std::string, std::shared_ptr<DataCallback>> g_dataCallbackMap;

static void OnDataReceivedAdapter(const char *deviceId, const char *data, uint32_t len, const char *abilityName)
{
    COMM_LOGI(COMM_SDK, "OnDataReceivedAdapter, len=%{public}u", len);
    if (data == nullptr || len == 0) {
        COMM_LOGE(COMM_SDK, "invalid data");
        return;
    }
    std::string abilityKey = (abilityName != nullptr) ? abilityName : "";
    std::shared_ptr<DataCallback> callback;
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        auto it = g_dataCallbackMap.find(abilityKey);
        if (it != g_dataCallbackMap.end()) {
            callback = it->second;
        }
    }
    if (callback == nullptr) {
        COMM_LOGE(COMM_SDK, "callback not found");
        return;
    }
    std::string devStr = (deviceId != nullptr) ? deviceId : "";
    std::vector<uint8_t> buffer(data, data + len);
    (*callback)(devStr, ::taihe::array<uint8_t>(buffer));
}

static ::ConversationListener g_listener = {
    .OnDataReceived = OnDataReceivedAdapter,
};

static void DumpPostConversationParam(::taihe::string_view deviceId, const std::string &bundleName,
    const std::string &abilityName, uint32_t dataLen)
{
    std::string deviceIdStr(deviceId);
    char *anonyDeviceId = nullptr;
    char *anonyBundleName = nullptr;
    char *anonyAbilityName = nullptr;
    Anonymize(deviceIdStr.c_str(), &anonyDeviceId);
    Anonymize(bundleName.c_str(), &anonyBundleName);
    Anonymize(abilityName.c_str(), &anonyAbilityName);
    COMM_LOGI(COMM_SDK,
        "PostConversationDataAsync start, deviceId=%{public}s, bundleName=%{public}s, "
        "abilityName=%{public}s, dataLen=%{public}u",
        AnonymizeWrapper(anonyDeviceId), AnonymizeWrapper(anonyBundleName),
        AnonymizeWrapper(anonyAbilityName), dataLen);
    AnonymizeFree(anonyDeviceId);
    AnonymizeFree(anonyBundleName);
    AnonymizeFree(anonyAbilityName);
}

static void LogListenerEntry(const std::string &bundleName, const std::string &abilityName,
    const char *funcName)
{
    char *anonyBundleName = nullptr;
    char *anonyAbilityName = nullptr;
    Anonymize(bundleName.c_str(), &anonyBundleName);
    Anonymize(abilityName.c_str(), &anonyAbilityName);
    COMM_LOGI(COMM_SDK, "%{public}s start, bundleName=%{public}s, abilityName=%{public}s",
        funcName, AnonymizeWrapper(anonyBundleName), AnonymizeWrapper(anonyAbilityName));
    AnonymizeFree(anonyBundleName);
    AnonymizeFree(anonyAbilityName);
}

::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo> GetTrustedDevice()
{
    COMM_LOGI(COMM_SDK, "GetTrustedDevice start");
    if (!IsSystemApp()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return ::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo>({});
    }
    if (!CheckPermission()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_ERR);
        return ::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo>({});
    }

    DeviceNodeInfo *list = nullptr;
    int32_t nums = 0;
    int32_t ret = ::GetTrustedDevice(&list, &nums);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "GetTrustedDevice fail, ret=%{public}d", ret);
        if (list != nullptr) {
            ::FreeDeviceNodeInfo(list);
        }
        ThrowBusinessException(ConvertToJsErrcode(ret));
        return ::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo>({});
    }

    std::vector<::ohos::distributedSoftBus::conversation::DeviceNodeInfo> devices;
    for (int32_t i = 0; i < nums; ++i) {
        ::ohos::distributedSoftBus::conversation::DeviceNodeInfo info = {
            .networkId = list[i].networkId,
            .deviceName = list[i].deviceName,
            .deviceTypeId = list[i].deviceTypeId,
            .nearby = list[i].nearby,
            .udid = list[i].udid,
        };
        devices.push_back(info);
    }

    if (list != nullptr) {
        ::FreeDeviceNodeInfo(list);
    }
    return ::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo>(
        taihe::move_data, devices.data(), devices.size());
}

void PostConversationDataAsync(::taihe::string_view deviceId,
    ::taihe::string_view bundleName, ::taihe::string_view abilityName,
    ::taihe::array_view<uint8_t> msg)
{
    std::string bundleNameStr(bundleName);
    std::string abilityNameStr(abilityName);
    DumpPostConversationParam(deviceId, bundleNameStr, abilityNameStr, static_cast<uint32_t>(msg.size()));
    if (!IsSystemApp()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return;
    }
    if (!CheckPermission()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_ERR);
        return;
    }

    std::string deviceIdStr(deviceId);
    if (deviceIdStr.empty()) {
        COMM_LOGE(COMM_SDK, "invalid deviceId");
        ThrowBusinessException(CONVERSATION_INVALID_PARAM);
        return;
    }
    if (bundleNameStr.empty() || abilityNameStr.empty() ||
        bundleNameStr.size() >= BUNDLE_NAME_LEN || abilityNameStr.size() >= ABILITY_NAME_LEN) {
        COMM_LOGE(COMM_SDK, "invalid business parameter");
        ThrowBusinessException(CONVERSATION_INVALID_PARAM);
        return;
    }
    if (msg.empty()) {
        COMM_LOGE(COMM_SDK, "msg is empty");
        ThrowBusinessException(CONVERSATION_INVALID_PARAM);
        return;
    }

    ::ConversationBusiness cBusiness;
    FillConversationBusiness(cBusiness, bundleNameStr, abilityNameStr);

    int32_t ret = ::PostConversationData(deviceIdStr.c_str(), &cBusiness,
        reinterpret_cast<const char *>(msg.data()), static_cast<uint32_t>(msg.size()));
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "PostConversationData fail, ret=%{public}d", ret);
        ThrowBusinessException(ConvertToJsErrcode(ret));
        return;
    }
    COMM_LOGI(COMM_SDK, "PostConversationDataAsync finish");
}

void RegisterConversationListener(::taihe::string_view bundleName, ::taihe::string_view abilityName,
    ::taihe::callback_view<void(::taihe::string_view networkId, ::taihe::array_view<uint8_t> msg)> callback)
{
    std::string bundleNameStr(bundleName);
    std::string abilityNameStr(abilityName);
    LogListenerEntry(bundleNameStr, abilityNameStr, "RegisterConversationListener");
    if (!IsSystemApp()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return;
    }
    if (!CheckPermission()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_ERR);
        return;
    }

    if (bundleNameStr.empty() || abilityNameStr.empty() ||
        bundleNameStr.size() >= BUNDLE_NAME_LEN || abilityNameStr.size() >= ABILITY_NAME_LEN) {
        COMM_LOGE(COMM_SDK, "invalid business parameter");
        ThrowBusinessException(CONVERSATION_INVALID_PARAM);
        return;
    }

    auto dataCallback = std::make_shared<DataCallback>(callback);
    bool isExisting = false;
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        if (g_dataCallbackMap.find(abilityNameStr) != g_dataCallbackMap.end()) {
            COMM_LOGI(COMM_SDK, "conversation listener already exist");
            isExisting = true;
        } else {
            g_dataCallbackMap[abilityNameStr] = dataCallback;
        }
    }

    ::ConversationBusiness cBusiness;
    FillConversationBusiness(cBusiness, bundleNameStr, abilityNameStr);

    int32_t ret = ::RegisterConversationListener(&cBusiness, &g_listener);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "RegisterConversationListener fail, ret=%{public}d", ret);
        if (!isExisting) {
            std::lock_guard<std::mutex> lock(g_callbackMutex);
            g_dataCallbackMap.erase(abilityNameStr);
        }
        ThrowBusinessException(ConvertToJsErrcode(ret));
    }
}

void UnregisterConversationListener(::taihe::string_view bundleName, ::taihe::string_view abilityName)
{
    std::string bundleNameStr(bundleName);
    std::string abilityNameStr(abilityName);
    LogListenerEntry(bundleNameStr, abilityNameStr, "UnregisterConversationListener");
    if (!IsSystemApp()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return;
    }
    if (!CheckPermission()) {
        ThrowBusinessException(CONVERSATION_PERMISSION_ERR);
        return;
    }

    if (bundleNameStr.empty() || abilityNameStr.empty() ||
        bundleNameStr.size() >= BUNDLE_NAME_LEN || abilityNameStr.size() >= ABILITY_NAME_LEN) {
        COMM_LOGE(COMM_SDK, "invalid business parameter");
        ThrowBusinessException(CONVERSATION_INVALID_PARAM);
        return;
    }

    ::ConversationBusiness cBusiness;
    FillConversationBusiness(cBusiness, bundleNameStr, abilityNameStr);

    int32_t ret = ::UnregisterConversationListener(&cBusiness);
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        g_dataCallbackMap.erase(abilityNameStr);
    }
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "UnregisterConversationListener fail, ret=%{public}d", ret);
        ThrowBusinessException(ConvertToJsErrcode(ret));
    }
}

} // namespace Softbus
} // namespace Communication

TH_EXPORT_CPP_API_GetTrustedDevices(Communication::OHOS::Softbus::GetTrustedDevice);
TH_EXPORT_CPP_API_PostConversationDataAsync(Communication::OHOS::Softbus::PostConversationDataAsync);
TH_EXPORT_CPP_API_RegisterConversationListener(Communication::OHOS::Softbus::RegisterConversationListener);
TH_EXPORT_CPP_API_UnregisterConversationListener(Communication::OHOS::Softbus::UnregisterConversationListener);
