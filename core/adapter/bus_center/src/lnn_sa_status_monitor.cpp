/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_sa_status_monitor.h"

#include "bus_center_event.h"
#include "iservice_registry.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_network_info.h"
#include "message_handler.h"
#include "refbase.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t MAX_RETRY_COUNT = 10;

namespace OHOS {
class ServiceStatusMonitorManager : public RefBase {
public:
    int32_t SubscribeSaById(int32_t saId);
    void UnSubscribeSaById(int32_t saId);

private:
    class SaStatusListener : public SystemAbilityStatusChangeStub {
    public:
        void OnAddSystemAbility(int32_t saId, const std::string &deviceId);
        void OnRemoveSystemAbility(int32_t saId, const std::string &deviceId);
    };
    sptr<SaStatusListener> statusLisener_ = nullptr;
};

void ServiceStatusMonitorManager::SaStatusListener::OnAddSystemAbility(int32_t saId, const std::string &deviceId)
{
    (void)deviceId;
    LNN_LOGI(LNN_EVENT, "onSaStart saId=%{public}d", saId);
    int32_t ret;
    switch (saId) {
        case WIFI_DEVICE_SYS_ABILITY_ID:
            ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnNotifyWifiServiceStart, NULL);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_EVENT, "async notify fail, ret=%{public}d", ret);
            }
            break;
        default:
            LNN_LOGE(LNN_EVENT, "invalid saId=%{public}d", saId);
            break;
    }
}

void ServiceStatusMonitorManager::SaStatusListener::OnRemoveSystemAbility(int32_t saId, const std::string &deviceId)
{
    (void)deviceId;
    LNN_LOGI(LNN_EVENT, "onRemove saId=%{public}d", saId);
}

int32_t ServiceStatusMonitorManager::SubscribeSaById(int32_t saId)
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "get samgr proxy failed");
        return SOFTBUS_TRANS_GET_SYSTEM_ABILITY_FAILED;
    }
    if (statusLisener_ == nullptr) {
        statusLisener_ = new (std::nothrow) SaStatusListener();
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(saId, statusLisener_);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_EVENT, "subscribe SA failed, ret=%{public}d, saId=%{public}d", ret, saId);
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "subscribe SA success, saId=%{public}d", saId);
    return SOFTBUS_OK;
}

void ServiceStatusMonitorManager::UnSubscribeSaById(int32_t saId)
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "get samgr proxy failed");
        return;
    }
    if (statusLisener_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "listener is nullptr");
        return;
    }
    int32_t ret = samgrProxy->UnSubscribeSystemAbility(saId, statusLisener_);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_EVENT, "unsubscribe SA failed, ret=%{public}d, saId=%{public}d", ret, saId);
        return;
    }
    LNN_LOGI(LNN_EVENT, "UnSubcribe SA success, saId=%{public}d", saId);
}
} // namespace OHOS

static OHOS::sptr<OHOS::ServiceStatusMonitorManager> g_serviceMonitorMgr;

static int32_t RegisterWifiService()
{
    if (g_serviceMonitorMgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "not init");
        return SOFTBUS_NO_INIT;
    }
    return g_serviceMonitorMgr->SubscribeSaById(OHOS::WIFI_DEVICE_SYS_ABILITY_ID);
}

static void UnRegisterWifiService()
{
    if (g_serviceMonitorMgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "not init");
        return;
    }
    g_serviceMonitorMgr->UnSubscribeSaById(OHOS::WIFI_DEVICE_SYS_ABILITY_ID);
}

static void InitSaStatusMonitor(void *para)
{
    (void)para;
    static uint32_t retryTimes = 0;
    if (retryTimes >= MAX_RETRY_COUNT) {
        LNN_LOGE(LNN_EVENT, "retry count exceed limit");
        g_serviceMonitorMgr = nullptr;
        return;
    }
    if (g_serviceMonitorMgr == nullptr) {
        g_serviceMonitorMgr = new (std::nothrow) OHOS::ServiceStatusMonitorManager();
    }
    if (g_serviceMonitorMgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "new object fail");
        return;
    }
    int32_t ret = RegisterWifiService();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "register wifi service fail, ret=%{public}d, retryTimes=%{public}u", ret, retryTimes);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), InitSaStatusMonitor, NULL, DELAY_LEN);
        retryTimes++;
        return;
    }
    LNN_LOGI(LNN_EVENT, "init success");
}

void LnnInitSaStatusMonitor(void)
{
    int32_t ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), InitSaStatusMonitor, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "async delay call fail, ret=%{public}d", ret);
        return;
    }
    LNN_LOGI(LNN_EVENT, "init success");
}

void LnnDeInitSaStatusMonitor(void)
{
    if (g_serviceMonitorMgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "not init");
        return;
    }
    UnRegisterWifiService();
}
