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
#include "proxy_observer.h"

#include "bluetooth_hfp_ag.h"
#include "conn_log.h"
#include "softbus_common.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
class ProxyObserver : public OHOS::Bluetooth::HandsFreeAudioGatewayObserver {
public:
    explicit ProxyObserver(const ProxyListener listener)
    {
        listener_ = listener;
    }
    ~ProxyObserver() {}
    // HFP reconnection callback
    void OnConnectionStateChanged(const Bluetooth::BluetoothRemoteDevice &device,
        int32_t state, int32_t cause) override;
    void OnScoStateChanged(const Bluetooth::BluetoothRemoteDevice &device,
        int32_t state, int32_t reason) override {}
    void OnActiveDeviceChanged(const Bluetooth::BluetoothRemoteDevice &device) override {}
    void OnHfEnhancedDriverSafetyChanged(const Bluetooth::BluetoothRemoteDevice &device,
        int32_t indValue) override {}
    void OnHfpStackChanged(const Bluetooth::BluetoothRemoteDevice &device, int32_t action) override {}

private:
    ProxyListener listener_;
};

void ProxyObserver::OnConnectionStateChanged(const OHOS::Bluetooth::BluetoothRemoteDevice &device,
    int32_t state, int32_t cause)
{
    std::string address = device.GetDeviceAddr();
    char anomizeAddress[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address.c_str(), BT_MAC_LEN);
    CONN_LOGW(CONN_PROXY, "hfp OnConnectionStateChanged %{public}s to %{public}d", anomizeAddress, state);
    if (state == (int)Bluetooth::BTConnectState::CONNECTED) {
        // the Bluetooth bottom layer has been reconnected
        if (listener_ != nullptr) {
            listener_(address.c_str(), SOFTBUS_HFP_CONNECTED);
        }
    }
}
}

int32_t RegisterHfpListener(const ProxyListener listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != nullptr, SOFTBUS_INVALID_PARAM, CONN_PROXY, "listener is null");
    std::shared_ptr<OHOS::SoftBus::ProxyObserver> observer =
        std::make_shared<OHOS::SoftBus::ProxyObserver>(listener);
    OHOS::Bluetooth::HandsFreeAudioGateway::GetProfile()->RegisterObserver(observer);
    return SOFTBUS_OK;
}