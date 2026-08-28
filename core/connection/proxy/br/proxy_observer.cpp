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

#include "bluetooth_def.h"
#include "bluetooth_hfp_ag.h"
#include "bluetooth_host.h"
#include "conn_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

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

class ProxyPairStatusObserver : public Bluetooth::BluetoothRemoteDeviceObserver  {
public:
    explicit ProxyPairStatusObserver(const ProxyListener listener)
    {
        listener_ = listener;
    }
    ~ProxyPairStatusObserver() {}
    void OnAclStateChanged(const Bluetooth::BluetoothRemoteDevice& device, int state, unsigned int reason) override {};
    void OnPairStatusChanged(const Bluetooth::BluetoothRemoteDevice& device, int status, int cause) override;
    void OnRemoteUuidChanged(const Bluetooth::BluetoothRemoteDevice& device,
        const std::vector<Bluetooth::ParcelUuid>& uuids) override {};
    void OnRemoteNameChanged(const Bluetooth::BluetoothRemoteDevice& device, const std::string& deviceName) override {};
    void OnRemoteAliasChanged(const Bluetooth::BluetoothRemoteDevice& device, const std::string& alias) override {};
    void OnRemoteCodChanged(const Bluetooth::BluetoothRemoteDevice& device,
        const Bluetooth::BluetoothDeviceClass& cod) override {};
    void OnRemoteBatteryLevelChanged(const Bluetooth::BluetoothRemoteDevice& device, int batteryLevel) override {};
    void OnReadRemoteRssiEvent(const Bluetooth::BluetoothRemoteDevice& device, int rssi, int status) override {};
    void OnRemoteBatteryChanged(const Bluetooth::BluetoothRemoteDevice& device,
        const Bluetooth::DeviceBatteryInfo& batteryInfo) override {};
private:
    ProxyListener listener_;
};

void ProxyPairStatusObserver::OnPairStatusChanged(const Bluetooth::BluetoothRemoteDevice& device, int status, int cause)
{
    std::string address = device.GetDeviceAddr();
    char anomizeAddress[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address.c_str(), BT_MAC_LEN);
    CONN_LOGW(CONN_PROXY, "pair status changed %{public}s to %{public}d, cause=%{public}d",
        anomizeAddress, status, cause);
    if (status ==  OHOS::Bluetooth::PAIR_NONE) {
        if (listener_ != nullptr) {
            listener_(address.c_str(), SOFTBUS_DEVICE_UNPAIRED);
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
    std::shared_ptr<OHOS::SoftBus::ProxyPairStatusObserver> pairStatusobserver =
        std::make_shared<OHOS::SoftBus::ProxyPairStatusObserver>(listener);
    OHOS::Bluetooth::BluetoothHost::GetDefaultHost().RegisterRemoteDeviceObserver(pairStatusobserver);
    return SOFTBUS_OK;
}

static std::string ConvertRealMacToHashMac(const std::string addr)
{
    uint8_t hashAddr[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(addr.c_str()),
        addr.length(), hashAddr);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_PROXY, "hash fail ret=%{public}d", ret);
    char hashAddrStr[HEXIFY_LEN(SHA_256_HASH_LEN)] = {0};
    ret = ConvertBytesToHexString(hashAddrStr, sizeof(hashAddrStr), hashAddr, sizeof(hashAddr));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_PROXY, "convert hex string fail, ret=%{public}d", ret);
    return std::string(hashAddrStr).substr(SHA_256_HASH_LEN, SHA_256_HASH_LEN);
}

static bool CompareIgnoreCase(const std::string &left, const std::string &right)
{
    std::string leftLower = left;
    std::transform(left.begin(), left.end(), leftLower.begin(), ::tolower);

    std::string rightLower = right;
    std::transform(right.begin(), right.end(), rightLower.begin(), ::tolower);
    return leftLower.compare(rightLower) == 0;
}

static bool IsSupportHfp(const OHOS::Bluetooth::BluetoothRemoteDevice& device)
{
    std::vector<std::string> uuids;
    device.GetDeviceUuids(uuids);
    for (const std::string& uuid : uuids) {
        if (CompareIgnoreCase(uuid, OHOS::Bluetooth::BLUETOOTH_UUID_HFP_HF)) {
            return true;
        }
    }
    return false;
}

bool IsPairedDevice(const char *addr, bool isRealMac, bool *isSupportHfp)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addr != nullptr, false, CONN_PROXY, "addr is null");
    std::vector<OHOS::Bluetooth::BluetoothRemoteDevice> remoteDeviceLists;
    int32_t ret = OHOS::Bluetooth::BluetoothHost::GetDefaultHost().GetPairedDevices(OHOS::Bluetooth::BT_TRANSPORT_BREDR,
        remoteDeviceLists);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, false, CONN_PROXY, "GetPairedDevices fail, ret=%{public}d", ret);
    for (const auto &device : remoteDeviceLists) {
        int32_t state = 0;
        device.GetPairState(state);
        CONN_LOGI(CONN_PROXY, "pair state=%{public}d", state);
        if (state == OHOS::Bluetooth::PAIR_PAIRED &&
            ((isRealMac && StrCmpIgnoreCase(device.GetDeviceAddr().c_str(), addr) == 0) ||
            (!isRealMac && StrCmpIgnoreCase(ConvertRealMacToHashMac(device.GetDeviceAddr()).c_str(), addr) == 0))) {
            if (isSupportHfp != nullptr) {
                *isSupportHfp = IsSupportHfp(device);
            }
            return true;
        }
    }
    return false;
}

int32_t GetRealMac(char *realAddr, uint32_t realAddrLen, const char *hashAddr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(realAddr != nullptr, SOFTBUS_INVALID_PARAM, CONN_PROXY, "realAddr is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(hashAddr != nullptr, SOFTBUS_INVALID_PARAM, CONN_PROXY, "hashAddr is null");
    std::vector<OHOS::Bluetooth::BluetoothRemoteDevice> remoteDeviceLists;
    int32_t ret = OHOS::Bluetooth::BluetoothHost::GetDefaultHost().GetPairedDevices(OHOS::Bluetooth::BT_TRANSPORT_BREDR,
        remoteDeviceLists);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_CONN_PROXY_INTERNAL_ERR,
        CONN_PROXY, "GetPairedDevices fail, ret=%{public}d", ret);
    for (const auto &device : remoteDeviceLists) {
        int32_t state = 0;
        device.GetPairState(state);
        CONN_LOGD(CONN_PROXY, "pair state=%{public}d", state);
        if (state == OHOS::Bluetooth::PAIR_PAIRED &&
            StrCmpIgnoreCase(ConvertRealMacToHashMac(device.GetDeviceAddr()).c_str(), hashAddr) == 0) {
            if (strncpy_s(realAddr, realAddrLen, device.GetDeviceAddr().c_str(), realAddrLen - 1) != EOK) {
                CONN_LOGE(CONN_PROXY, "copy real mac address fail");
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    CONN_LOGE(CONN_PROXY, "not found matching addr");
    return SOFTBUS_NOT_FIND;
}