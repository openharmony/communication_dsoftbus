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

#ifndef WIFI_CONFIG_INFO_H
#define WIFI_CONFIG_INFO_H

#include "interface_info.h"

namespace OHOS::SoftBus {
enum class WifiConfigInfoKey {
    INVALID = 0,
    VERSION = 1,
    IS_P2P_CHANNEL_OPTIMIZE_ENABLE = 2,
    IS_DBDC_SUPPORTED = 3,
    IS_CSA_SUPPORTED = 4,
    IS_RADAR_DETECTION_SUPPORTED = 5,
    IS_DFS_P2P_SUPPORTED = 6,
    IS_INDOOR_P2P_SUPPORTED = 7,
    STA_CHANNEL = 8,
    STA_PORTAL_STATE = 9,
    STA_SSID = 10,
    STA_BSSID = 11,
    STA_INTERNET_STATE = 12,
    P2P_CHANNEL_LIST = 13,
    STA_PWD = 14,
    STA_ENCRYPT_MODE = 15,
    IS_CONNECTED_TO_HW_ROUTER = 16,
    DEVICE_TYPE = 17,
    IGNORE = 18,
    DEVICE_ID = 19,
    INTERFACE_INFO_ARRAY = 20,
    WC_KEY_MAX,
};

class WifiConfigInfo : public Serializable, public InfoContainer<WifiConfigInfoKey> {
public:
    WifiConfigInfo() = default;
    explicit WifiConfigInfo(std::vector<uint8_t> &config);
    ~WifiConfigInfo() override = default;

    int Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const override;
    int Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input) override;

    void SetInterfaceInfoArray(const std::vector<InterfaceInfo> &value);
    std::vector<InterfaceInfo> GetInterfaceInfoArray() const;
    InterfaceInfo GetInterfaceInfo(const std::string &name) const;

    void SetDeviceId(const std::string &value);
    std::string GetDeviceId() const;

private:
    static constexpr int HEADER_LEN = 2;
    void MarshallingInterfaceArray(WifiDirectProtocol &protocol) const;
    void UnmarshallingInterfaceArray(WifiDirectProtocol &protocol, uint8_t *data, size_t size);
};
} // namespace OHOS::SoftBus
#endif // WIFI_CONFIG_INFO_H