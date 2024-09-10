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
#include "wifi_direct_anonymous.h"
#include "anonymizer.h"
#include "wifi_direct_utils.h"

namespace OHOS::SoftBus {
std::string WifiDirectAnonymizeMac(const std::string &mac)
{
    return WifiDirectAnonymize(mac);
}

std::string WifiDirectAnonymizeMac(const std::vector<uint8_t> &mac)
{
    return WifiDirectAnonymizeMac(WifiDirectUtils::MacArrayToString(mac));
}

std::string WifiDirectAnonymizeIp(const std::string &ip)
{
    return WifiDirectAnonymize(ip);
}

std::string WifiDirectAnonymizeDeviceId(const std::string &deviceId)
{
    return WifiDirectAnonymize(deviceId);
}

std::string WifiDirectAnonymizeSsid(const std::string &ssid)
{
    return WifiDirectAnonymize(ssid);
}

std::string WifiDirectAnonymizePsk(const std::string &psk)
{
    return WifiDirectAnonymize(psk);
}

std::string WifiDirectAnonymizePtk(const std::string &ptk)
{
    return WifiDirectAnonymize(ptk);
}

std::string WifiDirectAnonymizeData(const std::string &data)
{
    return WifiDirectAnonymize(data);
}

std::string WifiDirectAnonymize(const std::string &data)
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
} // namespace OHOS::SoftBus
