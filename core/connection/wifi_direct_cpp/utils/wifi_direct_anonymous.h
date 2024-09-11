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
#ifndef WIFI_DIRECT_ANONYMOUS_H
#define WIFI_DIRECT_ANONYMOUS_H

#include <string>
#include <vector>

namespace OHOS::SoftBus {
std::string WifiDirectAnonymizeMac(const std::string &mac);
std::string WifiDirectAnonymizeMac(const std::vector<uint8_t> &mac);
std::string WifiDirectAnonymizeIp(const std::string &ip);
std::string WifiDirectAnonymizeDeviceId(const std::string &deviceId);
std::string WifiDirectAnonymizeSsid(const std::string &ssid);
std::string WifiDirectAnonymizePsk(const std::string &psk);
std::string WifiDirectAnonymizePtk(const std::string &ptk);
std::string WifiDirectAnonymizeData(const std::string &data);
std::string WifiDirectAnonymize(const std::string &data);
}

#endif
