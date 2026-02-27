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
#include "softbus_adapter_crypto.h"
#include "softbus_utils.h"
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

std::string WifiDirectHashAnonymize(const std::vector<uint8_t> &input)
{
    uint8_t hashData[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash(input.data(), input.size(), hashData);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "hash fail ret=%{public}d", ret);
    char hashStr[HEXIFY_LEN(SHA_256_HASH_LEN)] = { 0 };
    ret = ConvertBytesToHexString(hashStr, sizeof(hashStr), hashData, sizeof(hashData));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "convert hex string fail, ret=%{public}d", ret);
    return WifiDirectAnonymize(std::string(hashStr).substr(SHA_256_HASH_LEN, SHA_256_HASH_LEN));
}

std::string WifiDirectHashAnonymize(const std::vector<char> &input)
{
    uint8_t hashData[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(input.data()), input.size(), hashData);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "hash fail ret=%{public}d", ret);
    char hashStr[HEXIFY_LEN(SHA_256_HASH_LEN)] = { 0 };
    ret = ConvertBytesToHexString(hashStr, sizeof(hashStr), hashData, sizeof(hashData));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "convert hex string fail, ret=%{public}d", ret);
    return WifiDirectAnonymize(std::string(hashStr).substr(SHA_256_HASH_LEN, SHA_256_HASH_LEN));
}
} // namespace OHOS::SoftBus
