/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_ipv4_info.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_network_utils.h"

int32_t WifiDirectIpStringToIpv4(const char *ipString, struct WifiDirectIpv4Info *ipv4)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(ipString, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ip is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(ipv4, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ipv4 is null");

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->ipStringToAddr(ipString, &ipv4->address);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert ip to addr failed");
    ipv4->prefixLength = DEFAULT_PREFIX_LEN;
    return SOFTBUS_OK;
}

int32_t WifiDirectIpv4ToString(const struct WifiDirectIpv4Info *ipv4, char *ipString, size_t ipStringSize)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(ipv4, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ipv4 is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(ipString, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ip is null");

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->ipAddrToString(ipv4->address, ipString, ipStringSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert addr to ip failed");

    return SOFTBUS_OK;
}

#define IPV4_INFO_TO_ARRAY(array, ipv4Info) do { \
    (array)[0] = (uint8_t)(((ipv4Info)->address & 0xff000000) >> 24); \
    (array)[1] = (uint8_t)(((ipv4Info)->address & 0x00ff0000) >> 16); \
    (array)[2] = (uint8_t)(((ipv4Info)->address & 0x0000ff00) >> 8); \
    (array)[3] = (uint8_t)(((ipv4Info)->address & 0x000000ff)); \
    (array)[4] = (ipv4Info)->prefixLength; \
} while (0)

#define IPV4_ARRAY_TO_INFO(ipv4Info, array) do { \
    (ipv4Info)->address = ((uint32_t)((array)[0]) << 24) | \
        ((uint32_t)((array)[1]) << 16) | \
        ((uint32_t)((array)[2]) << 8) | \
        ((uint32_t)((array)[3])); \
    (ipv4Info)->prefixLength = (array)[4]; \
} while (0)

int32_t WifiDirectIpv4InfoToBytes(const struct WifiDirectIpv4Info *ipv4, size_t ipv4Count,
                                  uint8_t *data, size_t *dataLen)
{
    size_t offset = 0;
    for (size_t i = 0; i < ipv4Count; i++) {
        if (offset + IPV4_INFO_BYTES_ARRAY_LEN > *dataLen) {
            CONN_LOGW(CONN_WIFI_DIRECT,
                "i=%{public}zu, dataLen=%{public}zu, ipv4count=%{public}zu, offset=%{public}zu",
                  i, *dataLen, ipv4Count, offset);
            return SOFTBUS_ERR;
        }

        IPV4_INFO_TO_ARRAY(&data[offset], &ipv4[i]);
        offset += IPV4_INFO_BYTES_ARRAY_LEN;
    }

    *dataLen = offset;
    return SOFTBUS_OK;
}

void WifiDirectIpv4BytesToInfo(const uint8_t *ipv4Bytes, size_t ipv4BytesLen,
                               struct WifiDirectIpv4Info *ipv4, size_t *ipv4Count)
{
    size_t offset = 0;
    if ((ipv4BytesLen % IPV4_INFO_BYTES_ARRAY_LEN) != 0) {
        CONN_LOGW(CONN_WIFI_DIRECT, "invalid ipv4BytesLen=%{public}zu", ipv4BytesLen);
        *ipv4Count = 0;
        return;
    }

    for (size_t i = 0; i + IPV4_INFO_BYTES_ARRAY_LEN <= ipv4BytesLen; i += IPV4_INFO_BYTES_ARRAY_LEN) {
        if (offset == *ipv4Count) {
            CONN_LOGW(CONN_WIFI_DIRECT, "invalid ipv4Count=%{public}zu, ipv4BytesLen=%{public}zu", *ipv4Count,
                ipv4BytesLen);
            *ipv4Count = 0;
            return;
        }

        IPV4_ARRAY_TO_INFO(&ipv4[offset], &ipv4Bytes[i]);
        offset++;
    }

    *ipv4Count = offset;
}