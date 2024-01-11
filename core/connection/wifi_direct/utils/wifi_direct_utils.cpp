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

#include "wifi_direct_utils.h"
#include <endian.h>
#include <cstring>
#include <cctype>
#include "syspara/parameters.h"
#include "securec.h"
#include "conn_log.h"
#include "wifi_direct_types.h"
#include "data/link_info.h"

static constexpr int32_t HEX_DUMP_LINE_NUM = 16;

static enum WifiDirectRole TransferModeToRole(enum WifiDirectApiRole mode)
{
    switch (mode) {
        case WIFI_DIRECT_API_ROLE_NONE:
            return WIFI_DIRECT_ROLE_NONE;
        case WIFI_DIRECT_API_ROLE_GC:
            return WIFI_DIRECT_ROLE_GC;
        case WIFI_DIRECT_API_ROLE_GO:
            return WIFI_DIRECT_ROLE_GO;
        case WIFI_DIRECT_API_ROLE_HML:
            return WIFI_DIRECT_ROLE_HML;
        default:
            return WIFI_DIRECT_ROLE_INVALID;
    }
}

static enum WifiDirectApiRole TransferRoleToPreferLinkMode(enum WifiDirectRole role)
{
    switch (role) {
        case WIFI_DIRECT_ROLE_NONE:
            return WIFI_DIRECT_API_ROLE_NONE;
        case WIFI_DIRECT_ROLE_GC:
            return static_cast<WifiDirectApiRole>(WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
        case WIFI_DIRECT_ROLE_GO:
            return static_cast<WifiDirectApiRole>(WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);
        case WIFI_DIRECT_ROLE_HML:
            return WIFI_DIRECT_API_ROLE_HML;
        default:
            return static_cast<WifiDirectApiRole>(WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO |
                                                  WIFI_DIRECT_API_ROLE_HML);
    }
}

static uint32_t BytesToInt(const uint8_t *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(len <= sizeof(uint32_t), 0, CONN_WIFI_DIRECT, "len invalid. len=%{public}u", len);
    uint32_t res = 0;
    CONN_CHECK_AND_RETURN_RET_LOGW(memcpy_s(&res, sizeof(res), data, len) == EOK, 0, CONN_WIFI_DIRECT,
        "memcpy_s failed");
    return le32toh(res);
}

static void IntToBytes(uint32_t data, uint32_t len, uint8_t *out, uint32_t outSize)
{
    if (len > sizeof(uint32_t)) {
        CONN_LOGW(CONN_WIFI_DIRECT, "len invalid. len=%{public}u", len);
        return;
    }

    data = htole32(data);
    CONN_CHECK_AND_RETURN_LOGW(memcpy_s(out, outSize, &data, len) == EOK, CONN_WIFI_DIRECT, "memcpy_s failed");
}

static void HexDump(const char *banana, const uint8_t *data, size_t size)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "banana=%{public}s, size=%{public}zu", banana, size);
    char line[64];
    int32_t pos = 0;
    bool isLastPrinted = false;
    for (size_t i = 1; i <= size; i++) {
        isLastPrinted = false;
        int32_t ret;
        if (i % HEX_DUMP_LINE_NUM == 1) {
            ret = sprintf_s(line + pos, sizeof(line) - pos, "%02x", data[i - 1]);
        } else {
            ret = sprintf_s(line + pos, sizeof(line) - pos, " %02x", data[i - 1]);
        }
        if (ret <= 0) {
            CONN_LOGI(CONN_WIFI_DIRECT, "sprintf failed");
            return;
        }
        pos += ret;
        if (i % HEX_DUMP_LINE_NUM == 0) {
            pos = 0;
            isLastPrinted = true;
            CONN_LOGI(CONN_WIFI_DIRECT, "line=%{public}s", line);
        }
    }
    if (!isLastPrinted) {
        CONN_LOGI(CONN_WIFI_DIRECT, "line=%{public}s", line);
    }
}

static void ShowLinkInfoList(const char *banana, ListNode *list)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "banana=%{public}s", banana);
    struct LinkInfo *info = nullptr;
    LIST_FOR_EACH_ENTRY(info, list, struct LinkInfo, node) {
        CONN_LOGI(CONN_WIFI_DIRECT,
            "interface=%{public}s, mode=%{public}d", info->getString(info, LI_KEY_LOCAL_INTERFACE, ""),
            info->getInt(info, LI_KEY_LOCAL_LINK_MODE, -1));
    }
}

static int32_t StrCompareIgnoreCase(const char *str1, const char *str2)
{
    while (*str1 && *str2) {
        int c1 = static_cast<int>(*str1);
        int c2 = static_cast<int>(*str2);
        if (std::isupper(c1)) {
            c1 = c1 + static_cast<int>('a') - static_cast<int>('A');
        }
        if (isupper(c2)) {
            c2 = c2 + static_cast<int>('a') - static_cast<int>('A');
        }
        if (c1 != c2) {
            return c1 - c2;
        }
        str1++;
        str2++;
    }
    return static_cast<int>(*str1) - static_cast<int>(*str2);
}

static bool SupportHml()
{
    bool support =  OHOS::system::GetBoolParameter("persist.sys.softbus.connect.hml", true);
    CONN_LOGI(CONN_WIFI_DIRECT, "persist.sys.softbus.connect.hml=%{public}d", support);
    return support;
}

static bool SupportHmlTwo()
{
    bool support =  OHOS::system::GetBoolParameter("persist.sys.softbus.connect.hml_two", false);
    CONN_LOGI(CONN_WIFI_DIRECT, "persist.sys.softbus.connect.hml_two=%{public}d", support);
    return support;
}

static struct WifiDirectUtils g_utils = {
    .transferModeToRole = TransferModeToRole,
    .transferRoleToPreferLinkMode = TransferRoleToPreferLinkMode,
    .bytesToInt = BytesToInt,
    .intToBytes = IntToBytes,
    .hexDump = HexDump,
    .showLinkInfoList = ShowLinkInfoList,
    .strCompareIgnoreCase = StrCompareIgnoreCase,
    .supportHml = SupportHml,
    .supportHmlTwo = SupportHmlTwo,
};

struct WifiDirectUtils* GetWifiDirectUtils(void)
{
    return &g_utils;
}