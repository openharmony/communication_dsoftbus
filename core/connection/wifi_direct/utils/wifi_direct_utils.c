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
#include <string.h>
#include <ctype.h>
#include "securec.h"
#include "softbus_log.h"
#include "wifi_direct_types.h"
#include "data/link_info.h"

#define LOG_LABEL "[WifiDirect] WifiDirectUtils: "

#define HEX_DUMP_LINE_NUM 16
#define PRINT_BUFFER_LEN 128

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
            return WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML;
        case WIFI_DIRECT_ROLE_GO:
            return WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
        case WIFI_DIRECT_ROLE_HML:
            return WIFI_DIRECT_API_ROLE_HML;
        default:
            return WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
    }
}

static uint32_t BytesToInt(const uint8_t *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_RET_LOG(len <= sizeof(uint32_t), 0, LOG_LABEL "len=%u invalid", len);
    uint32_t res = 0;
    CONN_CHECK_AND_RETURN_RET_LOG(memcpy_s(&res, sizeof(res), data, len) == EOK, 0, LOG_LABEL "memcpy_s failed");
    return le32toh(res);
}

static void IntToBytes(uint32_t data, uint32_t len, uint8_t *out, uint32_t outSize)
{
    if (len > sizeof(uint32_t)) {
        CLOGE(LOG_LABEL "len=%u invalid", len);
        return;
    }

    data = htole32(data);
    CONN_CHECK_AND_RETURN_LOG(memcpy_s(out, outSize, &data, len) == EOK, "memcpy_s failed");
}

static void HexDump(const char *banana, const uint8_t *data, size_t size)
{
    CLOGI(LOG_LABEL "%s size=%d", banana, size);
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
            CLOGI(LOG_LABEL "sprintf failed");
            return;
        }
        pos += ret;
        if (i % HEX_DUMP_LINE_NUM == 0) {
            pos = 0;
            isLastPrinted = true;
            CLOGI(LOG_LABEL "%s", line);
        }
    }
    if (!isLastPrinted) {
        CLOGI(LOG_LABEL "%s", line);
    }
}

static void ShowLinkInfoList(const char *banana, ListNode *list)
{
    CLOGI(LOG_LABEL "%s", banana);
    struct LinkInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, list, struct LinkInfo, node) {
        CLOGI(LOG_LABEL "interface=%s mode=%d", info->getString(info, LI_KEY_LOCAL_INTERFACE, ""),
              info->getInt(info, LI_KEY_LOCAL_LINK_MODE, -1));
    }
}

static void PrintLargeString(const char *string)
{
    char buffer[PRINT_BUFFER_LEN + 1] = {0};
    size_t stringLen = strlen(string);
    size_t printLen = 0;
    while (printLen < stringLen) {
        size_t copyLen = MIN(PRINT_BUFFER_LEN, stringLen - printLen);
        if (memcpy_s(buffer, copyLen, string + printLen, copyLen) != EOK) {
            CLOGE("buffer memcpy fail");
            return;
        }
        buffer[copyLen] = 0;
        printLen += copyLen;
        CLOGI(LOG_LABEL "%s", buffer);
    }
}

static int32_t StrCompareIgnoreCase(const char *str1, const char *str2)
{
    while (*str1 && *str2) {
        int c1 = *str1;
        int c2 = *str2;
        if (isupper(c1)) {
            c1 = c1 + 'a' - 'A';
        }
        if (isupper(c2)) {
            c2 = c2 + 'a' - 'A';
        }
        if (c1 != c2) {
            return c1 - c2;
        }
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

static struct WifiDirectUtils g_utils = {
    .transferModeToRole = TransferModeToRole,
    .transferRoleToPreferLinkMode = TransferRoleToPreferLinkMode,
    .bytesToInt = BytesToInt,
    .intToBytes = IntToBytes,
    .hexDump = HexDump,
    .showLinkInfoList = ShowLinkInfoList,
    .printLargeString = PrintLargeString,
    .strCompareIgnoreCase = StrCompareIgnoreCase,
};

struct WifiDirectUtils* GetWifiDirectUtils(void)
{
    return &g_utils;
}