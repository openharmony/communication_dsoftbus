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
#include "wifi_direct_anonymous.h"
#include "securec.h"
#include "conn_log.h"
#include "wifi_direct_types.h"

#define ANONYMOUS_BUF_NUM 2
#define MAC_ANONYMOUS_START 6
#define MAC_ANONYMOUS_END 11
#define DEVICE_ID_PREFIX_LEN 4
#define DEVICE_ID_SUFFIX_LEN 4
#define DEVICE_ID_BUF_LEN (DEVICE_ID_PREFIX_LEN + 2 + DEVICE_ID_SUFFIX_LEN + 1)

static __thread int32_t g_macIndex;
static __thread int32_t g_ipIndex;
static __thread int32_t g_deviceIdIndex;
static __thread char g_anonymousMac[ANONYMOUS_BUF_NUM][MAC_ADDR_STR_LEN];
static __thread char g_anonymousIp[ANONYMOUS_BUF_NUM][IP_ADDR_STR_LEN];
static __thread char g_anonymousDeviceId[ANONYMOUS_BUF_NUM][DEVICE_ID_BUF_LEN];

const char* WifiDirectAnonymizeMac(const char *mac)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(mac != NULL && strlen(mac) != 0, "", CONN_WIFI_DIRECT, "mac is null");
    g_macIndex = (g_macIndex + 1) % ANONYMOUS_BUF_NUM;
    int32_t ret = strcpy_s(g_anonymousMac[g_macIndex], MAC_ADDR_STR_LEN, mac);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, NULL, CONN_WIFI_DIRECT, "copy mac string failed");
    for (int32_t i = MAC_ANONYMOUS_START; i < MAC_ANONYMOUS_END; i++) {
        g_anonymousMac[g_macIndex][i] = '*';
    }
    return g_anonymousMac[g_macIndex];
}

const char* WifiDirectAnonymizeIp(const char *ip)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(ip != NULL && strlen(ip) != 0, "", CONN_WIFI_DIRECT, "ip is null");
    g_ipIndex = (g_ipIndex + 1) % ANONYMOUS_BUF_NUM;
    int32_t ret = strcpy_s(g_anonymousIp[g_ipIndex], IP_ADDR_STR_LEN, ip);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, NULL, CONN_WIFI_DIRECT, "copy ip string failed");

    char *startPos = strstr(g_anonymousIp[g_ipIndex], ".");
    CONN_CHECK_AND_RETURN_RET_LOGW(startPos != NULL, NULL, CONN_WIFI_DIRECT, "find start dot failed");
    startPos++;
    CONN_CHECK_AND_RETURN_RET_LOGW(*startPos != '\0', NULL, CONN_WIFI_DIRECT, "ip length invalid");
    char *endPos = strstr(startPos, ".");
    CONN_CHECK_AND_RETURN_RET_LOGW(endPos != NULL, NULL, CONN_WIFI_DIRECT, "find end dot failed");

    for (char *pos = startPos; pos < endPos; pos++) {
        *pos = '*';
    }
    return g_anonymousIp[g_ipIndex];
}

const char* WifiDirectAnonymizeDeviceId(const char *deviceId)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(deviceId != NULL, "", CONN_WIFI_DIRECT, "deviceId is null");
    size_t len = strlen(deviceId);
    CONN_CHECK_AND_RETURN_RET_LOGW(len > DEVICE_ID_BUF_LEN, "", CONN_WIFI_DIRECT, "len invalid");

    g_deviceIdIndex = (g_deviceIdIndex + 1) % ANONYMOUS_BUF_NUM;
    int32_t ret = strncpy_s(g_anonymousDeviceId[g_deviceIdIndex], DEVICE_ID_BUF_LEN, deviceId, DEVICE_ID_PREFIX_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, NULL, CONN_WIFI_DIRECT, "copy string failed");
    ret = strcat_s(g_anonymousDeviceId[g_deviceIdIndex], DEVICE_ID_BUF_LEN, "**");
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, NULL, CONN_WIFI_DIRECT, "copy string failed");
    ret = strcat_s(g_anonymousDeviceId[g_deviceIdIndex], DEVICE_ID_BUF_LEN, deviceId + len - DEVICE_ID_SUFFIX_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, NULL, CONN_WIFI_DIRECT, "copy string failed");

    return g_anonymousDeviceId[g_deviceIdIndex];
}