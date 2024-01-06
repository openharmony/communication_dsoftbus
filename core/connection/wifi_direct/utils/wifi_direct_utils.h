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
#ifndef WIFI_DIRECT_UTILS_H
#define WIFI_DIRECT_UTILS_H

#include "wifi_direct_types.h"
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct NegotiateMessage;
struct WifiDirectUtils {
    enum WifiDirectRole (*transferModeToRole)(enum WifiDirectApiRole mode);
    enum WifiDirectApiRole (*transferRoleToPreferLinkMode)(enum WifiDirectRole role);
    uint32_t (*bytesToInt)(const uint8_t *data, uint32_t len);
    void (*intToBytes)(uint32_t data, uint32_t len, uint8_t *out, uint32_t outSize);
    void (*hexDump)(const char *banana, const uint8_t *data, size_t size);
    void (*showLinkInfoList)(const char *banana, ListNode *list);
    int32_t (*strCompareIgnoreCase)(const char *str1, const char *str2);
    bool (*supportHml)(void);
    bool (*supportHmlTwo)(void);
};

struct WifiDirectUtils* GetWifiDirectUtils(void);

#ifdef __cplusplus
}
#endif
#endif