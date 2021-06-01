/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BUS_CENTER_INFO_KEY_H
#define BUS_CENTER_INFO_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICE_TYPE_BUF_LEN 17
#define NET_IF_NAME_LEN 20
#define IP_MAX_LEN 46
#define ID_MAX_LEN 72
#define VERSION_MAX_LEN 16
#define MAC_LEN 18

typedef enum {
    STRING_KEY_BEGIN = 0,
    STRING_KEY_HICE_VERSION = STRING_KEY_BEGIN,
    STRING_KEY_DEV_UDID,
    STRING_KEY_NETWORKID,
    STRING_KEY_UUID,
    STRING_KEY_DEV_TYPE,
    STRING_KEY_DEV_NAME,
    STRING_KEY_BT_MAC,
    STRING_KEY_WLAN_IP,
    STRING_KEY_NET_IF_NAME,
    STRING_KEY_END,
    NUM_KEY_BEGIN = 100,
    NUM_KEY_SESSION_PORT = NUM_KEY_BEGIN,
    NUM_KEY_AUTH_PORT,
    NUM_KEY_PROXY_PORT,
    NUM_KEY_NET_CAP,
    NUM_KEY_DEV_TYPE_ID,
    NUM_KEY_END,
} InfoKey;

#ifdef __cplusplus
}
#endif
#endif // BUS_CENTER_INFO_KEY_H