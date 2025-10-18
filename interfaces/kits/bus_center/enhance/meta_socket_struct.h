/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef META_SOCKET_STRUCT_H
#define META_SOCKET_STRUCT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DATA_LEN_MAX 2048

typedef enum {
    PROXY_TRANSMISION = 0, /**< Proxy Transmision */
    PROXY_HEARTBEAT = 1, /**< Proxy Heartbeat */
    PROXY_HICAR = 2,
    PROXY_ACS = 3,
    PROXY_SHARE = 4,
    PROXY_CASTPLUS = 5,
    PROXY_DM = 6,
    PROXY_WEAR = 7,
    PROXY_WINPC = 8,
    PROXY_COLLABORATION_FWK = 9,
    PROXY_DMSDP = 10,
    PROXY_SPE = 11,
    PROXY_MIDDLEWARE = 12,
    PROXY_SYNERGY = 13,
    CUSTOM_UNKNOWN, /**< Proxy Unknown */
    HA_META_TYPE = 100,
    META_TYPE_SDK = 101,
    META_TYPE_MAX,
} MetaNodeType;

typedef struct {
    MetaNodeType type; /**< user type */
    uint8_t data[DATA_LEN_MAX]; /**< user data */
} MetaCustomData;
#ifdef __cplusplus
}
#endif
#endif  //META_SOCKET_STRUCT_H