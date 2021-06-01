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

#ifndef LNN_EXCHANGE_LEDGER_INFO_H
#define LNN_EXCHANGE_LEDGER_INFO_H

#include <stdint.h>

#include "auth_interface.h"
#include "lnn_node_info.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CODE "CODE"
#define DEVICE_NAME "DEVICE_NAME"
#define DEVICE_TYPE "DEVICE_TYPE"
#define DEVICE_UDID "DEVICE_UDID"
#define NETWORK_ID "NETWORK_ID"
#define VERSION_TYPE "VERSION_TYPE"
#define BT_MAC "BT_MAC"
#define BUS_MAX_VERSION "BUS_MAX_VERSION"
#define BUS_MIN_VERSION "BUS_MIN_VERSION"
#define AUTH_PORT "AUTH_PORT"
#define SESSION_PORT "SESSION_PORT"
#define PROXY_PORT "PROXY_PORT"
#define CONN_CAP "CONN_CAP"
#define SW_VERSION "SW_VERSION"

#define CODE_VERIFY_IP 1
#define CODE_VERIFY_BT 5
#define BUS_V1 1
#define BUS_V2 2

typedef enum {
    AUTH_BT = 0,
    AUTH_WIFI,
    AUTH_MAX,
} AuthType;

typedef struct {
    ConnectType cnnType;
    AuthType authType;
} ConvertType;

typedef struct {
    uint8_t *buf;
    uint32_t len;
} ParseBuf;

typedef struct {
    AuthType type;
    char* (*pack)(const NodeInfo *info, SoftBusVersion version);
    int32_t (*unpack)(const cJSON* json, NodeInfo *info, SoftBusVersion version);
} ProcessLedgerInfo;

uint8_t *LnnGetExchangeNodeInfo(ConnectOption *option, SoftBusVersion version,
    uint32_t *outSize, AuthSideFlag *side);
int32_t LnnParsePeerNodeInfo(ConnectOption *option, NodeInfo *info,
    const ParseBuf *bufInfo, AuthSideFlag side, SoftBusVersion version);

#ifdef __cplusplus
}
#endif

#endif // LNN_EXCHANGE_LEDGER_INFO_H