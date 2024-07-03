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

#ifndef LNN_CONNECTION_ADDR_UTILS_H
#define LNN_CONNECTION_ADDR_UTILS_H

#include <stdbool.h>

#include "auth_interface.h"
#include "lnn_node_info.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort);
bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option);
bool LnnConvertOptionToAddr(ConnectionAddr *addr, const ConnectOption *option, ConnectionAddrType hintType);
DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type);
bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo);
bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType);

/* To avoid concurrency issues, this interface can only be used in BusCenter looper process. */
const char *LnnPrintConnectionAddr(const ConnectionAddr *addr);
bool LnnIsConnectionAddrInvalid(const ConnectionAddr *addr);

#ifdef __cplusplus
}
#endif
#endif /* LNN_CONNECTION_ADDR_UTILS_H */

