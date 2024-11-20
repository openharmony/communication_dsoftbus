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

#ifndef LNN_IP_UTILS_ADAPTER_H
#define LNN_IP_UTILS_ADAPTER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <securec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "softbus_def.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif // LNN_IP_UTILS_ADAPTER_H
