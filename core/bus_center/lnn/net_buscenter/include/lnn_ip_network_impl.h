/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_IP_NETWORK_IMPL_H
#define LNN_IP_NETWORK_IMPL_H

#include <stdint.h>
#include "softbus_common.h"

#define LNN_LOOPBACK_IP "127.0.0.1"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void LnnNotifyAllTypeOffline(ConnectionAddrType type);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_IP_NETWORK_IMPL_H */
