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
#ifndef PROXY_CHANNEL_OBSERVER_H
#define PROXY_CHANNEL_OBSERVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOFTBUS_HFP_CONNECTED 1
#define SOFTBUS_DEVICE_UNPAIRED 2

typedef void (*ProxyListener)(const char *addr, int32_t state);

int32_t RegisterHfpListener(const ProxyListener listener);
bool IsPairedDevice(const char *addr, bool isRealMac, bool *isSupportHfp);
int32_t GetRealMac(char *realAddr, uint32_t realAddrLen, const char *hashAddr);
#ifdef __cplusplus
}
#endif

#endif /* PROXY_CHANNEL_OBSERVER_H */