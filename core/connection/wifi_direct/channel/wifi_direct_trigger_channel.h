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

#ifndef WIFI_DIRECT_TRIGGER_CHANNEL_H
#define WIFI_DIRECT_TRIGGER_CHANNEL_H

#include "wifi_direct_types.h"
#include "processor/wifi_direct_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

struct TriggerMessage;
#define WIFI_DIRECT_TRIGGER_CHANNEL_BASE \
    int32_t (*startTrigger)(struct WifiDirectTriggerChannel *base, struct TriggerMessage *msg);              \
    void (*stopTrigger)(struct WifiDirectTriggerChannel *base, struct TriggerMessage *msg);                  \
    int32_t (*getDeviceId)(struct WifiDirectTriggerChannel *base, char *deviceId, size_t deviceIdLen);       \
    enum WifiDirectProcessorType (*getProcessorType)(struct WifiDirectTriggerChannel *base);                 \
    void (*destructor)(struct WifiDirectTriggerChannel *base)


struct WifiDirectTriggerChannel {
    WIFI_DIRECT_TRIGGER_CHANNEL_BASE;
};

#ifdef __cplusplus
}
#endif
#endif