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

#ifndef LNN_COAP_DISCOVERY_IMPL_STRUCT_H
#define LNN_COAP_DISCOVERY_IMPL_STRUCT_H

#include <stdint.h>

#include "form/lnn_event_form.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    void (*onDeviceFound)(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport);
} LnnDiscoveryImplCallback;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_COAP_DISCOVERY_IMPL_STRUCT_H */