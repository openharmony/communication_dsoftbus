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

#ifndef LNN_COAP_DISCOVERY_IMPL_H
#define LNN_COAP_DISCOVERY_IMPL_H

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

int32_t LnnInitCoapDiscovery(LnnDiscoveryImplCallback *callback);

int32_t LnnStartCoapPublish(void);

int32_t LnnStopCoapPublish(void);

int32_t LnnStartCoapDiscovery(void);

int32_t LnnStopCoapDiscovery(void);

void LnnDestroyCoapConnectList(void);

void LnnCoapConnect(const char *ip);

void LnnCoapConnectInit(void);

void LnnCoapConnectDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_COAP_DISCOVERY_IMPL_H */
