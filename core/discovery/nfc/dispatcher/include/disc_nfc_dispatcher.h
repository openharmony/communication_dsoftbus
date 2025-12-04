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

#ifndef DISC_NFC_DISPATCHER_H
#define DISC_NFC_DISPATCHER_H

#include "disc_nfc_dispatcher_struct.h"
#include "disc_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

DiscoveryFuncInterface *DiscNfcDispatcherInit(DiscInnerCallback *discInnerCb);
void DiscNfcDispatcherDeinit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DISC_NFC_DISPATCHER_H */