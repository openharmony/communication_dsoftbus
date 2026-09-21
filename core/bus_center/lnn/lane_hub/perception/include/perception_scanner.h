/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef PERCEPTION_SCANNER_H
#define PERCEPTION_SCANNER_H

#include <stdbool.h>

#include "lnn_perception.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t PerceptionScannerInit(void);
void PerceptionScannerDeinit(void);

int32_t PerceptionScanStart(PerceptionType type, PerceptionCycle cycle);
int32_t PerceptionScanStop(void);

int32_t PerceptionScanGetDeviceList(PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count);

void PerceptionScanOnBtStateChanged(bool isBtOn);

void PerceptionScanOnScreenStateChanged(bool isScreenOn);

#ifdef __cplusplus
}
#endif

#endif
