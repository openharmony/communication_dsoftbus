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
#ifndef PERCEPTION_ADVERTISER_H
#define PERCEPTION_ADVERTISER_H

#include <stdbool.h>

#include "lnn_perception.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t PerceptionAdvertiserInit(void);
void PerceptionAdvertiserDeinit(void);

int32_t PerceptionAdvStart(PerceptionType type, const PerceptionAdvParam *param);
int32_t PerceptionAdvStop(void);
int32_t PerceptionAdvSetHighFreq(PerceptionType type, const PerceptionAdvParam *param);

void PerceptionAdvOnBtStateChanged(bool isBtOn);

#ifdef __cplusplus
}
#endif

#endif
