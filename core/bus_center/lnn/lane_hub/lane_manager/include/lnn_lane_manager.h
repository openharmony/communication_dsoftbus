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

#ifndef LNN_LANE_MANAGER_H
#define LNN_LANE_MANAGER_H

#include <stdint.h>

#include "bus_center_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LnnLaneQosObserverNotify)(int32_t laneId, int32_t score);

int32_t LnnInitLaneManager(void);
uint32_t LnnGetLaneNum(LnnLanesObject *lanesObject);
int32_t LnnLaneQosObserverAttach(LnnLanesObject *object, LnnLaneQosObserverNotify notify);
void LnnLaneQosObserverDetach(LnnLanesObject *object);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_MANAGER_H */