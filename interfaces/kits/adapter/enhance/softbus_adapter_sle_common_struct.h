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

#ifndef SOFTBUS_ADAPTER_SLE_COMMON_STRUCT_H
#define SOFTBUS_ADAPTER_SLE_COMMON_STRUCT_H

#include <stdint.h>
#include "softbus_type_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SOFTBUS_SLE_STATE_TURNING_ON = 0X0,
  SOFTBUS_SLE_STATE_TURN_ON,
  SOFTBUS_SLE_STATE_TURNING_OFF,
  SOFTBUS_SLE_STATE_TURN_OFF,
  SOFTBUS_SLB_STATE_TURNING_ON,
  SOFTBUS_SLB_STATE_TURN_ON,
  SOFTBUS_SLB_STATE_TURNING_OFF,
  SOFTBUS_SLB_STATE_TURN_OFF,
  SOFTBUS_SLE_STATE_BUTT
} SoftBusSleStackState;

typedef struct {
  void (*onSleStateChanged)(int state);
} SoftBusSleStateListener;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_SLE_COMMON_STRUCT_H */