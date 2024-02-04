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

#ifndef SOFTBUS_SCENARIO_MANAGER_H
#define SOFTBUS_SCENARIO_MANAGER_H

#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    SM_ERROR_INNER = -1,
    SM_ERROR_INVALID_PARAM = -2,
    SM_ERROR_TYPE_NOT_SUPPORT = -3,
    SM_ERROR_INVALID_LOCAL_MAC = -4,
    SM_ERROR_OUT_OF_MEMORY = -5,
    SM_ERROR_OPT_NOT_SUPPORT = -6,
} ScenarioManagerError;

typedef enum {
    SM_MESSAGE_TYPE = 1,
    SM_BYTE_TYPE = 2,
    SM_FILE_TYPE = 3,
    SM_VIDEO_TYPE = 4,
    SM_AUDIO_TYPE = 5,
    SM_RAW_TYPE = 6,
} ScenarioManagerBusinessType;

typedef struct ScenarioManager ScenarioManager;

int32_t ScenarioManagerGetInstance(void);

// update scenarios based on the command and determine whether to deliver the driver.
int32_t AddScenario(const char *localMac, const char *peerMac, int localPid, int businessType);

int32_t DelScenario(const char *localMac, const char *peerMac, int localPid, int businessType);

// clear all scenarios
void ScenarioManagerdestroyInstance();

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_SCENARIO_MANAGER_H
