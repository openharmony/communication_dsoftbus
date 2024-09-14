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

#include "softbus_scenario_manager.h"

ScenarioManager *ScenarioManagerGetInstance(void)
{
    return NULL;
}

// update scenarios based on the command and determine whether to deliver the driver.
int32_t AddScenario(const char *localMac, const char *peerMac, int localPid, int businessType)
{
    (void)localMac;
    (void)peerMac;
    (void)localPid;
    (void)businessType;
    return 0;
}

int32_t DelScenario(const char *localMac, const char *peerMac, int localPid, int businessType)
{
    (void)localMac;
    (void)peerMac;
    (void)localPid;
    (void)businessType;
    return 0;
}

// clear all scenarios
void ScenarioManagerdestroyInstance()
{
    return;
}
