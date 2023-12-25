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

#include "wifi_direct_processor_factory.h"
#include "processor/p2p_v1_processor.h"

static struct WifiDirectProcessor* CreateProcessor(enum WifiDirectProcessorType type)
{
    if (type == WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1) {
        return (struct WifiDirectProcessor *)GetP2pV1Processor();
    }

    return NULL;
}

static struct WifiDirectProcessorFactory g_factory = {
    .createProcessor = CreateProcessor,
};

struct WifiDirectProcessorFactory* GetWifiDirectProcessorFactory(void)
{
    return &g_factory;
}