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

#include <string.h>

#include "softbus_config_adapter.h"
#include "softbus_def.h"

#define LNN_SUPPORT_ENHANCE_FEATURE 0x230FF7EA
#define ENHANCE_SUPPORT_AUTH_CAPACITY 0xFF
#define ENHANCE_LNN_NET_IF_NAME "0:eth0,1:wlan0,2:br0,3:ble0,4:ncm0,4:wwan0"

void SoftbusConfigAdapterInit(const ConfigSetProc *sets)
{
    if (sets == NULL) {
        return;
    }
#ifndef DSOFTBUS_CONFIG_ENHANCE
    int32_t val = 0x1;
    sets->SetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, (unsigned char *)&val, sizeof(val));
#else
    /* enable ble trigger and tlv capability */
    uint64_t featureVal = LNN_SUPPORT_ENHANCE_FEATURE;
    sets->SetConfig(SOFTBUS_INT_LNN_SUPPORT_FEATURE, (unsigned char *)&featureVal, sizeof(featureVal));

    /* auth support as server */
    int32_t authVal = 0x1;
    sets->SetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, (unsigned char *)&authVal, sizeof(authVal));

    /* set auth capacity */
    uint32_t authCapacity = ENHANCE_SUPPORT_AUTH_CAPACITY;
    sets->SetConfig(SOFTBUS_INT_AUTH_CAPACITY, (unsigned char *)&authCapacity, sizeof(authCapacity));

    /* set lnn net ifname */
    const char *netIfname = ENHANCE_LNN_NET_IF_NAME;
    sets->SetConfig(SOFTBUS_STR_LNN_NET_IF_NAME, (unsigned char *)netIfname, strlen(netIfname) + 1);
#endif
}