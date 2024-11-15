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

#include "lnn_net_capability.h"

#include <stdint.h>
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

/* support bit1:br, bit2:wifi, bit4:wifi 2.4G */
#define DEFAUTL_LNN_CAPBILITY 0x16

bool LnnHasCapability(uint32_t capability, NetCapability type)
{
    if (type >= BIT_COUNT) {
        LNN_LOGE(LNN_LEDGER, "in para error");
        return false;
    }
    uint32_t cap = 0;
    (void)LnnSetNetCapability(&cap, type);
    if ((capability & cap) != 0) {
        return true;
    }
    return false;
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    if (capability == NULL || type >= BIT_COUNT) {
        LNN_LOGE(LNN_LEDGER, "in para error");
        return SOFTBUS_INVALID_PARAM;
    }
    *capability = (*capability) | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    if (capability == NULL || type >= BIT_COUNT) {
        LNN_LOGE(LNN_LEDGER, "in para error");
        return SOFTBUS_INVALID_PARAM;
    }
    *capability = (*capability) & (~(1 << (uint32_t)type));
    return SOFTBUS_OK;
}

uint32_t LnnGetNetCapabilty(void)
{
    uint32_t capability = 0;
    uint32_t configValue;

    if (SoftbusGetConfig(SOFTBUS_INT_LNN_SUPPORT_CAPABILITY,
        (unsigned char *)&configValue, sizeof(configValue)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get lnn capbility fail, use default value");
        configValue = DEFAUTL_LNN_CAPBILITY;
    }
    LNN_LOGI(LNN_LEDGER, "lnn capbility configValue=%{public}u", configValue);
    if ((configValue & (1 << BIT_BLE)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_BLE);
    }
    if ((configValue & (1 << BIT_BR)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_BR);
    }
    if ((configValue & (1 << BIT_WIFI)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_WIFI);
    }
    if ((configValue & (1 << BIT_WIFI_P2P)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_WIFI_P2P);
    }
    if ((configValue & (1 << BIT_WIFI_24G)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_WIFI_24G);
    }
    if ((configValue & (1 << BIT_WIFI_5G)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_WIFI_5G);
    }
    if ((configValue & (1 << BIT_ETH)) != 0) {
        (void)LnnSetNetCapability(&capability, BIT_ETH);
    }
    return capability;
}