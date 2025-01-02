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

#include "lnn_feature_capability.h"

#include <stdint.h>

#include "lnn_log.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

#define DEFAUTL_LNN_FEATURE 0x3E2 // 0x3EA

int32_t LnnSetFeatureCapability(uint64_t *feature, FeatureCapability capaBit)
{
    if (feature == NULL || capaBit >= BIT_FEATURE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "in para error");
        return SOFTBUS_INVALID_PARAM;
    }
    *feature = (*feature) | (1 << (uint64_t)capaBit);
    return SOFTBUS_OK;
}

int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit)
{
    if (feature == NULL || capaBit >= BIT_FEATURE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "in para error");
        return SOFTBUS_INVALID_PARAM;
    }
    *feature = (*feature) & (~(1 << (uint64_t)capaBit));
    return SOFTBUS_OK;
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return ((feature & (1 << (uint64_t)capaBit)) != 0);
}

uint64_t LnnGetFeatureCapabilty(void)
{
    uint64_t configValue;
    if (SoftbusGetConfig(SOFTBUS_INT_LNN_SUPPORT_FEATURE,
        (unsigned char*)&configValue, sizeof(configValue)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get lnn feature fail, use default value");
        configValue = DEFAUTL_LNN_FEATURE;
    }
#if !defined(DSOFTBUS_FEATURE_CONN_PV2) && !defined(DSOFTBUS_FEATURE_CONN_HV1)
    LnnClearFeatureCapability(&configValue, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
    LNN_LOGI(LNN_LEDGER, "clear feature TLV configValue=%{public}" PRIu64, configValue);
#endif
#ifndef DSOFTBUS_FEATURE_CONN_HV2
    LnnClearFeatureCapability(&configValue, BIT_BLE_TRIGGER_CONNECTION);
    LNN_LOGI(LNN_LEDGER, "clear feature CONN_HV2 configValue=%{public}" PRIu64, configValue);
#endif
#ifndef DSOFTBUS_FEATURE_CONN_COC
    LnnClearFeatureCapability(&configValue, BIT_COC_CONNECT_CAPABILITY);
    LNN_LOGI(LNN_LEDGER, "clear feature CONN_COC configValue=%{public}" PRIu64, configValue);
#endif
#ifndef DSOFTBUS_FEATURE_CONN_BLE_DIRECT
    LnnClearFeatureCapability(&configValue, BIT_BLE_DIRECT_CONNECT_CAPABILITY);
    LnnClearFeatureCapability(&configValue, BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY);
    LNN_LOGI(LNN_LEDGER, "clear feature CONN_BLE_DIRECT configValue=%{public}" PRIu64, configValue);
#endif
    LNN_LOGI(LNN_LEDGER, "lnn feature configValue=%{public}" PRIu64, configValue);
    return configValue;
}