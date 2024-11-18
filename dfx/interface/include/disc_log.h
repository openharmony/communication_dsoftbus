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

#ifndef DSOFTBUS_DISC_LOG_H
#define DSOFTBUS_DISC_LOG_H

#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    DISC_INIT,
    DISC_CONTROL,
    DISC_LNN,
    DISC_BLE,
    DISC_BLE_ADAPTER,
    DISC_COAP,
    DISC_DFINDER,
    DISC_ABILITY,
    DISC_USB,
    DISC_USB_ADAPTER,
    DISC_SDK,
    DISC_BROADCAST,
    DISC_TEST,
} DiscLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel DISC_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    { DISC_INIT,        0xd0057a0,      "DiscInit"      },
    { DISC_CONTROL,     0xd0057a1,      "DiscControl"   },
    { DISC_LNN,         0xd0057a2,      "DiscLnn"       },
    { DISC_BLE,         0xd0057a3,      "DiscBle"       },
    { DISC_BLE_ADAPTER, 0xd0057a4,      "DiscBleAdapter"},
    { DISC_COAP,        0xd0057a5,      "DiscCoap"      },
    { DISC_DFINDER,     0xd0057a6,      "DiscDfinder"   },
    { DISC_ABILITY,     0xd0057a7,      "DiscAbility"   },
    { DISC_USB,         0xd0057a8,      "DiscUsb"       },
    { DISC_USB_ADAPTER, 0xd0057a9,      "DiscUsbAdapter"},
    { DISC_SDK,         0xd0057aa,      "DiscSdk"       },
    { DISC_BROADCAST,   0xd0057ab,      "DiscBroadcast" },
    { DISC_TEST,        DOMAIN_ID_TEST, "DiscTest"      },
};

#if defined(SOFTBUS_LITEOS_M)
#define DISC_LOGF(label, fmt, ...) SOFTBUS_LOGF_INNER(label, fmt, ##__VA_ARGS__)
#define DISC_LOGE(label, fmt, ...) SOFTBUS_LOGE_INNER(label, fmt, ##__VA_ARGS__)
#define DISC_LOGW(label, fmt, ...) SOFTBUS_LOGW_INNER(label, fmt, ##__VA_ARGS__)
#define DISC_LOGI(label, fmt, ...) SOFTBUS_LOGI_INNER(label, fmt, ##__VA_ARGS__)
#define DISC_LOGD(label, fmt, ...) SOFTBUS_LOGD_INNER(label, fmt, ##__VA_ARGS__)
#else
#define DISC_LOGF(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_FATAL, DISC_LABELS[label], fmt, ##__VA_ARGS__)
#define DISC_LOGE(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_ERROR, DISC_LABELS[label], fmt, ##__VA_ARGS__)
#define DISC_LOGW(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_WARN, DISC_LABELS[label], fmt, ##__VA_ARGS__)
#define DISC_LOGI(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_INFO, DISC_LABELS[label], fmt, ##__VA_ARGS__)
#define DISC_LOGD(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_DEBUG, DISC_LABELS[label], fmt, ##__VA_ARGS__)
#endif // SOFTBUS_LITEOS_M

#define DISC_CHECK_AND_RETURN_RET_LOGD(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, DISC_LOGD, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, DISC_LOGW, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, DISC_LOGE, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOGD(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, DISC_LOGD, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, DISC_LOGW, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, DISC_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_DISC_LOG_H
