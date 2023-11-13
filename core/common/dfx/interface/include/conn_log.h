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

#ifndef DSOFTBUS_CONN_LOG_H
#define DSOFTBUS_CONN_LOG_H

#include "anonymizer.h"
#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    CONN_INIT,
    CONN_BLE,
    CONN_BR,
    CONN_COMMON,
    CONN_WIFI_DIRECT,
    CONN_TEST,
} ConnLogLabelEnum;

/* Keep consistent with labels 0xd005760 - 0xd00577f*/
static const SoftBusLogLabel CONN_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {CONN_INIT,         0xd005760,      "ConnInit"},
    {CONN_BLE,          0xd005761,      "ConnBle"},
    {CONN_BR,           0xd005762,      "ConnBr"},
    {CONN_COMMON,       0xd005763,      "ConnCommon"},
    {CONN_WIFI_DIRECT,  0xd005764,      "ConnWD"},
    {CONN_TEST,    DOMAIN_ID_TEST,      "ConnTest"},
};

#define CONN_LOGF(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_FATAL, CONN_LABELS[label], ##__VA_ARGS__)
#define CONN_LOGE(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_ERROR, CONN_LABELS[label], ##__VA_ARGS__)
#define CONN_LOGW(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_WARN, CONN_LABELS[label], ##__VA_ARGS__)
#define CONN_LOGI(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_INFO, CONN_LABELS[label], ##__VA_ARGS__)
#define CONN_LOGD(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_DEBUG, CONN_LABELS[label], ##__VA_ARGS__)

#define CONN_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGW, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGE, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGW, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_CONN_LOG_H
