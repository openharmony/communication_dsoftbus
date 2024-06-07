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
    CONN_NEARBY,
    CONN_BLE_DIRECT,
    CONN_BROADCAST,
    CONN_NEWIP,
    CONN_ACTION,
    CONN_TEST,
} ConnLogLabelEnum;

/* Keep consistent with labels 0xd005760 - 0xd00577f*/
static const SoftBusLogLabel CONN_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {CONN_INIT,         0xd005760,      "ConnInit"},
    {CONN_BLE,          0xd005761,      "ConnBle"},
    {CONN_BR,           0xd005762,      "ConnBr"},
    {CONN_COMMON,       0xd005763,      "ConnCommon"},
    {CONN_WIFI_DIRECT,  0xd005764,      "ConnWD"},
    {CONN_NEARBY,       0xd005765,      "ConnNearby"},
    {CONN_BLE_DIRECT,   0xd005766,      "ConnBD"},
    {CONN_BROADCAST,    0xd005767,      "ConnBC"},
    {CONN_NEWIP,        0xd005768,      "ConnNewIp"},
    {CONN_ACTION,       0xd005769,      "ConnAction"},
    {CONN_TEST,         DOMAIN_ID_TEST, "ConnTest"},
};

#if defined(SOFTBUS_LITEOS_M)
#define CONN_LOGF(label, fmt, ...) SOFTBUS_LOGF_INNER(label, fmt, ##__VA_ARGS__)
#define CONN_LOGE(label, fmt, ...) SOFTBUS_LOGE_INNER(label, fmt, ##__VA_ARGS__)
#define CONN_LOGW(label, fmt, ...) SOFTBUS_LOGW_INNER(label, fmt, ##__VA_ARGS__)
#define CONN_LOGI(label, fmt, ...) SOFTBUS_LOGI_INNER(label, fmt, ##__VA_ARGS__)
#define CONN_LOGD(label, fmt, ...) SOFTBUS_LOGD_INNER(label, fmt, ##__VA_ARGS__)
#else
#define CONN_LOGF(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_FATAL, CONN_LABELS[label], fmt, ##__VA_ARGS__)
#define CONN_LOGE(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_ERROR, CONN_LABELS[label], fmt, ##__VA_ARGS__)
#define CONN_LOGW(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_WARN, CONN_LABELS[label], fmt, ##__VA_ARGS__)
#define CONN_LOGI(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_INFO, CONN_LABELS[label], fmt, ##__VA_ARGS__)
#define CONN_LOGD(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_DEBUG, CONN_LABELS[label], fmt, ##__VA_ARGS__)
#endif // SOFTBUS_LITEOS_M

#define CONN_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGW, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGE, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_RET_LOGI(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGI, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_RET_LOGD(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, CONN_LOGD, label, fmt, ##__VA_ARGS__)

#define CONN_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGW, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGE, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOGI(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGI, label, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOGD(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, CONN_LOGD, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_CONN_LOG_H
