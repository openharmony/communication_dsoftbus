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

#ifndef DSOFTBUS_LNN_LOG_H
#define DSOFTBUS_LNN_LOG_H

#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    LNN_INIT,
    LNN_TEST,
} TransLogLabel;

/* Keep consistent with labels */
static const SoftBusLogLabel LNN_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {LNN_INIT,  0xd005780,      "LnnInit"},
    { LNN_TEST, DOMAIN_ID_TEST, "LnnTest"},
};

#define LNN_LOGF(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_LOG_FATAL, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGE(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_LOG_ERROR, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGW(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_LOG_WARN, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGI(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_LOG_INFO, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGD(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_LOG_DEBUG, LNN_LABELS[label], ##__VA_ARGS__)

#define LNN_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, LNN_LOGW, label, fmt, ##__VA_ARGS__)
#define LNN_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, LNN_LOGE, label, fmt, ##__VA_ARGS__)
#define LNN_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, LNN_LOGW, label, fmt, ##__VA_ARGS__)
#define LNN_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, LNN_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_LNN_LOG_H
