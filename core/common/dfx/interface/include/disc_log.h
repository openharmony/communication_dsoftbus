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
    DISC_TEST,
} DiscLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel DISC_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {DISC_INIT,  0xd0057a0,      "DiscInit"},
    { DISC_TEST, DOMAIN_ID_TEST, "DiscTest"},
};

#define DISC_LOGF(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_FATAL, DISC_LABELS[label], ##__VA_ARGS__)
#define DISC_LOGE(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_ERROR, DISC_LABELS[label], ##__VA_ARGS__)
#define DISC_LOGW(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_WARN, DISC_LABELS[label], ##__VA_ARGS__)
#define DISC_LOGI(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_INFO, DISC_LABELS[label], ##__VA_ARGS__)
#define DISC_LOGD(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_DEBUG, DISC_LABELS[label], ##__VA_ARGS__)

#define DISC_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, DISC_LOGW, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, DISC_LOGE, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, DISC_LOGW, label, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, DISC_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_DISC_LOG_H
