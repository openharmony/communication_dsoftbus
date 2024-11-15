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

#ifndef DSOFTBUS_AUTH_LOG_H
#define DSOFTBUS_AUTH_LOG_H

#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    AUTH_INIT,
    AUTH_HICHAIN,
    AUTH_CONN,
    AUTH_FSM,
    AUTH_KEY,
    AUTH_TEST,
} AuthLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel AUTH_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    { AUTH_INIT,    0xd005720,      "AuthInit"    },
    { AUTH_HICHAIN, 0xd005721,      "AuthHiChain" },
    { AUTH_CONN,    0xd005722,      "AuthConn"    },
    { AUTH_FSM,     0xd005723,      "AuthFsm"     },
    { AUTH_KEY,     0xd005724,      "AuthKey"     },
    { AUTH_TEST,    DOMAIN_ID_TEST, "AuthTest"    },
};

#if defined(SOFTBUS_LITEOS_M)
#define AUTH_LOGF(label, fmt, ...) SOFTBUS_LOGF_INNER(label, fmt, ##__VA_ARGS__)
#define AUTH_LOGE(label, fmt, ...) SOFTBUS_LOGE_INNER(label, fmt, ##__VA_ARGS__)
#define AUTH_LOGW(label, fmt, ...) SOFTBUS_LOGW_INNER(label, fmt, ##__VA_ARGS__)
#define AUTH_LOGI(label, fmt, ...) SOFTBUS_LOGI_INNER(label, fmt, ##__VA_ARGS__)
#define AUTH_LOGD(label, fmt, ...) SOFTBUS_LOGD_INNER(label, fmt, ##__VA_ARGS__)
#else
#define AUTH_LOGF(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_FATAL, AUTH_LABELS[label], fmt, ##__VA_ARGS__)
#define AUTH_LOGE(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_ERROR, AUTH_LABELS[label], fmt, ##__VA_ARGS__)
#define AUTH_LOGW(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_WARN, AUTH_LABELS[label], fmt, ##__VA_ARGS__)
#define AUTH_LOGI(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_INFO, AUTH_LABELS[label], fmt, ##__VA_ARGS__)
#define AUTH_LOGD(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_DEBUG, AUTH_LABELS[label], fmt, ##__VA_ARGS__)
#endif // SOFTBUS_LITEOS_M

#define AUTH_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, AUTH_LOGW, label, fmt, ##__VA_ARGS__)
#define AUTH_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, AUTH_LOGE, label, fmt, ##__VA_ARGS__)
#define AUTH_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, AUTH_LOGW, label, fmt, ##__VA_ARGS__)
#define AUTH_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, AUTH_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_AUTH_LOG_H
