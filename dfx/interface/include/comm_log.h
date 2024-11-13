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

#ifndef DSOFTBUS_COMM_LOG_H
#define DSOFTBUS_COMM_LOG_H

#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    COMM_SDK,
    COMM_SVC,
    COMM_INIT,
    COMM_DFX,
    COMM_EVENT,
    COMM_VERIFY,
    COMM_PERM,
    COMM_UTILS,
    COMM_ADAPTER,
    COMM_TEST,
} CommLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel COMM_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    { COMM_SDK,     0xd005700,      "CommSdk"    },
    { COMM_SVC,     0xd005701,      "CommSvc"    },
    { COMM_INIT,    0xd005702,      "CommInit"   },
    { COMM_DFX,     0xd005703,      "CommDfx"    },
    { COMM_EVENT,   0xd005704,      "CommEvent"  },
    { COMM_VERIFY,  0xd005705,      "CommVerify" },
    { COMM_PERM,    0xd005706,      "CommPerm"   },
    { COMM_UTILS,   0xd005707,      "CommUtils"  },
    { COMM_ADAPTER, 0xd005708,      "CommAdapter"},
    { COMM_TEST,    DOMAIN_ID_TEST, "CommTest"   },
};

#if defined(SOFTBUS_LITEOS_M)
#define COMM_LOGF(label, fmt, ...) SOFTBUS_LOGF_INNER(label, fmt, ##__VA_ARGS__)
#define COMM_LOGE(label, fmt, ...) SOFTBUS_LOGE_INNER(label, fmt, ##__VA_ARGS__)
#define COMM_LOGW(label, fmt, ...) SOFTBUS_LOGW_INNER(label, fmt, ##__VA_ARGS__)
#define COMM_LOGI(label, fmt, ...) SOFTBUS_LOGI_INNER(label, fmt, ##__VA_ARGS__)
#define COMM_LOGD(label, fmt, ...) SOFTBUS_LOGD_INNER(label, fmt, ##__VA_ARGS__)
#else
#define COMM_LOGF(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_FATAL, COMM_LABELS[label], fmt, ##__VA_ARGS__)
#define COMM_LOGE(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_ERROR, COMM_LABELS[label], fmt, ##__VA_ARGS__)
#define COMM_LOGW(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_WARN, COMM_LABELS[label], fmt, ##__VA_ARGS__)
#define COMM_LOGI(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_INFO, COMM_LABELS[label], fmt, ##__VA_ARGS__)
#define COMM_LOGD(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_DEBUG, COMM_LABELS[label], fmt, ##__VA_ARGS__)
#endif // SOFTBUS_LITEOS_M

#define COMM_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, COMM_LOGW, label, fmt, ##__VA_ARGS__)
#define COMM_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, COMM_LOGE, label, fmt, ##__VA_ARGS__)
#define COMM_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, COMM_LOGW, label, fmt, ##__VA_ARGS__)
#define COMM_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, COMM_LOGE, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_COMM_LOG_H
