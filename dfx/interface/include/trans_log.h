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

#ifndef DSOFTBUS_TRANS_LOG_H
#define DSOFTBUS_TRANS_LOG_H

#include "anonymizer.h"
#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    TRANS_SDK,
    TRANS_SVC,
    TRANS_INIT,
    TRANS_CTRL,
    TRANS_BYTES,
    TRANS_FILE,
    TRANS_MSG,
    TRANS_STREAM,
    TRANS_QOS,
    TRANS_TEST,
} TransLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel TRANS_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    { TRANS_SDK,    0xd005740,      "TransSdk"   },
    { TRANS_SVC,    0xd005741,      "TransSvc"   },
    { TRANS_INIT,   0xd005742,      "TransInit"  },
    { TRANS_CTRL,   0xd005743,      "TransCtrl"  },
    { TRANS_BYTES,  0xd005744,      "TransBytes" },
    { TRANS_FILE,   0xd005745,      "TransFile"  },
    { TRANS_MSG,    0xd005746,      "TransMsg"   },
    { TRANS_STREAM, 0xd005747,      "TransStream"},
    { TRANS_QOS,    0xd005748,      "TransQos"   },
    { TRANS_TEST,   DOMAIN_ID_TEST, "TransTest"  },
};

#if defined(SOFTBUS_LITEOS_M)
#define TRANS_LOGF(label, fmt, ...) SOFTBUS_LOGF_INNER(label, fmt, ##__VA_ARGS__)
#define TRANS_LOGE(label, fmt, ...) SOFTBUS_LOGE_INNER(label, fmt, ##__VA_ARGS__)
#define TRANS_LOGW(label, fmt, ...) SOFTBUS_LOGW_INNER(label, fmt, ##__VA_ARGS__)
#define TRANS_LOGI(label, fmt, ...) SOFTBUS_LOGI_INNER(label, fmt, ##__VA_ARGS__)
#define TRANS_LOGD(label, fmt, ...) SOFTBUS_LOGD_INNER(label, fmt, ##__VA_ARGS__)
#else
#define TRANS_LOGF(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_FATAL, TRANS_LABELS[label], fmt, ##__VA_ARGS__)
#define TRANS_LOGE(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_ERROR, TRANS_LABELS[label], fmt, ##__VA_ARGS__)
#define TRANS_LOGW(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_WARN, TRANS_LABELS[label], fmt, ##__VA_ARGS__)
#define TRANS_LOGI(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_INFO, TRANS_LABELS[label], fmt, ##__VA_ARGS__)
#define TRANS_LOGD(label, fmt, ...) SOFTBUS_LOG_INNER(LOG_DEBUG, TRANS_LABELS[label], fmt, ##__VA_ARGS__)
#endif // SOFTBUS_LITEOS_M

#define TRANS_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, TRANS_LOGW, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, TRANS_LOGE, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, TRANS_LOGW, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, TRANS_LOGE, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_LOGD(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, TRANS_LOGD, label, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_TRANS_LOG_H
