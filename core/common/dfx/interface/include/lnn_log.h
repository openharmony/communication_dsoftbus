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
    LNN_HEART_BEAT,
    LNN_LEDGER,
    LNN_BUILDER,
    LNN_LANE,
    LNN_QOS,
    LNN_EVENT,
    LNN_STATE,
    LNN_META_NODE,
    LNN_CLOCK,
    LNN_TEST,
} LnnLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel LNN_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {LNN_INIT,        0xd005780,      "LnnInit"     },
    { LNN_HEART_BEAT, 0xd005781,      "LnnHeartBeat"},
    { LNN_LEDGER,     0xd005782,      "LnnLedger"   },
    { LNN_BUILDER,    0xd005783,      "LnnBuilder"  },
    { LNN_LANE,       0xd005784,      "LnnLane"     },
    { LNN_QOS,        0xd005785,      "LnnQos"      },
    { LNN_EVENT,      0xd005786,      "LnnEvent"    },
    { LNN_STATE,      0xd005787,      "LnnState"    },
    { LNN_META_NODE,  0xd005788,      "LnnMetaNode" },
    { LNN_CLOCK,      0xd005789,      "LnnClock"    },
    { LNN_TEST,       DOMAIN_ID_TEST, "LnnTest"     },
};

#ifndef SOFTBUS_STANDARD_SYSTEM
#define LNN_LOGF(label, ...) SOFTBUS_LITE_LOGF_INNER(label, ##__VA_ARGS__)
#define LNN_LOGE(label, ...) SOFTBUS_LITE_LOGE_INNER(label, ##__VA_ARGS__)
#define LNN_LOGW(label, ...) SOFTBUS_LITE_LOGW_INNER(label, ##__VA_ARGS__)
#define LNN_LOGI(label, ...) SOFTBUS_LITE_LOGI_INNER(label, ##__VA_ARGS__)
#define LNN_LOGD(label, ...) SOFTBUS_LITE_LOGD_INNER(label, ##__VA_ARGS__)
#else
#define LNN_LOGF(label, ...) (void)SOFTBUS_LOG_INNER(LOG_FATAL, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGE(label, ...) (void)SOFTBUS_LOG_INNER(LOG_ERROR, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGW(label, ...) (void)SOFTBUS_LOG_INNER(LOG_WARN, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGI(label, ...) (void)SOFTBUS_LOG_INNER(LOG_INFO, LNN_LABELS[label], ##__VA_ARGS__)
#define LNN_LOGD(label, ...) (void)SOFTBUS_LOG_INNER(LOG_DEBUG, LNN_LABELS[label], ##__VA_ARGS__)
#endif // SOFTBUS_STANDARD_SYSTEM

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
