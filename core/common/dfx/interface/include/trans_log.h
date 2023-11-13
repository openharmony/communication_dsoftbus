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
    TRANS_INIT,
    TRANS_CTRL,
    TRANS_BYTES,
    TRANS_FILE,
    TRANS_MSG,
    TRANS_STREAM,
    TRANS_QOS,
    TRANS_SDK,
    TRANS_SVC,
    TRANS_TEST,
} TransLogLabelEnum;

/* Keep consistent with labels */
static const SoftBusLogLabel TRANS_LABELS[MODULE_DOMAIN_MAX_LEN] = {
    {TRANS_INIT,     0xd005740,      "TransInit"   },
    { TRANS_CTRL,    0xd005741,      "TransCtrl"   },
    { TRANS_BYTES,   0xd005742,      "TransBytes"  },
    { TRANS_FILE,    0xd005743,      "TransFile"   },
    { TRANS_MSG,     0xd005744,      "TransMsg"    },
    { TRANS_STREAM,  0xd005745,      "TransStream" },
    { TRANS_QOS,     0xd005746,      "TransQos"    },
    { TRANS_SDK,     0xd005747,      "TransSdk"    },
    { TRANS_SVC,     0xd005748,      "TransSvc"    },
    { TRANS_TEST,    DOMAIN_ID_TEST, "TransTest"   },
};

#define TRANS_LOGF(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_FATAL, TRANS_LABELS[label], ##__VA_ARGS__)
#define TRANS_LOGE(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_ERROR, TRANS_LABELS[label], ##__VA_ARGS__)
#define TRANS_LOGW(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_WARN, TRANS_LABELS[label], ##__VA_ARGS__)
#define TRANS_LOGI(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_INFO, TRANS_LABELS[label], ##__VA_ARGS__)
#define TRANS_LOGD(label, ...) (void)SOFTBUS_LOG_INNER(SOFTBUS_DFX_LOG_DEBUG, TRANS_LABELS[label], ##__VA_ARGS__)

#define TRANS_CHECK_AND_RETURN_RET_LOGW(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, TRANS_LOGW, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_RET_LOGE(cond, ret, label, fmt, ...) \
    CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, TRANS_LOGE, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_LOGW(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, TRANS_LOGW, label, fmt, ##__VA_ARGS__)
#define TRANS_CHECK_AND_RETURN_LOGE(cond, label, fmt, ...) \
    CHECK_AND_RETURN_LOG_INNER(cond, TRANS_LOGE, label, fmt, ##__VA_ARGS__)

void PrintAnonymousPacket(TransLogLabelEnum label, const char *msg, const char *packet);

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_TRANS_LOG_H
