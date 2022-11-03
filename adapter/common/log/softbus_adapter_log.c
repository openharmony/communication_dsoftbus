/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_adapter_log.h"

void SoftBusOutPrint(const char *buf, SoftBusLogLevel level)
{
#ifdef SOFTBUS_PRINTF
    (void)level;
    printf("%s\n", buf);
    return;
#else
    switch (level) {
        case SOFTBUS_LOG_DBG:
            HILOG_DEBUG(SOFTBUS_HILOG_ID, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_INFO:
            HILOG_INFO(SOFTBUS_HILOG_ID, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_WARN:
            HILOG_WARN(SOFTBUS_HILOG_ID, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_ERROR:
            HILOG_ERROR(SOFTBUS_HILOG_ID, "%{public}s", buf);
            break;
        default:
            break;
    }
#endif
}
