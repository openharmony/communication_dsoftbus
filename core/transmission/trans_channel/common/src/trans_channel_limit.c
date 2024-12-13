/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "trans_channel_limit.h"

#include <securec.h>

#include "anonymizer.h"
#include "permission_entry.h"
#include "regex.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_log.h"

typedef struct {
    const char *sessionName;
    bool regexp;
} SessionWhiteList;

static const SessionWhiteList g_sessionWhiteList[] = {
    {
        .sessionName = "ohos.distributedhardware.devicemanager.resident",
        .regexp = false,
    },
    {
        .sessionName = "com.huawei.devicegroupmanage",
        .regexp = false,
    },
    {
        .sessionName = "IShareAuthSession",
        .regexp = false,
    },
    {
        .sessionName = "com.huawei.devicemanager.resident",
        .regexp = false,
    },
    {
        .sessionName = "com.huawei.plrdtest.dsoftbus",
        .regexp = false,
    },
    {
        .sessionName = "com.huawei.*CastPlusDiscoveryModule",
        .regexp = true,
    },
    {
        .sessionName = "com.huawei.dmsdp+dmsdp",
        .regexp = false,
    },
    {
        .sessionName = "com.huawei.devicemanager.dynamic",
        .regexp = false,
    },
    {
        .sessionName = "ohos.distributedhardware.devicemanager.pinholder",
        .regexp = false,
    }
};

bool CheckSessionNameValidOnAuthChannel(const char *sessionName)
{
    if (sessionName == NULL) {
        return false;
    }

    uint32_t count = sizeof(g_sessionWhiteList) / sizeof(g_sessionWhiteList[0]);
    for (uint32_t index = 0; index < count; ++index) {
        if (CompareString(g_sessionWhiteList[index].sessionName, sessionName,
                g_sessionWhiteList[index].regexp) == SOFTBUS_OK) {
            return true;
        }
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_CTRL,
        "auth channel sessionName invalid. sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return false;
}
