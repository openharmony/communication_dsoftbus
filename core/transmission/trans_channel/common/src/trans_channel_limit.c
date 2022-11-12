/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "softbus_def.h"
#include "softbus_log.h"


#define AUTH_SESSION_WHITE_LIST_NUM (3)

static char g_sessionWhiteList[AUTH_SESSION_WHITE_LIST_NUM][SESSION_NAME_SIZE_MAX] = {
    "ohos.distributedhardware.devicemanager.resident",
    "com.huawei.devicegroupmanage",
    "IShareAuthSession"
};

bool CheckSessionNameValidOnAuthChannel(const char *sessionName)
{
    if (sessionName == NULL) {
        return false;
    }

    uint16_t index = 0;
    size_t len = 0;
    for (; index < AUTH_SESSION_WHITE_LIST_NUM; ++index) {
        len = strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX);
        if (strncmp(sessionName, g_sessionWhiteList[index], len) == 0) {
            return true;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "auth channel sessionname[%s] invalid.", sessionName);
    return false;
}

