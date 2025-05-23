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

#include "softbus_disc_server.h"

#include "disc_log.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_discreporter.h"

int32_t DiscServerInit(void)
{
    int32_t ret = DiscMgrInit();
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "DiscServerInit failed");
        return ret;
    }
    return SOFTBUS_OK;
}

void DiscServerDeinit(void)
{
    DiscMgrDeinit();
}

void DiscServerDeathCallback(const char *pkgName, int32_t pid)
{
    DiscMgrDeathCallback(pkgName, pid);
}
