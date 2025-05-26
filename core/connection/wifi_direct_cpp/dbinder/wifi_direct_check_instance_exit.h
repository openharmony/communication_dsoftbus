/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_DIRECT_CHECK_INSTANCE_EXIT_H
#define OHOS_WIFI_DIRECT_CHECK_INSTANCE_EXIT_H

#include "conn_log.h"

#define CHECK_INSTANCE_EXIT(flag)                \
    if (flag) {                                  \
        CONN_LOGW(CONN_EVENT, "[wifi_direct_init] instance is exiting."); \
        return;                                  \
    }

#define CHECK_INSTANCE_EXIT_WITH_RETVAL(flag, retVal) \
    if (flag) {                                       \
        CONN_LOGW(CONN_EVENT, "[wifi_direct_init] instance is exiting."); \
        return retVal;                                \
    }

#endif // OHOS_WIFI_DIRECT_CHECK_INSTANCE_EXIT_H