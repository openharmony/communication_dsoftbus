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

#include "softbus_event.h"

#define SOFTBUS_EVENT_DOMAIN        "DSOFTBUS"
#define SOFTBUS_EVENT_PKG_NAME      "dsoftbus"
#define SOFTBUS_EVENT_TYPE_BEHAVIOR 4

void SoftbusEventInner(SoftbusEventModule module, SoftbusEventForm form)
{
    form.domain = SOFTBUS_EVENT_DOMAIN,
    form.eventType = SOFTBUS_EVENT_TYPE_BEHAVIOR,
    form.orgPkg = SOFTBUS_EVENT_PKG_NAME;
    switch (module) {
        case EVENT_MODULE_CONN:
        case EVENT_MODULE_DISC:
        case EVENT_MODULE_LNN:
        case EVENT_MODULE_TRANS:
            // Convert and write form to hisysevent
            break;
        default:
            break;
    }
}