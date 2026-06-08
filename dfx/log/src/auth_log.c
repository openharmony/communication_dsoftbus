/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_log.h"

/* Keep consistent with labels */
const SoftBusLogLabel AUTH_LABELS[AUTH_LABEL_MAX] = {
    { AUTH_INIT,    0xd005720,      "AuthInit"    },
    { AUTH_HICHAIN, 0xd005721,      "AuthHiChain" },
    { AUTH_CONN,    0xd005722,      "AuthConn"    },
    { AUTH_FSM,     0xd005723,      "AuthFsm"     },
    { AUTH_KEY,     0xd005724,      "AuthKey"     },
    { AUTH_TEST,    DOMAIN_ID_TEST, "AuthTest"    },
};
