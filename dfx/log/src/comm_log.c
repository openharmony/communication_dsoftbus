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

#include "comm_log.h"

/* Keep consistent with labels */
const SoftBusLogLabel COMM_LABELS[COMM_LABEL_MAX] = {
    { COMM_SDK,     0xd005700,      "CommSdk"    },
    { COMM_SVC,     0xd005701,      "CommSvc"    },
    { COMM_INIT,    0xd005702,      "CommInit"   },
    { COMM_DFX,     0xd005703,      "CommDfx"    },
    { COMM_EVENT,   0xd005704,      "CommEvent"  },
    { COMM_VERIFY,  0xd005705,      "CommVerify" },
    { COMM_PERM,    0xd005706,      "CommPerm"   },
    { COMM_UTILS,   0xd005707,      "CommUtils"  },
    { COMM_ADAPTER, 0xd005708,      "CommAdapter"},
    { COMM_TEST,    DOMAIN_ID_TEST, "CommTest"   },
};
