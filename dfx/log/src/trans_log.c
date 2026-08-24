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

#include "trans_log.h"

/* Keep consistent with labels */
const SoftBusLogLabel TRANS_LABELS[TRANS_LABEL_MAX] = {
    { TRANS_SDK,        0xd005740,      "TransSdk"      },
    { TRANS_SVC,        0xd005741,      "TransSvc"      },
    { TRANS_INIT,       0xd005742,      "TransInit"     },
    { TRANS_CTRL,       0xd005743,      "TransCtrl"     },
    { TRANS_BYTES,      0xd005744,      "TransBytes"    },
    { TRANS_FILE,       0xd005745,      "TransFile"     },
    { TRANS_MSG,        0xd005746,      "TransMsg"      },
    { TRANS_STREAM,     0xd005747,      "TransStream"   },
    { TRANS_QOS,        0xd005748,      "TransQos"      },
    { TRANS_EVENT,      0xd005749,      "TransEvent"    },
    { TRANS_TEST,       DOMAIN_ID_TEST, "TransTest"     },
};
