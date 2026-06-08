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

#include "lnn_log.h"

/* Keep consistent with labels */
const SoftBusLogLabel LNN_LABELS[LNN_LABEL_MAX] = {
    { LNN_INIT,       0xd005780,      "LnnInit"     },
    { LNN_HEART_BEAT, 0xd005781,      "LnnHeartBeat"},
    { LNN_LEDGER,     0xd005782,      "LnnLedger"   },
    { LNN_BUILDER,    0xd005783,      "LnnBuilder"  },
    { LNN_LANE,       0xd005784,      "LnnLane"     },
    { LNN_QOS,        0xd005785,      "LnnQos"      },
    { LNN_EVENT,      0xd005786,      "LnnEvent"    },
    { LNN_STATE,      0xd005787,      "LnnState"    },
    { LNN_META_NODE,  0xd005788,      "LnnMetaNode" },
    { LNN_CLOCK,      0xd005789,      "LnnClock"    },
    { LNN_TEST,       DOMAIN_ID_TEST, "LnnTest"     },
};
