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

#include "disc_log.h"

/* Keep consistent with labels */
const SoftBusLogLabel DISC_LABELS[DISC_LABEL_MAX] = {
    { DISC_INIT,        0xd0057a0,      "DiscInit"      },
    { DISC_CONTROL,     0xd0057a1,      "DiscControl"   },
    { DISC_LNN,         0xd0057a2,      "DiscLnn"       },
    { DISC_BLE,         0xd0057a3,      "DiscBle"       },
    { DISC_BLE_ADAPTER, 0xd0057a4,      "DiscAdp"       },
    { DISC_COAP,        0xd0057a5,      "DiscCoap"      },
    { DISC_DFINDER,     0xd0057a6,      "DiscDfinder"   },
    { DISC_ABILITY,     0xd0057a7,      "DiscAbility"   },
    { DISC_USB,         0xd0057a8,      "DiscUsb"       },
    { DISC_USB_ADAPTER, 0xd0057a9,      "DiscUsbAdapter"},
    { DISC_SDK,         0xd0057aa,      "DiscSdk"       },
    { DISC_BROADCAST,   0xd0057ab,      "DiscBC"        },
    { DISC_ACTION,      0xd0057ac,      "DiscAction"    },
    { DISC_EVENT,       0xd0057ad,      "DiscEvent"     },
    { DISC_VIRLINK,     0xd0057ae,      "DiscVirLink"   },
    { DISC_NFC,         0xd0057a8,      "DiscNfc"       },
    { DISC_TEST,        DOMAIN_ID_TEST, "DiscTest"      },
};
