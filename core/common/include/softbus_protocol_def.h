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
#ifndef SOFTBUS_PROTOCOL_DEF_H
#define SOFTBUS_PROTOCOL_DEF_H

#include <stdint.h>

// protocol ability
#define PROTOCOL_ABILITY_MESSAGE 0x1
#define PROTOCOL_ABILITY_BYTES   (0x1 << 1)
#define PROTOCOL_ABILITY_STREAM  (0x1 << 2)
#define PROTOCOL_ABILITY_FILE    (0x1 << 3)
typedef uint32_t LnnProtocolAbility;

// protocol type
#define LNN_PROTOCOL_BR    (0x1)
#define LNN_PROTOCOL_BLE   (1L << 1)
#define LNN_PROTOCOL_IP    (1L << 2)
#define LNN_PROTOCOL_DFILE (1L << 3)
#define LNN_PROTOCOL_COAP  (1L << 4)
#define LNN_PROTOCOL_DMSG  (1L << 5)
#define LNN_PROTOCOL_VTP   (1L << 6)
#define LNN_PROTOCOL_NIP   (1L << 7)
#define LNN_PROTOCOL_ALL   ((uint32_t)-1)
typedef uint32_t ProtocolType;

#define BIND_ADDR_ALL "0"

#endif
