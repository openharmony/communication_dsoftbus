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

#ifndef WRAPPER_BR_INTERFACE_H
#define WRAPPER_BR_INTERFACE_H

#include "softbus_adapter_bt_common.h"
#include "softbus_def.h"
#include "softbus_wrapper_br_interface_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

SppSocketDriver *InitSppSocketDriver(void);
bool IsAclConnected(const BT_ADDR mac);
#ifdef __cplusplus
}
#endif
#endif /* WRAPPER_BR_INTERFACE_H */