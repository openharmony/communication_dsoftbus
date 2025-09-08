/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

/**
 * @file softbus_broadcast_adapter_interface.h
 * @brief Different broadcast protocol stacks adapt layer interfaces
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H
#define SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H

#include "softbus_broadcast_adapter_interface_struct.h"
#include "softbus_broadcast_adapter_type_struct.h"
#include "softbus_broadcast_type.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines interface functions for registering different media
 *
 * @since 4.1
 * @version 1.0
 */
int32_t RegisterBroadcastMediumFunction(BroadcastProtocol type, const SoftbusBroadcastMediumInterface *interface);

/**
 * @brief Defines interface functions for unregistering different media
 *
 * @since 4.1
 * @version 1.0
 */
int32_t UnRegisterBroadcastMediumFunction(BroadcastProtocol type);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H */
