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

/**
 * @addtogroup SoftBus
 * @{
 *
 * @brief Provides secure, high-speed communications between devices.
 *
 * This module implements unified distributed communication management of nearby devices and provides link-independent
 * device discovery and transmission interfaces to support service publishing and data transmission.
 * @since 1.0
 * @version 1.0
 */

/**
 * @file inner_socket.h
 *
 * @brief Declare the function for getting the maximum transmission unit.
 *
 * @since 1.0
 * @version 1.0
 */
#ifndef INNER_SOCKET_H
#define INNER_SOCKET_H

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Get maximum transmission unit of socket
 *
 * @param socket Indicates the unique socket fd.
 * @param size Indicates the maximum transmission unit.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetMtuSize(int32_t socket, uint32_t *mtuSize);
#ifdef __cplusplus
}
#endif
#endif // INNER_SOCKET_H