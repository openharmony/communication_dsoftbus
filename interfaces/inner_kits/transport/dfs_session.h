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
 * @file dfs_session.h
 *
 * @brief Declare functions and constants for the distributed file service of DSoftBus. The functions can be used to:
 * <ul>
 * <li>Obtain the session key and session handle.</li>
 * <li>Disable listening for the distributed file service. </li>
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef DFS_SESSION_H
#define DFS_SESSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines the length of the session key, including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define SESSION_KEY_LEN 32

/**
 * @example dfs_demo.c
 */

/**
 * @brief Obtains the session key based on the session ID.
 *
 * @param sessionId Indicates the unique session ID.
 * @param key Indicates the pointer to the buffer that stores the session key.
 * @param len Indicates the length of the buffer.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;returns an error code otherwise.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_TRANS_FUNC_NOT_SUPPORT</b> if the session ID is not supported.
 * @return Returns <b>SOFTBUS_MEM_ERR</b> if the operation fails due to insufficient memory.
 * @since 1.0
 * @version 1.0
 */
int32_t GetSessionKey(int32_t sessionId, char *key, unsigned int len);

/**
 * @brief Obtains the session handle based on the session ID.
 *
 * @param sessionId Indicates the unique session ID.
 * @param handle Indicates the pointer to the buffer that stores the session handle.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;returns an error code otherwise.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_TRANS_FUNC_NOT_SUPPORT</b> if the session ID is not supported.
 * @return Returns <b>SOFTBUS_MEM_ERR</b> if the operation fails due to insufficient memory.
 * @since 1.0
 * @version 1.0
 */
int32_t GetSessionHandle(int32_t sessionId, int *handle);

/**
 * @brief Disables the session listener based on the session ID.
 *
 * @param sessionId Indicates the unique session ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;returns an error code otherwise.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_TRANS_FUNC_NOT_SUPPORT</b> if the session ID is not supported.
 * @since 1.0
 * @version 1.0
 */
int32_t DisableSessionListener(int32_t sessionId);

#ifdef __cplusplus
}
#endif
#endif // DFS_SESSION_H