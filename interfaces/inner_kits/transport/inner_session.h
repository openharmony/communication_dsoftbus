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
 * @file inner_session.h
 *
 * @brief Declares the functions for DSoftBus identity authentication. The functions can be used to:
 * <ul>
 * <li>Open an identity authentication session.</li>
 * <li>Send an authentication success notification.</li>
 *
 * @since 1.0
 * @version 1.0
 */
#ifndef INNER_SESSION_H
#define INNER_SESSION_H

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @example openauthsession_demo.c
 */

/**
 * @brief Opens a session for identity authentication.
 *
 * @param sessionName Indicates the pointer to the session name for identity authentication.
 * The session name uniquely identifies a session service. The value cannot be empty or exceed 256 characters.
 * @param addrInfo Indicates the pointer to the address information for the connection between devices.
 * @param num Indicates the number of device connection records.
 * @param mixAddr Indicates the pointer to the connection address information.
 * If the address information passed by <b>addrInfo</b> is invalid,
 * this parameter can be used to obtain the connection information.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>INVALID_SESSION_ID</b> if the session ID is invalid.
 * @return Returns the session ID (an integer greater than <b>0</b>) if the operation is successful;
 * return an error code otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo, int num, const char *mixAddr);

/**
 * @brief Notifies the upper-layer service of the identity authentication success.
 *
 * @param sessionId Indicates the unique session ID.
 *
 * @since 1.0
 * @version 1.0
 */
void NotifyAuthSuccess(int sessionId);

#ifdef __cplusplus
}
#endif
#endif