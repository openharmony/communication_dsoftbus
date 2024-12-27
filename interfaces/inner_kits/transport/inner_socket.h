/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "socket.h"
#include "softbus_common.h"
#include "trans_type.h"

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

/**
 * @brief Grant permission to socket with uid and pid.
 *
 * @param uid Indicates the uid of the process.
 * @param pid Indicates the pid of the process.
 * @param socketName Indicates the name of the socket to grant permission.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const char *socketName);

/**
 * @brief Removes permissions for a specific socket
 *
 * @param socketName Indicates the name of the socket to remove permission.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t DBinderRemovePermission(const char *socketName);

/**
 * @brief Bind for dfs.
 *
 * @param socket Indicates the the unique socket fd.
 * @param listener Indicates the pointer to the socket callback.
 * @return Returns <b>SOFTBUS_TRANS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>INVALID_SOCKET</b> if the operation fails.
 * @return Returns <b>SOFTBUS_OK</b> if the socket is bind;
 * returns an error code otherwise.
 * @since 1.0
 * @version 1.0
 */
int32_t DfsBind(int32_t socket, const ISocketListener *listener);

/**
 * @brief Set socket option.
 *
 * @param socket Indicates the unique socket fd.
 * @param level Indicates the level of option.
 * @param optType Indicates the type of option.
 * @param optValue Indicates the pointer to the option value to set, which cannot be <b>NULL</b>.
 * @param optValueSize Indicates the length of the option value to set.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>optValue</b> is <b>NULL</b> or <b>optValueSize</b> is zero.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SetSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize);

/**
 * @brief Get socket option.
 *
 * @param socket Indicates the unique socket fd.
 * @param level Indicates the level of option.
 * @param optType Indicates the type of option.
 * @param optValue Indicates the pointer to the option value to get, which cannot be <b>NULL</b>.
 * @param optValueSize Indicates the pointer to the optValue size to get, which cannot be <b>NULL</b>.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>optValue</b> is <b>NULL</b> or <b>optValueSize</b> is <b>NULL</b>.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GetSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize);

/**
 * @brief privilege shutdown session only dms service can call.
 *
 * @param tokenId Indicates the token of channel creater.
 * @param pid Indicates the pid of channel creater.
 * @param peerNetworkId Indicates the peer device network id. empty mean all peer device
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t PrivilegeShutdown(uint64_t tokenId, int32_t pid, const char *peerNetworkId);

/**
 * @brief Defines socket bind relation checker
 *
 * When a socket is binding, relation checker will be called to check the feature ability relation.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    /**
     * @brief Called when a socket is binding
     *
     * When a socket is bind, sink side will to call this function to check feature ability relation.
     *
     * @param sourceInfo Indicates the source Collab info.
     * @param sinkInfo Indicates the sink Collab info.
     *
     * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
     *
     * @since 2.0
     * @version 2.0
    */
    int32_t (*CheckCollabRelation)(CollabInfo sourceInfo, CollabInfo sinkInfo);
} IFeatureAbilityRelationChecker;

/**
 * @brief Register feature ability relation checker.
 *
 * @param relationChecker relation checker.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 *
 * @since 2.0
 * @version 2.0
 */
int32_t RegisterRelationChecker(IFeatureAbilityRelationChecker *relationChecker);
#ifdef __cplusplus
}
#endif
#endif // INNER_SOCKET_H