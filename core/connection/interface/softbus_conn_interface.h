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

#ifndef SOFTBUS_CONN_INTERFACE_H
#define SOFTBUS_CONN_INTERFACE_H

#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"
#include "softbus_conn_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @ingroup softbus_conn_manager
 * @brief Get connection header size.
 * @return <b>SOFTBUS_OK</b> if the header length get is successfully.
 */
uint32_t ConnGetHeadSize(void);

/**
 * @brief The initialization of the connection server is mainly for the initialization of tcp, br, and ble.
 * This interface is only called once when the soft bus service is created.
 * @see {@link ConnServerDeinit}
 * @return <b>SOFTBUS_OK</b> Successfully initialized connection server
 * returns an error code less than zero otherwise.
 */
int32_t ConnServerInit(void);

/**
 * @brief Deinitialize the connection server, the tcp, br, and ble connection servers will be deinitialized.
 * This interface is only called once when the soft bus service is destroyed.
 * @see {@link ConnServerInit}
 */
void ConnServerDeinit(void);

/**
 * @ingroup Softbus_conn_manager
 * @brief Register connection callback.
 * @see {@link ConnUnSetConnectCallback}
 * @param[in] moduleId Module ID. For details, see {@link ConnModule}.
 * @param[in] callback Indicates a pointer to the connection callback. For details, see {@link ConnectCallback}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_OK</b> if set the connection callback is successfully.
 */
int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback);

/**
 * @ingroup Softbus_conn_manager
 * @brief Unset the connection callback, clear the callback setting of ConnSetConnectCallback.
 * @see {@link ConnSetConnectCallback}
 * @param[in] moduleId Module ID.For details, see {@link ConnModule}.
 */
void ConnUnSetConnectCallback(ConnModule moduleId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Send data to peer.
 * @param[in] connectionId Connection ID.
 * @param[in] data Connection message content. For details, see {@link ConnPostData}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null.
 * @return <b>SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID</b> if the data parameter length is wrong.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null or invalid.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the bytes result is null.
 * @return <b>SOFTBUS_OK</b> if sending by byte is successfully.
 */
int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data);

/**
 * @ingroup Softbus_conn_manager
 * @brief Type checking of the connection module to check if this type is supported.
 * @param[in] type Connection type. For details, see {@link ConnectType}.
 * @return <b>SOFTBUS_OK</b> If checked the connection type is successfully.
 */
int32_t ConnTypeIsSupport(ConnectType type);

/**
 * @ingroup Softbus_conn_manager
 * @brief set keep alive by connectionId.
 * @param[in] connectionId Connection Id.
 * @param[in] needKeepalive tcp need keepalive.
 * @return <b>SOFTBUS_OK</b> set keepalive success.
 */
int32_t ConnSetKeepAliveByConnectionId(uint32_t connectionId, bool needKeepalive);

/**
 * @ingroup Softbus_conn_manager
 * @brief Get inner object based on connection id.
 * @param[in] connectionId Connection ID.
 * @param[in] info Indicates a pointer to the connection information. For details, see {@link ConnectionInfo}.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null or invalid.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the result is null.
 * @return <b>SOFTBUS_OK</b> if the connection information get is successfully.
 */
int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief Request connection id.
 * @param[in] moduleId ConnModule module ID. For details, see {@link ConnModule}.
 * @return <b>SOFTBUS_OK</b> if get new request ID is successfully.
 */
uint32_t ConnGetNewRequestId(ConnModule moduleId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Connect the device interface, call this interface to initiate a connection to the remote end.
 * @see {@link ConnDisconnectDevice}
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] requestId Request ID.
 * @param[in] result Indicates a pointer to the connection request. For details, see {@link ConnectResult}.
 * @return <b>SOFTBUS_OK</b> if the connection to the device is successfully
 * returns an error code less than zero otherwise.
 */
int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

/**
 * @ingroup Softbus_conn_manager
 * @brief Disconnect the device connection interface, disconnect the device logical connection,
 * and disconnect the physical connection when the logical connection reference is zero.
 * @see {@link ConnConnectDevice}
 * @param[in] connectionId Connection ID.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the disconnection device function of type is null.
 * @return <b>SOFTBUS_OK</b> if the device disconnected is successfully.
 */
int32_t ConnDisconnectDevice(uint32_t connectionId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Disconnects all connected device interfaces,
 * and disconnects the logical and physical connections on the specified device.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the option is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b>
 * if all connected devices all disconnected function of type is null.
 * @return <b>SOFTBUS_OK</b> if all connected devices all disconnected are successfully.
 */
int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);

/**
 * @ingroup Softbus_conn_manager
 * @brief Stop the local monitoring service and stop monitoring the peer connection event.
 * @see {@link ConnStartLocalListening}
 * @param[in] info Indicates a pointer to local listener information. For details, see {@link LocalListenerInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the info is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if local listener stop function of type is null.
 * @return <b>SOFTBUS_OK</b> if local listener stop successfully.
 */
int32_t ConnStopLocalListening(const LocalListenerInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief Start the local monitoring service and listen for the peer connection event.
 * @see {@link ConnStopLocalListening}
 * @param[in] info Indicates a pointer to local listener information. For details, see {@link LocalListenerInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the info is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if local listener start function of type is null.
 * @return <b>SOFTBUS_OK</b> if local listeners start successfully.
 */
int32_t ConnStartLocalListening(const LocalListenerInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief call this interface to initiate a ble direct connection or sle direct connection to the remote end.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] requestId Request ID.
 * @param[in] result Indicates a pointer to the connection request. For details, see {@link ConnectResult}.
 * @return <b>SOFTBUS_OK</b> if the connection to the device is successfully
 * returns an error code less than zero otherwise.
 */
int32_t ConnDirectConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

/**
 * @ingroup Softbus_conn_manager.
 * @brief call this interface to check ble direct connect support or not.
 * @return <b>false</b> if not support.
 * @return <b>true</b> if support.
 */
bool ConnBleDirectIsEnable(BleProtocolType protocol);

bool CheckActiveConnection(const ConnectOption *option, bool needOccupy);

/**
 * @ingroup Softbus_conn_manager
 * @brief update connection properties as need
 * @param[in] connectionId connection id which should be update.
 * @param[in] option the option will acts on connection
 * @return <b>SOFTBUS_OK</b> if update connection properties successfully, others if failed.
 */
int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option);

/**
 * @ingroup Softbus_conn_manager
 * @brief Prevent connect other devices in specified time.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] time time in millisecond
 * @return <b>SOFTBUS_OK</b> if prevent connect other devices successfully, others if failed.
 */
int32_t ConnPreventConnection(const ConnectOption *option, uint32_t time);

/**
 * @ingroup Softbus_conn_manager
 * @brief Obtain link type based on connection ID.
 * @param[in] connectionId Connection ID.
 * @param[out] type Indicates a pointer to the link type. For details, see {@link ConnectType}.
 * @return <b>SOFTBUS_OK</b> if prevent connect other devices successfully, others if failed.
 */
int32_t ConnGetTypeByConnectionId(uint32_t connectionId, ConnectType *type);

/**
 * @ingroup Softbus_conn_manager
 * @param configuration flow control configuration of posting data
 * @return <b>SOFTBUS_OK</b> if success, others if failed.
 */
int32_t ConnConfigPostLimit(const LimitConfiguration *configuration);

void ConnDeathCallback(const char *pkgName, int32_t pid);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
