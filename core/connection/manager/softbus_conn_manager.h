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

#ifndef SOFTBUS_CONN_MANAGER_H
#define SOFTBUS_CONN_MANAGER_H

#include "softbus_conn_interface.h"

#define CONNECT_TYPE_SHIFT 16

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    /**
     * @brief To connect the device, you can use the br/ble/tcp type to initiate a connection to the remote end.
     * The existing connection can be reused. If there is no physical connection, the logical connection will be made.
     * @see {@link TcpConnectDevice} or {@link ConnectDevice} or {@link BleConnectDevice}.
     * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
     * @param[in] requestId Request ID.
     * @param[in] result Indicates a pointer to the connection request. For details, see {@link ConnectResult}.
     * @return <b>SOFTBUS_OK</b> if the connection to the device is successfully.
     */
    int32_t (*ConnectDevice)(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

    /**
     * @brief Send data to the peer. Enable br/ble/tcp to send data.
     * @see {@link TcpPostBytes} or {@link PostBytes} or {@link BlePostBytes}.
     * @param[in] connectionId Connection ID.
     * @param[in] data Connection message content.
     * @param[in] len Data length.
     * @param[in] pid Identification ID.
     * @param[in] flag Message send flag.
     * @param[in] module Message source module.
     * @param[in] seq Message sequence.
     * @return <b>SOFTBUS_OK</b> if sending by byte is successfully.
     */
    int32_t (*PostBytes)(
        uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq);

    /**
     * @brief To disconnect the device, use the br/ble/tcp type of disconnect device logically to disconnect
     * the physical connection when the logical connection reference is zero.
     * @see {@link TcpDisconnectDevice} or {@link DisconnectDevice} or {@link BleDisconnectDevice}.
     * @param[in] connectionId Connection ID.
     * @return <b>SOFTBUS_OK</b> if the device disconnected is successfully.
     */
    int32_t (*DisconnectDevice)(uint32_t connectionId);

    /**
     * @brief Disconnects all connected devices, and disconnects logical and physical connections on
     * specified devices of type br/ble/tcp.
     * @see {@link TcpDisconnectDeviceNow} or {@link DisconnectDeviceNow} or {@link BleDisconnectDeviceNow}.
     * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
     * @return <b>SOFTBUS_OK</b> If the device is successfully disconnected through the address.
     */
    int32_t (*DisconnectDeviceNow)(const ConnectOption *option);

    /**
     * @brief Get an internal object of type br/ble/tcp based on the connection id.
     * @see {@link TcpGetConnectionInfo} or {@link GetConnectionInfo} or {@link BleGetConnectionInfo}.
     * @param[in] connectionId Connection ID.
     * @param[out] info Indicates a pointer to the connection information. For details, see {@link ConnectionInfo}.
     * @return <b>SOFTBUS_OK</b> if get the connection information is successfully.
     */
    int32_t (*GetConnectionInfo)(uint32_t connectionId, ConnectionInfo *info);

    /**
     * @brief Start the local monitoring service and listen for br/ble/tcp peer connection events.
     * @see {@link TcpStartLocalListening} or {@link StartLocalListening} or {@link BleStartLocalListening}.
     * @param[in] info Indicates a pointer to local listener information.
     * For details, see {@link LocalListenerInfo}.
     * @return <b>SOFTBUS_OK</b> if local listeners start successfully.
     */
    int32_t (*StartLocalListening)(const LocalListenerInfo *info);

    /**
     * @brief Stop the local monitoring service and stop monitoring br/ble/tcp peer connection events.
     * @see {@link TcpStopLocalListening} or {@link StopLocalListening} or {@link BleStopLocalListening}.
     * @param[in] info Indicates a pointer to local listener information. For details, see {@link LocalListenerInfo}.
     * @return <b>SOFTBUS_OK</b> if local listeners start successfully.
     */
    int32_t (*StopLocalListening)(const LocalListenerInfo *info);
    bool (*CheckActiveConnection)(const ConnectOption *info, bool needOccupy);
    int32_t (*UpdateConnection)(uint32_t connectionId, UpdateOption *option);

    /**
     * @brief Prevent connect other devices in specified time.
     * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
     * @param[in] time time in millisecond
     * @return <b>SOFTBUS_OK</b> if prevent connect other devices successfully, others if failed.
     */
    int32_t (*PreventConnection)(const ConnectOption *option, uint32_t time);

    /**
     * @brief Config flow control of posting data
     * @param configuration flow control configuration of posting data
     */
    int32_t (*ConfigPostLimit)(const LimitConfiguration *configuration);
} ConnectFuncInterface;

#define MAGIC_NUMBER  0xBABEFACE

#define CONN_FEATURE_SUPPORT_NETWORKID_EXCAHNGE 0
#define CONN_FEATURE_SUPPORT_ACTION_ENCODE 1

typedef struct {
    int32_t magic;
    int32_t module;
    int64_t seq;
    int32_t flag;
    uint32_t len;
} __attribute__((packed))ConnPktHead;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif