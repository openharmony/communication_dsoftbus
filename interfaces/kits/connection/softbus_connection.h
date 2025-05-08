/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include "softbus_common.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONNECTION_STATE_CONNECTED_SUCCESS = 0,
    CONNECTION_STATE_CONNECTED_FAILED,
    CONNECTION_STATE_DISCONNECTED,
} GeneralConnectionState;

/**
 * @brief Defines connection callbacks.
 *
 * When accepts a connection or the connection state is changed or data is received or the softbus_server process died,
 * the related callback is invoked.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    /**
     * @brief Called when server side accept a connection request.
     *
     * This callback is invoked when the server side accept a connection request.
     * The server side refers to the side that called {@GeneralCreateServer} function.
     *
     * @param name Indicates the session name of the connection.
     * @param handle Indicates the handle of the connection.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 2.0
     * @version 2.0
     */
    int32_t (*OnAcceptConnect)(const char *name, uint32_t handle);

    /**
     * @brief Called when a connection state is changed.
     *
     * @param handle Indicates the handle of the connection.
     * @param state Indicates the new state of the connection.
     * @param reason Indicates the reason of the connection state change.

     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 2.0
     * @version 2.0
     */
    int32_t (*OnConnectionStateChange)(uint32_t handle, int32_t state, int32_t reason);

    /**
     * @brief Called when data is received.
     *
     * This callback is invoked when data is received.
     *
     * @param handle Indicates the handle of the connection.
     * @param data Indicates the data received.
     * @param len Indicates the length of the data received.
     * @since 2.0
     * @version 2.0
     */
    void (*OnDataReceived)(uint32_t handle, const uint8_t *data, uint32_t len);

    /**
     * @brief Called when server side softbus_server process died.
     *
     * This callback is invoked when the server side softbus_server process died.
     * @since 2.0
     * @version 2.0
     */
    void (*OnServiceDied)(void);
} IGeneralListener;

/**
 * @brief Registers a connection listener.
 *
 * @param listener Indicates the pointer to the connection callback.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the listen creation is successful;
 * returns an error code less than zero otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralRegisterListener(IGeneralListener *listener);

/**
 * @brief Unregisters a connection listener.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns an error code less than zero otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralUnregisterListener();

/**
 * @brief Creates a server.
 *
 * @param pkgName Indicates the package name of the server.
 * @param name Indicates the session name of the server.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralCreateServer(const char *pkgName, const char *name);

/**
 * @brief Removes a server.
 *
 * @param pkgName Indicates the package name of the server.
 * @param name Indicates the session name of the server.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralRemoveServer(const char *pkgName, const char *name);

/**
 * @brief Defines the address of a remote device.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    ConnectionAddrType addrType; /**< Address type */
    union {
        struct BleAddress {
            char mac[BT_MAC_LEN]; /**< MAC address */
        } ble;
    } addr;
} Address;

/**
 * @brief Connects to a remote device.
 *
 * @param pkgName Indicates the package name of the client.
 * @param name Indicates the session name of the client.
 * @param address Indicates the address of the remote device.
 *
 * @return Returns handle of the connection if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralConnect(const char *pkgName, const char *name, const Address *address);

/**
 * @brief Disconnects a connection.
 *
 * @param handle Indicates the handle of the connection.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralDisconnect(uint32_t handle);

/**
 * @brief Sends data to a remote device.
 *
 * @param handle Indicates the handle of the connection.
 * @param data Indicates the data to be sent.
 * @param len Indicates the length of the data to be sent.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneralSend(uint32_t handle, const uint8_t *data, uint32_t len);

/**
 * @brief Gets the peer device id of a connection.
 *
 * @param handle Indicates the handle of the connection.
 * @param deviceId Indicates the pointer to the buffer to store the peer device id.
 * @param len Indicates the length of the buffer to store the peer device id.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful;
 * returns a non-zero value otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t GeneraConnGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len);
#ifdef __cplusplus
}
#endif
#endif // CONNECTION_H
