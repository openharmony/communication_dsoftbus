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
 * @brief Provides high-speed, secure communications between devices.
 *
 * This module implements unified distributed communication management of
 * nearby devices, and provides link-independent device discovery and transmission interfaces
 * to support service publishing and data transmission.
 *
 * @since 2.0
 * @version 2.0
 */

/**
 * @file socket.h
 *
 * @brief Declares unified data transmission interfaces.
 *
 * This file provides data transmission capabilities, including creating and removing a socket server,
 * opening and closing sockets, receiving data, and querying basic socket information. \n
 * You can use the interfaces to transmit data across the nearby devices that are discovered and networked.
 * \n
 *
 * @since 2.0
 * @version 2.0
 */
#ifndef SOCKET_H
#define SOCKET_H

#include <stdint.h>
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the QoS feedback types.
 *
 * @since 2.0
 * @version 2.0
 */
typedef enum {
    QOS_SATISFIED,     /**< Feedback on satisfied quality */
    QOS_NOT_SATISFIED, /**< Feedback on not satisfied quality */
} QoSEvent;

/**
 * @brief Defines socket callbacks.
 *
 * When a socket is opened or closed, or there is data to process, the related callback is invoked.
 *
 * @since 2.0
 * @version 2.0
 */
typedef struct {
    /**
     * @brief Called when a socket is bind.
     *
     * This callback is invoked to verify the socket or initialize resources related to the socket.
     *
     * @param socket Indicates the unique socket fd; socket fd = <b>0</b> if the bind is failed.
     * @since 2.0
     * @version 2.0
     */
    void (*OnBind)(int32_t socket, PeerSocketInfo info);

    /**
     * @brief Called when a socket is closed.
     *
     * This callback is invoked to release resources related to the socket.
     *
     * @param socket Indicates the unique socket fd.
     * @param reason Indicates the reason for closing the socket.
     * @since 2.0
     * @version 2.0
     */
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);

    /**
     * @brief Called when bytes data is received.
     *
     * This callback is invoked to notify that data is received.
     *
     * @param socket Indicates the unique socket fd.
     * @param data Indicates the pointer to the bytes data received.
     * @param dataLen Indicates the length of the bytes data received.
     * @since 2.0
     * @version 2.0
     */
    void (*OnBytes)(int32_t socket, const void *data, uint32_t dataLen);

    /**
     * @brief Called when message data is received.
     *
     * This callback is invoked to notify that message data is received.
     *
     * @param socket Indicates the unique socket fd.
     * @param data Indicates the pointer to the message data received.
     * @param dataLen Indicates the length of the message data received.
     * @since 2.0
     * @version 2.0
     */
    void (*OnMessage)(int32_t socket, const void *data, uint32_t dataLen);

    /**
     * @brief Called when stream data is received.
     *
     * This callback is invoked to notify that stream data is received.
     *
     * @param socket Indicates the unique socket fd.
     * @param data Indicates the pointer to the stream data received.
     * @param ext Indicates the pointer to the extended service data received.
     * @param param Indicates the pointer to the stream data frame information.
     * @since 2.0
     * @version 2.0
     */
    void (*OnStream)(int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);

    /**
     * @brief Called when file data is received.
     *
     * This callback is invoked to notify that file data is received.
     *
     * @param socket Indicates the unique socket fd.
     * @param event Indicates the file event.
     * @param data Indicates the pointer to the file data received.
     * @since 2.0
     * @version 2.0
     */
    void (*OnFile)(int32_t socket, FileEvent *event);

    /**
     * @brief Called when QoS state is changed.
     *
     * This callback is invoked to notify that QoS state is changed.
     *
     * @param socket Indicates the unique socket fd.
     * @param event Indicates the type of QoS state change.
     * @param qos[] Indicates the QoS status that we can provide.
     * @since 2.0
     * @version 2.0
     */
    void (*OnQos)(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount);
} ISocketListener;

/**
 * @brief Creates a socket.
 *
 * A maximum of 10 socket can be created.
 *
 * @param info Indicates the description of the socket structure.
 * It is the unique identifier of the upper-layer service. The value cannot be empty or exceed 64 characters.
 *
 * @return Returns <b>socket fd</b> if the socket creation is successful; returns <b>-1</b> otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t Socket(SocketInfo info);

/**
 * @brief Listens a socket, which is called by server.
 *
 * @param socket Indicates the the unique socket fd.
 * @param qos Indicates the QoS requirements for socket. The value cannot be empty.
 * @param listener Indicates the pointer to the socket callback.
 *
 * @return Returns <b>0</b> if the listen creation is successful; returns <b>-1</b> otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);

/**
 * @brief Binds a socket, which is called by client.
 *
 * {@link OnBind} is invoked to return whether the socket is successfully bind.
 * Data can be transmitted only after the socket is successfully bind.
 *
 * @param socket Indicates the the unique socket fd.
 * @param qos Indicates the QoS requirements for socket. The value cannot be empty.
 * @param listener Indicates the pointer to the socket callback.
 *
 * @return Returns <b>SOFTBUS_TRANS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>INVALID_SOCKET</b> if the operation fails.
 * @return Returns the socket fd (an integer greater than <b>0</b>) if the socket is bind;
 * returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);

/**
 * @example sendbytes_message_demo.c
 */

/**
 * @brief Sends bytes data.
 *
 * @param socket Indicates the unique socket fd.
 * @param data Indicates the pointer to the bytes data to send, which cannot be <b>NULL</b>.
 * @param len Indicates the length of the bytes data to send.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if invalid parameters are detected.
 * @return Returns <b>SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT</b> if the bytes data exceeds the maximum limit.
 * @return Returns <b>SOFTBUS_TRANS_INVALID_SOCKET</b> if <b>socket</b> is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SOCKET_NO_ENABLE</b> if the socket is not bind.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SendBytes(int32_t socket, const void *data, uint32_t len);

/**
 * @brief Sends message data.
 *
 * @param socket Indicates the unique socket fd.
 * @param data Indicates the pointer to the message data to send, which cannot be <b>NULL</b>.
 * @param len Indicates the length of the message data to send.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>data</b> is <b>NULL</b> or <b>len</b> is zero.
 * @return Returns <b>SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT</b> if the message data length exceeds the limit.
 * @return Returns <b>SOFTBUS_INVALID_SOCKET</b> if <b>socket</b> is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SOCKET_NO_ENABLE</b> if the socket is not bind.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SendMessage(int32_t socket, const void *data, uint32_t len);

/**
 * @example sendstream_demo.c
 */

/**
 * @brief Sends stream data.
 *
 * @param socket Indicates the unique socket fd.
 * @param data Indicates the pointer to the stream data to send, which cannot be <b>NULL</b>.
 * @param ext Indicates the pointer to the extended stream data to send, which cannot be <b>NULL</b>.
 * @param param Indicates the pointer to the stream frame information, which cannot be <b>NULL</b>.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any of the input parameters is <b>NULL</b>.
 * @return Returns <b>SOFTBUS_INVALID_SOCKET</b> if <b>socket</b> is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SOCKET_NO_ENABLE</b> if the socket is not bind.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SendStream(int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);

/**
 * @example sendfile_demo.c
 */

/**
 * @brief Sends files data.
 *
 * @param socket Indicates the unique socket fd.
 * @param sFileList Indicates the pointer to the source files data to send, which cannot be <b>NULL</b>.
 * @param dFileList Indicates the pointer to the destination files data, which cannot be <b>NULL</b>.
 * @param fileCnt Indicates the number of files data to send, which cannot be <b>0</b>.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>sFileList</b> is <b>NULL</b> or <b>fileCnt</b> is <b>0</b>.
 * @return Returns <b>SOFTBUS_INVALID_SOCKET</b> if <b>socket</b> is invalid.
 * @return Returns <b>SOFTBUS_TRANS_SOCKET</b> if the socket is not bind.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SendFile(int32_t socket, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);

/**
 * @brief Get socket based on a socket fd.
 *
 * @param socket Indicates the unique socket fd.
 *
 * @return Returns no value.
 * @since 2.0
 * @version 2.0
 */
void Shutdown(int32_t socket);

/**
 * @brief Evaluate quality of service.
 *
 * @param peerNetworkId Indicates the pointer to the remote device ID.
 * @param dataType Indicates the type of data.
 * @param qos Indicates the expected quality of service.
 * @param qosLen Indicates the number of qos
 *
 * @return Returns no value.
 * @since 2.0
 * @version 2.0
 */
int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount);
#ifdef __cplusplus
}
#endif
#endif // SOCKET_H
