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

#ifndef SOFTBUS_TRANSMISSION_H
#define SOFTBUS_TRANSMISSION_H

#include <stdint.h>

#include "lnn_lane_interface.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    /**
    * @brief callback after the specified channel is opened.
    * @see {@link TransRegisterNetworkingChannelListener}
    * @param[in] channelId indicates that channel is open.
    * @param[in] uuid indicates the pointer to the uuid.
    * @param[in] isServer indicates server side or client side.
    * @return <b>SOFTBUS_OK</b> the processing success after the callback; returns an error code otherwise..
    */
    int (*onChannelOpened)(int32_t channelId, const char *uuid, unsigned char isServer);
    /**
    * @brief callback after open channel failed.
    * @see {@link TransRegisterNetworkingChannelListener}
    * @param[in] channelId indicates the opening channelId.
    * @param[in] uuid indicates the pointer to the uuid.
    */
    void (*onChannelOpenFailed)(int32_t channelId, const char *uuid);
    /**
    * @brief callback after closed channel.
    * @see {@link TransRegisterNetworkingChannelListener}
    * @param[in] channelId indicates the opening channelId.
    */
    void (*onChannelClosed)(int32_t channelId);
    /**
    * @brief callback after receive message.
    * @see {@link TransRegisterNetworkingChannelListener}
    * @param[in] channelId indicates the opened channelId.
    * @param[in] data indicates the pointer to the message data.
    * @param[in] len indicates the message data of len.
    */
    void (*onMessageReceived)(int32_t channelId, const char *data, uint32_t len);
} INetworkingListener;

/**
 * @brief To open a proxy channel to the specified device.
 * @see {@link TransCloseNetWorkingChannel}
 * @param[in] sessionName indicates the pointer to the package name.
 * @param[in] peerNetworkId indicates the pointer to the peer network id.
 * @param[in] preferred indicates the pointer to preferred link list, allow null
 * @return <b>INVALID_CHANNEL_ID</b> Failed to open channel, return invalid channel id.
 * @return <b>NewChannelId</b> Success to open channel, and return valid channel id.
 */
int TransOpenNetWorkingChannel(
    const char *sessionName, const char *peerNetworkId, const LanePreferredLinkList *preferred);

/**
 * @brief To close the sepcified proxy channel.
 * this interface is only called once when the channelId already opened.
 * @see {@link TransOpenNetWorkingChannel}
 * @param[in] channelId indicates the opened ChannelId.
 * @return <b>SOFTBUS_MALLOC_ERR</b> Failed to allocate space for global variable of information.
 * @return <b>SOFTBUS_OK</b> Success to close this proxy channel, returns other internal error codes otherwise.
 */
int TransCloseNetWorkingChannel(int32_t channelId);

/**
 * @brief send message through the sepcified channel.
 * this interface is current only called once when the sync device info.
 * @see {@link TransOpenNetWorkingChannel}
 * @param[in] channelId indicates the opened ChannelId.
 * @param[in] data indicates the pointer to message data.
 * @param[in] dataLen indicates the message data of len.
 * @param[in] priority indicates the message send priority.
 * @return <b>SOFTBUS_MALLOC_ERR</b> Failed to allocate space for global variable of information.
 * @return <b>SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID</b> the channel status is abnormal.
 * @return <b>SOFTBUS_TRANS_PROXY_PACKMSG_ERR</b> Failed to packaged the message data.
 * @return <b>SOFTBUS_OK</b> Success to send message to the channel, returns other internal error codes otherwise.
 */
int TransSendNetworkingMessage(int32_t channelId, const char *data, uint32_t dataLen, int32_t priority);

/**
 * @brief regiester listener to channel listener manager.
 * this interface is current only called once when the sync info manager.
 * @see {@link INetworkingListener}
 * @param[in] listener indicates regiestered function callback.
 * @return <b>SOFTBUS_OK</b> Success to register channel listener, return other internal errorcodes otherwise.
 */
int TransRegisterNetworkingChannelListener(const char *sessionName, const INetworkingListener *listener);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif
