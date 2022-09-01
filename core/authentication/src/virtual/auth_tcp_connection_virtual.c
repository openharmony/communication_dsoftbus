/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_tcp_connection.h"
#include "auth_channel.h"
#include "softbus_errcode.h"
#include "softbus_def.h"
#include "softbus_log.h"

int32_t RegAuthChannelListener(int32_t module, const AuthChannelListener *listener)
{
    (void)module;
    (void)listener;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "%s not implement.", __func__);
    return SOFTBUS_OK;
}

void UnregAuthChannelListener(int32_t module)
{
    (void)module;
    return;
}

int32_t AuthOpenChannel(const char *ip, int32_t port)
{
    (void)ip;
    (void)port;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "%s not implement.", __func__);
    return INVALID_CHANNEL_ID;
}

void AuthCloseChannel(int32_t channelId)
{
    (void)channelId;
    return;
}

int32_t AuthPostChannelData(int32_t channelId, const AuthChannelData *data)
{
    (void)channelId;
    (void)data;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SetSocketCallback(const SocketCallback *cb)
{
    (void)cb;
    return SOFTBUS_OK;
}

void UnsetSocketCallback(void)
{
    return;
}

int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode)
{
    (void)ip;
    (void)port;
    (void)isBlockMode;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "%s not implement.", __func__);
    return SOFTBUS_NOT_IMPLEMENT;
}

void SocketDisconnectDevice(int32_t fd)
{
    (void)fd;
    return;
}

int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    (void)fd;
    (void)head;
    (void)data;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SocketGetConnInfo(int32_t fd, AuthConnInfo *connInfo, bool *isServer)
{
    (void)fd;
    (void)connInfo;
    (void)isServer;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t StartSocketListening(const char *ip, int32_t port)
{
    (void)ip;
    (void)port;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "%s not implement.", __func__);
    return SOFTBUS_NOT_IMPLEMENT;
}

void StopSocketListening(void)
{
    return;
}
