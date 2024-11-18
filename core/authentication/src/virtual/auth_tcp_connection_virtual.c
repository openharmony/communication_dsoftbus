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
#include "auth_log.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

int32_t RegAuthChannelListener(int32_t module, const AuthChannelListener *listener)
{
    (void)module;
    (void)listener;
    AUTH_LOGW(AUTH_CONN, "not implement.");
    return SOFTBUS_OK;
}

void UnregAuthChannelListener(int32_t module)
{
    (void)module;
}

int32_t AuthOpenChannel(const char *ip, int32_t port)
{
    (void)ip;
    (void)port;
    AUTH_LOGW(AUTH_CONN, "not implement.");
    return INVALID_CHANNEL_ID;
}

void AuthCloseChannel(int32_t channelId, int32_t moduleId)
{
    (void)channelId;
    (void)moduleId;
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
    AUTH_LOGW(AUTH_CONN, "not implement.");
    return SOFTBUS_NOT_IMPLEMENT;
}

void SocketDisconnectDevice(ListenerModule module, int32_t fd)
{
    (void)module;
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

int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info)
{
    (void)module;
    (void)info;
    AUTH_LOGW(AUTH_CONN, "not implement.");
    return SOFTBUS_NOT_IMPLEMENT;
}

void StopSocketListening(ListenerModule moduleId)
{
    (void)moduleId;
    return;
}
