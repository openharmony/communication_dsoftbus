/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_errcode.h"
#include "softbus_tcp_connect_manager.h"

uint32_t CalTcpConnectionId(int32_t fd)
{
    (void)fd;
    return 0;
}

int32_t TcpGetConnNum(void)
{
    return 0;
}

int32_t TcpConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    (void)option;
    (void)requestId;
    (void)result;
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDevice(uint32_t connectionId)
{
    (void)connectionId;
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDeviceNow(const ConnectOption *option)
{
    (void)option;
    return SOFTBUS_OK;
}

int32_t TcpPostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    (void)connectionId;
    (void)data;
    (void)len;
    (void)pid;
    (void)flag;
    return SOFTBUS_OK;
}

int32_t TcpGetConnectionInfo(uint32_t connectionId, ConnectionInfo *Info)
{
    (void)connectionId;
    (void)Info;
    return SOFTBUS_OK;
}

int32_t TcpStartListening(const LocalListenerInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

int32_t TcpStopListening(const LocalListenerInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    (void)callback;
    return NULL;
}
