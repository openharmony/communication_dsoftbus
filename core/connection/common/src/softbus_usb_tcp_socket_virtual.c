/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_usb_tcp_socket.h"

#include "conn_log.h"
#include "softbus_error_code.h"

static int32_t GetUsbSockPort(int32_t fd)
{
    (void)fd;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

static int32_t OpenUsbClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    (void)option;
    (void)myIp;
    (void)isNonBlock;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

static int32_t OpenUsbServerSocket(const LocalListenerInfo *option)
{
    (void)option;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

static int32_t AcceptUsbClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    (void)fd;
    (void)clientAddr;
    (void)cfd;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

static SocketInterface usbTcpSocketIntf = {
    .name = "USB_TCP",
    .type = LNN_PROTOCOL_USB,
    .GetSockPort = GetUsbSockPort,
    .OpenServerSocket = OpenUsbServerSocket,
    .OpenClientSocket = OpenUsbClientSocket,
    .AcceptClient = AcceptUsbClient,
};

const SocketInterface *GetUsbProtocol(void)
{
    return &usbTcpSocketIntf;
}
