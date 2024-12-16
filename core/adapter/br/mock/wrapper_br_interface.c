/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "wrapper_br_interface.h"

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gap.h"
#include "c_header/ohos_bt_spp.h"
#include "c_header/ohos_bt_socket.h"
#include "conn_log.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "string.h"

#define IS_BR_ENCRYPT false

static void Init(const struct tagSppSocketDriver *sppDriver)
{
    (void)sppDriver;
}

static int32_t OpenSppServer(const char *name, int32_t nameLen, const char *uuid, int32_t isSecure)
{
    if (name == NULL || nameLen <= 0) {
        CONN_LOGW(CONN_BR, "OpenSppServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)isSecure;

    BtCreateSocketPara socketPara;
    (void)memset_s((char *)&socketPara, sizeof(socketPara), 0, sizeof(socketPara));
    socketPara.uuid.uuid = (char *)uuid;
    socketPara.uuid.uuidLen = strlen(uuid);
    socketPara.socketType = OHOS_SPP_SOCKET_RFCOMM;
    socketPara.isEncrypt = IS_BR_ENCRYPT;
    return SppServerCreate(&socketPara, name, nameLen);
}

static void CloseSppServer(int32_t serverFd)
{
    CONN_LOGI(CONN_BR, "[CloseServer Connect, and serverFd=%{public}d]", serverFd);
    SppServerClose(serverFd);
}

static int32_t ConnectByPort(const char *uuid, const BT_ADDR mac, const int socketPsmValue, void *connectCallback)
{
    if (mac == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    BluetoothCreateSocketPara socketPara;
    (void)memset_s((char *)&socketPara, sizeof(socketPara), 0, sizeof(socketPara));
    socketPara.uuid.uuid = (char *)uuid;
    socketPara.uuid.uuidLen = strlen(uuid);
    socketPara.socketType = OHOS_SOCKET_SPP_RFCOMM;
    socketPara.isEncrypt = IS_BR_ENCRYPT;

    BdAddr bdAddr;
    (void)memset_s((char *)&bdAddr, sizeof(bdAddr), 0, sizeof(bdAddr));
    if (memcpy_s((char *)bdAddr.addr, OHOS_BD_ADDR_LEN, mac, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BR, "Connect memcpy_s failed");
        return SOFTBUS_MEM_ERR;
    }
    int ret = SocketConnectEx(&socketPara, &bdAddr, socketPsmValue, (BtSocketConnectionCallback *)connectCallback);
    if (ret < 0) {
        int32_t errorCode = ret == BT_SOCKET_LIMITED_RESOURCES ? SOFTBUS_CONN_BR_SOCKET_LIMITED_RESOURCES :
                                                                 SOFTBUS_CONN_BR_SOCKET_CONNECT_ERR;
        CONN_LOGE(CONN_BR, "connect failed, ret=%{public}d", ret);
        return errorCode;
    }
    CONN_LOGI(CONN_BR, "SocketConnectEx ok. clientId=%{public}d", ret);
    return ret;
}

static int32_t Connect(const char *uuid, const BT_ADDR mac, void *connectCallback)
{
    return ConnectByPort(uuid, mac, -1 ,connectCallback);
}

static int32_t DisConnect(int32_t clientFd)
{
    CONN_LOGI(CONN_BR, "[DisConnect, and clientFd=%{public}d]", clientFd);
    return SppDisconnect(clientFd);
}

static bool IsConnected(int32_t clientFd)
{
    CONN_LOGI(CONN_BR, "[get connected state from bt, clientFd=%{public}d]", clientFd);
    return IsSppConnected(clientFd);
}

static int32_t Accept(int32_t serverFd)
{
    CONN_LOGI(CONN_BR, "[Accept remote device to connect, and serverFd=%{public}d]", serverFd);
    int32_t ret = SppServerAccept(serverFd);
    if (ret == BT_SPP_INVALID_ID) {
        CONN_LOGE(CONN_BR, "Accept spp server failed");
        return SOFTBUS_CONN_BR_SPP_SERVER_ERR;
    }
    return ret;
}

static int32_t Write(int32_t clientFd, const uint8_t *buf, const int32_t len)
{
    return SppWrite(clientFd, (const char *)buf, len);
}

static int32_t Read(int32_t clientFd, uint8_t *buf, const int32_t len)
{
    int32_t ret = SppRead(clientFd, (char *)buf, len);
    if (ret == BT_SPP_READ_SOCKET_CLOSED) {
        return BR_READ_SOCKET_CLOSED;
    } else if (ret == BT_SPP_READ_FAILED) {
        return BR_READ_FAILED;
    }
    return ret;
}

static int32_t GetRemoteDeviceInfo(int32_t clientFd, const BluetoothRemoteDevice *device)
{
    CONN_LOGI(CONN_BR, "[to get remotedeviceinfo, clientFd=%{public}d]", clientFd);
    BdAddr bdAddr;
    (void)memset_s((char *)&bdAddr, sizeof(bdAddr), 0, sizeof(bdAddr));
    (void)SppGetRemoteAddr(clientFd, &bdAddr);
    if (memcpy_s((char *)device->mac, BT_ADDR_LEN, (char *)bdAddr.addr, OHOS_BD_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BR, "GetRemoteDeviceInfo memcpy_s failed");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}
static int32_t GetSppServerPort(int serverId)
{
    return SocketGetScn(serverId);
}

static SppSocketDriver g_sppSocketDriver = {
    .Init = Init,
    .OpenSppServer = OpenSppServer,
    .CloseSppServer = CloseSppServer,
    .Connect = Connect,
    .ConnectByPort = ConnectByPort,
    .DisConnect = DisConnect,
    .IsConnected = IsConnected,
    .Accept = Accept,
    .Write = Write,
    .Read = Read,
    .GetRemoteDeviceInfo = GetRemoteDeviceInfo,
    .GetSppServerPort = GetSppServerPort
};

bool IsAclConnected(const BT_ADDR mac)
{
    CONN_LOGW(CONN_BR, "IsAclConnected not implement");
    return false;
}

SppSocketDriver *InitSppSocketDriver()
{
    CONN_LOGI(CONN_INIT, "[InitSppSocketDriver]");
    Init(&g_sppSocketDriver);
    return &g_sppSocketDriver;
}
