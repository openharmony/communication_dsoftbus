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
#include "wrapper_br_interface.h"

#include "message_handler.h"
#include "ohos_bt_def.h"
#include "ohos_bt_gap.h"
#include "ohos_bt_spp.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "string.h"

#define IS_BR_ENCRYPT false

static void Init(const struct tagSppSocketDriver *sppDriver)
{
    (void)sppDriver;
}

static int32_t OpenSppServer(const char *name, int32_t nameLen, const char *uuid, int32_t isSecure)
{
    if (name == NULL || nameLen <= 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSppServer invalid param");
        return SOFTBUS_ERR;
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
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[CloseServer Connect, and serverFd = %d]", serverFd);
    SppServerClose(serverFd);
}

static int32_t Connect(const char *uuid, const BT_ADDR mac)
{
    if (mac == NULL) {
        return SOFTBUS_ERR;
    }
    BtCreateSocketPara socketPara;
    (void)memset_s((char *)&socketPara, sizeof(socketPara), 0, sizeof(socketPara));
    socketPara.uuid.uuid = (char *)uuid;
    socketPara.uuid.uuidLen = strlen(uuid);
    socketPara.socketType = OHOS_SPP_SOCKET_RFCOMM;
    socketPara.isEncrypt = IS_BR_ENCRYPT;

    BdAddr bdAddr;
    (void)memset_s((char *)&bdAddr, sizeof(bdAddr), 0, sizeof(bdAddr));
    if (memcpy_s((char *)bdAddr.addr, OHOS_BD_ADDR_LEN, mac, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Connect memcpy_s failed");
        return SOFTBUS_ERR;
    }
    int ret = SppConnect(&socketPara, &bdAddr);
    if (ret == BT_SPP_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "[BT_SPP_INVALID_ID]");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SppConnect ok clientId: %d", ret);
    return ret;
}

static int32_t DisConnect(int32_t clientFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[DisConnect, and clientFd = %d]", clientFd);
    return SppDisconnect(clientFd);
}

static bool IsConnected(int32_t clientFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[get connected state from bt, clientFd = %d]", clientFd);
    return IsSppConnected(clientFd);
}

static int32_t Accept(int32_t serverFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[Accept remote device to connect, and serverFd = %d]", serverFd);
    int32_t ret = SppServerAccept(serverFd);
    if (ret == BT_SPP_INVALID_ID) {
        return SOFTBUS_ERR;
    }
    return ret;
}

static int32_t Write(int32_t clientFd, const char *buf, const int32_t len)
{
    return SppWrite(clientFd, buf, len);
}

static int32_t Read(int32_t clientFd, char *buf, const int32_t len)
{
    int32_t ret = SppRead(clientFd, buf, len);
    if (ret == BT_SPP_READ_SOCKET_CLOSED) {
        return BR_READ_SOCKET_CLOSED;
    } else if (ret == BT_SPP_READ_FAILED) {
        return BR_READ_FAILED;
    }
    return ret;
}

static int32_t GetRemoteDeviceInfo(int32_t clientFd, const BluetoothRemoteDevice *device)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[to get remotedeviceinfo, clientFd = %d]", clientFd);
    BdAddr bdAddr;
    (void)memset_s((char *)&bdAddr, sizeof(bdAddr), 0, sizeof(bdAddr));
    (void)SppGetRemoteAddr(clientFd, &bdAddr);
    if (memcpy_s((char *)device->mac, BT_ADDR_LEN, (char *)bdAddr.addr, OHOS_BD_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetRemoteDeviceInfo memcpy_s failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static SppSocketDriver g_sppSocketDriver = {
    .Init = Init,
    .OpenSppServer = OpenSppServer,
    .CloseSppServer = CloseSppServer,
    .Connect = Connect,
    .DisConnect = DisConnect,
    .IsConnected = IsConnected,
    .Accept = Accept,
    .Write = Write,
    .Read = Read,
    .GetRemoteDeviceInfo = GetRemoteDeviceInfo
};

int32_t SppGattsRegisterHalCallback(const SoftBusBtStateListener *lister)
{
    return SoftBusAddBtStateListener(lister);
}

SppSocketDriver *InitSppSocketDriver()
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[InitSppSocketDriver]");
    Init(&g_sppSocketDriver);
    return &g_sppSocketDriver;
}
