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

#include "bt_rfcom.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static SppSocketEventCallback *g_connectCallback = NULL;
static SppSocketEventCallback *g_connectServiceCallback = NULL;

static void OnEventRfcom(uint8 type, uint8 handle, int value)
{
    g_connectCallback->OnEvent((int32_t)type, (int32_t)handle, value);
}

static void OnDataReceivedRfcom(uint8 handle, const uint8 *buf, uint16 len)
{
    g_connectCallback->OnDataReceived((int32_t)handle, (char*)buf, (int32_t)len);
}

static BtRfcomEventCallback g_rfcomEventcb = {
    .OnEvent = OnEventRfcom,
    .OnDataReceived = OnDataReceivedRfcom
};

static void OnEventServiceRfcom(uint8 type, uint8 handle, int value)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO,
        "[Client event call back form bt, and socketid = %u, tpye = %u]", handle, type);
    if (g_connectServiceCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[g_connectServiceCallback is NULL]");
        return;
    }
    g_connectServiceCallback->OnEvent((int32_t)type, (int32_t)handle, value);
}

static void OnDataReceivedServiceRfcom(uint8 handle, const uint8 *buf, uint16 len)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO,
        "[Client received call back form bt, and socketid = %u, len = %u]", handle, len);
    if (g_connectServiceCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[g_connectServiceCallback is NULL]");
        return;
    }
    g_connectServiceCallback->OnDataReceived((int32_t)handle, (char*)buf, (int32_t)len);
}

static BtRfcomEventCallback g_rfcomServiceEventcb = {
    .OnEvent = OnEventServiceRfcom,
    .OnDataReceived = OnDataReceivedServiceRfcom
};

static int32_t Connect(int32_t clientFd, const SppSocketEventCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[mock clientFd = %d]", clientFd);
    g_connectCallback = (SppSocketEventCallback*)callback;
    int ret = BtRfcomClientConnect((uint8)clientFd, &g_rfcomEventcb);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[BtRfcom return  = %d]", ret);
    ret = (ret == BT_RFCOM_STATUS_OK) ? SOFTBUS_OK : SOFTBUS_ERR;
    return ret;
}

static void Init(const struct tagSppSocketDriver *sppDriver)
{
    (void)sppDriver;
}

static int32_t OpenSppServer(const BT_ADDR mac, const BT_UUIDL uuid, int32_t isSecure)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[OpenSppServer connect]");
    return SOFTBUS_ERR;
}

static int32_t OpenSppClient(const BT_ADDR mac, const BT_UUIDL uuid, int32_t isSecure)
{
    (void)isSecure;
    int ret = BtRfcomClientCreate(mac, uuid);
    if (ret == BT_RFCOM_CLIENT_INVALID_HANDLE) {
        return SOFTBUS_ERR;
    }
    return ret;
}

static int32_t CloseClient(int32_t clientFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[CloseClient connect, and serverFd = %d]", clientFd);
    return BtRfcomClientDisconnect((uint8)clientFd);
}

static void CloseServer(int32_t serverFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[CloseServer Connect, and serverFd = %d]", serverFd);
}


static int32_t GetRemoteDeviceInfo(int32_t clientFd, const BluetoothRemoteDevice *device)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[to get remotedeviceinfo, clientFd = %d]", clientFd);
    return 0;
}

static int32_t IsConnected(int32_t clientFd)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[to get connected state from bt, clientFd = %d]", clientFd);
    return true;
}

static int32_t Accept(int32_t serverFd, const SppSocketEventCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[Accept remote device to connect, and serverFd = %d]", serverFd);
    g_connectServiceCallback = (SppSocketEventCallback*)callback;
    return 0;
}

static int32_t Write(int32_t g_clientFd, const char *buf, const int32_t length)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[mock Write] g_clientFd=%d,len=%d", g_clientFd, length);
    return BtRfcomClientWrite((uint8)g_clientFd, (uint8 *)buf, (uint16)length);
}

static SppSocketDriver g_sppSocketDriver = {
    .Init = Init,
    .OpenSppServer = OpenSppServer,
    .OpenSppClient = OpenSppClient,
    .CloseClient = CloseClient,
    .CloseServer = CloseServer,
    .Connect = Connect,
    .GetRemoteDeviceInfo = GetRemoteDeviceInfo,
    .IsConnected = IsConnected,
    .Accept = Accept,
    .Write = Write
};

SppSocketDriver *InitSppSocketDriver()
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[InitSppSocketDriver]");
    Init(&g_sppSocketDriver);
    return &g_sppSocketDriver;
}