/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "trans_server_proxy.h"

#include "iproxy_client.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;

static int ProxyCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "publish service callback error[%d].", code);
        return SOFTBUS_ERR;
    }

    ReadInt32(reply, (int *)owner);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "publish service return[%d].", *(int32_t*)owner);
    return SOFTBUS_OK;
}

static int OpenSessionProxyCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "publish service callback error[%d].", code);
        return SOFTBUS_ERR;
    }
    uint32_t size;
    ReadUint32(reply, &size);
    void *data = (void *)ReadBuffer(reply, size);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pop data is null.");
        return SOFTBUS_ERR;
    }
    *(TransSerializer *)owner = *(TransSerializer *)data;
    return SOFTBUS_OK;
}

int32_t TransServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server proxy has initialized.");
        return SOFTBUS_OK;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans start get server proxy");
    int32_t proxyInitCount = 0;
    while (g_serverProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans get server proxy error");
            return SOFTBUS_OK;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QueryInterface failed [%d]", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans get server proxy ok");
    return SOFTBUS_OK;
}

void TransServerProxyDeInit(void)
{
    g_serverProxy = NULL;
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcCreateSessionServer");
    if ((pkgName == NULL) || (sessionName == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, sessionName);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_CREATE_SESSION_SERVER, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcCreateSessionServer callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcCreateSessionServer succ");
    return ret;
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcRemoveSessionServer");
    if ((pkgName == NULL) || (sessionName == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, sessionName);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_REMOVE_SESSION_SERVER, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcRemoveSessionServer callback ret [%d]", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcRemoveSessionServer");
    return ret;
}

int32_t ServerIpcOpenSession(const SessionParam *param, TransInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenSession");

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, param->sessionName);
    WriteString(&request, param->peerSessionName);
    WriteString(&request, param->peerDeviceId);
    WriteString(&request, param->groupId);
    bool value = WriteRawData(&request, (void*)param->attr, sizeof(SessionAttribute));
    if (!value) {
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    TransSerializer transSerializer;
    transSerializer.ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OPEN_SESSION, &request,
        &transSerializer, OpenSessionProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcOpenSession callback ret [%d]", transSerializer.ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    info->channelId = transSerializer.transInfo.channelId;
    info->channelType = transSerializer.transInfo.channelType;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenSession");
    return transSerializer.ret;
}

int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenAuthSession begin");

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, sessionName);
    bool value = WriteRawData(&request, (void*)addrInfo, sizeof(ConnectionAddr));
    if (!value) {
        return SOFTBUS_ERR;
    }

    int32_t ret = SOFTBUS_ERR;
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OPEN_AUTH_SESSION, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcOpenAuthSession callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenAuthSession end");
    return ret;
}

int32_t ServerIpcNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcNotifyAuthSuccess begin");

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);
    int32_t ret = SOFTBUS_ERR;
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_NOTIFY_AUTH_SUCCESS, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcNotifyAuthSuccess end");
    return ret;
}

int32_t ServerIpcCloseChannel(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcCloseSession");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_CLOSE_CHANNEL, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcCloseSession callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcCloseSession");
    return ret;
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcSendMessage");

    uint32_t ipcDataLen = len + MAX_SOFT_BUS_IPC_LEN;
    uint8_t *ipcData = (uint8_t *)SoftBusCalloc(ipcDataLen);
    if (ipcData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcSendMessage malloc failed!");
        return SOFTBUS_MALLOC_ERR;
    }
    
    IpcIo request = {0};
    IpcIoInit(&request, ipcData, ipcDataLen, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);
    WriteInt32(&request, msgType);
    WriteUint32(&request, len);
    WriteBuffer(&request, data, len);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        SoftBusFree(ipcData);
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_SESSION_SENDMSG, &request, &ret, ProxyCallback);
    SoftBusFree(ipcData);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcSendMessage callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcSendMessage");
    return ret;
}

int32_t ServerIpcQosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)channelId;
    (void)chanType;
    (void)appType;
    (void)quality;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcGrantPermission(int uid, int pid, const char *sessionName)
{
    (void)uid;
    (void)pid;
    (void)sessionName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcRemovePermission(const char *sessionName)
{
    (void)sessionName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_NOT_IMPLEMENT;
}