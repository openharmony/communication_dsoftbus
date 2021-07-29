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

#include "trans_server_proxy.h"

#include "iproxy_client.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_os_interface.h"

static IClientProxy *g_serverProxy = NULL;

static int ProxyCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "publish service callback error[%d].", code);
        return SOFTBUS_ERR;
    }

    *(int32_t*)owner = IpcIoPopInt32(reply);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "publish service return[%d].", *(int32_t*)owner);
    return SOFTBUS_OK;
}

int32_t TransServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server proxy has initialized.");
        return SOFTBUS_OK;
    }

    IUnknown *iUnknown = NULL;
    int ret;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans start get server proxy");
    int proxyInitTime = 0;
    while (g_serverProxy == NULL) {
        proxyInitTime++;
        if (proxyInitTime == 25) {
            break;
        }

        iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QueryInterface failed [%d]", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans get server proxy ok");
    return SOFTBUS_OK;
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
    IpcIoPushString(&request, pkgName);
    IpcIoPushString(&request, sessionName);

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
    IpcIoPushString(&request, pkgName);
    IpcIoPushString(&request, sessionName);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_REMOVE_SESSION_SERVER, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcRemoveSessionServer callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcRemoveSessionServer");
    return ret;
}

int32_t ServerIpcOpenSession(const char *mySessionName, const char *peerSessionName,
                             const char *peerDeviceId, const char *groupId, int32_t flags)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenSession");

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushString(&request, mySessionName);
    IpcIoPushString(&request, peerSessionName);
    IpcIoPushString(&request, peerDeviceId);
    IpcIoPushString(&request, groupId);
    IpcIoPushInt32(&request, flags);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
        return SOFTBUS_NO_INIT;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OPEN_SESSION, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcOpenSession callback ret [%d]", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcOpenSession");
    return ret;
}

int32_t ServerIpcCloseChannel(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcCloseSession");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&request, channelId);
    IpcIoPushInt32(&request, channelType);

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

int32_t ServerIpcSendMessage(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ServerIpcSendMessage");

    uint32_t ipcDataLen = len + MAX_SOFT_BUS_IPC_LEN;
    uint8_t *ipcData = (uint8_t *)SoftBusCalloc(ipcDataLen);
    IpcIo request = {0};
    IpcIoInit(&request, ipcData, ipcDataLen, 0);
    IpcIoPushInt32(&request, channelId);
    IpcIoPushInt32(&request, msgType);
    IpcIoPushFlatObj(&request, data, len);

    int32_t ret = SOFTBUS_ERR;
    /* sync */
    if (g_serverProxy == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server proxy not init");
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