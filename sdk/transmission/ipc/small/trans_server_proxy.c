/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_log.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;

static int ProxyCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "publish service callback errCode=%{public}d.", code);
        return SOFTBUS_INVALID_PARAM;
    }

    ReadInt32(reply, (int *)owner);
    TRANS_LOGI(TRANS_SDK, "publish service owner=%{public}d.", *(int32_t*)owner);
    return SOFTBUS_OK;
}

static int OpenSessionProxyCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "publish service callback errCode=%{public}d.", code);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    ReadUint32(reply, &size);
    void *data = (void *)ReadBuffer(reply, size);
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "pop data is null.");
        return SOFTBUS_MEM_ERR;
    }
    *(TransSerializer *)owner = *(TransSerializer *)data;
    return SOFTBUS_OK;
}

static bool WriteQosInfo(IpcIo *request, const SessionParam *param)
{
    if (!WriteBool(request, param->isQosLane)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write qos flag failed!");
        return false;
    }

    if (!param->isQosLane) {
        return true;
    }

    if (!WriteUint32(request, param->qosCount)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write count of qos failed!");
        return false;
    }

    if (param->qosCount > 0) {
        if (!WriteBuffer(request, param->qos, sizeof(QosTV) * param->qosCount)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write qos info failed!");
            return false;
        }
    }

    return true;
}

int32_t TransServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        TRANS_LOGE(TRANS_INIT, "server proxy has init.");
        return SOFTBUS_NO_INIT;
    }

    TRANS_LOGI(TRANS_INIT, "get trans server proxy");
    int32_t proxyInitCount = 0;
    while (g_serverProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            TRANS_LOGE(TRANS_SDK, "trans get server proxy error");
            return SOFTBUS_OK;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            TRANS_LOGE(TRANS_SDK, "QueryInterface failed ret=%{public}d", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    return SOFTBUS_OK;
}

void TransServerProxyDeInit(void)
{
    g_serverProxy = NULL;
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    if ((pkgName == NULL) || (sessionName == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, sessionName);

    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_CREATE_SESSION_SERVER, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    return ret;
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    if ((pkgName == NULL) || (sessionName == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, sessionName);

    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_REMOVE_SESSION_SERVER, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    return ret;
}

static bool TransWriteIpcSessionAttrs(IpcIo *request, const SessionAttribute *attrs)
{
    if (attrs == NULL || request == NULL) {
        TRANS_LOGE(TRANS_SDK, "attrs is NULL!");
        return false;
    }

    if (!WriteInt32(request, attrs->dataType)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs dataType failed!");
        return false;
    }

    if (!WriteInt32(request, attrs->linkTypeNum)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs linkTypeNum failed!");
        return false;
    }

    if (attrs->linkTypeNum > 0) {
        if (!WriteBuffer(request, attrs->linkType, sizeof(LinkType) * attrs->linkTypeNum)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs linkType failed!");
            return false;
        }
    }

    if (!WriteInt32(request, attrs->attr.streamAttr.streamType)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs streamAttr failed!");
        return false;
    }

    if (attrs->fastTransData != NULL) {
        if (!WriteUint16(request, attrs->fastTransDataSize)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransDataSize failed!");
            return false;
        }
        if (!WriteRawData(request, attrs->fastTransData, attrs->fastTransDataSize)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransData failed!");
            return false;
        }
    } else {
        if (!WriteUint16(request, 0)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransDataSize failed!");
            return false;
        }
    }

    return true;
}

int32_t ServerIpcOpenSession(const SessionParam *param, TransInfo *info)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, param->sessionName);
    WriteString(&request, param->peerSessionName);
    WriteString(&request, param->peerDeviceId);
    WriteString(&request, param->groupId);
    WriteBool(&request, param->isAsync);
    WriteInt32(&request, param->sessionId);
    if (!TransWriteIpcSessionAttrs(&request, param->attr)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write attr failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    if (!WriteQosInfo(&request, param)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write qosinfo failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    TransSerializer transSerializer;
    transSerializer.ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return transSerializer.ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OPEN_SESSION, &request,
        &transSerializer, OpenSessionProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", transSerializer.ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    if (param->isAsync) {
        return transSerializer.ret;
    }
    info->channelId = transSerializer.transInfo.channelId;
    info->channelType = transSerializer.transInfo.channelType;
    return transSerializer.ret;
}

int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, sessionName);
    bool value = WriteRawData(&request, (void*)addrInfo, sizeof(ConnectionAddr));
    if (!value) {
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    int32_t ret = SOFTBUS_NO_INIT;
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OPEN_AUTH_SESSION, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    return ret;
}

int32_t ServerIpcNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);
    int32_t ret = SOFTBUS_NO_INIT;
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_NOTIFY_AUTH_SUCCESS, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    return ret;
}

int32_t ServerIpcReleaseResources(int32_t channelId)
{
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, channelId);

    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_RELEASE_RESOURCES, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_IPC_ERR;
    }
    return ret;
}

int32_t ServerIpcCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        WriteString(&request, sessionName);
    }
    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_CLOSE_CHANNEL, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return ans;
    }
    return ret;
}

int32_t ServerIpcCloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    (void)channelId;
    (void)channelType;
    (void)laneId;
    (void)dataInfo;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint32_t ipcDataLen = len + MAX_SOFT_BUS_IPC_LEN;
    uint8_t *ipcData = (uint8_t *)SoftBusCalloc(ipcDataLen);
    if (ipcData == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc failed!");
        return SOFTBUS_MALLOC_ERR;
    }

    IpcIo request = {0};
    IpcIoInit(&request, ipcData, ipcDataLen, 0);
    WriteInt32(&request, channelId);
    WriteInt32(&request, channelType);
    WriteInt32(&request, msgType);
    WriteUint32(&request, len);
    WriteBuffer(&request, data, len);

    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        SoftBusFree(ipcData);
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_SESSION_SENDMSG, &request, &ret, ProxyCallback);
    SoftBusFree(ipcData);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    TRANS_LOGD(TRANS_SDK, "ok");
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

int32_t ServerIpcEvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    (void)peerNetworkId;
    (void)dataType;
    (void)qos;
    (void)qosCount;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ServerIpcProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&request, eventType);
    WriteInt32(&request, len);
    bool value = WriteRawData(&request, buf, len);
    if (!value) {
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    int32_t ret = SOFTBUS_NO_INIT;
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_PROCESS_INNER_EVENT, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return ans;
    }
    return ret;
}

int32_t ServerIpcPrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteUint64(&request, tokenId);
    WriteInt32(&request, pid);
    WriteString(&request, peerNetworkId);
    int32_t ret = SOFTBUS_NO_INIT;
    /* sync */
    if (g_serverProxy == NULL) {
        TRANS_LOGE(TRANS_SDK, "server proxy not init");
        return ret;
    }
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_PRIVILEGE_CLOSE_CHANNEL, &request, &ret, ProxyCallback);
    if (ans != EC_SUCCESS) {
        TRANS_LOGE(TRANS_SDK, "callback ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_INVOKE_FAILED;
    }
    return ret;
}