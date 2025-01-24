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

#include "bus_center_server_proxy.h"

#include "securec.h"

#include "iproxy_client.h"
#include "lnn_log.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_server_ipc_interface_code.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

typedef enum {
    GET_ALL_ONLINE_NODE_INFO = 0,
    GET_LOCAL_DEVICE_INFO,
    GET_NODE_KEY_INFO,
    ACTIVE_META_NODE,
    DEACTIVE_META_NODE,
    GET_ALL_META_NODE,
    SHIFT_LNN_GEAR,
    START_REFRESH_LNN,
    START_PUBLISH_LNN,
} FunID;

typedef struct {
    FunID id;
    int32_t arg1;
    int32_t retCode;
    void* data;
    int32_t dataLen;
} Reply;

typedef int32_t (*ClientBusCenterFunIdHandler)(Reply *, IpcIo *, uint32_t);

typedef struct {
    int32_t funIdType;
    ClientBusCenterFunIdHandler funIdHandler;
} ClientBusCenterStateHandler;

static int32_t OnOnlineNodeInfo(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnLocalDeviceInfo(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnNodeKeyInfo(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnActiveMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnDeactiveMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnAllMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnShiftLnnGear(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnStartRefreshLnn(Reply *info, IpcIo *reply, uint32_t infoSize);
static int32_t OnStartPublishLnn(Reply *info, IpcIo *reply, uint32_t infoSize);

static ClientBusCenterStateHandler g_busCenterStateHandler[] = {
    {GET_ALL_ONLINE_NODE_INFO, OnOnlineNodeInfo  },
    { GET_LOCAL_DEVICE_INFO,   OnLocalDeviceInfo },
    { GET_NODE_KEY_INFO,       OnNodeKeyInfo     },
    { ACTIVE_META_NODE,        OnActiveMetaNode  },
    { DEACTIVE_META_NODE,      OnDeactiveMetaNode},
    { GET_ALL_META_NODE,       OnAllMetaNode     },
    { SHIFT_LNN_GEAR,          OnShiftLnnGear    },
    { START_REFRESH_LNN,       OnStartRefreshLnn },
    { START_PUBLISH_LNN,       OnStartPublishLnn },
};

static IClientProxy *g_serverProxy = NULL;

static int32_t OnOnlineNodeInfo(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->arg1));
    if (info->arg1 > 0) {
        ReadUint32(reply, &infoSize);
        info->data = (void *)ReadBuffer(reply, infoSize);
    }
    return SOFTBUS_OK;
}

static int32_t OnLocalDeviceInfo(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &infoSize);
    info->dataLen = infoSize;
    info->data = (void *)ReadBuffer(reply, infoSize);
    return SOFTBUS_OK;
}

static int32_t OnNodeKeyInfo(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &infoSize);
    info->dataLen = infoSize;
    info->data = (void *)ReadBuffer(reply, infoSize);
    return SOFTBUS_OK;
}

static int32_t OnActiveMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    if (info->retCode == SOFTBUS_OK) {
        info->data = (void *)ReadString(reply, &infoSize);
        if (infoSize != (NETWORK_ID_BUF_LEN - 1)) {
            LNN_LOGE(LNN_EVENT, "invalid meta node id length=%{public}u", infoSize);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    return SOFTBUS_OK;
}

static int32_t OnDeactiveMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    return SOFTBUS_OK;
}

static int32_t OnAllMetaNode(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    if (info->retCode == SOFTBUS_OK) {
        ReadInt32(reply, &(info->arg1));
        if (info->arg1 > 0) {
            ReadUint32(reply, &infoSize);
            info->data = (void *)ReadBuffer(reply, infoSize);
        }
    }
    return SOFTBUS_OK;
}

static int32_t OnShiftLnnGear(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    return SOFTBUS_OK;
}

static int32_t OnStartRefreshLnn(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    return SOFTBUS_OK;
}

static int32_t OnStartPublishLnn(Reply *info, IpcIo *reply, uint32_t infoSize)
{
    ReadInt32(reply, &(info->retCode));
    return SOFTBUS_OK;
}

static int32_t ClientBusCenterResultCb(Reply *info, int32_t ret, IpcIo *reply)
{
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "ClientBusCenterResultCb failed. ret=%{public}d", ret);
        return ret;
    }
    uint32_t infoSize;
    uint32_t count = sizeof(g_busCenterStateHandler) / sizeof(ClientBusCenterStateHandler);
    for (uint32_t i = 0; i < count; i++) {
        if (g_busCenterStateHandler[i].funIdType == info->id) {
            return (g_busCenterStateHandler[i].funIdHandler)(info, reply, infoSize);
        }
    }
    LNN_LOGI(LNN_INIT, "funcId not exist");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t BusCenterServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        LNN_LOGI(LNN_INIT, "server proxy has initialized");
        return SOFTBUS_OK;
    }

    LNN_LOGI(LNN_INIT, "bus center start get server proxy");
    int32_t proxyInitCount = 0;
    while (g_serverProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            LNN_LOGE(LNN_INIT, "bus center get server proxy error");
            return SOFTBUS_SERVER_NOT_INIT;
        }

        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            LNN_LOGE(LNN_INIT, "QueryInterface failed=%{public}d", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    LNN_LOGI(LNN_INIT, "bus center get server proxy ok");
    return SOFTBUS_OK;
}

void BusCenterServerProxyDeInit(void)
{
    g_serverProxy = NULL;
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is NULL");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteUint32(&request, infoTypeLen);
    Reply reply = {0};
    reply.id = GET_ALL_ONLINE_NODE_INFO;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_GET_ALL_ONLINE_NODE_INFO, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    uint32_t maxConnCount = UINT32_MAX;
    (void)SoftbusGetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, (unsigned char *)&maxConnCount, sizeof(maxConnCount));
    *infoNum = reply.arg1;
    if (*infoNum < 0 || (uint32_t)(*infoNum) > maxConnCount) {
        LNN_LOGE(LNN_EVENT, "invoke failed=%{public}d", *infoNum);
        return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
    }
    int32_t infoSize = (*infoNum) * (int32_t)infoTypeLen;
    *info = NULL;
    if (infoSize > 0) {
        if (reply.data == NULL) {
            LNN_LOGE(LNN_EVENT, "read node info failed");
            return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == NULL) {
            LNN_LOGE(LNN_EVENT, "malloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(*info, infoSize, reply.data, infoSize) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy node info failed");
            SoftBusFree(*info);
            *info = NULL;
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteUint32(&request, infoTypeLen);
    Reply reply = {0};
    reply.id = GET_LOCAL_DEVICE_INFO;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_GET_LOCAL_DEVICE_INFO, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    if (reply.data == NULL) {
        LNN_LOGE(LNN_EVENT, "read node info failed");
        return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
    }
    if (memcpy_s(info, infoTypeLen, reply.data, infoTypeLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy node info failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len)
{
    if (networkId == NULL || buf == NULL) {
        LNN_LOGW(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGW(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, networkId);
    WriteInt32(&request, key);
    WriteUint32(&request, len);
    Reply reply = {0};
    reply.id = GET_NODE_KEY_INFO;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_GET_NODE_KEY_INFO, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "GetNodeKeyInfo invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    if (reply.data == NULL || reply.dataLen <= 0 || (uint32_t)reply.dataLen > len) {
        LNN_LOGE(LNN_EVENT,
            "GetNodeKeyInfo read retBuf failed, inlen=%{public}u, reply.dataLen=%{public}d", len, reply.dataLen);
        return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
    }
    if (memcpy_s(buf, len, reply.data, reply.dataLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "GetNodeKeyInfo copy node key info failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, networkId);
    WriteInt16(&request, dataChangeFlag);
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_SET_NODE_DATA_CHANGE_FLAG, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcRegDataLevelChangeCb(const char *pkgName)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    IpcIo request = {0};
    return g_serverProxy->Invoke(g_serverProxy, SERVER_REG_DATA_LEVEL_CHANGE_CB, &request, NULL, NULL);
}

int32_t ServerIpcUnregDataLevelChangeCb(const char *pkgName)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    IpcIo request = {0};
    return g_serverProxy->Invoke(g_serverProxy, SERVER_UNREG_DATA_LEVEL_CHANGE_CB, &request, NULL, NULL);
}

int32_t ServerIpcSetDataLevel(const DataLevel *dataLevel)
{
    if (dataLevel == NULL) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    IpcIo request = {0};
    return g_serverProxy->Invoke(g_serverProxy, SERVER_SET_DATA_LEVEL, &request, NULL, NULL);
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    LNN_LOGD(LNN_EVENT, "join Lnn ipc client push");
    if (addr == NULL || pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteUint32(&request, addrTypeLen);
    WriteBuffer(&request, addr, addrTypeLen);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_JOIN_LNN, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "join Lnn invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    LNN_LOGD(LNN_EVENT, "leave Lnn ipc client push");
    if (pkgName == NULL || networkId == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "ServerIpcLeaveLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, networkId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_LEAVE_LNN, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "leave Lnn invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    LNN_LOGD(LNN_EVENT, "start time sync ipc client push");
    if (targetNetworkId == NULL || pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, targetNetworkId);
    WriteInt32(&request, accuracy);
    WriteInt32(&request, period);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_START_TIME_SYNC, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "StartTimeSync invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    LNN_LOGD(LNN_EVENT, "stop time sync ipc client push");
    if (targetNetworkId == NULL || pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, targetNetworkId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_STOP_TIME_SYNC, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "StopTimeSync invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    LNN_LOGD(LNN_EVENT, "publish Lnn ipc client push");
    if (info == NULL || pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN_EX] = {0};
    IpcIo request = {0};
    Reply reply = {0};
    reply.id = START_PUBLISH_LNN;
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, info->publishId);
    WriteInt32(&request, info->mode);
    WriteInt32(&request, info->medium);
    WriteInt32(&request, info->freq);
    WriteString(&request, info->capability);
    WriteUint32(&request, info->dataLen);
    if (info->dataLen != 0) {
        WriteString(&request, info->capabilityData);
    }
    WriteBool(&request, info->ranging);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_PUBLISH_LNN, &request, &reply, ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "publish Lnn invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    LNN_LOGD(LNN_EVENT, "stop publish lnn ipc client push");
    if (pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, publishId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_STOP_PUBLISH_LNN, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "ServerIpcStopPublishLNN invoke failed. ans=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    LNN_LOGD(LNN_EVENT, "refresh Lnn ipc client push");
    if (info == NULL || pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN_EX] = {0};
    IpcIo request = {0};
    Reply reply = {0};
    reply.id = START_REFRESH_LNN;
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, info->subscribeId);
    WriteInt32(&request, info->mode);
    WriteInt32(&request, info->medium);
    WriteInt32(&request, info->freq);
    WriteBool(&request, info->isSameAccount);
    WriteBool(&request, info->isWakeRemote);
    WriteString(&request, info->capability);
    WriteUint32(&request, info->dataLen);
    if (info->dataLen != 0) {
        WriteString(&request, info->capabilityData);
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_REFRESH_LNN, &request, &reply, ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "refresh Lnn invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    LNN_LOGD(LNN_EVENT, "stop refresh lnn ipc client push");
    if (pkgName == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, refreshId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_STOP_REFRESH_LNN, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed=%{public}d", ans);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN_EX] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    WriteString(&request, pkgName);
    bool ret = WriteRawData(&request, info, sizeof(MetaNodeConfigInfo));
    if (!ret) {
        return SOFTBUS_NETWORK_READRAWDATA_FAILED;
    }
    Reply reply = {0};
    reply.id = ACTIVE_META_NODE;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_ACTIVE_META_NODE, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    if (reply.data == NULL) {
        LNN_LOGE(LNN_EVENT, "read data failed");
        return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
    }
    if (strncpy_s(metaNodeId, NETWORK_ID_BUF_LEN, (char *)reply.data, strlen((char *)reply.data)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy meta node id failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcDeactiveMetaNode(const char *pkgName, const char *metaNodeId)
{
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, metaNodeId);
    Reply reply = {0};
    reply.id = DEACTIVE_META_NODE;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_DEACTIVE_META_NODE, &request,
        &reply, ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, *infoNum);
    Reply reply = {0};
    reply.id = GET_ALL_META_NODE;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_GET_ALL_META_NODE_INFO, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return SOFTBUS_NETWORK_PROXY_INVOKE_FAILED;
    }
    if (reply.arg1 > 0) {
        if (reply.data == NULL) {
            LNN_LOGE(LNN_EVENT, "read meta node info failed");
            return SOFTBUS_NETWORK_INVALID_REPLY_DATA;
        }
        if (memcpy_s(infos, *infoNum * sizeof(MetaNodeInfo), reply.data, reply.arg1 * sizeof(MetaNodeInfo)) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy meta node info failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    *infoNum = reply.arg1;
    return SOFTBUS_OK;
}

int32_t ServerIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    if (pkgName == NULL || callerId == NULL || mode == NULL) {
        LNN_LOGW(LNN_EVENT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    bool targetNetworkIdIsNull = targetNetworkId == NULL ? true : false;
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteString(&request, callerId);
    WriteBool(&request, targetNetworkIdIsNull);
    if (!targetNetworkIdIsNull) {
        WriteString(&request, targetNetworkId);
    }
    WriteRawData(&request, mode, sizeof(GearMode));
    Reply reply = {0};
    reply.id = SHIFT_LNN_GEAR;
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_SHIFT_LNN_GEAR, &request, &reply,
        ClientBusCenterResultCb);
    if (ans != SOFTBUS_OK || reply.retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "invoke failed. ans=%{public}d, retCode=%{public}d", ans, reply.retCode);
        return ans != SOFTBUS_OK ? SOFTBUS_NETWORK_PROXY_INVOKE_FAILED : reply.retCode;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)msg;
    (void)msgLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcSetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    (void)pkgName;
    (void)nameData;
    (void)len;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}