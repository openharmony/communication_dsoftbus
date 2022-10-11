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

#include <ohos_init.h>

#include "bus_center_server_stub.h"
#include "disc_server_stub.h"
#include "ipc_skeleton.h"
#include "iproxy_server.h"
#include "lnn_bus_center_ipc.h"
#include "samgr_lite.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_info_manager.h"
#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_server_frame.h"
#include "trans_server_stub.h"
#include "trans_session_service.h"

#define STACK_SIZE 0x800
#define QUEUE_SIZE 20
#define WAIT_FOR_SERVER 2
typedef struct {
    INHERIT_SERVER_IPROXY;
} DefaultFeatureApi;

typedef struct {
    INHERIT_SERVICE;
    INHERIT_IUNKNOWNENTRY(DefaultFeatureApi);
    Identity identity;
} SoftbusSamgrService;

static const char *GetName(Service *service)
{
    (void)service;
    return SOFTBUS_SERVICE;
}

static BOOL Initialize(Service *service, Identity identity)
{
    if (service == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return TRUE;
    }

    SoftbusSamgrService *samgrService = (SoftbusSamgrService *)service;
    samgrService->identity = identity;
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    if (service == NULL || msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return TRUE;
    }
    return FALSE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = { LEVEL_HIGH, PRI_BELOW_NORMAL, STACK_SIZE, QUEUE_SIZE, SHARED_TASK };
    return config;
}

static void ComponentDeathCallback(const char *pkgName)
{
    DiscServerDeathCallback(pkgName);
    TransServerDeathCallback(pkgName);
    BusCenterServerDeathCallback(pkgName);
}

static void ClientDeathCb(void *arg)
{
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "package name is NULL.");
        return;
    }
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName((const char *)arg, &svcId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not found client by package name.");
        SoftBusFree(arg);
        arg = NULL;
        return;
    }
    SERVER_UnregisterService((const char *)arg);
    ComponentDeathCallback((const char *)arg);
    SoftBusFree(arg);
    arg = NULL;
    SvcIdentity sid = {0};
    sid.handle = svcId.handle;
    sid.token = svcId.token;
    sid.cookie = svcId.cookie;
    ReleaseSvc(sid);
}

static int32_t ServerRegisterService(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "register service ipc server pop.");
    size_t len = 0;
    int ret = SOFTBUS_ERR;
    struct CommonScvId svcId = {0};

    const char *name = (const char*)ReadString(req, &len);
    SvcIdentity svc;
    bool value = ReadRemoteObject(req, &svc);
    if (!value || name == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get data fail");
        goto EXIT;
    }
    int32_t callingUid = GetCallingUid();
    if (!CheckBusCenterPermission(callingUid, name)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRegisterService no permission.");
        goto EXIT;
    }
    svcId.handle = svc.handle;
    svcId.token = svc.token;
    svcId.cookie = svc.cookie;

    char *pkgName = (char *)SoftBusMalloc(len + 1);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus malloc failed!");
        goto EXIT;
    }
    if (strcpy_s(pkgName, len + 1, name) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus strcpy_s failed!");
        SoftBusFree(pkgName);
        goto EXIT;
    }
    uint32_t cbId = 0;
    AddDeathRecipient(svc, ClientDeathCb, pkgName, &cbId);
    svcId.cbId = cbId;
    ret = SERVER_RegisterService(name, &svcId);
EXIT:
    WriteInt32(reply, ret);
    return SOFTBUS_OK;
}

typedef struct {
    enum SoftBusFuncId id;
    int32_t (*func)(IpcIo *req, IpcIo *reply);
} ServerInvokeCmd;

ServerInvokeCmd g_serverInvokeCmdTbl[] = {
    { MANAGE_REGISTER_SERVICE, ServerRegisterService },
    { SERVER_PUBLISH_SERVICE, ServerPublishService },
    { SERVER_UNPUBLISH_SERVICE, ServerUnPublishService },
    { SERVER_START_DISCOVERY, ServerStartDiscovery },
    { SERVER_STOP_DISCOVERY, ServerStopDiscovery },
    { SERVER_JOIN_LNN, ServerJoinLNN },
    { SERVER_JOIN_LNN, ServerJoinMetaNode },
    { SERVER_LEAVE_LNN, ServerLeaveLNN },
    { SERVER_LEAVE_LNN, ServerLeaveMetaNode },
    { SERVER_GET_ALL_ONLINE_NODE_INFO, ServerGetAllOnlineNodeInfo },
    { SERVER_GET_LOCAL_DEVICE_INFO, ServerGetLocalDeviceInfo },
    { SERVER_GET_NODE_KEY_INFO, ServerGetNodeKeyInfo },
    { SERVER_START_TIME_SYNC, ServerStartTimeSync },
    { SERVER_STOP_TIME_SYNC, ServerStopTimeSync },
    { SERVER_PUBLISH_LNN, ServerPublishLNN },
    { SERVER_STOP_PUBLISH_LNN, ServerStopPublishLNN },
    { SERVER_REFRESH_LNN, ServerRefreshLNN },
    { SERVER_STOP_REFRESH_LNN, ServerStopRefreshLNN },
    { SERVER_ACTIVE_META_NODE, ServerActiveMetaNode},
    { SERVER_DEACTIVE_META_NODE, ServerDeactiveMetaNode },
    { SERVER_GET_ALL_META_NODE_INFO, ServerGetAllMetaNodeInfo },
    { SERVER_SHIFT_LNN_GEAR, ServerShiftLnnGear },
    { SERVER_CREATE_SESSION_SERVER, ServerCreateSessionServer },
    { SERVER_REMOVE_SESSION_SERVER, ServerRemoveSessionServer },
    { SERVER_OPEN_SESSION, ServerOpenSession },
    { SERVER_OPEN_AUTH_SESSION, ServerOpenAuthSession},
    { SERVER_NOTIFY_AUTH_SUCCESS, ServerNotifyAuthSuccess},
    { SERVER_CLOSE_CHANNEL, ServerCloseChannel },
    { SERVER_SESSION_SENDMSG, ServerSendSessionMsg },
    { SERVER_SET_NODE_DATA_CHANGE_FLAG, ServerSetNodeDataChangeFlag},
};

static int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "RECEIVE FUNCID:%d", funcId);
    if (GetServerIsInit() == false) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server not init");
        WriteInt32(reply, SOFTBUS_SERVER_NOT_INIT);
        return SOFTBUS_ERR;
    }
    int tblSize = sizeof(g_serverInvokeCmdTbl) / sizeof(ServerInvokeCmd);
    for (int i = 0; i < tblSize; i++) {
        if (funcId == g_serverInvokeCmdTbl[i].id) {
            return g_serverInvokeCmdTbl[i].func(req, reply);
        }
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not support func[%d]", funcId);
    return SOFTBUS_ERR;
}

static SoftbusSamgrService g_samgrService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
};

void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

int ServerStubInit(void)
{
    HOS_SystemInit();

    if (LnnIpcInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Center Ipc init failed.");
        return SOFTBUS_ERR;
    }

    if (SERVER_InitClient() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client manager init failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void Init(void)
{
    sleep(WAIT_FOR_SERVER);
    SAMGR_GetInstance()->RegisterService((Service *)&g_samgrService);
    SAMGR_GetInstance()->RegisterDefaultFeatureApi(SOFTBUS_SERVICE, GET_IUNKNOWN(g_samgrService));
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "Init success %s", SOFTBUS_SERVICE);
}
SYSEX_SERVICE_INIT(Init);