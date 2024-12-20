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

#include <ohos_init.h>

#include "bus_center_server_stub.h"
#include "comm_log.h"
#include "ipc_skeleton.h"
#include "iproxy_server.h"
#include "lnn_bus_center_ipc.h"
#include "samgr_lite.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_info_manager.h"
#include "softbus_disc_server.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
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
        COMM_LOGE(COMM_SVC, "invalid param");
        return FALSE;
    }

    SoftbusSamgrService *samgrService = (SoftbusSamgrService *)service;
    samgrService->identity = identity;
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    if (service == NULL || msg == NULL) {
        COMM_LOGE(COMM_SVC, "invalid param");
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

static void ComponentDeathCallback(const char *pkgName, int32_t pid)
{
    DiscServerDeathCallback(pkgName);
    TransServerDeathCallback(pkgName, pid);
    BusCenterServerDeathCallback(pkgName);
}

typedef struct DeathCbArg {
    char *pkgName;
    int32_t pid;
} DeathCbArg;

static void ClientDeathCb(void *arg)
{
    if (arg == NULL) {
        COMM_LOGE(COMM_SVC, "arg is NULL.");
        return;
    }
    DeathCbArg* argStrcut = (DeathCbArg*)arg;
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName((const char *)argStrcut->pkgName, &svcId) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "not found client by package name.");
        SoftBusFree(argStrcut->pkgName);
        SoftBusFree(argStrcut);
        return;
    }
    SERVER_UnregisterService((const char *)argStrcut->pkgName);
    ComponentDeathCallback((const char *)argStrcut->pkgName, argStrcut->pid);
    SoftBusFree(argStrcut->pkgName);
    SoftBusFree(argStrcut);
    SvcIdentity sid = {0};
    sid.handle = (int32_t)svcId.handle;
    sid.token = (uintptr_t)svcId.token;
    sid.cookie = (uintptr_t)svcId.cookie;
    ReleaseSvc(sid);
}

static int32_t ServerRegisterService(IpcIo *req, IpcIo *reply)
{
    COMM_LOGI(COMM_SVC, "register service ipc server pop.");
    size_t len = 0;
    int ret = SOFTBUS_ERR;
    struct CommonScvId svcId = {0};

    const char *name = (const char*)ReadString(req, &len);
    SvcIdentity svc;
    if ((name == NULL) || (len == 0)) {
        COMM_LOGE(COMM_SVC, "ServerRegisterService read name or len fail");
        goto EXIT;
    }
    int32_t callingUid = GetCallingUid();
    if (!CheckBusCenterPermission(callingUid, name)) {
        COMM_LOGE(COMM_SVC, "ServerRegisterService no permission.");
        goto EXIT;
    }
    bool value = ReadRemoteObject(req, &svc);

    svcId.handle = svc.handle;
    svcId.token = svc.token;
    svcId.cookie = svc.cookie;

    char *pkgName = (char *)SoftBusMalloc(len + 1);
    if (pkgName == NULL) {
        COMM_LOGE(COMM_SVC, "softbus pkgName malloc failed!");
        goto EXIT;
    }
    if (strcpy_s(pkgName, len + 1, name) != EOK) {
        COMM_LOGE(COMM_SVC, "softbus strcpy_s failed!");
        SoftBusFree(pkgName);
        goto EXIT;
    }

    DeathCbArg *argStrcut = (DeathCbArg*)SoftBusMalloc(sizeof(DeathCbArg));
    if (argStrcut == NULL) {
        COMM_LOGE(COMM_SVC, "softbus argStrcut malloc failed!");
        SoftBusFree(pkgName);
        goto EXIT;
    }
    argStrcut->pkgName = pkgName;
    argStrcut->pid = GetCallingPid();

    uint32_t cbId = 0;
    AddDeathRecipient(svc, ClientDeathCb, argStrcut, &cbId);
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

const ServerInvokeCmd g_serverInvokeCmdTbl[] = {
    { MANAGE_REGISTER_SERVICE, ServerRegisterService },
    { SERVER_JOIN_LNN, ServerJoinLNN },
    { SERVER_JOIN_METANODE, ServerJoinMetaNode },
    { SERVER_LEAVE_LNN, ServerLeaveLNN },
    { SERVER_LEAVE_METANODE, ServerLeaveMetaNode },
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
    { SERVER_SET_NODE_DATA_CHANGE_FLAG, ServerSetNodeDataChangeFlag },
    { SERVER_REG_DATA_LEVEL_CHANGE_CB, ServerRegDataLevelChangeCb },
    { SERVER_UNREG_DATA_LEVEL_CHANGE_CB, ServerUnregDataLevelChangeCb },
    { SERVER_SET_DATA_LEVEL, ServerSetDataLevel },
    { SERVER_RELEASE_RESOURCES, ServerReleaseResources },
    { SERVER_PRIVILEGE_CLOSE_CHANNEL, ServerPrivilegeCloseChannel },
};

static int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    COMM_LOGI(COMM_SVC, "RECEIVE FUNCID. funcId=%{public}d", funcId);
    if (GetServerIsInit() == false) {
        COMM_LOGE(COMM_SVC, "server not init");
        WriteInt32(reply, SOFTBUS_SERVER_NOT_INIT);
        return SOFTBUS_ERR;
    }
    int tblSize = sizeof(g_serverInvokeCmdTbl) / sizeof(ServerInvokeCmd);
    for (int i = 0; i < tblSize; i++) {
        if (funcId == g_serverInvokeCmdTbl[i].id) {
            return g_serverInvokeCmdTbl[i].func(req, reply);
        }
    }
    COMM_LOGE(COMM_SVC, "not support func. funcId=%{public}d", funcId);
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
        COMM_LOGE(COMM_SVC, "Center Ipc init failed.");
        return SOFTBUS_ERR;
    }

    if (SERVER_InitClient() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "client manager init failed.");
        LnnIpcDeinit();
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void Init(void)
{
    sleep(WAIT_FOR_SERVER);
    SAMGR_GetInstance()->RegisterService((Service *)&g_samgrService);
    SAMGR_GetInstance()->RegisterDefaultFeatureApi(SOFTBUS_SERVICE, GET_IUNKNOWN(g_samgrService));
    COMM_LOGI(COMM_SVC, "Init success SOFTBUS_SERVICE=%{public}s", SOFTBUS_SERVICE);
}
SYSEX_SERVICE_INIT(Init);