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

#include "if_softbus_server.h"

#include "comm_log.h"
#include "softbus_error_code.h"

namespace OHOS {
int32_t ISoftBusServer::GrantPermission(int uid, int pid, const char *sessionName)
{
    (void)uid;
    (void)pid;
    (void)sessionName;
    COMM_LOGI(COMM_SVC, "GrantPermission ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::RemovePermission(const char *sessionName)
{
    (void)sessionName;
    COMM_LOGI(COMM_SVC, "RemovePermission ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::PublishLNN(const char *pkgName, const PublishInfo *info)
{
    (void)pkgName;
    (void)info;
    COMM_LOGI(COMM_SVC, "PublishLNN ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    (void)pkgName;
    (void)publishId;
    COMM_LOGI(COMM_SVC, "StopPublishLNN ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::RefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    (void)pkgName;
    (void)info;
    COMM_LOGI(COMM_SVC, "RefreshLNN ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    (void)pkgName;
    (void)refreshId;
    COMM_LOGI(COMM_SVC, "StopRefreshLNN ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)info;
    (void)metaNodeId;
    COMM_LOGE(COMM_SVC, "ActiveMetaNode ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::DeactiveMetaNode(const char *metaNodeId)
{
    (void)metaNodeId;
    COMM_LOGE(COMM_SVC, "DeactiveMetaNode ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::GetAllMetaNodeInfo(MetaNodeInfo *info, int32_t *infoNum)
{
    (void)info;
    (void)infoNum;
    COMM_LOGE(COMM_SVC, "GetAllMetaNodeInfo ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    (void)pkgName;
    (void)callerId;
    (void)targetNetworkId;
    (void)mode;
    COMM_LOGE(COMM_SVC, "ShiftLNNGear ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::SyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)msg;
    (void)msgLen;
    COMM_LOGE(COMM_SVC, "ipc default impl");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ISoftBusServer::GetSoftbusSpecObject(sptr<IRemoteObject> &object)
{
    COMM_LOGE(COMM_SVC, "GetSoftbusSpecObject ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::GetBusCenterExObj(sptr<IRemoteObject> &object)
{
    COMM_LOGE(COMM_SVC, "GetBusCenterExObj ipc default impl");
    return SOFTBUS_IPC_ERR;
}

int32_t ISoftBusServer::SetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    (void)pkgName;
    (void)nameData;
    (void)len;
    COMM_LOGE(COMM_SVC, "ipc default impl");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
} // namespace OHOS