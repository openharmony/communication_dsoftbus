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

#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
int32_t ISoftBusServer::GrantPermission(int uid, int pid, const char *sessionName)
{
    (void)uid;
    (void)pid;
    (void)sessionName;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GrantPermission ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::RemovePermission(const char *sessionName)
{
    (void)sessionName;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "RemovePermission ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::PublishLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "PublishLNN ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    (void)pkgName;
    (void)publishId;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "StopPublishLNN ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::RefreshLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "RefreshLNN ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    (void)pkgName;
    (void)refreshId;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "StopRefreshLNN ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)info;
    (void)metaNodeId;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ActiveMetaNode ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::DeactiveMetaNode(const char *metaNodeId)
{
    (void)metaNodeId;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "DeactiveMetaNode ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::GetAllMetaNodeInfo(MetaNodeInfo *info, int32_t *infoNum)
{
    (void)info;
    (void)infoNum;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo ipc default impl");
    return SOFTBUS_ERR;
}

int32_t ISoftBusServer::ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    (void)pkgName;
    (void)callerId;
    (void)targetNetworkId;
    (void)mode;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ShiftLNNGear ipc default impl");
    return SOFTBUS_ERR;
}
} // namespace OHOS