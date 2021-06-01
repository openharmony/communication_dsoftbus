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

#include <stdlib.h>

#include "iproxy_server.h"
#include "samgr_lite.h"
#include "securec.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_server_weak.h"

static IpcContext *g_svcIpcCtx = NULL;

static void ConvertSvcId(const struct CommonScvId *svcId, SvcIdentity *svc)
{
    if ((svcId == NULL) || (svc == NULL)) {
        LOG_ERR("scvId is NULL, convert failed.");
        return;
    }
    svc->handle = svcId->handle;
    svc->token = svcId->token;
    svc->cookie = svcId->cookie;
#ifdef __LINUX__
    svc->ipcContext = svcId->ipcCtx;
#endif
}

static struct ClientProvideInterface g_clientProvideInterface = {
    .onChannelOpened = ClientIpcOnChannelOpened,
    .onChannelClosed = ClientIpcOnChannelClosed,
    .onChannelMsgReceived = ClientIpcOnChannelMsgReiceived,
    .onJoinLNNResult = ClientIpcOnJoinLNNResult,
    .onLeaveLNNResult = ClientIpcOnLeaveLNNResult,
    .onNodeOnlineStateChanged = ClientIpcOnNodeOnlineStateChanged,
    .onNodeBasicInfoChanged = ClientIpcOnNodeBasicInfoChanged,
};

struct ClientProvideInterface *GetClientProvideInterface(void)
{
    return &g_clientProvideInterface;
}

int ClientProvideInterfaceInit(void)
{
    g_svcIpcCtx = NULL;
    return SOFTBUS_OK;
}

void *SoftBusGetIpcContext(void)
{
    return g_svcIpcCtx;
}
