/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_command_manager.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "channel/wifi_direct_negotiate_channel.h"

#define LOG_LABEL "[WD] CM: "

static void EnqueueCommand(struct WifiDirectCommand *command)
{
    struct WifiDirectCommandManager *self = GetWifiDirectCommandManager();
    SoftBusMutexLock(&self->mutex);
    ListTailInsert(&GetWifiDirectCommandManager()->commands, &command->node);
    SoftBusMutexUnlock(&self->mutex);
}

static struct WifiDirectCommand* DequeueCommand(void)
{
    struct WifiDirectCommandManager *self = GetWifiDirectCommandManager();
    SoftBusMutexLock(&self->mutex);
    if (IsListEmpty(&self->commands)) {
        SoftBusMutexUnlock(&self->mutex);
        return NULL;
    }

    struct WifiDirectCommand *command = LIST_ENTRY(self->commands.next, struct WifiDirectCommand, node);
    ListDelInit(&command->node);
    SoftBusMutexUnlock(&self->mutex);
    return command;
}

static struct WifiDirectCommandManager g_manager = {
    .enqueueCommand = EnqueueCommand,
    .dequeueCommand = DequeueCommand,
};

struct WifiDirectCommandManager* GetWifiDirectCommandManager(void)
{
    return &g_manager;
}

int32_t WifiDirectCommandManagerInit(void)
{
    ListInit(&g_manager.commands);
    SoftBusMutexAttr attr;
    int32_t ret = SoftBusMutexAttrInit(&attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "init mutex attr failed");
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&g_manager.mutex, &attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "init mutex ailed");
    return SOFTBUS_OK;
}