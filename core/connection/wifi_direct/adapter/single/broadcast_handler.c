/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "broadcast_handler.h"
#include "conn_log.h"
#include "link_manager_broadcast_handler.h"
#include "p2p_entity_broadcast_handler.h"
#include "resource_manager_broadcast_handler.h"
#include "softbus_error_code.h"

int32_t BroadcastHandlerInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    P2pEntityBroadcastHandlerInit();
    ResourceManagerBroadcastHandlerInit();
    LinkManagerBroadcastHandlerInit();
    return SOFTBUS_OK;
}