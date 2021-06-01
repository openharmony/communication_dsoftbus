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

#include "softbus_server_frame.h"

#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

int __attribute__ ((weak)) BusCenterServerInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) BusCenterServerDeinit(void)
{
}

int __attribute__ ((weak)) TransServerInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) TransServerDeinit(void)
{
}

int __attribute__ ((weak)) AuthInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) AuthDeinit(void)
{
}

int __attribute__ ((weak)) ConnServerInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) ConnServerDeinit(void)
{
}

int __attribute__ ((weak)) DiscServerInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) DiscServerDeinit(void)
{
}

static void ServerModuleDeinit(void)
{
    DiscServerDeinit();
    ConnServerDeinit();
    TransServerDeinit();
    BusCenterServerDeinit();
    AuthDeinit();
    SoftBusTimerDeInit();
    LooperDeinit();
}

void InitSoftBusServer(void)
{
    if (SoftBusTimerInit() != SOFTBUS_OK) {
        return;
    }

    if (LooperInit() != SOFTBUS_OK) {
        return;
    }

    if (ConnServerInit() != SOFTBUS_OK) {
        LOG_ERR("softbus conn server init failed.");
        goto ERR_EXIT;
    }

    if (TransServerInit() != SOFTBUS_OK) {
        LOG_ERR("softbus trans server init failed.");
        goto ERR_EXIT;
    }

    if (AuthInit() != SOFTBUS_OK) {
        LOG_ERR("softbus auth init failed.");
        goto ERR_EXIT;
    }

    if (BusCenterServerInit() != SOFTBUS_OK) {
        LOG_ERR("softbus buscenter server init failed.");
        goto ERR_EXIT;
    }

    if (DiscServerInit() != SOFTBUS_OK) {
        LOG_ERR("softbus disc server init failed.");
        goto ERR_EXIT;
    }

    return;

ERR_EXIT:
    ServerModuleDeinit();
    LOG_ERR("softbus server framework init failed.");
    return;
}