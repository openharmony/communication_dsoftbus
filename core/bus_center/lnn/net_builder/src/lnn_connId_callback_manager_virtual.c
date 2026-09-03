/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_connId_callback_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitConnIdCallbackManager(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitConnIdCallbackManager(void)
{
}

int32_t AddConnIdCallbackInfoItem(const ConnectionAddr *sessionAddr, const LnnServerJoinExtCallBack *callBack,
    uint32_t connId, char *peerUdid)
{
    (void)sessionAddr;
    (void)callBack;
    (void)connId;
    (void)peerUdid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t DelConnIdCallbackInfoItem(uint32_t connId)
{
    (void)connId;
    return SOFTBUS_NOT_IMPLEMENT;
}

void InvokeCallbackForJoinExt(const char *udid, int32_t result)
{
    (void)udid;
    (void)result;
}

int32_t GetConnIdCbInfoByAddr(const ConnectionAddr *addr, ConnIdCbInfo *dupItem)
{
    (void)addr;
    (void)dupItem;
    return SOFTBUS_NOT_IMPLEMENT;
}
