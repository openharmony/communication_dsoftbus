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

#include "lnn_p2p_info.h"

#include "softbus_error_code.h"

void LnnLoadPtkInfo(void)
{
    return;
}

int32_t UpdateLocalPtkIfValid(char *udid)
{
    (void)udid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGenerateLocalPtk(char *udid, char *uuid)
{
    (void)udid;
    (void)uuid;
    return SOFTBUS_OK;
}

int32_t LnnSetLocalPtkConn(char *udid)
{
    (void)udid;
    return SOFTBUS_OK;
}

int32_t LnnGetLocalPtkByUdid(const char *udid, char *localPtk, uint32_t len)
{
    (void)udid;
    (void)localPtk;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    (void)uuid;
    (void)localPtk;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    (void)uuid;
    (void)localPtk;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len)
{
    (void)uuid;
    (void)remotePtk;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnSyncPtk(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t LnnGenerateMetaPtk(uint32_t connId)
{
    (void)connId;
    return SOFTBUS_OK;
}

int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len)
{
    (void)connId;
    (void)metaPtk;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnDeleteMetaPtk(uint32_t connectionId)
{
    (void)connectionId;
    return SOFTBUS_OK;
}

int32_t UpdatePtkByAuth(char *networkId, AuthHandle authHandle)
{
    (void)networkId;
    (void)authHandle;
    return SOFTBUS_OK;
}

int32_t LnnInitPtk(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitPtk(void)
{
    return;
}
