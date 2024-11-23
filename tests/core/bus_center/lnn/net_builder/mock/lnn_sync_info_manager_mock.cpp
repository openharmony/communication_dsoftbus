/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_sync_info_manager_mock.h"

namespace OHOS {
void *g_lnnSyncInfoManagerInterface;
LnnSyncInfoManagerInterfaceMock::LnnSyncInfoManagerInterfaceMock()
{
    g_lnnSyncInfoManagerInterface = reinterpret_cast<void *>(this);
}

LnnSyncInfoManagerInterfaceMock::~LnnSyncInfoManagerInterfaceMock()
{
    g_lnnSyncInfoManagerInterface = nullptr;
}

static LnnSyncInfoManagerInterface *LnnSyncInfoManagerInstance()
{
    return reinterpret_cast<LnnSyncInfoManagerInterfaceMock *>(g_lnnSyncInfoManagerInterface);
}

extern "C" {
JsonObj *JSON_CreateObject()
{
    return LnnSyncInfoManagerInstance()->JSON_CreateObject();
}

bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value)
{
    return LnnSyncInfoManagerInstance()->JSON_AddInt64ToObject(obj, key, value);
}

bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value)
{
    return LnnSyncInfoManagerInstance()->JSON_AddInt32ToObject(obj, key, value);
}

void JSON_Delete(JsonObj *obj)
{
    return LnnSyncInfoManagerInstance()->JSON_Delete(obj);
}

char *JSON_PrintUnformatted(const JsonObj *obj)
{
    return LnnSyncInfoManagerInstance()->JSON_PrintUnformatted(obj);
}

JsonObj *JSON_Parse(const char *str, uint32_t len)
{
    return LnnSyncInfoManagerInstance()->JSON_Parse(str, len);
}

bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value)
{
    return LnnSyncInfoManagerInstance()->JSON_GetInt64FromOject(obj, key, value);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return LnnSyncInfoManagerInstance()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value)
{
    return LnnSyncInfoManagerInstance()->JSON_GetInt32FromOject(obj, key, value);
}

bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size)
{
    return LnnSyncInfoManagerInstance()->JSON_GetStringFromOject(obj, key, value, size);
}

AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    return LnnSyncInfoManagerInstance()->GetAuthManagerByAuthId(authId);
}

void DelAuthManager(AuthManager *auth, int32_t type)
{
    return LnnSyncInfoManagerInstance()->DelAuthManager(auth, type);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return LnnSyncInfoManagerInstance()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return LnnSyncInfoManagerInstance()->AuthPostTransData(authHandle, dataInfo);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return LnnSyncInfoManagerInstance()->LnnGetRemoteNumU64Info(networkId, key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info)
{
    return LnnSyncInfoManagerInstance()->LnnGetRemoteNumU32Info(netWorkId, key, info);
}

int32_t GetHmlOrP2pAuthHandle(AuthHandle **authHandle, int32_t *num)
{
    return LnnSyncInfoManagerInstance()->GetHmlOrP2pAuthHandle(authHandle, num);
}

bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value)
{
    return LnnSyncInfoManagerInstance()->JSON_AddStringToObject(obj, key, value);
}
}
} // namespace OHOS