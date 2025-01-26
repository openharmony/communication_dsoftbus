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

#include "lnn_cipherkey_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitCipherKeyManager(void)
{
    LNN_LOGI(LNN_INIT, "init virtual lnn cipherkey manager");
    return SOFTBUS_OK;
}

void LnnDeinitCipherKeyManager(void)
{
    LNN_LOGI(LNN_INIT, "Deinit virtual lnn cipherkey manager");
}

bool GetCipherKeyByNetworkId(const char *networkId, int32_t seq, uint32_t tableIndex, AesCtrCipherKey *cipherkey,
    int32_t keyLen)
{
    (void)networkId;
    (void)seq;
    (void)tableIndex;
    (void)cipherkey;
    (void)keyLen;
    return true;
}

bool GetLocalCipherKey(int32_t seq, uint32_t *tableIndex, AesCtrCipherKey *cipherkey, int32_t keyLen)
{
    (void)seq;
    (void)tableIndex;
    (void)cipherkey;
    (void)keyLen;
    return true;
}

bool PackCipherKeySyncMsg(void *json)
{
    (void)json;
    return true;
}

void ProcessCipherKeySyncInfo(const void *json, const char *networkId)
{
    (void)json;
    (void)networkId;
    return;
}

void LoadBleBroadcastKey(void)
{
    return;
}

bool IsCipherManagerFindKey(const char *udid)
{
    (void)udid;
    return false;
}

int32_t LnnLoadLocalBroadcastCipherKey(void)
{
    return SOFTBUS_OK;
}

int32_t LnnGetLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey)
{
    (void)broadcastKey;
    return SOFTBUS_OK;
}

int32_t LnnSaveLocalBroadcastCipherKey(const BroadcastCipherKey *broadcastKey)
{
    (void)broadcastKey;
    return SOFTBUS_OK;
}

int32_t LnnUpdateLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey)
{
    (void)broadcastKey;
    return SOFTBUS_OK;
}

int32_t LnnGetLocalBroadcastCipherInfo(CloudSyncInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

int32_t LnnSetRemoteBroadcastCipherInfo(const char *value, const char *udid)
{
    (void)value;
    (void)udid;
    return SOFTBUS_OK;
}

int32_t LnnSyncBroadcastLinkKey(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_OK;
}

bool IsNeedSyncBroadcastLinkKey(const char *networkId)
{
    (void)networkId;
    return true;
}

int32_t LnnInitBroadcastLinkKey(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitBroadcastLinkKey(void)
{
    return;
}
