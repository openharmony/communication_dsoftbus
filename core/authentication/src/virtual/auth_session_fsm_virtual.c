/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "auth_session_fsm.h"

void AuthSessionSetReSyncDeviceName(void) { }

int32_t AuthNotifyRequestVerify(int64_t authSeq)
{
    (void)authSeq;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthSessionFsmExit(void) { }

int32_t AuthSessionGetAuthVersion(int64_t authSeq, int32_t *version)
{
    (void)authSeq;
    (void)version;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool AuthSessionGetIsSameAccount(int64_t authSeq)
{
    (void)authSeq;
    return false;
}

int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size)
{
    (void)authSeq;
    (void)udid;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionGetUserId(int64_t authSeq)
{
    (void)authSeq;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason)
{
    (void)authSeq;
    (void)reason;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionHandleAuthFinish(int64_t authSeq, AclWriteState aclState)
{
    (void)authSeq;
    (void)aclState;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId, bool isNeedDisconnect)
{
    (void)connId;
    (void)isNeedDisconnect;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionHandleDeviceNotTrusted(const char *udid)
{
    (void)udid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessCancelAuthByConnId(uint64_t connId, bool isConnectServer, const uint8_t *data, uint32_t len)
{
    (void)connId;
    (void)isConnectServer;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    (void)connId;
    (void)isServer;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    (void)authSeq;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    (void)connId;
    (void)isServer;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len)
{
    (void)authSeq;
    (void)key;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSessionStartAuth(const AuthParam *authParam, const AuthConnInfo *connInfo, const DeviceKeyId *deviceKeyId)
{
    (void)authParam;
    (void)connInfo;
    (void)deviceKeyId;
    return SOFTBUS_NOT_IMPLEMENT;
}

