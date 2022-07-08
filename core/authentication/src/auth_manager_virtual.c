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

#include "auth_manager.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t AuthInit(void)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "init virtual auth manager");
    return SOFTBUS_OK;
}

void AuthDeinit(void)
{
}

uint32_t AuthGetEncryptHeadLen(void)
{
    return 0;
}

int32_t AuthEncrypt(const ConnectOption *option, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outbuf)
{
    (void)option;
    (void)side;
    (void)data;
    (void)len;
    (void)outbuf;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDecrypt(const ConnectOption *option, AuthSideFlag side, uint8_t *data, uint32_t len, OutBuf *outbuf)
{
    (void)option;
    (void)side;
    (void)data;
    (void)len;
    (void)outbuf;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthPostData(const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    (void)head;
    (void)data;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen)
{
    (void)option;
    (void)buf;
    (void)bufLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetServerSideByOption(const ConnectOption *option, bool *isServerSide)
{
    (void)option;
    (void)isServerSide;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthTransDataRegCallback(AuthTransModule moduleId, AuthTransCallback *cb)
{
    (void)moduleId;
    (void)cb;
    return SOFTBUS_OK;
}

void AuthTransDataUnRegCallback(AuthTransModule moduleId)
{
    (void)moduleId;
}

int64_t AuthOpenChannel(const ConnectOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthCloseChannel(int64_t authId)
{
    (void)authId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    (void)info;
    (void)requestId;
    (void)callback;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthCloseConn(int64_t authId)
{
    (void)authId;
}

uint32_t AuthGenRequestId(void)
{
    return 0;
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *info)
{
    (void)authId;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetDeviceUuid(int64_t authId, char *buf, uint32_t size)
{
    (void)authId;
    (void)buf;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    (void)uuid;
    (void)connInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSetP2pMac(int64_t authId, const char *mac)
{
    (void)authId;
    (void)mac;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetConnectOptionByP2pMac(const char *mac, AuthLinkType type, ConnectOption *option)
{
    (void)mac;
    (void)type;
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthEncryptBySeq(int32_t seq, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf)
{
    (void)seq;
    (void)side;
    (void)data;
    (void)len;
    (void)outBuf;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetActiveConnectOption(const char *uuid, ConnectType type, ConnectOption *option)
{
    (void)uuid;
    (void)type;
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}
