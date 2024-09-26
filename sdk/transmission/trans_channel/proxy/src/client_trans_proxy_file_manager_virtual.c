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

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.h"
#include "softbus_error_code.h"

int32_t ClinetTransProxyFileManagerInit(void)
{
    return SOFTBUS_OK;
}

void ClinetTransProxyFileManagerDeinit(void)
{
    return;
}

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    (void)sessionId;
    (void)channelId;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    (void)channelId;
    (void)sFileList;
    (void)dFileList;
    (void)fileCnt;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ClientDeleteRecvFileList(int32_t sessionId)
{
    (void)sessionId;
    return;
}