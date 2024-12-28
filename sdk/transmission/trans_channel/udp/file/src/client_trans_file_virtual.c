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

#include "client_trans_file_listener.h"
#include "client_trans_udp_manager.h"
#include "client_trans_file.h"
#include "softbus_error_code.h"

int TransFileInit(void)
{
    return SOFTBUS_OK;
}

void TransFileDeinit(void) {}

int32_t TransSetFileReceiveListener(const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir)
{
    (void)sessionName;
    (void)recvListener;
    (void)rootDir;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSetFileSendListener(const char *sessionName, const IFileSendListener *sendListener)
{
    (void)sessionName;
    (void)sendListener;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener)
{
    (void)sessionName;
    (void)fileListener;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransDeleteFileListener(const char *sessionName)
{
    (void)sessionName;
}

void RegisterFileCb(const UdpChannelMgrCb *fileCb)
{
    (void)fileCb;
}

int32_t TransOnFileChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *filePort)
{
    (void)sessionName;
    (void)channel;
    (void)filePort;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransCloseFileChannel(int32_t dfileId)
{
    (void)dfileId;
}

int32_t TransSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    (void)channelId;
    (void)sFileList;
    (void)dFileList;
    (void)fileCnt;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSetSocketFileListener(const char *sessionName, SocketFileCallbackFunc fileCallback, bool isReceiver)
{
    (void)sessionName;
    (void)fileCallback;
    (void)isReceiver;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}