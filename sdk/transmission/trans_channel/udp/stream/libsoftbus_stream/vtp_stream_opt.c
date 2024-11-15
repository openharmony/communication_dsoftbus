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

#include "vtp_stream_opt.h"

#include "softbus_error_code.h"

int32_t VtpSetSocketMultiLayer(int fd, OnFrameEvt *cb, const void *para)
{
    (void)fd;
    (void)cb;
    (void)para;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

bool IsVtpFrameSentEvt(const FtEventCbkInfo *info)
{
    (void)info;
    return false;
}

int HandleVtpFrameEvt(int fd, OnFrameEvt cb, const FtEventCbkInfo *info)
{
    (void)fd;
    (void)cb;
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}