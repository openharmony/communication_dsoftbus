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

#ifndef VTP_STREAM_OPT_H
#define VTP_STREAM_OPT_H

#ifdef __cplusplus
#include <cstdbool>
#else
#include <stdbool.h>
#endif
#include "fillpinc.h"
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif
int32_t VtpSetSocketMultiLayer(int fd, OnFrameEvt *cb, const void *para);

bool IsVtpFrameSentEvt(const FtEventCbkInfo *info);

int HandleVtpFrameEvt(int fd, OnFrameEvt cb, const FtEventCbkInfo *info);
#ifdef __cplusplus
}
#endif
#endif // VTP_STREAM_OPT_H