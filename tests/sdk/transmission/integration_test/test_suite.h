/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ECHO_TEST_SUITE_H
#define ECHO_TEST_SUITE_H

#include <cstdio>

#include "session.h"

#define LOG(FMT, args...) printf(FMT "\n", ##args)

#define ECHO_SERVICE_PKGNAME               "dms"
#define ECHO_SERVICE_SESSION_NAME          "ohos.distributedschedule.dms.echo"
#define ECHO_SERVICE_CONSUMER_SESSION_NAME "ohos.distributedschedule.dms.echo"

inline void EsOnDataReceived(int32_t sessionId, const void *data, unsigned int dataLen) { }

inline void EsOnStreamReceived(
    int32_t sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    LOG("%s:enter", __func__);
}
inline void EsOnQosEvent(int32_t sessionId, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    LOG("%s:enter", __func__);
}

#endif