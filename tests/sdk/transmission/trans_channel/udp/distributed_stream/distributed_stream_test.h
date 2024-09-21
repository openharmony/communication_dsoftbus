/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef DISTRIBUTED_STREAM_TEST_H
#define DISTRIBUTED_STREAM_TEST_H

#include <string>
#include <unordered_map>
#include <ctime>
#include <iostream>

#define BYTES_SIZE (16)
#define STREAM_SIZE (150 * 1024)
#define I_FRAME_SIZE (150 * 1024)
#define P_FRAME_SIZE (30 * 1024)
#define MS_PER_SECOND (1000)
#define US_PER_MS (1000)
#define NS_PER_MS (1000 * 1000)

const std::string TEST_PKG_NAME = "dms";
const std::string STREAM_SESSION_NAME = "ohos.distributedschedule.dms.JtSendStream_10";
const std::string CONTRL_SESSION_NAME = "ohos.distributedschedule.dms.TestContrl";

namespace OHOS {
inline time_t GetCurrent(void)
{
    struct timespec time;
    int32_t ret = clock_gettime(CLOCK_MONOTONIC, &time);
    if (ret != 0) {
        std::cout <<"get time failed!" << std::endl;
    }
    return time.tv_sec * MS_PER_SECOND + time.tv_nsec / NS_PER_MS;
}
}

#endif