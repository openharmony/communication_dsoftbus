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

#ifndef COMMUNICATION_DSOFTBUS_HILOG_MOCK_H
#define COMMUNICATION_DSOFTBUS_HILOG_MOCK_H

#include <atomic>
#include <cstdint>
#include <gmock/gmock.h>

#include "hilog/log_c.h"

class HilogInterface {
public:
    virtual int HiLogPrint(
        LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...) = 0;
};

class HilogMock : public HilogInterface {
public:
    static HilogMock *GetMock()
    {
        return mock.load();
    }

    HilogMock();
    ~HilogMock();

    int HiLogPrint(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...) override;

    MOCK_METHOD6(
        HiLogPrint, int(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, char *));

private:
    static inline std::atomic<HilogMock *> mock = nullptr;
};

#endif // COMMUNICATION_DSOFTBUS_HILOG_MOCK_H
