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

#ifndef HISYSEVENT_MOCK_H
#define HISYSEVENT_MOCK_H

#include <atomic>
#include <cstdint>
#include <gmock/gmock.h>

#include "hisysevent_c.h"

class HiSysEventInterface {
public:
    virtual int MockHiSysEvent_Write(const char *func, int64_t line, const char *domain, const char *name,
        HiSysEventEventType type, const HiSysEventParam params[], size_t size) = 0;
};

class HiSysEventMock : public HiSysEventInterface {
public:
    static HiSysEventMock *GetMock()
    {
        return mock.load();
    }

    HiSysEventMock();
    ~HiSysEventMock();

    MOCK_METHOD7(HiSysEvent_Write,
        int(const char *func, int64_t line, const char *domain, const char *name, HiSysEventEventType type,
            const HiSysEventParam params[], size_t size));

    int MockHiSysEvent_Write(const char *func, int64_t line, const char *domain, const char *name,
        HiSysEventEventType type, const HiSysEventParam params[], size_t size) override;

private:
    static inline std::atomic<HiSysEventMock *> mock = nullptr;
};

#endif // HISYSEVENT_MOCK_H
