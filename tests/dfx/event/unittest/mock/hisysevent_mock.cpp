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

#include "hisysevent_mock.h"

int HiSysEventMock::MockHiSysEvent_Write(const char *func, int64_t line, const char *domain, const char *name,
    HiSysEventEventType type, const HiSysEventParam params[], size_t size)
{
    return 0;
}

HiSysEventMock::HiSysEventMock()
{
    mock.store(this);
}
HiSysEventMock::~HiSysEventMock()
{
    mock.store(nullptr);
}

int HiSysEvent_Write(const char *func, int64_t line, const char *domain, const char *name, HiSysEventEventType type,
    const HiSysEventParam params[], size_t size)
{
    return HiSysEventMock::GetMock()->HiSysEvent_Write(func, line, domain, name, type, params, size);
}
