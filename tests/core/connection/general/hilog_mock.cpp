/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include "hilog/log_c.h"

int32_t HiLogPrintDictNew(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...)
{
    char *args;
    va_list va_args;
    va_start(va_args, fmt);
    args = va_arg(va_args, char *);
    va_end(va_args);
    return HiLogPrint(type, level, domain, tag, fmt, args);
}