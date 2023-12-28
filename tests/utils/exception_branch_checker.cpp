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

#include "exception_branch_checker.h"
#include "softbus_log.h"
#include "securec.h"

#if defined(__LITEOS_M__)
#define SOFTBUS_PRINTF
#include "log.h"
#else
#include "hilog/log.h"
#endif

static void SoftBusLogExtraInfoFormat(char *line, const char *fileName, int lineNum, const char *funName)
{
    (void)sprintf_s(line, LOG_LINE_MAX_LENGTH + 1, "[%s:%d] %s# ", fileName, lineNum, funName);
}

static void SoftBusLogPrint(const char *buf, SoftBusLogLevel level, unsigned int domain, const char *tag)
{
#ifdef SOFTBUS_PRINTF
    (void)level;
    (void)domain;
    (void)tag;
    printf("%s\n", buf);
#else
    (void)HiLogPrint(LOG_CORE, (LogLevel)level, domain, tag, "%{public}s", buf);
#endif
}

void SoftBusLogInnerImpl(SoftBusLogLevel level, SoftBusLogLabel label, const char *fileName, int lineNum,
    const char *funName, const char *fmt, ...)
{
    uint32_t pos;
    va_list args = { 0 };
    char buffer[LOG_LINE_MAX_LENGTH + 1] = { 0 };

    SoftBusLogExtraInfoFormat(buffer, fileName, lineNum, funName);
    pos = strlen(buffer);
    va_start(args, fmt);
    int32_t ret = vsprintf_s(&buffer[pos], sizeof(buffer) - pos, fmt, args);
    if (ret < 0) {
        return;
    }
    va_end(args);
    SoftBusLogPrint(buffer, level, label.domain, label.tag);

    auto *checker = ExceptionBranchChecker::GetCurrentInstance();
    if (checker != nullptr) {
        checker->WriteLog(buffer);
    }
}

ExceptionBranchChecker* ExceptionBranchChecker::GetCurrentInstance()
{
    return instance_.load();
}

ExceptionBranchChecker::ExceptionBranchChecker(const std::string &branch)
    : isMatched_(false), matchBranch_(branch)
{
    instance_.store(this);
}

ExceptionBranchChecker::~ExceptionBranchChecker()
{
    instance_.store(nullptr);
}

void ExceptionBranchChecker::WriteLog(const std::string& log)
{
    if (log.find(matchBranch_) != std::string::npos) {
        isMatched_ = true;
    }
}

bool ExceptionBranchChecker::GetResult() const
{
    return isMatched_;
}