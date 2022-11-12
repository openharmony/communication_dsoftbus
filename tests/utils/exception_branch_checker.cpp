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

static constexpr int32_t LOG_BUF_LEN = 512;
static const char *g_logName[SOFTBUS_LOG_MODULE_MAX] = {
    "AUTH", "TRAN", "CONN", "LNN", "DISC", "COMM"
};

void SoftBusLog(SoftBusLogModule module, SoftBusLogLevel level, const char *fmt, ...)
{
    if (module >= SOFTBUS_LOG_MODULE_MAX) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[COMM] log module exceed max");
        return;
    }

    char buffer[LOG_BUF_LEN];

    int usedLen = sprintf_s(buffer, LOG_BUF_LEN, "[%s] ", g_logName[module]);
    if (usedLen < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[COMM] sprintf_s log error");
        return;
    }

    va_list arg;
    va_start(arg, fmt);
    int ret = vsprintf_s(buffer + usedLen, LOG_BUF_LEN - usedLen, fmt, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[COMM] vsprintf_s log error");
        return;
    }

    switch (level) {
        case SOFTBUS_LOG_DBG:
            HILOG_DEBUG(SOFTBUS_HILOG_ID, "%{public}s", buffer);
            break;
        case SOFTBUS_LOG_INFO:
            HILOG_INFO(SOFTBUS_HILOG_ID, "%{public}s", buffer);
            break;
        case SOFTBUS_LOG_WARN:
            HILOG_WARN(SOFTBUS_HILOG_ID, "%{public}s", buffer);
            break;
        case SOFTBUS_LOG_ERROR:
            HILOG_ERROR(SOFTBUS_HILOG_ID, "%{public}s", buffer);
            break;
        default:
            break;
    }

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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[Unit Test] exception branch match !!");
        isMatched_ = true;
    }
}

bool ExceptionBranchChecker::GetResult() const
{
    return isMatched_;
}