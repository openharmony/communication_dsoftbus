/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "hilog/log.h"
#include "securec.h"

#define MAX_LOG_LEN 1024
#define PERMISSION_NUM 3

namespace {
std::vector<std::string> g_hilogPermissionList = {"{public}", "{private}", "{protect}"};

void RemoveHilogModifiers(const char *fmt, char *modifiedFmt)
{
    std::string strTypeFmt = fmt;
    std::string::size_type pos = 0;
    for (int32_t i = 0; i < PERMISSION_NUM; i++) {
        while ((pos = strTypeFmt.find(g_hilogPermissionList[i], pos)) != std::string::npos) {
            strTypeFmt.erase(pos, g_hilogPermissionList[i].length());
        }
    }
    if (strcpy_s(modifiedFmt, strTypeFmt.length() + 1, strTypeFmt.c_str()) != EOK) {
        return;
    }
}
}

#ifdef HILOG_FMTID
int32_t HiLogPrintDictNew(const LogType type, const LogLevel level, const unsigned int domain, const char *tag,
    const unsigned int uuid, const unsigned int fmtOffset, const char *fmt, ...)
#else
int32_t HiLogPrint(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...)
#endif
{
    va_list args = { 0 };
    char buffer[MAX_LOG_LEN] = { 0 };
    char modifiedFmt[MAX_LOG_LEN] = { 0 };

    RemoveHilogModifiers(fmt, modifiedFmt);

    va_start(args, fmt);
    int32_t ret = vsprintf_s(&buffer[0], sizeof(buffer), modifiedFmt, args);
    va_end(args);
    if (ret < 0) {
        return ret;
    }

    auto *checker = ExceptionBranchChecker::GetCurrentInstance();
    if (checker != nullptr) {
        checker->WriteLog(buffer);
    }

    return ret;
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