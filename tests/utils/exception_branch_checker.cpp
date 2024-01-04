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