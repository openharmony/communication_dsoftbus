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

#include "softbus_file_test_entry.h"

#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "gtest/gtest.h"

using namespace std;

namespace {
unordered_map<string, int> g_customArgs {
    {"--gtest_trans_side", 0},
    {"--gtest_trans_time", 3600},
    {"--gtest_trans_num", 10},
    {"--gtest_trans_pressure", 100},
    {"--gtest_with_phone", 0}
};
SoftbusTestEntry g_testEntry;
}

const SoftbusTestEntry *GetTestEntry(void)
{
    g_testEntry.testSide_ = g_customArgs["--gtest_trans_side"];
    g_testEntry.aliveTime_ = g_customArgs["--gtest_trans_time"];
    g_testEntry.transNums_ = g_customArgs["--gtest_trans_num"];
    g_testEntry.pressureNums_ = g_customArgs["--gtest_trans_pressure"];
    g_testEntry.isTestWithPhone_ = g_customArgs["--gtest_with_phone"] != 0 ? true : false;
    return &g_testEntry;
}

static void ProcessCustomArgs(const char *arg, unordered_map<string, int> &customArgs, int32_t *custom)
{
    int32_t result = 0;
    int32_t customCnt = 0;
    for (auto &argItem : customArgs) {
        if (!strncmp(arg, argItem.first.c_str(), strlen(argItem.first.c_str()))) {
            const char *findPtr = strchr(arg, '=');
            if (findPtr == NULL) {
                return;
            }
            result = atoi(findPtr + 1);
            argItem.second = result;
            customCnt++;
        }
    }

    *custom = customCnt;
}

int32_t main(int32_t argc, char **argv)
{
    printf("Running main() from %s\n", __FILE__);
    testing::GTEST_FLAG(output) = "xml:./";
    int32_t isCustomArg = 0;
    int32_t customCnt = 0;

    for (int32_t i = 1; i < argc; i++) {
        ProcessCustomArgs(argv[i], g_customArgs, &isCustomArg);
        if (isCustomArg > 0) {
            customCnt = customCnt + isCustomArg;
        }
    }

    if (customCnt > argc - 1) {
        printf("invalid custom args input.\n");
        return 0;
    }

    argc = argc - customCnt;
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
