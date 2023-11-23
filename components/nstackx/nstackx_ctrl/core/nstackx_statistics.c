/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "nstackx_statistics.h"
#include <securec.h>

static uint64_t g_statistics[STATS_MAX];

void ResetStatistics(void)
{
    (void)memset_s(&g_statistics[0], sizeof(g_statistics), 0, sizeof(g_statistics));
}

void IncStatistics(StatisticsType type)
{
    g_statistics[type]++;
}

const uint64_t *GetStatistics(void)
{
    return &g_statistics[0];
}
