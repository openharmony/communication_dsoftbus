/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "disc_mgr_config.h"
#include "disc_log.h"
#include "disc_manager_struct.h"
#include "softbus_def.h"
#include "softbus_common.h"

typedef struct {
    int32_t maxCallTimes;
} DiscMgrConfig;

static const DiscMgrConfig g_discMgrConfig[CAPABILITY_MAX_BITNUM] = {
    [HICALL_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [PROFILE_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [CASTPLUS_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [AA_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [DVKIT_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [DDMP_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [OSD_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [SHARE_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [APPROACH_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [VLINK_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [TOUCH_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [OOP_CAPABILITY_BITMAP] = {
        .maxCallTimes = DEFAULT_CALL_TIMES,
    },
    [OH_APPROACH_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [SD_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [RAISE_HAND_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [PC_COLLABORATION_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    },
    [NFC_SHARE_CAPABILITY_BITMAP] = {
        .maxCallTimes = NO_LIMITED_TIMES,
    }
};

int32_t DiscMgrGetMaxCallTimes(int32_t bitmap)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(bitmap >= 0 &&
        bitmap < (int32_t)ARRAY_SIZE(g_discMgrConfig), NO_LIMITED_TIMES, DISC_CONTROL,
        "invalid bitmap: %{public}d", bitmap);
    return g_discMgrConfig[bitmap].maxCallTimes;
}
