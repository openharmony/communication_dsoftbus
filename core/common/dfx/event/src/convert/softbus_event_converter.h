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

#ifndef SOFTBUS_EVENT_CONVERTER_H
#define SOFTBUS_EVENT_CONVERTER_H

#include <securec.h>
#include <string.h>

#include "comm_log.h"
#include "form/softbus_event_form.h"
#include "hisysevent_c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_INT_VALUE    0
#define PARAM_STRING_MAX_LEN 256

typedef struct {
    HiSysEventParam value;
    bool isValid;
} SoftbusEventParam;

typedef struct {
    char name[MAX_LENGTH_OF_PARAM_NAME];
    HiSysEventParamType type;
    bool (*Assign)(const char[], HiSysEventParamType, SoftbusEventForm, SoftbusEventParam *);
} SoftbusEventParamAssigner;

static inline bool InitString(char **str)
{
    *str = (char *)malloc(PARAM_STRING_MAX_LEN);
    if (*str == NULL) {
        COMM_LOGE(COMM_DFX, "malloc param string fail");
        return false;
    }
    if (memset_s(*str, PARAM_STRING_MAX_LEN + 1, 0, PARAM_STRING_MAX_LEN) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s param string fail");
        return false;
    }
    return true;
}

static inline bool CopyString(char *destName, const char *srcName)
{
    if (strcpy_s(destName, strlen(srcName) + 1, srcName) != EOK) {
        COMM_LOGE(COMM_DFX, "strcpy_s param name fail, srcName=%s", srcName);
        return false;
    }
    return true;
}

static inline bool AssignerInt32(int32_t value, HiSysEventParam *param)
{
    if (value == INVALID_INT_VALUE) {
        param->v.i32 = INVALID_INT_VALUE;
        return false;
    }
    param->v.i32 = value;
    return true;
}

static inline bool AssignerString(const char *value, HiSysEventParam *param)
{
    if (value == NULL || strlen(value) == 0) {
        param->v.s = NULL;
        return false;
    }
    return InitString(&param->v.s) && CopyString(param->v.s, value);
}

#define SOFTBUS_ASSIGNER(dataType, filedName, filed)                                                             \
    static inline bool SoftbusAssigner##filedName(                                                        \
        const char name[], HiSysEventParamType type, SoftbusEventForm form, SoftbusEventParam *param) \
    {                                                                                                 \
        if (!Assigner##dataType(form.filed, &param->value)) {                                         \
            return false;                                                                             \
        }                                                                                             \
        param->value.t = type;                                                                        \
        return CopyString(param->value.name, name);                                                   \
    }

SOFTBUS_ASSIGNER(Int32, Scene, scene)
SOFTBUS_ASSIGNER(Int32, Stage, stage)
SOFTBUS_ASSIGNER(String, OrgPkg, orgPkg)
SOFTBUS_ASSIGNER(String, Func, func)

#define SOFTBUS_ASSIGNER_SIZE 4 // Size of g_softbusAssigners
static const SoftbusEventParamAssigner g_softbusAssigners[] = {
    {"BIZ_SCENE",  HISYSEVENT_INT32,  SoftbusAssignerScene },
    { "BIZ_STAGE", HISYSEVENT_INT32,  SoftbusAssignerStage },
    { "ORG_PKG",   HISYSEVENT_STRING, SoftbusAssignerOrgPkg},
    { "FUNC",      HISYSEVENT_STRING, SoftbusAssignerFunc  },
 // Modification Note: remember updating SOFTBUS_ASSIGNER_SIZE
};

static inline void ConvertSoftbusForm2Param(SoftbusEventParam params[], size_t size, SoftbusEventForm form)
{
    for (size_t i = 0; i < size; ++i) {
        SoftbusEventParamAssigner assigner = g_softbusAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[i])) {
            params[i].isValid = true;
            continue;
        }
        params[i].isValid = false;
    }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_EVENT_CONVERTER_H
