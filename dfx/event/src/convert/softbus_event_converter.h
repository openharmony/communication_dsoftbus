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
#include "anonymizer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_INT_VALUE               0
#define PARAM_STRING_VALUE_MAX_LEN      256
#define PARAM_LONG_STRING_VALUE_MAX_LEN (256 * 1024)

typedef struct {
    char name[MAX_LENGTH_OF_PARAM_NAME];
    HiSysEventParamType type;
    bool (*Assign)(const char[], HiSysEventParamType, SoftbusEventForm *, HiSysEventParam *);
} HiSysEventParamAssigner;

static inline bool InitString(char **str, size_t maxLen)
{
    *str = (char *)malloc(maxLen);
    if (*str == NULL) {
        COMM_LOGE(COMM_DFX, "malloc param string fail");
        return false;
    }
    if (memset_s(*str, maxLen, 0, maxLen) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s param string fail");
        return false;
    }
    return true;
}

static inline bool CopyString(char *destName, const char *srcName, size_t maxLen)
{
    if (strcpy_s(destName, maxLen, srcName) != EOK) {
        COMM_LOGE(COMM_DFX, "strcpy_s fail, srcName=%{public}s, maxLen=%{public}zu", srcName, maxLen);
        return false;
    }
    return true;
}

/* Used by ASSIGNER macros */
static inline bool AssignerInt32(int32_t value, HiSysEventParam **param)
{
    if (value <= INVALID_INT_VALUE) {
        (*param)->v.i32 = INVALID_INT_VALUE;
        return false;
    }
    (*param)->v.i32 = value;
    return true;
}

/* Used by ASSIGNER macros */
static inline bool AssignerInt64(int64_t value, HiSysEventParam **param)
{
    (*param)->v.i64 = value;
    return true;
}

/* Used by ASSIGNER macros */
static inline bool AssignerString(const char *value, HiSysEventParam **param)
{
    if (value == NULL || value[0] == '\0' || strnlen(value, PARAM_STRING_VALUE_MAX_LEN) == PARAM_STRING_VALUE_MAX_LEN) {
        (*param)->v.s = NULL;
        return false;
    }
    return InitString(&(*param)->v.s, PARAM_STRING_VALUE_MAX_LEN) &&
        CopyString((*param)->v.s, value, PARAM_STRING_VALUE_MAX_LEN);
}

/* Used by ASSIGNER macros */
static inline bool AssignerLongString(const char *value, HiSysEventParam **param)
{
    if (value == NULL || value[0] == '\0' || strnlen(value,
        PARAM_LONG_STRING_VALUE_MAX_LEN) == PARAM_LONG_STRING_VALUE_MAX_LEN) {
        (*param)->v.s = NULL;
        return false;
    }
    return InitString(&(*param)->v.s, PARAM_LONG_STRING_VALUE_MAX_LEN) &&
        CopyString((*param)->v.s, value, PARAM_LONG_STRING_VALUE_MAX_LEN);
}

/* Used by ASSIGNER macros */
static inline bool AssignerAnonymizeString(const char *value, HiSysEventParam **param)
{
    if (value == NULL || value[0] == '\0' || strnlen(value, PARAM_STRING_VALUE_MAX_LEN) == PARAM_STRING_VALUE_MAX_LEN) {
        (*param)->v.s = NULL;
        return false;
    }
    if (!InitString(&(*param)->v.s, PARAM_STRING_VALUE_MAX_LEN)) {
        return false;
    }
    char *anonyStr = NULL;
    Anonymize(value, &anonyStr);
    bool status = CopyString((*param)->v.s, anonyStr, PARAM_STRING_VALUE_MAX_LEN);
    AnonymizeFree(anonyStr);
    return status;
}

/* Used by ASSIGNER macros */
static inline bool AssignerErrcode(int32_t value, HiSysEventParam **param)
{
    (*param)->v.i32 = (value < 0) ? (-value) : value;
    return true;
}

/* Used by ASSIGNER macros */
static inline bool AssignerUint64(uint64_t value, HiSysEventParam **param)
{
    (*param)->v.ui64 = value;
    return true;
}

/* Used by ASSIGNER macros */
static inline bool AssignerUint32(uint32_t value, HiSysEventParam **param)
{
    (*param)->v.ui32 = value;
    return true;
}

#define SOFTBUS_ASSIGNER(type, fieldName, field)                                                                   \
    static inline bool SoftbusAssigner##fieldName(                                                                 \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param)      \
    {                                                                                                              \
        if (Assigner##type(form->field, &param) && CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) { \
            param->t = paramType;                                                                                  \
            return true;                                                                                           \
        }                                                                                                          \
        return false;                                                                                              \
    }

SOFTBUS_ASSIGNER(Int32, Scene, scene)
SOFTBUS_ASSIGNER(Int32, Stage, stage)
SOFTBUS_ASSIGNER(String, OrgPkg, orgPkg)
SOFTBUS_ASSIGNER(String, Func, func)

#define SOFTBUS_ASSIGNER_SIZE 4 // Size of g_softbusAssigners
static HiSysEventParamAssigner g_softbusAssigners[] = {
    { "BIZ_SCENE", HISYSEVENT_INT32,  SoftbusAssignerScene },
    { "BIZ_STAGE", HISYSEVENT_INT32,  SoftbusAssignerStage },
    { "ORG_PKG",   HISYSEVENT_STRING, SoftbusAssignerOrgPkg},
    { "FUNC",      HISYSEVENT_STRING, SoftbusAssignerFunc  },
    // Modification Note: remember updating SOFTBUS_ASSIGNER_SIZE
};

static inline size_t ConvertSoftbusForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_softbusAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_EVENT_CONVERTER_H
