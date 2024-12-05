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

#ifndef LNN_DECISION_DB_H
#define LNN_DECISION_DB_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_ENCRYPT_LEVEL_DE = 0,
    LNN_ENCRYPT_LEVEL_CE,
    LNN_ENCRYPT_LEVEL_ECE,
    LNN_ENCRYPT_LEVEL_MAX,
} LnnEncryptDataLevel;

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid);
int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId);
int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num);
bool LnnIsPotentialHomeGroup(const char *udid);
int32_t UpdateRecoveryDeviceInfoFromDb(void);

int32_t LnnCheckGenerateSoftBusKeyByHuks(void);
int32_t LnnInitDecisionDbDelay(void);
int32_t EncryptStorageData(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len);
int32_t DecryptStorageData(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len);
int32_t LnnGenerateCeParams(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_DECISION_DB_H