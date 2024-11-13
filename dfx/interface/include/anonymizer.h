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

#ifndef SOFTBUS_DFX_ANONYMIZE_H
#define SOFTBUS_DFX_ANONYMIZE_H

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Anonymize the sensitive plain text.
 *
 * @note Need to call {@link AnonymizeFree} to release anonymizedStr.
 * @param plainStr The plain string to be anonymized.
 * @param anonymizedStr The anonymized string.
 */
void Anonymize(const char *plainStr, char **anonymizedStr);

/**
 * Release the anonymized string.
 *
 * @param anonymizedStr The anonymized string.
 */
void AnonymizeFree(char *anonymizedStr);

/**
 * Return the anonymized string if anonymizedStr is not null,
 * else return "NULL"
 *
 * @param anonymizedStr The anonymized string.
 */
const char *AnonymizeWrapper(const char *anonymizedStr);

#ifdef __cplusplus
}
#endif
#endif // SOFTBUS_DFX_ANONYMIZE_H
