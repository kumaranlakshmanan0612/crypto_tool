#ifndef ECY_HSM_CSAI_H
#define ECY_HSM_CSAI_H

#include <stdint.h>

typedef int ecy_hsm_Csai_session_t;
typedef int ecy_hsm_Csai_hJob_t;
typedef int ecy_hsm_Csai_key_id_t;

typedef enum {
    ecy_hsm_CSAI_OK = 0,
    ecy_hsm_CSAI_ERR_SESSION_LIMIT_EXCEEDED = -1,
    ecy_hsm_CSAI_ERR_INVALID_PARAM = -2,
    ecy_hsm_CSAI_ERR_INTERNAL = -3
} ecy_hsm_Csai_error_t;

ecy_hsm_Csai_session_t ecy_hsm_Csai_OpenSession(void);
void ecy_hsm_Csai_CloseSession(ecy_hsm_Csai_session_t session);
void ecy_hsm_Csai_CloseSessionAsync(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_hJob_t *job);
void ecy_hsm_Csai_PollHandle(ecy_hsm_Csai_hJob_t job);

/* Just declarations of job-related APIs – analyzer only needs names/signatures */
ecy_hsm_Csai_error_t ecy_hsm_Csai_HashStart(ecy_hsm_Csai_session_t session, const int *msg, int msg_len, ecy_hsm_Csai_hJob_t *job);
ecy_hsm_Csai_error_t ecy_hsm_Csai_HashFast(ecy_hsm_Csai_session_t session, const int *msg, int msg_len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_Update(ecy_hsm_Csai_session_t session, const int *data, int data_len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_Finish(ecy_hsm_Csai_session_t session, int *out, int *out_len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_MacGenerateFast(ecy_hsm_Csai_session_t session, const int *msg, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_MacVerifyFast(ecy_hsm_Csai_session_t session, const int *msg, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_MacGenerate(ecy_hsm_Csai_session_t session, const int *msg, int len, ecy_hsm_Csai_hJob_t *job);
ecy_hsm_Csai_error_t ecy_hsm_Csai_MacVerify(ecy_hsm_Csai_session_t session, const int *msg, int len, ecy_hsm_Csai_hJob_t *job);
ecy_hsm_Csai_error_t ecy_hsm_Csai_BulkMacVerifyFast(ecy_hsm_Csai_session_t session, const int *msg, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_BulkMacGenerateFast(ecy_hsm_Csai_session_t session, const int *msg, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_WriteKeyToNv(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_key_id_t key_id, const int *data, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_WriteData(ecy_hsm_Csai_session_t session, int id, const int *data, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_DeleteData(ecy_hsm_Csai_session_t session, int id);
ecy_hsm_Csai_error_t ecy_hsm_Csai_LoadKey(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_key_id_t key_id);
ecy_hsm_Csai_error_t ecy_hsm_Csai_LoadKeyFast(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_key_id_t key_id);
ecy_hsm_Csai_error_t ecy_hsm_Csai_GenerateKey(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_key_id_t key_id);
ecy_hsm_Csai_error_t ecy_hsm_Csai_TbRefTblPartInit(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_hJob_t *job);
ecy_hsm_Csai_error_t ecy_hsm_Csai_TbRefTblPartUpdate(ecy_hsm_Csai_session_t session, const int *data, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_TbRefTblPartFinish(ecy_hsm_Csai_session_t session);
ecy_hsm_Csai_error_t ecy_hsm_Csai_Encrypt(ecy_hsm_Csai_session_t session, const int *in, int in_len, int *out);
ecy_hsm_Csai_error_t ecy_hsm_Csai_Decrypt(ecy_hsm_Csai_session_t session, const int *in, int in_len, int *out);
ecy_hsm_Csai_error_t ecy_hsm_Csai_EncryptFast(ecy_hsm_Csai_session_t session, const int *in, int in_len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_DecryptFast(ecy_hsm_Csai_session_t session, const int *in, int in_len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_GetRandom(ecy_hsm_Csai_session_t session, int *out, int len);
ecy_hsm_Csai_error_t ecy_hsm_Csai_GetRandomFast(ecy_hsm_Csai_session_t session, int *out, int len);

ecy_hsm_Csai_error_t SHE_LoadKey(ecy_hsm_Csai_session_t session, ecy_hsm_Csai_key_id_t key_id);
ecy_hsm_Csai_error_t SHE_PrepareKeyUpdate(ecy_hsm_Csai_session_t session, int *msg, int len);
ecy_hsm_Csai_error_t SHE_VerifyMac(ecy_hsm_Csai_session_t session, int *msg, int len);
ecy_hsm_Csai_error_t SHE_GenerateMac(ecy_hsm_Csai_session_t session, int *msg, int len);

#endif /* ECY_HSM_CSAI_H */
