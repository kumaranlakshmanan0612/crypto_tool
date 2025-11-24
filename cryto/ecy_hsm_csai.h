#ifndef FAKE_HSM_API_H
#define FAKE_HSM_API_H

/* ============================================================
   CycurHSM Fake Header for Static Analysis
   ------------------------------------------------------------
   THIS FILE CONTAINS ONLY TYPEDEFS AND FUNCTION PROTOTYPES.
   NO CONFIDENTIAL IMPLEMENTATION DETAILS.
   SAFE FOR REVERSE ENGINEERING, STATIC ANALYSIS, AND TOOLING.
   ============================================================ */

/* ------------------------
   Primitive Base Types
   ------------------------ */
typedef unsigned char      uint8_t;
typedef unsigned long      uint32_t;
typedef unsigned long long uint64_t;
typedef int                ecy_hsm_Csai_return_t;

/* All CycurHSM sessions and job handles are simple integers */
typedef uint32_t ecy_hsm_Csai_session_t;
typedef uint32_t ecy_hsm_Csai_handle_t;

/* Boolean substitute */
typedef uint32_t ecy_hsm_bool_t;
#define TRUE  1
#define FALSE 0

/* ------------------------
   Priority Levels
   ------------------------ */
typedef enum {
    ECY_HSM_PRIORITY_LOW = 0,
    ECY_HSM_PRIORITY_MEDIUM = 1,
    ECY_HSM_PRIORITY_HIGH = 2
} ecy_hsm_priority_t;

/* ------------------------
   Common Return Values
   ------------------------ */
#define ecy_hsm_CSAI_SUCCESS          0
#define ecy_hsm_CSAI_FC_PENDING       1001
#define ecy_hsm_CSAI_ERROR_GENERIC    2000

/* ------------------------
   HASH Types
   ------------------------ */
typedef enum {
    ECY_HSM_HASH_SHA256 = 0,
    ECY_HSM_HASH_SHA1   = 1
} ecy_hsm_hash_type_t;

/* ============================================================
   SESSION MANAGEMENT APIs
   ============================================================ */

ecy_hsm_Csai_session_t ecy_hsm_Csai_OpenSession(void);

ecy_hsm_Csai_return_t ecy_hsm_Csai_CloseSession(
        ecy_hsm_Csai_session_t session);

ecy_hsm_Csai_return_t ecy_hsm_Csai_CloseSessionAsync(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_PollHandle(
        ecy_hsm_Csai_handle_t handle);

/* ============================================================
   HASH APIs
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_HashStart(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_hash_type_t    type,
        const uint8_t         *data,
        uint32_t               dataLen,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_Update(
        ecy_hsm_Csai_handle_t handle,
        const uint8_t        *data,
        uint32_t              len);

ecy_hsm_Csai_return_t ecy_hsm_Csai_Finish(
        ecy_hsm_Csai_handle_t handle);

ecy_hsm_Csai_return_t ecy_hsm_Csai_HashFast(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_hash_type_t    type,
        const uint8_t         *data,
        uint32_t               len,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

/* ============================================================
   MAC APIs
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_MacGenerateFast(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *msg,
        uint32_t               msgLen,
        uint8_t               *mac,
        uint32_t               macLen,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_MacVerifyFast(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *msg,
        uint32_t               msgLen,
        const uint8_t         *mac,
        uint32_t               macLen,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_bool_t ecy_hsm_Csai_GetResultFlag(
        ecy_hsm_Csai_handle_t handle);

/* ============================================================
   BULK MAC APIs
   ============================================================ */

typedef struct {
    uint32_t keyHandle;
    const uint8_t *message;
    uint32_t messageLength;
    uint8_t *mac;
    uint32_t macLength;
    ecy_hsm_bool_t isActive;
    ecy_hsm_bool_t isValid;
    ecy_hsm_bool_t resultFlag;
    ecy_hsm_Csai_return_t errorCode;
} ecy_hsm_Csai_BulkMacVerJob;

ecy_hsm_Csai_return_t ecy_hsm_Csai_BulkMacVerifyFast(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_BulkMacVerJob *jobs,
        uint32_t               numJobs,
        ecy_hsm_Csai_handle_t *hJob);

/* ============================================================
   ENCRYPT / DECRYPT APIs
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_EncryptFast(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *plain,
        uint32_t               len,
        uint8_t               *cipher,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_DecryptFast(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *cipher,
        uint32_t               len,
        uint8_t               *plain,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

/* ============================================================
   RNG API
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_GetRandomFast(
        ecy_hsm_Csai_session_t session,
        uint8_t               *buf,
        uint32_t               len,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

/* ============================================================
   NVRAM / KEY STORE APIs
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_WriteKeyToNv(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *keyData,
        uint32_t               keyLen,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_WriteData(
        ecy_hsm_Csai_session_t session,
        uint32_t               id,
        const uint8_t         *data,
        uint32_t               len,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_DeleteData(
        ecy_hsm_Csai_session_t session,
        uint32_t               id,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_LoadKey(
        ecy_hsm_Csai_session_t session,
        uint32_t               keyHandle,
        const uint8_t         *key,
        uint32_t               len,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

/* ============================================================
   SHE APIs
   ============================================================ */

ecy_hsm_Csai_return_t SHE_LoadKey(
        uint32_t key, const uint8_t *data);

ecy_hsm_Csai_return_t SHE_GenerateMac(
        uint32_t key, const uint8_t *msg,
        uint32_t len, uint8_t *mac);

ecy_hsm_Csai_return_t SHE_VerifyMac(
        uint32_t key, const uint8_t *msg,
        uint32_t len, const uint8_t *mac);

/* ============================================================
   TB (Trusted Boot) APIs
   ============================================================ */

ecy_hsm_Csai_return_t ecy_hsm_Csai_TbRefTblPartInit(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_priority_t     priority,
        uint32_t swId,
        uint32_t addr,
        uint32_t mode,
        uint32_t order,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_TbRefTblPartUpdate(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_priority_t     priority,
        const uint8_t         *chunk,
        uint32_t               len,
        ecy_hsm_Csai_handle_t *hJob);

ecy_hsm_Csai_return_t ecy_hsm_Csai_TbRefTblPartFinish(
        ecy_hsm_Csai_session_t session,
        ecy_hsm_priority_t     priority,
        ecy_hsm_Csai_handle_t *hJob);

#endif /* FAKE_HSM_API_H */
