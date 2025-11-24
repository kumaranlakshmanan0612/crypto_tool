#include "ecy_hsm_csai.h"
#include <stdint.h>

void good_usage_example(void)
{
    ecy_hsm_Csai_session_t s1;
    ecy_hsm_Csai_handle_t  hJob;
    ecy_hsm_Csai_return_t rc;

    /* Correct usage: session opened once */
    s1 = ecy_hsm_Csai_OpenSession();

    /* Start a MAC verify job */
    rc = ecy_hsm_Csai_MacVerifyFast(
            s1,
            10,           /* keyHandle */
            (uint8_t*)"ABC", 3,
            (uint8_t*)"XYZ", 3,
            ECY_HSM_PRIORITY_HIGH,
            &hJob);

    /* Poll until complete */
    while (rc == ecy_hsm_CSAI_FC_PENDING) {
        rc = ecy_hsm_Csai_PollHandle(hJob);
    }

    /* Close session correctly */
    ecy_hsm_Csai_CloseSession(s1);
}


// void session_leak_example(void)
// {
//     ecy_hsm_Csai_session_t s2;

//     /* Session opened but never closed → leak */
//     s2 = ecy_hsm_Csai_OpenSession();

//     /* Start job but forget to poll */
//     ecy_hsm_Csai_handle_t hJob2;
//     ecy_hsm_Csai_MacVerifyFast(
//         s2,
//         11,
//         (uint8_t*)"MSG", 3,
//         (uint8_t*)"MAC", 3,
//         ECY_HSM_PRIORITY_LOW,
//         &hJob2);

//     /* Missing PollHandle AND missing CloseSession */
// }


void overwritten_session_example(void)
{
    ecy_hsm_Csai_session_t s3;

    s3 = ecy_hsm_Csai_OpenSession();
    /* Wrong: overwrite session handle without closing old session */
    s3 = ecy_hsm_Csai_OpenSession();

    /* This job now uses only the second session; first is leaked */
    ecy_hsm_Csai_handle_t hJob3;
    ecy_hsm_Csai_HashStart(
        s3,
        ECY_HSM_HASH_SHA256,
        (uint8_t*)"data", 4,
        ECY_HSM_PRIORITY_MEDIUM,
        &hJob3);

    /* Poll */
    ecy_hsm_Csai_PollHandle(hJob3);

    /* Session not closed */
}


void async_close_without_poll(void)
{
    ecy_hsm_Csai_session_t s4;
    ecy_hsm_Csai_handle_t hCloseJob;

    s4 = ecy_hsm_Csai_OpenSession();

    /* Async close – but NO poll on returned job handle! */
    ecy_hsm_Csai_CloseSessionAsync(s4, &hCloseJob);
}


void job_handle_reuse_example(void)
{
    ecy_hsm_Csai_session_t s5;
    ecy_hsm_Csai_handle_t hJob5;

    s5 = ecy_hsm_Csai_OpenSession();

    /* Start a job */
    ecy_hsm_Csai_HashStart(
        s5,
        ECY_HSM_HASH_SHA256,
        (uint8_t*)"block1", 6,
        ECY_HSM_PRIORITY_LOW,
        &hJob5);

    /* Never poll → job remains active */

    /* Wrong: overwrite job handle before completing previous job */
    ecy_hsm_Csai_HashStart(
        s5,
        ECY_HSM_HASH_SHA256,
        (uint8_t*)"block2", 6,
        ECY_HSM_PRIORITY_HIGH,
        &hJob5);

    /* Close session without finishing any job */
    ecy_hsm_Csai_CloseSession(s5);
}