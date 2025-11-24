#include "ecy_hsm_csai.h"
#include <stdint.h>

void test_session_overwrite(void)
{
    ecy_hsm_Csai_session_t s1;
    ecy_hsm_Csai_session_t s2;  /* unused, just to make scenario realistic */

    /* First session created */
    s1 = ecy_hsm_Csai_OpenSession();

    /* OOPS: Overwriting s1 with another session handle.
             Now there is no way to close the first session. */
    s1 = ecy_hsm_Csai_OpenSession();

    /* Start a job on the new session */
    ecy_hsm_Csai_error_t hJob;
    ecy_hsm_Csai_HashStart(
        s1,
        ECY_HSM_HASH_SHA256,
        (uint8_t*)"ABCD", 4,
        ECY_HSM_PRIORITY_LOW,
        &hJob
    );

    /* Not polling hJob is also a leak but overwrite is the main issue here */
}
