#include "ecy_hsm_csai.h"

void test_limit_exceeded(void)
{
    ecy_hsm_Csai_session_t s1, s2, s3;

    s1 = ecy_hsm_Csai_OpenSession();
    s2 = ecy_hsm_Csai_OpenSession();
    s3 = ecy_hsm_Csai_OpenSession();  /* 3 concurrent, if max-sessions = 2 => ERROR */
}
