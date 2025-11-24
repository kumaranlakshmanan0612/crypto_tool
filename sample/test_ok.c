#include "ecy_hsm_csai.h"

void test_handle_overwrite(void)
{
    ecy_hsm_Csai_session_t s1;

    s1 = ecy_hsm_Csai_OpenSession();
    ecy_hsm_Csai_CloseSession(s1);
    s1 = ecy_hsm_Csai_OpenSession();  /* session closed and then open - 0 issue */
}
