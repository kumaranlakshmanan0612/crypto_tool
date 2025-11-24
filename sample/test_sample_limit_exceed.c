#include "ecy_hsm_csai.h"

void test_simple_ok(void)
{
    ecy_hsm_Csai_session_t session[10];

    for(int i=0;i<10;i++){
        session[i]=ecy_hsm_Csai_OpenSession();
    }
}
