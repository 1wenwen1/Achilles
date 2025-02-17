#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../App/config.h"
#include "../App/types.h"
#include "../App/key.h"
#include "../Enclave/user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t initialize_variables(PID* me, pids_t* others, unsigned int* q);
sgx_status_t TEEsign(just_t* just);
sgx_status_t TEEprepare(hash_t* hash, just_t* just, just_t* res);
sgx_status_t TEEstore(just_t* just, just_t* res);
sgx_status_t TEEaccum(votes_t* vs, accum_t* res);
sgx_status_t TEEaccumSp(uvote_t* vote, accum_t* res);
sgx_status_t COMB_TEEsign(just_t* just);
sgx_status_t COMB_TEEprepare(hash_t* hash, accum_t* acc, just_t* res);
sgx_status_t COMB_TEEstore(just_t* just, just_t* res);
sgx_status_t COMB_TEEaccum(onejusts_t* js, accum_t* res);
sgx_status_t COMB_TEEaccumSp(just_t* just, accum_t* res);
sgx_status_t FREE_TEEauth(payload_t* text, auth_t* res);
sgx_status_t FREE_TEEverify(payload_t* text, auths_t* a, bool* res);
sgx_status_t FREE_TEEverify2(payload_t* text1, auths_t* a1, payload_t* text2, auths_t* a2, bool* res);
sgx_status_t FREE_TEEstore(pjust_t* just, fvjust_t* res);
sgx_status_t FREE_TEEaccum(fjust_t* j, fjusts_t* js, hash_t* prp, haccum_t* res);
sgx_status_t FREE_TEEaccumSp(ofjust_t* just, hash_t* prp, haccum_t* res);
sgx_status_t FREE_initialize_variables(PID* me, unsigned int* q);
sgx_status_t OP_TEEverify(payload_t* text, auths_t* a, bool* res);
sgx_status_t OP_TEEprepare(hash_t* hash, opproposal_t* res);
sgx_status_t OP_TEEvote(hash_t* hash, opvote_t* res);
sgx_status_t OP_TEEstore(opproposal_t* just, opstore_t* res);
sgx_status_t OP_TEEaccum(opstore_t* j, opstores_t* js, opaccum_t* res);
sgx_status_t OP_TEEaccumSp(opprepare_t* just, opaccum_t* res);
sgx_status_t OP_initialize_variables(PID* me, unsigned int* q);
sgx_status_t CH_TEEsign(just_t* just);
sgx_status_t CH_TEEprepare(jblock_t* block, jblock_t* block0, jblock_t* block1, just_t* res);
sgx_status_t CH_COMB_TEEsign(just_t* just);
sgx_status_t CH_COMB_TEEprepare(cblock_t* block, hash_t* hash, just_t* res);
sgx_status_t CH_COMB_TEEaccum(onejusts_t* js, accum_t* res);
sgx_status_t CH_COMB_TEEaccumSp(just_t* just, accum_t* res);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_test(KEY* key);
sgx_status_t SGX_CDECL ocall_setCtime(void);
sgx_status_t SGX_CDECL ocall_recCStime(void);
sgx_status_t SGX_CDECL ocall_recCVtime(void);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
