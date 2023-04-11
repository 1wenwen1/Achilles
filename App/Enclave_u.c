#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_initialize_variables_t {
	sgx_status_t ms_retval;
	PID* ms_me;
	pids_t* ms_others;
	unsigned int* ms_q;
} ms_initialize_variables_t;

typedef struct ms_TEEsign_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
} ms_TEEsign_t;

typedef struct ms_TEEprepare_t {
	sgx_status_t ms_retval;
	hash_t* ms_hash;
	just_t* ms_just;
	just_t* ms_res;
} ms_TEEprepare_t;

typedef struct ms_TEEstore_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
	just_t* ms_res;
} ms_TEEstore_t;

typedef struct ms_TEEaccum_t {
	sgx_status_t ms_retval;
	votes_t* ms_vs;
	accum_t* ms_res;
} ms_TEEaccum_t;

typedef struct ms_TEEaccumSp_t {
	sgx_status_t ms_retval;
	uvote_t* ms_vote;
	accum_t* ms_res;
} ms_TEEaccumSp_t;

typedef struct ms_COMB_TEEsign_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
} ms_COMB_TEEsign_t;

typedef struct ms_COMB_TEEprepare_t {
	sgx_status_t ms_retval;
	hash_t* ms_hash;
	accum_t* ms_acc;
	just_t* ms_res;
} ms_COMB_TEEprepare_t;

typedef struct ms_COMB_TEEstore_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
	just_t* ms_res;
} ms_COMB_TEEstore_t;

typedef struct ms_COMB_TEEaccum_t {
	sgx_status_t ms_retval;
	onejusts_t* ms_js;
	accum_t* ms_res;
} ms_COMB_TEEaccum_t;

typedef struct ms_COMB_TEEaccumSp_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
	accum_t* ms_res;
} ms_COMB_TEEaccumSp_t;

typedef struct ms_FREE_TEEauth_t {
	sgx_status_t ms_retval;
	payload_t* ms_text;
	auth_t* ms_res;
} ms_FREE_TEEauth_t;

typedef struct ms_FREE_TEEverify_t {
	sgx_status_t ms_retval;
	payload_t* ms_text;
	auths_t* ms_a;
	bool* ms_res;
} ms_FREE_TEEverify_t;

typedef struct ms_FREE_TEEverify2_t {
	sgx_status_t ms_retval;
	payload_t* ms_text1;
	auths_t* ms_a1;
	payload_t* ms_text2;
	auths_t* ms_a2;
	bool* ms_res;
} ms_FREE_TEEverify2_t;

typedef struct ms_FREE_TEEstore_t {
	sgx_status_t ms_retval;
	pjust_t* ms_just;
	fvjust_t* ms_res;
} ms_FREE_TEEstore_t;

typedef struct ms_FREE_TEEaccum_t {
	sgx_status_t ms_retval;
	fjust_t* ms_j;
	fjusts_t* ms_js;
	hash_t* ms_prp;
	haccum_t* ms_res;
} ms_FREE_TEEaccum_t;

typedef struct ms_FREE_TEEaccumSp_t {
	sgx_status_t ms_retval;
	ofjust_t* ms_just;
	hash_t* ms_prp;
	haccum_t* ms_res;
} ms_FREE_TEEaccumSp_t;

typedef struct ms_FREE_initialize_variables_t {
	sgx_status_t ms_retval;
	PID* ms_me;
	unsigned int* ms_q;
} ms_FREE_initialize_variables_t;

typedef struct ms_OP_TEEverify_t {
	sgx_status_t ms_retval;
	payload_t* ms_text;
	auths_t* ms_a;
	bool* ms_res;
} ms_OP_TEEverify_t;

typedef struct ms_OP_TEEprepare_t {
	sgx_status_t ms_retval;
	hash_t* ms_hash;
	opproposal_t* ms_res;
} ms_OP_TEEprepare_t;

typedef struct ms_OP_TEEvote_t {
	sgx_status_t ms_retval;
	hash_t* ms_hash;
	opvote_t* ms_res;
} ms_OP_TEEvote_t;

typedef struct ms_OP_TEEstore_t {
	sgx_status_t ms_retval;
	opproposal_t* ms_just;
	opstore_t* ms_res;
} ms_OP_TEEstore_t;

typedef struct ms_OP_initialize_variables_t {
	sgx_status_t ms_retval;
	PID* ms_me;
	unsigned int* ms_q;
} ms_OP_initialize_variables_t;

typedef struct ms_CH_TEEsign_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
} ms_CH_TEEsign_t;

typedef struct ms_CH_TEEprepare_t {
	sgx_status_t ms_retval;
	jblock_t* ms_block;
	jblock_t* ms_block0;
	jblock_t* ms_block1;
	just_t* ms_res;
} ms_CH_TEEprepare_t;

typedef struct ms_CH_COMB_TEEsign_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
} ms_CH_COMB_TEEsign_t;

typedef struct ms_CH_COMB_TEEprepare_t {
	sgx_status_t ms_retval;
	cblock_t* ms_block;
	hash_t* ms_hash;
	just_t* ms_res;
} ms_CH_COMB_TEEprepare_t;

typedef struct ms_CH_COMB_TEEaccum_t {
	sgx_status_t ms_retval;
	onejusts_t* ms_js;
	accum_t* ms_res;
} ms_CH_COMB_TEEaccum_t;

typedef struct ms_CH_COMB_TEEaccumSp_t {
	sgx_status_t ms_retval;
	just_t* ms_just;
	accum_t* ms_res;
} ms_CH_COMB_TEEaccumSp_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_test_t {
	KEY* ms_key;
} ms_ocall_test_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_test(void* pms)
{
	ms_ocall_test_t* ms = SGX_CAST(ms_ocall_test_t*, pms);
	ocall_test(ms->ms_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_setCtime(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_setCtime();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recCStime(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_recCStime();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recCVtime(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_recCVtime();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[14];
} ocall_table_Enclave = {
	14,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_test,
		(void*)Enclave_ocall_setCtime,
		(void*)Enclave_ocall_recCStime,
		(void*)Enclave_ocall_recCVtime,
		(void*)Enclave_u_sgxssl_ftime,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_pthread_wait_timeout_ocall,
		(void*)Enclave_pthread_create_ocall,
		(void*)Enclave_pthread_wakeup_ocall,
	}
};
sgx_status_t initialize_variables(sgx_enclave_id_t eid, sgx_status_t* retval, PID* me, pids_t* others, unsigned int* q)
{
	sgx_status_t status;
	ms_initialize_variables_t ms;
	ms.ms_me = me;
	ms.ms_others = others;
	ms.ms_q = q;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TEEsign(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just)
{
	sgx_status_t status;
	ms_TEEsign_t ms;
	ms.ms_just = just;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TEEprepare(sgx_enclave_id_t eid, sgx_status_t* retval, hash_t* hash, just_t* just, just_t* res)
{
	sgx_status_t status;
	ms_TEEprepare_t ms;
	ms.ms_hash = hash;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TEEstore(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just, just_t* res)
{
	sgx_status_t status;
	ms_TEEstore_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TEEaccum(sgx_enclave_id_t eid, sgx_status_t* retval, votes_t* vs, accum_t* res)
{
	sgx_status_t status;
	ms_TEEaccum_t ms;
	ms.ms_vs = vs;
	ms.ms_res = res;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TEEaccumSp(sgx_enclave_id_t eid, sgx_status_t* retval, uvote_t* vote, accum_t* res)
{
	sgx_status_t status;
	ms_TEEaccumSp_t ms;
	ms.ms_vote = vote;
	ms.ms_res = res;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t COMB_TEEsign(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just)
{
	sgx_status_t status;
	ms_COMB_TEEsign_t ms;
	ms.ms_just = just;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t COMB_TEEprepare(sgx_enclave_id_t eid, sgx_status_t* retval, hash_t* hash, accum_t* acc, just_t* res)
{
	sgx_status_t status;
	ms_COMB_TEEprepare_t ms;
	ms.ms_hash = hash;
	ms.ms_acc = acc;
	ms.ms_res = res;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t COMB_TEEstore(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just, just_t* res)
{
	sgx_status_t status;
	ms_COMB_TEEstore_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t COMB_TEEaccum(sgx_enclave_id_t eid, sgx_status_t* retval, onejusts_t* js, accum_t* res)
{
	sgx_status_t status;
	ms_COMB_TEEaccum_t ms;
	ms.ms_js = js;
	ms.ms_res = res;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t COMB_TEEaccumSp(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just, accum_t* res)
{
	sgx_status_t status;
	ms_COMB_TEEaccumSp_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEauth(sgx_enclave_id_t eid, sgx_status_t* retval, payload_t* text, auth_t* res)
{
	sgx_status_t status;
	ms_FREE_TEEauth_t ms;
	ms.ms_text = text;
	ms.ms_res = res;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEverify(sgx_enclave_id_t eid, sgx_status_t* retval, payload_t* text, auths_t* a, bool* res)
{
	sgx_status_t status;
	ms_FREE_TEEverify_t ms;
	ms.ms_text = text;
	ms.ms_a = a;
	ms.ms_res = res;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEverify2(sgx_enclave_id_t eid, sgx_status_t* retval, payload_t* text1, auths_t* a1, payload_t* text2, auths_t* a2, bool* res)
{
	sgx_status_t status;
	ms_FREE_TEEverify2_t ms;
	ms.ms_text1 = text1;
	ms.ms_a1 = a1;
	ms.ms_text2 = text2;
	ms.ms_a2 = a2;
	ms.ms_res = res;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEstore(sgx_enclave_id_t eid, sgx_status_t* retval, pjust_t* just, fvjust_t* res)
{
	sgx_status_t status;
	ms_FREE_TEEstore_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEaccum(sgx_enclave_id_t eid, sgx_status_t* retval, fjust_t* j, fjusts_t* js, hash_t* prp, haccum_t* res)
{
	sgx_status_t status;
	ms_FREE_TEEaccum_t ms;
	ms.ms_j = j;
	ms.ms_js = js;
	ms.ms_prp = prp;
	ms.ms_res = res;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_TEEaccumSp(sgx_enclave_id_t eid, sgx_status_t* retval, ofjust_t* just, hash_t* prp, haccum_t* res)
{
	sgx_status_t status;
	ms_FREE_TEEaccumSp_t ms;
	ms.ms_just = just;
	ms.ms_prp = prp;
	ms.ms_res = res;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t FREE_initialize_variables(sgx_enclave_id_t eid, sgx_status_t* retval, PID* me, unsigned int* q)
{
	sgx_status_t status;
	ms_FREE_initialize_variables_t ms;
	ms.ms_me = me;
	ms.ms_q = q;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t OP_TEEverify(sgx_enclave_id_t eid, sgx_status_t* retval, payload_t* text, auths_t* a, bool* res)
{
	sgx_status_t status;
	ms_OP_TEEverify_t ms;
	ms.ms_text = text;
	ms.ms_a = a;
	ms.ms_res = res;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t OP_TEEprepare(sgx_enclave_id_t eid, sgx_status_t* retval, hash_t* hash, opproposal_t* res)
{
	sgx_status_t status;
	ms_OP_TEEprepare_t ms;
	ms.ms_hash = hash;
	ms.ms_res = res;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t OP_TEEvote(sgx_enclave_id_t eid, sgx_status_t* retval, hash_t* hash, opvote_t* res)
{
	sgx_status_t status;
	ms_OP_TEEvote_t ms;
	ms.ms_hash = hash;
	ms.ms_res = res;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t OP_TEEstore(sgx_enclave_id_t eid, sgx_status_t* retval, opproposal_t* just, opstore_t* res)
{
	sgx_status_t status;
	ms_OP_TEEstore_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t OP_initialize_variables(sgx_enclave_id_t eid, sgx_status_t* retval, PID* me, unsigned int* q)
{
	sgx_status_t status;
	ms_OP_initialize_variables_t ms;
	ms.ms_me = me;
	ms.ms_q = q;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_TEEsign(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just)
{
	sgx_status_t status;
	ms_CH_TEEsign_t ms;
	ms.ms_just = just;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_TEEprepare(sgx_enclave_id_t eid, sgx_status_t* retval, jblock_t* block, jblock_t* block0, jblock_t* block1, just_t* res)
{
	sgx_status_t status;
	ms_CH_TEEprepare_t ms;
	ms.ms_block = block;
	ms.ms_block0 = block0;
	ms.ms_block1 = block1;
	ms.ms_res = res;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_COMB_TEEsign(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just)
{
	sgx_status_t status;
	ms_CH_COMB_TEEsign_t ms;
	ms.ms_just = just;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_COMB_TEEprepare(sgx_enclave_id_t eid, sgx_status_t* retval, cblock_t* block, hash_t* hash, just_t* res)
{
	sgx_status_t status;
	ms_CH_COMB_TEEprepare_t ms;
	ms.ms_block = block;
	ms.ms_hash = hash;
	ms.ms_res = res;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_COMB_TEEaccum(sgx_enclave_id_t eid, sgx_status_t* retval, onejusts_t* js, accum_t* res)
{
	sgx_status_t status;
	ms_CH_COMB_TEEaccum_t ms;
	ms.ms_js = js;
	ms.ms_res = res;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t CH_COMB_TEEaccumSp(sgx_enclave_id_t eid, sgx_status_t* retval, just_t* just, accum_t* res)
{
	sgx_status_t status;
	ms_CH_COMB_TEEaccumSp_t ms;
	ms.ms_just = just;
	ms.ms_res = res;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

