#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_initialize_variables(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_initialize_variables_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_initialize_variables_t* ms = SGX_CAST(ms_initialize_variables_t*, pms);
	ms_initialize_variables_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_initialize_variables_t), ms, sizeof(ms_initialize_variables_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	PID* _tmp_me = __in_ms.ms_me;
	size_t _len_me = sizeof(PID);
	PID* _in_me = NULL;
	pids_t* _tmp_others = __in_ms.ms_others;
	size_t _len_others = sizeof(pids_t);
	pids_t* _in_others = NULL;
	unsigned int* _tmp_q = __in_ms.ms_q;
	size_t _len_q = sizeof(unsigned int);
	unsigned int* _in_q = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_me, _len_me);
	CHECK_UNIQUE_POINTER(_tmp_others, _len_others);
	CHECK_UNIQUE_POINTER(_tmp_q, _len_q);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_me != NULL && _len_me != 0) {
		_in_me = (PID*)malloc(_len_me);
		if (_in_me == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_me, _len_me, _tmp_me, _len_me)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_others != NULL && _len_others != 0) {
		_in_others = (pids_t*)malloc(_len_others);
		if (_in_others == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_others, _len_others, _tmp_others, _len_others)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q != NULL && _len_q != 0) {
		if ( _len_q % sizeof(*_tmp_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q = (unsigned int*)malloc(_len_q);
		if (_in_q == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q, _len_q, _tmp_q, _len_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = initialize_variables(_in_me, _in_others, _in_q);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_me) free(_in_me);
	if (_in_others) free(_in_others);
	if (_in_q) free(_in_q);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TEEsign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEEsign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEEsign_t* ms = SGX_CAST(ms_TEEsign_t*, pms);
	ms_TEEsign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEEsign_t), ms, sizeof(ms_TEEsign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		if ((_in_just = (just_t*)malloc(_len_just)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_just, 0, _len_just);
	}
	_in_retval = TEEsign(_in_just);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_just) {
		if (memcpy_verw_s(_tmp_just, _len_just, _in_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TEEprepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEEprepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEEprepare_t* ms = SGX_CAST(ms_TEEprepare_t*, pms);
	ms_TEEprepare_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEEprepare_t), ms, sizeof(ms_TEEprepare_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(hash_t);
	hash_t* _in_hash = NULL;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);
	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_hash != NULL && _len_hash != 0) {
		_in_hash = (hash_t*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (just_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = TEEprepare(_in_hash, _in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_hash) free(_in_hash);
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TEEstore(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEEstore_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEEstore_t* ms = SGX_CAST(ms_TEEstore_t*, pms);
	ms_TEEstore_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEEstore_t), ms, sizeof(ms_TEEstore_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (just_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = TEEstore(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TEEaccum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEEaccum_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEEaccum_t* ms = SGX_CAST(ms_TEEaccum_t*, pms);
	ms_TEEaccum_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEEaccum_t), ms, sizeof(ms_TEEaccum_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	votes_t* _tmp_vs = __in_ms.ms_vs;
	size_t _len_vs = sizeof(votes_t);
	votes_t* _in_vs = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_vs, _len_vs);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_vs != NULL && _len_vs != 0) {
		_in_vs = (votes_t*)malloc(_len_vs);
		if (_in_vs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vs, _len_vs, _tmp_vs, _len_vs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = TEEaccum(_in_vs, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_vs) free(_in_vs);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TEEaccumSp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEEaccumSp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEEaccumSp_t* ms = SGX_CAST(ms_TEEaccumSp_t*, pms);
	ms_TEEaccumSp_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEEaccumSp_t), ms, sizeof(ms_TEEaccumSp_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uvote_t* _tmp_vote = __in_ms.ms_vote;
	size_t _len_vote = sizeof(uvote_t);
	uvote_t* _in_vote = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_vote, _len_vote);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_vote != NULL && _len_vote != 0) {
		_in_vote = (uvote_t*)malloc(_len_vote);
		if (_in_vote == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vote, _len_vote, _tmp_vote, _len_vote)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = TEEaccumSp(_in_vote, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_vote) free(_in_vote);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_COMB_TEEsign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_COMB_TEEsign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_COMB_TEEsign_t* ms = SGX_CAST(ms_COMB_TEEsign_t*, pms);
	ms_COMB_TEEsign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_COMB_TEEsign_t), ms, sizeof(ms_COMB_TEEsign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		if ((_in_just = (just_t*)malloc(_len_just)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_just, 0, _len_just);
	}
	_in_retval = COMB_TEEsign(_in_just);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_just) {
		if (memcpy_verw_s(_tmp_just, _len_just, _in_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	return status;
}

static sgx_status_t SGX_CDECL sgx_COMB_TEEprepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_COMB_TEEprepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_COMB_TEEprepare_t* ms = SGX_CAST(ms_COMB_TEEprepare_t*, pms);
	ms_COMB_TEEprepare_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_COMB_TEEprepare_t), ms, sizeof(ms_COMB_TEEprepare_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(hash_t);
	hash_t* _in_hash = NULL;
	accum_t* _tmp_acc = __in_ms.ms_acc;
	size_t _len_acc = sizeof(accum_t);
	accum_t* _in_acc = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);
	CHECK_UNIQUE_POINTER(_tmp_acc, _len_acc);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_hash != NULL && _len_hash != 0) {
		_in_hash = (hash_t*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_acc != NULL && _len_acc != 0) {
		_in_acc = (accum_t*)malloc(_len_acc);
		if (_in_acc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_acc, _len_acc, _tmp_acc, _len_acc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = COMB_TEEprepare(_in_hash, _in_acc, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_hash) free(_in_hash);
	if (_in_acc) free(_in_acc);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_COMB_TEEstore(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_COMB_TEEstore_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_COMB_TEEstore_t* ms = SGX_CAST(ms_COMB_TEEstore_t*, pms);
	ms_COMB_TEEstore_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_COMB_TEEstore_t), ms, sizeof(ms_COMB_TEEstore_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (just_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = COMB_TEEstore(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_COMB_TEEaccum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_COMB_TEEaccum_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_COMB_TEEaccum_t* ms = SGX_CAST(ms_COMB_TEEaccum_t*, pms);
	ms_COMB_TEEaccum_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_COMB_TEEaccum_t), ms, sizeof(ms_COMB_TEEaccum_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	onejusts_t* _tmp_js = __in_ms.ms_js;
	size_t _len_js = sizeof(onejusts_t);
	onejusts_t* _in_js = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_js, _len_js);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_js != NULL && _len_js != 0) {
		_in_js = (onejusts_t*)malloc(_len_js);
		if (_in_js == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_js, _len_js, _tmp_js, _len_js)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = COMB_TEEaccum(_in_js, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_js) free(_in_js);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_COMB_TEEaccumSp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_COMB_TEEaccumSp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_COMB_TEEaccumSp_t* ms = SGX_CAST(ms_COMB_TEEaccumSp_t*, pms);
	ms_COMB_TEEaccumSp_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_COMB_TEEaccumSp_t), ms, sizeof(ms_COMB_TEEaccumSp_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (just_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = COMB_TEEaccumSp(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEauth(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEauth_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEauth_t* ms = SGX_CAST(ms_FREE_TEEauth_t*, pms);
	ms_FREE_TEEauth_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEauth_t), ms, sizeof(ms_FREE_TEEauth_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	payload_t* _tmp_text = __in_ms.ms_text;
	size_t _len_text = sizeof(payload_t);
	payload_t* _in_text = NULL;
	auth_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(auth_t);
	auth_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_text, _len_text);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_text != NULL && _len_text != 0) {
		_in_text = (payload_t*)malloc(_len_text);
		if (_in_text == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text, _len_text, _tmp_text, _len_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (auth_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEauth(_in_text, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_text) free(_in_text);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEverify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEverify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEverify_t* ms = SGX_CAST(ms_FREE_TEEverify_t*, pms);
	ms_FREE_TEEverify_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEverify_t), ms, sizeof(ms_FREE_TEEverify_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	payload_t* _tmp_text = __in_ms.ms_text;
	size_t _len_text = sizeof(payload_t);
	payload_t* _in_text = NULL;
	auths_t* _tmp_a = __in_ms.ms_a;
	size_t _len_a = sizeof(auths_t);
	auths_t* _in_a = NULL;
	bool* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(bool);
	bool* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_text, _len_text);
	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_text != NULL && _len_text != 0) {
		_in_text = (payload_t*)malloc(_len_text);
		if (_in_text == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text, _len_text, _tmp_text, _len_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_a != NULL && _len_a != 0) {
		_in_a = (auths_t*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (bool*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEverify(_in_text, _in_a, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_text) free(_in_text);
	if (_in_a) free(_in_a);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEverify2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEverify2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEverify2_t* ms = SGX_CAST(ms_FREE_TEEverify2_t*, pms);
	ms_FREE_TEEverify2_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEverify2_t), ms, sizeof(ms_FREE_TEEverify2_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	payload_t* _tmp_text1 = __in_ms.ms_text1;
	size_t _len_text1 = sizeof(payload_t);
	payload_t* _in_text1 = NULL;
	auths_t* _tmp_a1 = __in_ms.ms_a1;
	size_t _len_a1 = sizeof(auths_t);
	auths_t* _in_a1 = NULL;
	payload_t* _tmp_text2 = __in_ms.ms_text2;
	size_t _len_text2 = sizeof(payload_t);
	payload_t* _in_text2 = NULL;
	auths_t* _tmp_a2 = __in_ms.ms_a2;
	size_t _len_a2 = sizeof(auths_t);
	auths_t* _in_a2 = NULL;
	bool* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(bool);
	bool* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_text1, _len_text1);
	CHECK_UNIQUE_POINTER(_tmp_a1, _len_a1);
	CHECK_UNIQUE_POINTER(_tmp_text2, _len_text2);
	CHECK_UNIQUE_POINTER(_tmp_a2, _len_a2);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_text1 != NULL && _len_text1 != 0) {
		_in_text1 = (payload_t*)malloc(_len_text1);
		if (_in_text1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text1, _len_text1, _tmp_text1, _len_text1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_a1 != NULL && _len_a1 != 0) {
		_in_a1 = (auths_t*)malloc(_len_a1);
		if (_in_a1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a1, _len_a1, _tmp_a1, _len_a1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_text2 != NULL && _len_text2 != 0) {
		_in_text2 = (payload_t*)malloc(_len_text2);
		if (_in_text2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text2, _len_text2, _tmp_text2, _len_text2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_a2 != NULL && _len_a2 != 0) {
		_in_a2 = (auths_t*)malloc(_len_a2);
		if (_in_a2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a2, _len_a2, _tmp_a2, _len_a2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (bool*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEverify2(_in_text1, _in_a1, _in_text2, _in_a2, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_text1) free(_in_text1);
	if (_in_a1) free(_in_a1);
	if (_in_text2) free(_in_text2);
	if (_in_a2) free(_in_a2);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEstore(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEstore_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEstore_t* ms = SGX_CAST(ms_FREE_TEEstore_t*, pms);
	ms_FREE_TEEstore_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEstore_t), ms, sizeof(ms_FREE_TEEstore_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	pjust_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(pjust_t);
	pjust_t* _in_just = NULL;
	fvjust_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(fvjust_t);
	fvjust_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (pjust_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (fvjust_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEstore(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEaccum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEaccum_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEaccum_t* ms = SGX_CAST(ms_FREE_TEEaccum_t*, pms);
	ms_FREE_TEEaccum_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEaccum_t), ms, sizeof(ms_FREE_TEEaccum_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	fjust_t* _tmp_j = __in_ms.ms_j;
	size_t _len_j = sizeof(fjust_t);
	fjust_t* _in_j = NULL;
	fjusts_t* _tmp_js = __in_ms.ms_js;
	size_t _len_js = sizeof(fjusts_t);
	fjusts_t* _in_js = NULL;
	hash_t* _tmp_prp = __in_ms.ms_prp;
	size_t _len_prp = sizeof(hash_t);
	hash_t* _in_prp = NULL;
	haccum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(haccum_t);
	haccum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_j, _len_j);
	CHECK_UNIQUE_POINTER(_tmp_js, _len_js);
	CHECK_UNIQUE_POINTER(_tmp_prp, _len_prp);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_j != NULL && _len_j != 0) {
		_in_j = (fjust_t*)malloc(_len_j);
		if (_in_j == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_j, _len_j, _tmp_j, _len_j)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_js != NULL && _len_js != 0) {
		_in_js = (fjusts_t*)malloc(_len_js);
		if (_in_js == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_js, _len_js, _tmp_js, _len_js)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_prp != NULL && _len_prp != 0) {
		_in_prp = (hash_t*)malloc(_len_prp);
		if (_in_prp == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_prp, _len_prp, _tmp_prp, _len_prp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (haccum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEaccum(_in_j, _in_js, _in_prp, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_j) free(_in_j);
	if (_in_js) free(_in_js);
	if (_in_prp) free(_in_prp);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_TEEaccumSp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_TEEaccumSp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_TEEaccumSp_t* ms = SGX_CAST(ms_FREE_TEEaccumSp_t*, pms);
	ms_FREE_TEEaccumSp_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_TEEaccumSp_t), ms, sizeof(ms_FREE_TEEaccumSp_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	ofjust_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(ofjust_t);
	ofjust_t* _in_just = NULL;
	hash_t* _tmp_prp = __in_ms.ms_prp;
	size_t _len_prp = sizeof(hash_t);
	hash_t* _in_prp = NULL;
	haccum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(haccum_t);
	haccum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_prp, _len_prp);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (ofjust_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_prp != NULL && _len_prp != 0) {
		_in_prp = (hash_t*)malloc(_len_prp);
		if (_in_prp == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_prp, _len_prp, _tmp_prp, _len_prp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (haccum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = FREE_TEEaccumSp(_in_just, _in_prp, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_prp) free(_in_prp);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_FREE_initialize_variables(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_FREE_initialize_variables_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_FREE_initialize_variables_t* ms = SGX_CAST(ms_FREE_initialize_variables_t*, pms);
	ms_FREE_initialize_variables_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_FREE_initialize_variables_t), ms, sizeof(ms_FREE_initialize_variables_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	PID* _tmp_me = __in_ms.ms_me;
	size_t _len_me = sizeof(PID);
	PID* _in_me = NULL;
	unsigned int* _tmp_q = __in_ms.ms_q;
	size_t _len_q = sizeof(unsigned int);
	unsigned int* _in_q = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_me, _len_me);
	CHECK_UNIQUE_POINTER(_tmp_q, _len_q);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_me != NULL && _len_me != 0) {
		_in_me = (PID*)malloc(_len_me);
		if (_in_me == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_me, _len_me, _tmp_me, _len_me)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q != NULL && _len_q != 0) {
		if ( _len_q % sizeof(*_tmp_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q = (unsigned int*)malloc(_len_q);
		if (_in_q == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q, _len_q, _tmp_q, _len_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = FREE_initialize_variables(_in_me, _in_q);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_me) free(_in_me);
	if (_in_q) free(_in_q);
	return status;
}

static sgx_status_t SGX_CDECL sgx_OP_TEEverify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_OP_TEEverify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_OP_TEEverify_t* ms = SGX_CAST(ms_OP_TEEverify_t*, pms);
	ms_OP_TEEverify_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_OP_TEEverify_t), ms, sizeof(ms_OP_TEEverify_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	payload_t* _tmp_text = __in_ms.ms_text;
	size_t _len_text = sizeof(payload_t);
	payload_t* _in_text = NULL;
	auths_t* _tmp_a = __in_ms.ms_a;
	size_t _len_a = sizeof(auths_t);
	auths_t* _in_a = NULL;
	bool* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(bool);
	bool* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_text, _len_text);
	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_text != NULL && _len_text != 0) {
		_in_text = (payload_t*)malloc(_len_text);
		if (_in_text == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text, _len_text, _tmp_text, _len_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_a != NULL && _len_a != 0) {
		_in_a = (auths_t*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (bool*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = OP_TEEverify(_in_text, _in_a, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_text) free(_in_text);
	if (_in_a) free(_in_a);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_OP_TEEprepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_OP_TEEprepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_OP_TEEprepare_t* ms = SGX_CAST(ms_OP_TEEprepare_t*, pms);
	ms_OP_TEEprepare_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_OP_TEEprepare_t), ms, sizeof(ms_OP_TEEprepare_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(hash_t);
	hash_t* _in_hash = NULL;
	opproposal_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(opproposal_t);
	opproposal_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_hash != NULL && _len_hash != 0) {
		_in_hash = (hash_t*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (opproposal_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = OP_TEEprepare(_in_hash, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_hash) free(_in_hash);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_OP_TEEvote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_OP_TEEvote_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_OP_TEEvote_t* ms = SGX_CAST(ms_OP_TEEvote_t*, pms);
	ms_OP_TEEvote_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_OP_TEEvote_t), ms, sizeof(ms_OP_TEEvote_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(hash_t);
	hash_t* _in_hash = NULL;
	opvote_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(opvote_t);
	opvote_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_hash != NULL && _len_hash != 0) {
		_in_hash = (hash_t*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (opvote_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = OP_TEEvote(_in_hash, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_hash) free(_in_hash);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_OP_TEEstore(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_OP_TEEstore_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_OP_TEEstore_t* ms = SGX_CAST(ms_OP_TEEstore_t*, pms);
	ms_OP_TEEstore_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_OP_TEEstore_t), ms, sizeof(ms_OP_TEEstore_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	opproposal_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(opproposal_t);
	opproposal_t* _in_just = NULL;
	opstore_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(opstore_t);
	opstore_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (opproposal_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (opstore_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = OP_TEEstore(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_OP_initialize_variables(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_OP_initialize_variables_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_OP_initialize_variables_t* ms = SGX_CAST(ms_OP_initialize_variables_t*, pms);
	ms_OP_initialize_variables_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_OP_initialize_variables_t), ms, sizeof(ms_OP_initialize_variables_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	PID* _tmp_me = __in_ms.ms_me;
	size_t _len_me = sizeof(PID);
	PID* _in_me = NULL;
	unsigned int* _tmp_q = __in_ms.ms_q;
	size_t _len_q = sizeof(unsigned int);
	unsigned int* _in_q = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_me, _len_me);
	CHECK_UNIQUE_POINTER(_tmp_q, _len_q);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_me != NULL && _len_me != 0) {
		_in_me = (PID*)malloc(_len_me);
		if (_in_me == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_me, _len_me, _tmp_me, _len_me)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q != NULL && _len_q != 0) {
		if ( _len_q % sizeof(*_tmp_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q = (unsigned int*)malloc(_len_q);
		if (_in_q == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q, _len_q, _tmp_q, _len_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = OP_initialize_variables(_in_me, _in_q);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_me) free(_in_me);
	if (_in_q) free(_in_q);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_TEEsign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_TEEsign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_TEEsign_t* ms = SGX_CAST(ms_CH_TEEsign_t*, pms);
	ms_CH_TEEsign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_TEEsign_t), ms, sizeof(ms_CH_TEEsign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		if ((_in_just = (just_t*)malloc(_len_just)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_just, 0, _len_just);
	}
	_in_retval = CH_TEEsign(_in_just);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_just) {
		if (memcpy_verw_s(_tmp_just, _len_just, _in_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_TEEprepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_TEEprepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_TEEprepare_t* ms = SGX_CAST(ms_CH_TEEprepare_t*, pms);
	ms_CH_TEEprepare_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_TEEprepare_t), ms, sizeof(ms_CH_TEEprepare_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	jblock_t* _tmp_block = __in_ms.ms_block;
	size_t _len_block = sizeof(jblock_t);
	jblock_t* _in_block = NULL;
	jblock_t* _tmp_block0 = __in_ms.ms_block0;
	size_t _len_block0 = sizeof(jblock_t);
	jblock_t* _in_block0 = NULL;
	jblock_t* _tmp_block1 = __in_ms.ms_block1;
	size_t _len_block1 = sizeof(jblock_t);
	jblock_t* _in_block1 = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_block, _len_block);
	CHECK_UNIQUE_POINTER(_tmp_block0, _len_block0);
	CHECK_UNIQUE_POINTER(_tmp_block1, _len_block1);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_block != NULL && _len_block != 0) {
		_in_block = (jblock_t*)malloc(_len_block);
		if (_in_block == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_block, _len_block, _tmp_block, _len_block)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_block0 != NULL && _len_block0 != 0) {
		_in_block0 = (jblock_t*)malloc(_len_block0);
		if (_in_block0 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_block0, _len_block0, _tmp_block0, _len_block0)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_block1 != NULL && _len_block1 != 0) {
		_in_block1 = (jblock_t*)malloc(_len_block1);
		if (_in_block1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_block1, _len_block1, _tmp_block1, _len_block1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = CH_TEEprepare(_in_block, _in_block0, _in_block1, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_block) free(_in_block);
	if (_in_block0) free(_in_block0);
	if (_in_block1) free(_in_block1);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_COMB_TEEsign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_COMB_TEEsign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_COMB_TEEsign_t* ms = SGX_CAST(ms_CH_COMB_TEEsign_t*, pms);
	ms_CH_COMB_TEEsign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_COMB_TEEsign_t), ms, sizeof(ms_CH_COMB_TEEsign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		if ((_in_just = (just_t*)malloc(_len_just)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_just, 0, _len_just);
	}
	_in_retval = CH_COMB_TEEsign(_in_just);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_just) {
		if (memcpy_verw_s(_tmp_just, _len_just, _in_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_COMB_TEEprepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_COMB_TEEprepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_COMB_TEEprepare_t* ms = SGX_CAST(ms_CH_COMB_TEEprepare_t*, pms);
	ms_CH_COMB_TEEprepare_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_COMB_TEEprepare_t), ms, sizeof(ms_CH_COMB_TEEprepare_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	cblock_t* _tmp_block = __in_ms.ms_block;
	size_t _len_block = sizeof(cblock_t);
	cblock_t* _in_block = NULL;
	hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(hash_t);
	hash_t* _in_hash = NULL;
	just_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(just_t);
	just_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_block, _len_block);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_block != NULL && _len_block != 0) {
		_in_block = (cblock_t*)malloc(_len_block);
		if (_in_block == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_block, _len_block, _tmp_block, _len_block)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		_in_hash = (hash_t*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (just_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = CH_COMB_TEEprepare(_in_block, _in_hash, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_block) free(_in_block);
	if (_in_hash) free(_in_hash);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_COMB_TEEaccum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_COMB_TEEaccum_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_COMB_TEEaccum_t* ms = SGX_CAST(ms_CH_COMB_TEEaccum_t*, pms);
	ms_CH_COMB_TEEaccum_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_COMB_TEEaccum_t), ms, sizeof(ms_CH_COMB_TEEaccum_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	onejusts_t* _tmp_js = __in_ms.ms_js;
	size_t _len_js = sizeof(onejusts_t);
	onejusts_t* _in_js = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_js, _len_js);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_js != NULL && _len_js != 0) {
		_in_js = (onejusts_t*)malloc(_len_js);
		if (_in_js == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_js, _len_js, _tmp_js, _len_js)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = CH_COMB_TEEaccum(_in_js, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_js) free(_in_js);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_CH_COMB_TEEaccumSp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_CH_COMB_TEEaccumSp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_CH_COMB_TEEaccumSp_t* ms = SGX_CAST(ms_CH_COMB_TEEaccumSp_t*, pms);
	ms_CH_COMB_TEEaccumSp_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_CH_COMB_TEEaccumSp_t), ms, sizeof(ms_CH_COMB_TEEaccumSp_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	just_t* _tmp_just = __in_ms.ms_just;
	size_t _len_just = sizeof(just_t);
	just_t* _in_just = NULL;
	accum_t* _tmp_res = __in_ms.ms_res;
	size_t _len_res = sizeof(accum_t);
	accum_t* _in_res = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_just, _len_just);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_just != NULL && _len_just != 0) {
		_in_just = (just_t*)malloc(_len_just);
		if (_in_just == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_just, _len_just, _tmp_just, _len_just)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (accum_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	_in_retval = CH_COMB_TEEaccumSp(_in_just, _in_res);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res) {
		if (memcpy_verw_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_just) free(_in_just);
	if (_in_res) free(_in_res);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[29];
} g_ecall_table = {
	29,
	{
		{(void*)(uintptr_t)sgx_initialize_variables, 0, 0},
		{(void*)(uintptr_t)sgx_TEEsign, 0, 0},
		{(void*)(uintptr_t)sgx_TEEprepare, 0, 0},
		{(void*)(uintptr_t)sgx_TEEstore, 0, 0},
		{(void*)(uintptr_t)sgx_TEEaccum, 0, 0},
		{(void*)(uintptr_t)sgx_TEEaccumSp, 0, 0},
		{(void*)(uintptr_t)sgx_COMB_TEEsign, 0, 0},
		{(void*)(uintptr_t)sgx_COMB_TEEprepare, 0, 0},
		{(void*)(uintptr_t)sgx_COMB_TEEstore, 0, 0},
		{(void*)(uintptr_t)sgx_COMB_TEEaccum, 0, 0},
		{(void*)(uintptr_t)sgx_COMB_TEEaccumSp, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEauth, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEverify, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEverify2, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEstore, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEaccum, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_TEEaccumSp, 0, 0},
		{(void*)(uintptr_t)sgx_FREE_initialize_variables, 0, 0},
		{(void*)(uintptr_t)sgx_OP_TEEverify, 0, 0},
		{(void*)(uintptr_t)sgx_OP_TEEprepare, 0, 0},
		{(void*)(uintptr_t)sgx_OP_TEEvote, 0, 0},
		{(void*)(uintptr_t)sgx_OP_TEEstore, 0, 0},
		{(void*)(uintptr_t)sgx_OP_initialize_variables, 0, 0},
		{(void*)(uintptr_t)sgx_CH_TEEsign, 0, 0},
		{(void*)(uintptr_t)sgx_CH_TEEprepare, 0, 0},
		{(void*)(uintptr_t)sgx_CH_COMB_TEEsign, 0, 0},
		{(void*)(uintptr_t)sgx_CH_COMB_TEEprepare, 0, 0},
		{(void*)(uintptr_t)sgx_CH_COMB_TEEaccum, 0, 0},
		{(void*)(uintptr_t)sgx_CH_COMB_TEEaccumSp, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[14][29];
} g_dyn_entry_table = {
	14,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_test(KEY* key)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_key = sizeof(KEY);

	ms_ocall_test_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_test_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(key, _len_key);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_test_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_test_t));
	ocalloc_size -= sizeof(ms_ocall_test_t);

	if (key != NULL) {
		if (memcpy_verw_s(&ms->ms_key, sizeof(KEY*), &__tmp, sizeof(KEY*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setCtime(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(2, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_recCStime(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(3, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_recCVtime(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(4, NULL);

	return status;
}
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		if (memcpy_verw_s(&ms->ms_timeptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeptr = __tmp;
		memset_verw(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_timeb_len, sizeof(ms->ms_timeb_len), &timeb_len, sizeof(timeb_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

