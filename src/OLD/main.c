
static void *threadMD5(struct hashWidget_t *HashWidget){
	g_thread_new("t1", (GThreadFunc)compute_md5, HashWidget);
}

static void *threadSHA1(struct hashWidget_t *HashWidget){
	g_thread_new("t2", (GThreadFunc)compute_sha1, HashWidget);
}

static void *threadSHA256(struct hashWidget_t *HashWidget){
	g_thread_new("t3", (GThreadFunc)compute_sha256, HashWidget);
}

static void *threadSHA3_256(struct hashWidget_t *HashWidget){
	g_thread_new("t4", (GThreadFunc)compute_sha3_256, HashWidget);
}

static void *threadSHA512(struct hashWidget_t *HashWidget){
	g_thread_new("t5", (GThreadFunc)compute_sha512, HashWidget);
}

static void *threadSHA3_512(struct hashWidget_t *HashWidget){
	g_thread_new("t6", (GThreadFunc)compute_sha3_512, HashWidget);
}

static void *threadWHIRLPOOL(struct hashWidget_t *HashWidget){
	g_thread_new("t7", (GThreadFunc)compute_whirlpool, HashWidget);
}

static void *threadGOST94(struct hashWidget_t *HashWidget){
	g_thread_new("t8", (GThreadFunc)compute_gost94, HashWidget);
}
