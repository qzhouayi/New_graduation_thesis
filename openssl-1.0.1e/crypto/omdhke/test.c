//old
BIGNUM *Egcd(const BIGNUM *n, const BIGNUM *m, BIGNUM *x, BIGNUM *y)
	{
		//print_bn("n", n);
		//print_bn("m", m);
		
	BIGNUM *value = BN_new();
	BIGNUM *temp = BN_new();
	BIGNUM *t1 = BN_new();
	BIGNUM *t2 = BN_new();
	BIGNUM *new_m = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	
	if (BN_is_zero(m))
		{
		BN_set_word(x, 1);
		BN_set_word(y, 0);
		value = BN_dup(n);
		
		//print_bn("x", x);
		//print_bn("y", y);
	
		return value;
		}	
		
	BN_mod(new_m, n, m, ctx);
	//printf("called once\n");
	value = BN_dup(Egcd(m, new_m, x, y));
	
	print_bn("n", n);
	print_bn("m", m);
	print_bn("old_x", x);
	print_bn("old_y", y);
	
	temp = BN_dup(x);
	
	x = BN_dup(y);
	
	/* y = temp - (n/m) * y */
	BN_div(t1, NULL, n, m, ctx);
	BN_mul(t2, t1, y, ctx);
	BN_sub(y, temp, t2);
	
	print_bn("x", x);
	print_bn("y", y);
	
	return value;
	}
