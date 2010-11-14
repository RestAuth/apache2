# apxs is required, is setup by installing apache from source

.libs/mod_authn_restauth.so: mod_authn_restauth.c
	apxs2 -c -l curl mod_authn_restauth.c

install: .libs/mod_authn_restauth.so
	apxs2 -i -a -n authn_restauth .libs/mod_authn_restauth.so

clean:
	rm -rf mod_authn_restauth.so mod_authn_restauth.la mod_authn_restauth.lo mod_authn_restauth.slo mod_authn_restauth.o .libs
