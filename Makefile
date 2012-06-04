# apxs is required, is setup by installing apache from source

# uncomment to build without memcached support
# NO_MEMCACHED := 1

FLAGS := -l curl

ifeq ($(NO_MEMCACHED), 1)
FLAGS := $(FLAGS) -DNO_MEMCACHED
else
FLAGS := $(FLAGS) -l memcached
endif

.libs/mod_authnz_restauth.so: mod_authnz_restauth.c
	apxs2 -c $(FLAGS) mod_authnz_restauth.c

install: .libs/mod_authnz_restauth.so
	apxs2 -i -a -n authnz_restauth .libs/mod_authnz_restauth.so

clean:
	rm -rf mod_authnz_restauth.so mod_authnz_restauth.la mod_authnz_restauth.lo mod_authnz_restauth.slo mod_authnz_restauth.o .libs
