all:
	gcc -g -c dc_locate.c
	gcc -g -c lsa_cldap.c
	gcc -g -c lsa_srv.c
	gcc -g test_dc.c lsa_cldap.o lsa_srv.o dc_locate.o -lldap -lsocket -lnsl -lresolv -lcmdutils -lumem
