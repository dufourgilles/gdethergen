CC = cc


gdethergen: gdethergen.c gd_packet.o gd_util.o gd_parent.c gd_child.c gd_inject.c
	    $(CC) `libnet-config --defines` -o gdethergen gdethergen.c gd_packet.o gd_util.o `libnet-config --libs` -lpcap 

gd_packet.o: gd_packet.c gdethergen.h gd_packet.h

gd_util.o: gd_util.c gd_util.h gdethergen.h gd_packet.h



