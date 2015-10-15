MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/cryptoki_compat

dist_man_MANS =		p11speed.1

bin_PROGRAMS =		p11speed

AUTOMAKE_OPTIONS =	subdir-objects

p11speed_SOURCES =	p11speed.cpp \
			getpw.cpp \
			library.cpp
p11speed_LDADD =	-lpthread

EXTRA_DIST =		$(srcdir)/cryptoki_compat/*.h \
			$(srcdir)/*.h \
			$(srcdir)/*.cpp
