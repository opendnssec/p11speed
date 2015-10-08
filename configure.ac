##################
#                #
#    Version     #
#                #
################

# Program version

define([P11SPEED_VERSION_MAJOR], [0])
define([P11SPEED_VERSION_MINOR], [1])
define([P11SPEED_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [])

##################
#                #
# Configure code #
#                #
##################

# Init
AC_PREREQ(2.61)
AC_INIT([p11speed],[P11SPEED_VERSION_MAJOR.P11SPEED_VERSION_MINOR.P11SPEED_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX

# Compiler flags
ACX_PEDANTIC
ACX_STRICT
ACX_64BIT
ACX_DESTRUCTOR

# Check for libraries
ACX_DLOPEN

# Check for headers
AC_CHECK_HEADERS([pthread.h])

# Set full directory paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

AC_DEFINE_UNQUOTED(
        [MAX_PIN_LEN],
        [255],
        [Maximum PIN length]
)
AC_DEFINE_UNQUOTED(
        [MIN_PIN_LEN],
        [4],
        [Minimum PIN length]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_PKCS11_LIB],
	["$full_libdir/softhsm/libsofthsm2.so"],
	[The default PKCS#11 library]
)

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/bin/Makefile
])

AC_OUTPUT
