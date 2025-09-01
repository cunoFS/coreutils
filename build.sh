MY_CFLAGS=-Wno-error
## MY_CFLAGS="-Wno-error -O3 -g"
## MY_CFLAGS="-Wno-error -O0 -g"


if [ -f /etc/alpine-release ]; then
	make CFLAGS='-Wno-error -Wno-cpp' || true
fi

make clean
cd cpp_src
cp full-write-tmp.h ../lib/full-write.h
./build.sh
err=$?
cd ..
if [ $err  -ne 0 ] ; then
   exit $err
fi



echo MAKE the package
LDFLAG=-lstdc++ make CFLAGS="$MY_CFLAGS" -w  src/cp.o src/copy.o src/cp-hash.o src/extent-scan.o src/force-link.o src/selinux.o lib/test_print.o src/libver.a lib/libcoreutils.a
# I found that the extended debug CFLAGS somehow did not get used for the second, explicit make calls
# Useful arg V=1 prints the full compiler line.
##
#default make will fail for reasons i haven't diagnosed (the stdc++ link seeks to be ignored) fno-common a problem?
#in any case we need to add our extra cpp compiled objects built by cpp_src/build.sh
#lets just manually run a stripped version of the linker for now
#exit 1
echo EXPLICIT link of cp binary with extra assets
if [ ! -f /etc/alpine-release ]; then
	gcc -Werror -pthread -o src/cp src/cp.o src/copy.o src/cp-hash.o src/extent-scan.o src/force-link.o src/selinux.o lib/test_print.o src/libver.a lib/libcoreutils.a /opt/rh/devtoolset-6/root/usr/lib/gcc/x86_64-redhat-linux/6.3.1/libstdc++.a -lselinux -lrt -lacl -lattr
else
	clang -Wno-error -Wl,-Bstatic -static-libgcc -pthread -o src/cp src/cp.o src/copy.o src/cp-hash.o src/extent-scan.o src/force-link.o src/selinux.o lib/test_print.o src/libver.a dependencies/attr-2.5.1/.libs/libattr.a lib/libcoreutils.a /usr/lib/libstdc++.a /usr/lib/libselinux.a -Idependencies/gettext-0.19.2/gettext-tools/intl -lintl -lrt -lacl -lpcre -lsepol -lselinux -Wl,-Bdynamic
fi
