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
LDFLAG=-lstdc++ make src/cp
#default make will fail for reasons i haven't diagnosed (the stdc++ link seeks to be ignored) fno-common a problem?
#lets just manually run a stripped version of the linker for now
echo EXPLICIT link of cp binary
gcc -Werror -pthread -o src/cp src/cp.o src/copy.o src/cp-hash.o src/extent-scan.o src/force-link.o src/selinux.o lib/test_print.o src/libver.a lib/libcoreutils.a  lib/libcoreutils.a /opt/rh/devtoolset-6/root/usr/lib/gcc/x86_64-redhat-linux/6.3.1/libstdc++.a -lselinux -lrt -lacl -lattr
