echo EXPLICIT compile of cpp module
gcc -lstdc++ -std=c++11 -pthread -c -o test_print.o file_rw.cpp -g -O3
mv test_print.o ../lib/test_print.o
