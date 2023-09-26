mkdir dependencies
sudo yum install -y texinfo
sudo yum install -y help2man
sudo yum install -y gperf

cd dependencies
wget https://ftp.gnu.org/gnu/texinfo/texinfo-6.1.tar.gz --no-check-certificate
tar -xvzf texinfo-6.1.tar.gz

wget https://ftp.gnu.org/gnu/gettext/gettext-0.19.2.tar.gz --no-check-certificate
tar -xvzf gettext-0.19.2.tar.gz

git clone --depth=1 git://git.sv.gnu.org/autoconf.git
cd autoconf
git pull --tags
git checkout v2.64
autoreconf -vi
./configure --prefix=$prefix
sudo make install
cd ..

cd gettext-0.19.2
./configure
make
sudo make install
cd ..

cd texinfo-6.1
./configure
make
sudo make install
cd ..
cd ..

sed -i 's/wget/wget --no-check-certificate/g' bootstrap
./bootstrap
#NOTE: Need to remove bad C++ flag when compiling against g++
