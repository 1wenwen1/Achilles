#!/bin/bash
set -e

apt update

tar -xvzf archive.tar.gz

curl -fsSL https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh | bash -s - install --auto --dkms -p metrics -p page0 -p version

DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
apt-get install -y build-essential python-is-python3
apt-get install -y libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
apt-get install -y libssl-dev libcurl4-openssl-dev libprotobuf-dev

# sdk
echo -e "no\n/opt/intel\n" | ./sgx_linux_x64_sdk_2.23.100.2.bin

# psw
tar -xvzf sgx_debian_local_repo.tar.gz
echo 'deb [trusted=yes arch=amd64] file:/root/sgx_debian_local_repo focal main' >> /etc/apt/sources.list
apt-get -o Acquire::GzipIndexes=false -o APT::Sandbox::User=root update
apt-get install -y libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex libsgx-dcap-ql

tar -xvzf sgxssl.tar.gz
mkdir -p /opt/intel/sgxssl//lib64/
mkdir -p /opt/intel/sgxssl//include/
cp -prf package/lib64//*  /opt/intel/sgxssl//lib64/
cp -prf package/include//* /opt/intel/sgxssl//include/

echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/opt/intel/sgxsdk/sdk_libs" >> ~/.bashrc
echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib" >> ~/.bashrc
source ~/.bashrc

echo "https://vsejgfb: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@github.com" > ~/.git-credentials
git config --global credential.helper store

sudo apt install -y cmake libuv1-dev libssl-dev
python3 -m pip install pathlib matplotlib
source /opt/intel/sgxsdk/environment

cd ~
mkdir resilientdb && cd resilientdb
mkdir obj
mkdir results

cd ~
git https://github.com/1wenwen1/Achilles.git
cd Achilles
git submodule init
git submodule update
(cd salticidae; cmake . -DCMAKE_INSTALL_PREFIX=.; make; make install)


apt install tpm2-tools
