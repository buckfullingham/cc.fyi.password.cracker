FROM almalinux:8

RUN dnf -v -y update \
&&  dnf -v -y install \
    gcc-toolset-13 \
    llvm-toolset \
    git-core \
    python3-devel \
    cmake \
    gcc-toolset-13-libasan-devel \
    gcc-toolset-13-liblsan-devel \
    gcc-toolset-13-libtsan-devel \
    gcc-toolset-13-libubsan-devel \
    clang-tools-extra \
    perf \
    valgrind \
    systemtap-sdt-devel \
    tbb-devel \
&&  dnf -v -y clean all \
&&  pip3 install --upgrade 'conan<2'

ENV PATH=/opt/rh/gcc-toolset-13/root/bin:/usr/share/Modules/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/opt/rh/gcc-toolset-13/root/lib
