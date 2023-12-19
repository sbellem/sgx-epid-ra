##############################################################################
#                                                                            #
#                            Build enclave (trusted)                         #
#                                                                            #
##############################################################################
FROM  nixpkgs/cachix-flakes AS build-enclave

WORKDIR /usr/src

COPY . .

RUN set -eux; \
    \
    mkdir -p ~/.config/nixpkgs; \
    echo "{ permittedInsecurePackages = [ \"openssl-1.1.1u\" ]; }" \
        >> ~/.config/nixpkgs/config.nix;

RUN cachix use gluonixpkgs
RUN nix build --impure


FROM ghcr.io/initc3/sgx:2.19-jammy as run-app

RUN apt-get update && apt-get install -y \
                autotools-dev \
                automake \
                xxd \
                iputils-ping \
                python3.11 \
                python3.11-dev \
                python3-pip \
                python-is-python3 \
                vim \
        && rm -rf /var/lib/apt/lists/*

RUN pip install ipython requests pyyaml web3

WORKDIR /usr/src/sgx_epid_ra

ENV PATH ${PATH}:${SGX_SDK}/bin:${SGX_SDK}/bin/x64
ENV PKG_CONFIG_PATH ${SGX_SDK}/pkgconfig
ENV LD_LIBRARY_PATH ${SGX_SDK}/sdk_libs

COPY . .

RUN set -eux; \
    ./bootstrap; \
    ./configure --with-sgxsdk=${SGX_SDK}; \
    make;

# Copy reproducible signed enclave build from build-enclave stage
COPY --from=build-enclave /usr/src/result/bin/Enclave.signed.so Enclave/Enclave.signed.so
