**NOTE**: Experimental work-in-progress repository based on Intel's original
[sgx-ra-sample](https://github.com/intel/sgx-ra-sample) repository. The goal is to
provide a minimal client example that only requests a quote from an enclave. The server
component that communicates with Intel's attestation service has been removed.

# SGX Quote Generation

<!--
* [Introduction](#intro)
* [What's New](#new)
* [License](#license)
* [Building](#build)
  * [Linux*](#build-linux)
    * [Linux build notes](#build-linux-notes)
* [Running (Quick-start)](#running-quick)
* [Running (Advanced)](#running-adv)
* [Sample Output](#output)

## <a name="intro"></a>Introduction
-->
This code sample demonstrates a simple client requesting a quote from an enclave. Upon
receiving the quote from the enclave, the client dumps it to the terminal. It could be
sent to Intel's Attestation Service (IAS) by another component.

A docker-compose based development environment is provided, and is the recommended way
to try this sample, as it has not been tested on other platforms. See the Quickstart
section just below to see how to try it.

## <a name="quickstart"></a>Quickstart
### Prerequisites
* You need [docker](https://docs.docker.com/engine/install/) and
  [docker compose](https://docs.docker.com/compose/install/).

* The docker-based development environment assumes it is running on an SGX-enabled
  processor. If you are not sure whether your computer supports SGX, and/or how to
  enable it, see https://github.com/ayeks/SGX-hardware#test-sgx.

* Obtain a **linkable** subscription key for the
  [Intel SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/).

* Optionally, you can install [nix](https://nixos.org/download.html#nix-quick-install).

#### Set Environment Variables
* Edit the `settings` file to add your `SPID`, `IAS_PRIMARY_SUBSCRIPTION_KEY`
  **DO NOT COMMIT changes for this file, as it will
  contain secret data, namely your subscription keys.**

To interact with IAS via Python code, before starting a container, set the two
following environment variables:

* `SGX_SPID` - used to create a quote
* `IAS_PRIMARY_KEY` - used to access Intel's Attestation Service (IAS)

```shell
export SGX_SPID=<your-SPID>
export IAS_PRIMARY_KEY=<your-ias-primary-key>
```

Alternatively, you can place the environment variables in a `.env` file, under
the root of the repository. **NOTE** that the `IAS_PRIMARY_KEY` **MUST** be kept
secret. Consequently, the file `.env` is not tracked by git, as it **MUST NOT** be
uploaded to a public repository, such as on GitHub.

```shell
# .env sample
SGX_SPID=<your-SPID>
IAS_PRIMARY_KEY=<your-ias-primary-key>
```

Build the image, (for the client code):

```shell
$ docker compose build
```

#### Note about building the enclave
The `Dockerfile`, takes care of building the enclave (`Enclave.signed.so`)
in a reproducible manner using `nix`. For convenience it is done in the docker image,
but it could also be built *just* with `nix`. See the `Dockerfile` for the details on
how to do so.

### Quote Generation
Generate a quote:

```console
docker compose run --rm genquote ipython
```
```python
from epidcontest import gen_quote

addr = '0x00000000000000000000000000000000000000a0'
msg = 'hey'

quote = gen_quote(addr, msg)
```

Verify the quote

```python
from epidcontest import verify_epid

>>> verify_epid(quote=quote)
['610B0000',
 b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0                                         hey']
```
