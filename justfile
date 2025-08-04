image := "quay.io/fedora/fedora-coreos:42.20250705.3.0"

test-container: prepare-test-env get-reference-values
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo build
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/target/debug/:/var/srv \
        {{image}} \
        /var/srv/compute-pcrs all \
        > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr4.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

get-reference-values:
    #!/bin/bash
    set -euo pipefail
    if [ ! -d test-data ]; then
        git clone git@github.com:confidential-clusters/reference-values.git test-data
    fi

get-test-data:
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test-data/6.15.4-200.fc42.x86_64
    podman run --rm -ti \
        --security-opt label=disable \
        -v $PWD/test-data:/var/srv:rw \
        {{image}} \
        cp -a \
            /usr/lib/bootupd/updates/EFI \
            /var/srv
    podman run --rm -ti \
        --security-opt label=disable \
        -v $PWD/test-data:/var/srv:rw \
        {{image}} \
        cp \
            /usr/lib/modules/6.15.4-200.fc42.x86_64/vmlinuz \
            /var/srv/6.15.4-200.fc42.x86_64

prepare-test-env:
    #!/bin/bash
    set -euo pipefail
    mkdir -p test

prepare-test-env-local: get-reference-values prepare-test-env get-test-data

clean-tests:
    #!/bin/bash
    set -euo pipefail
    rm -rf test-data test

test-vmlinuz: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr4 -k test-data -e test-data

test-uki: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr11 uki

