# SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
# SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

image := "https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/42.20250705.3.0/x86_64/fedora-coreos-42.20250705.3.0-ostree.x86_64.ociarchive"
target_container_ociarchive_path := absolute_path(join("/tmp", file_name(image)))
target_container_name := without_extension(file_name(image))
container_image_name := "compute-pcrs"
skip_build := "false"

pull-target-container-image:
    #!/bin/bash
    set -euo pipefail
    if ! podman image exists {{target_container_name}}; then
        curl --skip-existing -o {{target_container_ociarchive_path}} {{image}}
        image_id=$(podman load -i {{target_container_ociarchive_path}} 2>/dev/null | awk -F ':' '{print $NF}')
        podman tag $image_id {{target_container_name}}
    fi

build-container:
    #!/bin/bash
    set -euo pipefail
    # set -x
    if ! podman image exists {{container_image_name}} || [ "{{skip_build}}" = "false" ]; then
        podman build . \
            --security-opt label=disable \
            -t {{container_image_name}}
    fi;

test-container: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs all \
            --kernels /var/srv/image/usr/lib/modules \
            --esp /var/srv/image/usr/lib/bootupd/updates \
            --efivars /var/srv/test-data/efivars/qemu-ovmf/fedora-42 \
            --mok-variables /var/srv/test-data/mok-variables/fedora-42 \
            > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/all-pcrs.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

get-reference-values:
    #!/bin/bash
    # set -x
    set -euo pipefail
    if [ ! -d test-data ]; then
        git clone git@github.com:confidential-clusters/reference-values.git test-data
    else
        cd test-data
        git pull --ff-only
    fi

prepare-test-env:
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test

prepare-test-deps: get-reference-values prepare-test-env build-container pull-target-container-image

clean-tests:
    #!/bin/bash
    set -euo pipefail
    # set -x
    rm -rf test-data test
    podman image rm {{target_container_name}}
    rm {{target_container_ociarchive_path}}

test-vmlinuz: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs pcr4 \
            --kernels /var/srv/image/usr/lib/modules \
            --esp /var/srv/image/usr/lib/bootupd/updates

test-uki: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs pcr11 uki \

test-secureboot-enabled: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs pcr7 \
            --esp /var/srv/image/usr/lib/bootupd/updates \
            --efivars /var/srv/test-data/efivars/qemu-ovmf/fedora-42 \
            > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr7-sb-enabled.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

test-secureboot-disabled: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test-data/efivars/qemu-ovmf/fedora-42-sb-disabled
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs pcr7 \
            --esp /var/srv/image/usr/lib/bootupd/updates \
            --efivars /var/srv/test-data/efivars/qemu-ovmf/fedora-42-sb-disabled \
            --secureboot-disabled \
            > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr7-sb-disabled.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

test-default-mok-keys: prepare-test-deps
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{target_container_name}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs pcr14 \
            --mok-variables /var/srv/test-data/mok-variables/fedora-42 \
            > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr14.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"
