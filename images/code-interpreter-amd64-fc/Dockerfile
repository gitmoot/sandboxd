# Root filesystem of the Firecracker E2B code-interpreter guest (linux/amd64),
# the image of the code-interpreter-v1 template. build.sh exports this image
# into a read-only ext4 file; it never runs as a container.
#
# The heavy layers translate make_template() (python, r, javascript, bash and
# java kernels, non-docker variant) of upstream e2b-dev/code-interpreter
# template/template.py at tag @e2b/code-interpreter-template@0.4.6 (commit
# 8d51873c, Apache-2.0, see /usr/share/doc/code-interpreter); build.sh puts
# that template/ directory into the build context as sbx-ci/template/.
# Differences from upstream: everything upstream leaves floating that can be
# pinned is pinned (marked "Pinned:"); apt installs skip recommended packages;
# package caches, apt lists, man/info pages, message catalogs, package docs
# (not copyright files) and the JDK's jmods/src.zip are removed; upstream's
# two systemd units are replaced by /root/.jupyter/sandboxd-start.sh (no
# systemd: the guest agent is PID 1). The last layers add the e2b guest
# contract of images/e2b-amd64-fc: e2fsprogs (the agent formats the writable
# root disk), guest agent, upstream envd 0.9.0, /etc/sandboxd/env, user
# 1000:1000 with passwordless sudo.
FROM --platform=linux/amd64 python:3.13@sha256:138ea0589fbe6c86a54ec0734b1183d2955f0531285254ea962feb0f1d4d920d

# Every RUN carries this marker so build.sh can find (and drop) exactly the
# build-cache entries of this image.
SHELL ["/usr/bin/env", "SBX_IMAGE=code-interpreter-amd64-fc", "/bin/bash", "-o", "pipefail", "-c"]

# Template.set_user("root").set_workdir("/root").set_envs(...)
WORKDIR /root
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    JAVA_VERSION=11 \
    IJAVA_VERSION=1.3.0 \
    R_VERSION=4.5.*
ENV JAVA_HOME=/usr/lib/jvm/jdk-${JAVA_VERSION}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive DEBCONF_NOWARNINGS=yes apt-get install -y --no-install-recommends \
        build-essential curl git util-linux jq sudo fonts-noto-cjk ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upstream pipes https://deb.nodesource.com/setup_20.x into bash. This is
# what that script configures (signing key, nodistro source, priority 600
# pins), with the key checked against its SHA-256. Pinned: nodejs version.
ARG NODESOURCE_GPG_SHA256=b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d
ARG NODEJS_VERSION=20.20.2-1nodesource1
RUN curl -fsSL -o /tmp/nodesource.key https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    && printf '%s  %s\n' "$NODESOURCE_GPG_SHA256" /tmp/nodesource.key | sha256sum -c --quiet - \
    && mkdir -p /usr/share/keyrings \
    && gpg --dearmor -o /usr/share/keyrings/nodesource.gpg </tmp/nodesource.key \
    && chmod 0644 /usr/share/keyrings/nodesource.gpg \
    && rm -f /tmp/nodesource.key \
    && printf '%s\n' 'Types: deb' 'URIs: https://deb.nodesource.com/node_20.x' 'Suites: nodistro' \
        'Components: main' 'Architectures: amd64' 'Signed-By: /usr/share/keyrings/nodesource.gpg' \
        >/etc/apt/sources.list.d/nodesource.sources \
    && printf '%s\n' 'Package: nsolid' 'Pin: origin deb.nodesource.com' 'Pin-Priority: 600' \
        >/etc/apt/preferences.d/nsolid \
    && printf '%s\n' 'Package: nodejs' 'Pin: origin deb.nodesource.com' 'Pin-Priority: 600' \
        >/etc/apt/preferences.d/nodejs \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive DEBCONF_NOWARNINGS=yes apt-get install -y --no-install-recommends \
        "nodejs=$NODEJS_VERSION" \
    && rm -rf /var/lib/apt/lists/*

# Pinned: upstream's requirements.txt leaves e2b_charts unpinned ("Latest
# version"); 1.0.0 is the latest release and the version of the repository's
# own chart_data_extractor at the template commit.
COPY sbx-ci/template/requirements.txt requirements.txt
RUN sed -i 's/^e2b_charts$/e2b_charts==1.0.0/' requirements.txt \
    && grep -qx 'e2b_charts==1.0.0' requirements.txt \
    && pip install --no-cache-dir -r requirements.txt

# Python kernel
RUN ipython kernel install --name 'python3' --user

# R kernel. Pinned: IRkernel and its CRAN dependencies come from the dated
# Posit Package Manager CRAN snapshot instead of the moving
# cloud.r-project.org (IRkernel 1.3.2 there).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive DEBCONF_NOWARNINGS=yes apt-get install -y --no-install-recommends \
        "r-base=${R_VERSION}" r-base-dev \
    && rm -rf /var/lib/apt/lists/* \
    && R -e "options(Ncpus = 4); install.packages('IRkernel', repos='https://packagemanager.posit.co/cran/2026-10-01')" \
    && R -e "IRkernel::installspec(user = FALSE, name = 'r', displayname = 'R')" \
    && rm -rf /tmp/Rtmp*

# JavaScript kernel. Pinned: e2b-dev/ijavascript at master commit 79cb7d56
# (upstream installs the moving default branch). Its own dependencies are
# not locked: the git dependencies e2b-dev/nel and e2b-dev/ijavascript-babel
# follow their default branches and @babel/* and jp-kernel resolve semver
# ranges (a global install of a git package has no lockfile to pin them).
ARG IJAVASCRIPT_COMMIT=79cb7d56dcfe0df9ff55eff0ca4dc920a6dcc361
RUN npm install -g --unsafe-perm "git+https://github.com/e2b-dev/ijavascript.git#$IJAVASCRIPT_COMMIT" \
    && ijsinstall --install=global \
    && npm cache clean --force \
    && rm -rf /root/.npm /root/.cache/node-gyp /tmp/npm-*

# Bash kernel. Pinned: bash_kernel 0.10.0 (upstream: unpinned).
RUN pip install --no-cache-dir bash_kernel==0.10.0 \
    && python -m bash_kernel.install

# Java 11 and the IJava kernel. The JDK SHA-256 is the one java.net publishes
# next to the tarball; IJava publishes none, so its zip is pinned to the
# observed SHA-256. The unpacked installer files are removed afterwards
# (install.py copies the kernel to /usr/local/share/jupyter/kernels/java),
# and so are the JDK's jmods and src.zip, which only jlink and IDEs read.
ARG JDK_SHA256=3784cfc4670f0d4c5482604c7c513beb1a92b005f569df9bf100e8bef6610f2e
ARG IJAVA_SHA256=484cc62579cb77510b0f0c78283f043794396d8ae9d76a8f2ab5d7368ec246b2
RUN mkdir -p /usr/lib/jvm \
    && curl -fsSL -o /tmp/openjdk.tar.gz "https://download.java.net/java/ga/jdk${JAVA_VERSION}/openjdk-${JAVA_VERSION}_linux-x64_bin.tar.gz" \
    && printf '%s  %s\n' "$JDK_SHA256" /tmp/openjdk.tar.gz | sha256sum -c --quiet - \
    && tar -xzf /tmp/openjdk.tar.gz -C /usr/lib/jvm \
    && rm -f /tmp/openjdk.tar.gz \
    && update-alternatives --install /usr/bin/java java "/usr/lib/jvm/jdk-${JAVA_VERSION}/bin/java" 1 \
    && update-alternatives --install /usr/bin/javac javac "/usr/lib/jvm/jdk-${JAVA_VERSION}/bin/javac" 1 \
    && curl -fsSL -o "ijava-${IJAVA_VERSION}.zip" "https://github.com/SpencerPark/IJava/releases/download/v${IJAVA_VERSION}/ijava-${IJAVA_VERSION}.zip" \
    && printf '%s  %s\n' "$IJAVA_SHA256" "ijava-${IJAVA_VERSION}.zip" | sha256sum -c --quiet - \
    && unzip -q "ijava-${IJAVA_VERSION}.zip" \
    && python install.py --sys-prefix \
    && rm -rf "ijava-${IJAVA_VERSION}.zip" install.py java \
        "/usr/lib/jvm/jdk-${JAVA_VERSION}/jmods" "/usr/lib/jvm/jdk-${JAVA_VERSION}/lib/src.zip"

# Code-interpreter server (FastAPI on port 49999) in its own virtualenv.
COPY sbx-ci/template/server .server
RUN python -m venv .server/.venv \
    && .server/.venv/bin/pip install --no-cache-dir -r .server/requirements.txt

# Configuration files
COPY sbx-ci/template/matplotlibrc .config/matplotlib/.matplotlibrc
COPY --chmod=0755 sbx-ci/template/jupyter-healthcheck.sh .jupyter/jupyter-healthcheck.sh
COPY sbx-ci/template/jupyter_server_config.py .jupyter/
COPY sbx-ci/template/ipython_kernel_config.py .ipython/profile_default/
COPY sbx-ci/template/startup_scripts .ipython/profile_default/startup

# Replaces template/systemd/jupyter.service + code-interpreter.service; see
# the script header for the start and ready contract.
COPY --chmod=0755 sbx-ci/sandboxd-start.sh .jupyter/sandboxd-start.sh

# Guest contract, as in images/e2b-amd64-fc: the tools the guest agent and
# E2B's base expect (mkfs.ext4 formats the writable root disk), and the
# guest user (E2B's base provides it upstream).
# Size: man and info pages, message catalogs and package documentation other
# than the copyright files go (about 200 MB).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive DEBCONF_NOWARNINGS=yes apt-get install -y --no-install-recommends \
        e2fsprogs iproute2 netbase procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 user \
    && useradd --uid 1000 --gid 1000 --home /home/user --create-home --shell /bin/bash user \
    && chmod 0755 /home/user \
    && usermod --shell /bin/bash root \
    && printf 'user ALL=(ALL:ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/user \
    && chmod 0440 /etc/sudoers.d/user \
    && rm -rf /usr/share/man /usr/share/info \
    && find /usr/share/locale -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + \
    && find /usr/share/doc -mindepth 1 ! -type d ! -name copyright -delete \
    && find /usr/share/doc -mindepth 1 -type d -empty -delete \
    && mkdir -p /etc/sandboxd /usr/share/doc/envd /usr/share/doc/code-interpreter

COPY sbx-ci/doc/code-interpreter/LICENSE sbx-ci/doc/code-interpreter/SOURCE /usr/share/doc/code-interpreter/

# PID 1: mounts the guest filesystems, sets up the writable root and starts
# envd (cmd/sandboxd-guest-agent).
COPY sbx-ci/sandboxd-guest-agent /sbin/sandboxd-agent

# E2B envd 0.9.0 release binary; build.sh verifies its SHA-256.
COPY sbx-ci/envd /usr/bin/envd
COPY sbx-ci/doc/envd/LICENSE sbx-ci/doc/envd/SOURCE /usr/share/doc/envd/

# The image environment, applied to every guest command (Dockerfile ENV is
# lost by the export). Request variables replace entries of the same name.
COPY sbx-ci/env /etc/sandboxd/env
