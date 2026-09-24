# Build for linux/arm64 from the resolved immutable image index.
FROM --platform=linux/arm64 golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git make gcc g++ python3 tar gzip unzip \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 user \
    && useradd --uid 1000 --gid 1000 --home /home/user --create-home --shell /bin/sh user

# The provider mounts a private 10 GiB ext4 volume over this directory; the
# image itself contains no GitHub or model credential material.
ENV HOME=/home/user GOTOOLCHAIN=local GOPATH=/home/user/go \
    GOCACHE=/home/user/.cache/go-build TMPDIR=/tmp
WORKDIR /home/user
USER 1000:1000
CMD ["/bin/sleep", "2147483647"]
