#!/bin/bash
# Supervisor of the code-interpreter guest, installed as
# /root/.jupyter/sandboxd-start.sh. Our guests have no systemd (the guest
# agent is PID 1), so this one script replaces upstream's
# template/systemd/jupyter.service and code-interpreter.service:
#   - Jupyter Server on 127.0.0.1:8888 (MATPLOTLIBRC set, stdout discarded),
#     restarted 1 s after it exits (Restart=on-failure, RestartSec=1);
#   - once /root/.jupyter/jupyter-healthcheck.sh passes, the code-interpreter
#     server (uvicorn, port 49999), restarted 1 s after it exits or after a
#     failed health check;
#   - when Jupyter exits, the code-interpreter server and the kernels Jupyter
#     started are stopped and everything starts again (PartOf=jupyter.service
#     plus the unit's control group).
# Contract with sandboxd: it runs this once per sandbox as root through envd
# (/bin/bash -l -c /root/.jupyter/sandboxd-start.sh), never waits for it and
# polls the ready command
#   curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:49999/health
# until it succeeds. The script runs in the foreground until killed; a second
# instance exits at once. Its messages go to /var/log/sandboxd-start.log,
# Jupyter's stderr to /var/log/jupyter.log and the server's output to
# /var/log/code-interpreter.log. None of its own command lines contain
# "jupyter server" or "uvicorn main:app", which upstream's tests pgrep for.
set -u

log_file=/var/log/sandboxd-start.log
jupyter_log=/var/log/jupyter.log
server_log=/var/log/code-interpreter.log
kernel_files=/root/.local/share/jupyter/runtime/kernel-

exec </dev/null >>"$log_file" 2>&1
exec 9>/run/sandboxd-start.lock
if ! flock -n 9; then
    echo "$(date -u +%FT%TZ) another supervisor is running; exiting"
    exit 0
fi

# Same environment whatever envd passed: root's, as under systemd, plus the
# template variables the kernels use.
export HOME=/root USER=root LOGNAME=root SHELL=/bin/bash
export PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C.UTF-8 TMPDIR=/tmp
export JAVA_HOME=/usr/lib/jvm/jdk-11
export PIP_DEFAULT_TIMEOUT=100 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1

log() { echo "$(date -u +%FT%TZ) $*"; }

# Keeps one previous generation of a service log over 10 MiB.
rotate() {
    if [ -f "$1" ] && [ "$(stat -c %s "$1")" -gt 10485760 ]; then
        mv -f "$1" "$1.1"
    fi
}

# Jupyter starts every kernel in its own session (process group), so the
# kernels outlive a killed Jupyter; systemd would have killed them with the
# unit's control group. Their command lines name their connection file.
kill_kernels() {
    local pid
    for pid in $(pgrep -f -- "$kernel_files"); do
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
        log "killed kernel $pid"
    done
}

# Stops child $1: SIGTERM, then SIGKILL after 5 s (systemd's stop, shorter).
stop_child() {
    local pid=$1 guard
    kill -TERM "$pid" 2>/dev/null || return 0
    (sleep 5; kill -KILL "$pid" 2>/dev/null) 9>&- &
    guard=$!
    wait "$pid" 2>/dev/null
    kill "$guard" 2>/dev/null
    wait "$guard" 2>/dev/null
}

# code-interpreter.service: runs in a subshell, stopped with SIGTERM.
code_interpreter() {
    local child= status
    trap '[ -z "$child" ] || stop_child "$child"; exit 0' TERM
    while :; do
        /root/.jupyter/jupyter-healthcheck.sh 9>&- &
        child=$!
        wait "$child"
        status=$?
        child=
        if [ "$status" -eq 0 ]; then
            rotate "$server_log"
            (cd /root/.server && exec .venv/bin/uvicorn main:app --host 0.0.0.0 --port 49999 \
                --workers 1 --no-access-log --no-use-colors --timeout-keep-alive 640) \
                >>"$server_log" 2>&1 9>&- &
            child=$!
            log "code-interpreter server started (pid $child)"
            wait "$child"
            status=$?
            child=
            log "code-interpreter server exited (status $status); restarting in 1 s"
        else
            log "jupyter health check failed (status $status); retrying in 1 s"
        fi
        sleep 1
    done
}

jupyter=
server=
shutdown() {
    log "supervisor stopping"
    [ -z "$server" ] || stop_child "$server"
    [ -z "$jupyter" ] || stop_child "$jupyter"
    kill_kernels
    exit 0
}
trap shutdown TERM INT HUP

log "supervisor started (pid $$)"
while :; do
    kill_kernels
    rotate "$jupyter_log"
    (cd / && MATPLOTLIBRC=/root/.config/matplotlib/.matplotlibrc \
        exec /usr/local/bin/jupyter server --IdentityProvider.token="") \
        >/dev/null 2>>"$jupyter_log" 9>&- &
    jupyter=$!
    log "jupyter started (pid $jupyter)"
    code_interpreter 9>&- &
    server=$!
    wait "$jupyter"
    status=$?
    jupyter=
    log "jupyter exited (status $status); stopping the code-interpreter server, restarting in 1 s"
    stop_child "$server"
    server=
    sleep 1
done
