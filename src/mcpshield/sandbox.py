"""Generate Linux and Kubernetes confinement configuration."""

import re

BASE = """arch_prctl brk clock_gettime close close_range dup dup2 dup3 execve
exit exit_group faccessat faccessat2 fcntl fstat futex getcwd getdents64 getegid
geteuid getgid getpid getrandom gettid getuid ioctl lseek madvise mmap mprotect
mremap munmap newfstatat openat pread64 prlimit64 read readlink readlinkat
rseq rt_sigaction rt_sigprocmask rt_sigreturn sched_getaffinity set_robust_list
set_tid_address sigaltstack statx uname write""".split()
NETWORK = "socket connect getsockopt setsockopt sendto recvfrom shutdown".split()


def seccomp(network=False):
    return {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{
        "names": sorted(BASE + (NETWORK if network else [])),
        "action": "SCMP_ACT_ALLOW",
    }]}


def kubernetes(name, image, namespace):
    for label in (name, namespace):
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", label):
            raise ValueError("invalid Kubernetes name or namespace")
    return [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": namespace, "labels": {
             "pod-security.kubernetes.io/enforce": "restricted"}}},
        {"apiVersion": "v1", "kind": "Pod",
         "metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
         "spec": {"runtimeClassName": "gvisor", "automountServiceAccountToken": False,
                  "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                      "seccompProfile": {"type": "RuntimeDefault"}},
                  "containers": [{"name": name, "image": image, "securityContext": {
                      "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                      "capabilities": {"drop": ["ALL"]}}}]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": name, "namespace": namespace},
         "spec": {"podSelector": {"matchLabels": {"app": name}},
                  "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}},
    ]
