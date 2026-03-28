use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let sock_syscalls_strings = vec![
        "socket",
        "bind",
        "connect",
        "listen",
        "accept",
        "getsockname",
        "getpeername",
        "socketpair",
        "sendto",
        "recvfrom",
        "sendto",
        "recvfrom",
        "shutdown",
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
        "accept4",
        "sendmmsg",
        "recvmmsg",
    ];

    let mut sock_syscalls = Vec::new();
    for sock_syscall in sock_syscalls_strings {
        sock_syscalls.push(
            LinuxSyscallBuilder::default()
                .action(LinuxSeccompAction::ScmpActAllow)
                .names(vec![sock_syscall.to_string()])
                .build()?,
        )
    }

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(sock_syscalls)
        .build()?;
    let inst_data = SeccompProgramPlan::try_from(spec_seccomp)?;
    let mut seccomp = Seccomp::new();
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    seccomp.export_bpf(&mut io::stdout())?;

    Ok(())
}
