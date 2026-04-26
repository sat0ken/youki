use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};
use seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use std::io;

fn main() -> anyhow::Result<()> {
    let syscall_arr: Vec<String> = vec![
        "semop",
        "semtimedop",
        "semget",
        "semctl",
        "msgsnd",
        "msgrcv",
        "msgget",
        "msgctl",
        "shmat",
        "shmdt",
        "shmget",
        "shmctl",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let syscalls = LinuxSyscallBuilder::default()
        .names(syscall_arr)
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()?;

    let spec_seccomp = LinuxSeccompBuilder::default()
        .architectures(vec![OciSpecArch::ScmpArchX86_64])
        .default_action(LinuxSeccompAction::ScmpActKill)
        .syscalls(vec![syscalls])
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
