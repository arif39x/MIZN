use std::env;
use std::process::{exit, Command};

fn main() {
    let mut command_line_arguments = env::args().skip(1);
    let primary_instruction = command_line_arguments.next();

    if let Some(instruction) = primary_instruction {
        if instruction == "build" {
            execute_kernel_space_build_phase();
            execute_user_space_build_phase();
        } else {
            exit(1);
        }
    } else {
        exit(1);
    }
}

fn execute_kernel_space_build_phase() {
    let mut kernel_space_build_command = Command::new("cargo");

    kernel_space_build_command.arg("+nightly");
    kernel_space_build_command.arg("build");
    kernel_space_build_command.arg("--manifest-path");
    kernel_space_build_command.arg("mizn-ebpf/Cargo.toml");
    kernel_space_build_command.arg("--target");
    kernel_space_build_command.arg("bpfel-unknown-none");
    kernel_space_build_command.arg("--release");
    kernel_space_build_command.arg("--target-dir");
    kernel_space_build_command.arg("target");
    kernel_space_build_command.arg("-Z");
    kernel_space_build_command.arg("build-std=core");
    kernel_space_build_command.env(
        "RUSTFLAGS",
        "--cfg has_atomics_64 --cfg has_atomics",
    );

    let kernel_space_build_status = kernel_space_build_command
        .status()
        .unwrap_or_else(|_| exit(1));

    if !kernel_space_build_status.success() {
        exit(kernel_space_build_status.code().unwrap_or(1));
    }
}

fn execute_user_space_build_phase() {
    let mut user_space_build_command = Command::new("cargo");

    user_space_build_command.arg("build");
    user_space_build_command.arg("--workspace");
    user_space_build_command.arg("--exclude");
    user_space_build_command.arg("xtask");

    let user_space_build_status = user_space_build_command
        .status()
        .unwrap_or_else(|_| exit(1));

    if !user_space_build_status.success() {
        exit(user_space_build_status.code().unwrap_or(1));
    }
}
