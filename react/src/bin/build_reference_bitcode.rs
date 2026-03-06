//! build dataset
//!
//! - build bitcode

use std::{fs, path, process};

use anyhow::{Ok, Result};
use clap::Parser;
use react::config::Config;
use react::dataset::{read_cves, Cve, Project, State};

const GCLANG: &str = "gclang";
const GETBC: &str = "get-bc";
const MULTITHREAD: usize = 8;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// path to dataset directory
    #[arg(short, long)]
    dataset: String,
}

trait CompileScript {
    /* Variable */
    fn repo_path(&self, cfg: &Config) -> String;
    fn generate_files(&self) -> Vec<&str>;
    fn file_name_in_repo(&self, file: &str) -> String;
    fn file_name_in_bitcode(&self, state: &State) -> String;

    /* Script */
    fn checkout_script(&self, stat: &State) -> String;
    fn configure_script(&self) -> String;
    fn extract_script(&self, state: &State, cfg: &Config) -> String;
    fn build_script(&self) -> String {
        format!("make -j {}", MULTITHREAD)
    }
    fn clean_script(&self) -> String {
        "git clean -f".to_string()
    }

    /* Command */
    fn run_command(&self, cmd: &str, cfg: &Config) -> Result<()> {
        let output = process::Command::new("bash")
            .arg("-c")
            .arg(cmd)
            .current_dir(&self.repo_path(cfg))
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            println!("{}", String::from_utf8_lossy(&output.stderr));
            anyhow::bail!(format!("{} failed", cmd));
        }
    }

    fn run_commands(&self, cmds: Vec<String>, cfg: &Config) -> Result<()> {
        for cmd in cmds {
            println!("{}", cmd);
            self.run_command(&cmd, cfg)?;
        }
        Ok(())
    }

    fn compile(&self, state: State, cfg: &Config) -> Result<()> {
        self.run_commands(
            vec![
                self.clean_script(),
                self.checkout_script(&state),
                self.configure_script(),
                self.build_script(),
                self.extract_script(&state, cfg),
                self.clean_script(),
            ],
            cfg,
        )
    }
}

fn check_or_create(path: &str) -> Result<()> {
    if !path::Path::new(path).exists() {
        fs::create_dir(path)?;
    }
    Ok(())
}

fn prepare_dirs(cfg: &Config) -> Result<()> {
    // check if dataset/bitcodes/ exists
    check_or_create(&cfg.dataset_dir)?;
    check_or_create(&cfg.bitcode_dir)?;
    let projects = vec![
        Project::FFmpeg,
        Project::OpenSSL,
        Project::LibXml2,
        Project::Tcpdump,
    ];
    for project in projects {
        let project_dir = format!("{}/{}", cfg.bitcode_dir, project);
        check_or_create(&project_dir)?;
    }
    Ok(())
}

impl CompileScript for Cve {
    fn repo_path(&self, cfg: &Config) -> String {
        format!("{}/repos/{}", cfg.dataset_dir, self.project)
    }

    fn file_name_in_repo(&self, file: &str) -> String {
        match self.project {
            Project::FFmpeg => format!("{file}_g"),
            #[cfg(target_os = "linux")]
            Project::OpenSSL => {
                if self.vuln.starts_with('1') {
                    format!("{file}.so.1.1")
                } else {
                    format!("{file}.so3")
                }
            }
            #[cfg(target_os = "macos")]
            Project::OpenSSL => {
                if self.vuln.starts_with('1') {
                    format!("{file}.1.1.dylib")
                } else {
                    format!("{file}.3.dylib")
                }
            }
            Project::Tcpdump => file.to_string(),
            #[cfg(target_os = "linux")]
            Project::LibXml2 => format!("./.libs/{file}.so.{}", &self.vuln[0..1]),
            #[cfg(target_os = "macos")]
            Project::LibXml2 => format!("./.libs/{file}.dylib.{}", &self.vuln[0..1]),
            _ => file.to_string(),
        }
    }

    fn file_name_in_bitcode(&self, state: &State) -> String {
        format!("{}_{}", self.id, state)
    }

    fn generate_files(&self) -> Vec<&str> {
        match self.project {
            Project::FFmpeg => vec!["ffmpeg"],
            Project::OpenSSL => vec!["libssl", "libcrypto"],
            Project::Tcpdump => vec!["tcpdump"],
            Project::LibXml2 => vec!["libxml2"],
            _ => vec![&self.file],
        }
    }

    fn checkout_script(&self, state: &State) -> String {
        let commit = match state {
            State::Patch => self.commit.clone(),
            State::Vuln => self.commit.clone() + "~1",
            State::Unknown => unreachable!("Unknown is a result state, not an input state"),
        };
        format!("git checkout {}", commit)
    }

    fn extract_script(&self, state: &State, cfg: &Config) -> String {
        for file in self.generate_files() {
            if self.file.starts_with(file) {
                return format!(
                    "{} {} -o {}/{}/{}",
                    GETBC,
                    self.file_name_in_repo(file),
                    cfg.bitcode_dir,
                    self.project,
                    self.file_name_in_bitcode(state)
                );
            }
        }
        panic!("{} extract bitcode not found", self.id);
    }

    fn configure_script(&self) -> String {
        match self.project {
            Project::FFmpeg => format!("./configure --disable-optimizations --cc={GCLANG}"),
            Project::OpenSSL => {
                if self.vuln.starts_with("1.1.1") {
                    format!("CC={GCLANG} ./config --debug")
                } else {
                    format!("CC={GCLANG} ./Configure --debug")
                }
            }
            _ => format!(r#"./configure CC={GCLANG} CFLAGS="-O0 -g""#),
        }
    }
}

fn main() {
    let args = Args::parse();
    let cfg = Config::new(&args.dataset);
    prepare_dirs(&cfg).unwrap();
    let cves = read_cves(&cfg.cve_info).unwrap();
    for cve in cves.values() {
        if cve.project != Project::OpenSSL {
            continue;
        }
        cve.compile(State::Vuln, &cfg).unwrap();
        cve.compile(State::Patch, &cfg).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffmpeg_script() {
        let cve = Cve {
            id: "CVE-2020-22019".to_string(),
            func: Some("ff_vmafmotion_init".to_string()),
            vuln: "4.4".to_string(),
            patch: "4.4.1".to_string(),
            file: "ffmpeg".to_string(),
            commit: "cea03683b93c1569b33611d71233235933b3cbce".to_string(),
            project: Project::FFmpeg,
        };
        let commit = cve.checkout_script(&State::Vuln);
        assert_eq!(
            commit,
            "git checkout cea03683b93c1569b33611d71233235933b3cbce~1"
        );
        let commit = cve.checkout_script(&State::Patch);
        assert_eq!(
            commit,
            "git checkout cea03683b93c1569b33611d71233235933b3cbce"
        );
        let configure = cve.configure_script();
        assert_eq!(configure, "./configure --disable-optimizations --cc=gclang");
    }

    #[test]
    fn test_openssl_script() {
        let cve = Cve {
            id: "CVE-2021-3711".to_string(),
            commit: "f6b9b7e".to_string(),
            vuln: "1.1.1".to_string(),
            project: Project::OpenSSL,
            func: Some("EVP_DigestSignInit".to_string()),
            patch: "openssl-1.1.1k".to_string(),
            file: "libssl".to_string(),
        };
        let configure = cve.configure_script();
        assert_eq!(configure, "CC=gclang ./config --debug");
    }
}
