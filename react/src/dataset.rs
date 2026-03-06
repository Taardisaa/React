use std::collections::HashMap;
use std::fmt::Display;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_jsonlines::json_lines;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Project {
    #[serde(alias = "FFmpeg")]
    FFmpeg,
    OpenSSL,
    Tcpdump,
    LibXml2,
    Assimp,
    Binutils,
    Curl,
    Dbus,
    Elfutils,
    Exiv2,
    Expat,
    Freetype,
    Ghostscript,
    Git,
    Glib,
    Gnuplot,
    Gnutls,
    Gzip,
    #[serde(rename = "image-magick")]
    ImageMagick,
    Jasper,
    Krb5,
    Lcms,
    Libarchive,
    Libdwarf,
    Libgd,
    Libpng,
    Libtiff,
    Libx11,
    Matio,
    Mbedtls,
    Mysql,
    Ncurses,
    Opencv,
    OpenJDK,
    Openjpeg,
    Openssh,
    Pcre2,
    Perl,
    Poppler,
    Postgresql,
    Ruby,
    Emacs,
    Sqlite,
    Yasm,
}

impl Display for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Project::ImageMagick => write!(f, "image-magick"),
            _ => write!(f, "{}", format!("{:?}", self).to_lowercase()),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Hash, Copy)]
pub enum State {
    #[serde(rename = "patch")]
    Patch,
    #[serde(rename = "vuln")]
    Vuln,
    /// Analysis inconclusive - no distinguishing features found
    #[serde(rename = "unknown")]
    Unknown,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            State::Patch => "patch",
            State::Vuln => "vuln",
            State::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Hash)]
pub struct TestCase {
    pub file: String,
    pub cve: String,
    pub commit: String,
    pub ground_truth: State,
    pub project: Project,
}

impl Display for TestCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} {} {}]", self.cve, self.file, self.ground_truth)
    }
}

impl TestCase {
    /// tcpdump_tcpdump-4.9.3_O0_x86_clang -> (clang, O0)
    pub fn compiler_opt(&self) -> (String, String) {
        let parts: Vec<&str> = self.file.split('_').collect();
        let compiler = parts[parts.len() - 1].to_string();
        let opt = parts[parts.len() - 3].to_string();
        (compiler, opt)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct TestResult {
    pub test: TestCase,
    pub result: State,
}

impl TestResult {
    pub fn compiler_opt(&self) -> (String, String) {
        self.test.compiler_opt()
    }
}

impl Display for TestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.test, self.result)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct Cve {
    #[serde(rename = "CVE")]
    pub id: String,
    #[serde(default)]
    pub func: Option<String>,
    pub vuln: String,
    pub patch: String,
    pub file: String,
    pub commit: String,
    pub project: Project,
}

pub fn read_cves(path: &str) -> Result<HashMap<String, Cve>> {
    let values = json_lines(path)?.collect::<std::io::Result<Vec<Cve>>>()?;
    Ok(values
        .into_iter()
        .map(|cve| (cve.id.clone(), cve))
        .collect())
}

pub fn read_tests(path: &str) -> Result<Vec<(String, Vec<TestCase>)>> {
    let testcases = json_lines(path)?.collect::<std::io::Result<Vec<TestCase>>>()?;
    // group by CVE
    let mut cve_to_testcases = HashMap::new();
    for testcase in testcases {
        let cve = testcase.cve.clone();
        let testcases = cve_to_testcases.entry(cve).or_insert_with(Vec::new);
        testcases.push(testcase);
    }
    Ok(cve_to_testcases.into_iter().collect())
}
