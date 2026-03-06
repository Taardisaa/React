pub struct Config {
    pub dataset_dir: String,
    pub cve_info: String,
    pub test: String,
    pub diff_dir: String,
    pub bitcode_dir: String,
    pub binaries_dir: String,
}

impl Config {
    pub fn new(dataset_dir: &str) -> Self {
        let dataset_dir = dataset_dir.to_string();
        Self {
            cve_info: format!("{}/CVE_info.jsonl", dataset_dir),
            test: format!("{}/test.jsonl", dataset_dir),
            diff_dir: format!("{}/diff", dataset_dir),
            bitcode_dir: format!("{}/bitcodes", dataset_dir),
            binaries_dir: format!("{}/binary", dataset_dir),
            dataset_dir,
        }
    }
}
