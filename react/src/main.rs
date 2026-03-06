//! Main Program

use ir_analysis::IRState;

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::{fs, io};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use ir_analysis::{smt::init_ctx, IRAnalysis2, Smt};
use react::config::Config;
use react::dataset::*;
use react::metric::precision_recall_f1;

const LOG_FILE: &str = "log.txt";
const DETAIL_RESULT_FILE: &str = "detailed_result.jsonl";
const DETAIL_SUMMARY_FILE: &str = "detailed_result_summary.json";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// path to dataset directory
    #[arg(short, long)]
    dataset: String,
    /// CVE Pattern, None for all
    #[arg(short, long)]
    cve: Option<String>,
    /// number of test cases to run, None for all
    #[arg(short, long)]
    test: Option<usize>,
    /// specify which binary to run
    #[arg(short, long)]
    binary: Option<String>,
    /// specify which cve not to run
    #[arg(short, long)]
    exclude: Option<String>,
    /// output path for per-test detailed jsonl
    #[arg(long, default_value = DETAIL_RESULT_FILE)]
    detail_result: String,
    /// output path for detailed summary json
    #[arg(long, default_value = DETAIL_SUMMARY_FILE)]
    detail_summary: String,
}

#[derive(Default)]
struct Confusion {
    tp: usize,
    fp: usize,
    fn_count: usize,
    tn: usize,
    unknown: usize,
}

#[derive(Serialize)]
struct DetailedResultRow {
    project: String,
    cve: String,
    commit: String,
    file: String,
    ground_truth: State,
    result: State,
    correct: bool,
}

#[derive(Serialize)]
struct SummaryMetrics {
    total: usize,
    tp: usize,
    fp: usize,
    #[serde(rename = "fn")]
    fn_count: usize,
    tn: usize,
    unknown: usize,
    precision: f64,
    recall: f64,
    f1: f64,
    accuracy: f64,
}

#[derive(Serialize)]
struct DetailedSummary {
    positive_label: &'static str,
    negative_label: &'static str,
    overall: SummaryMetrics,
    by_cve: BTreeMap<String, SummaryMetrics>,
}

fn test_one_target(
    testcase: &TestCase,
    ir_analysis: &mut IRAnalysis2,
    solver: &mut Smt,
    cfg: &Config,
) -> TestResult {
    println!("testing {} ...", testcase);
    let test_bitcode_path = format!(
        "{}/{}/{}.bc",
        cfg.bitcode_dir, testcase.project, testcase.file
    );
    let result = match ir_analysis.test(&test_bitcode_path, solver) {
        IRState::Patch => State::Patch,
        IRState::Vuln => State::Vuln,
        IRState::Unknown => State::Unknown,
    };
    // write to file log.txt
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .unwrap();
    file.write_fmt(format_args!("{}  tested: {}\n", testcase, result))
        .unwrap();
    TestResult {
        test: testcase.clone(),
        result,
    }
}

fn test_each_cve(
    cve: &Cve,
    tests: &[TestCase],
    number: Option<usize>,
    case: &Option<String>,
    solver: &mut Smt,
    cfg: &Config,
) -> Vec<TestResult> {
    println!("testing {} ...", cve.id);
    if cfg!(debug_assertions) {
        for test in tests {
            assert_eq!(test.cve, cve.id);
        }
    }
    let source_diff_path = &format!("{}/{}_{}.diff", cfg.diff_dir, cve.id, &cve.commit[0..6]);
    let (bitcode_path1, bitcode_path2) = resolve_reference_bitcode_paths(cfg, cve);
    let mut ir_analysis = IRAnalysis2::new(&bitcode_path1, &bitcode_path2, source_diff_path);
    tests
        .iter()
        .filter(|test| case.is_none() || test.file.contains(case.as_ref().unwrap()))
        .take(number.unwrap_or(tests.len()))
        .map(|test| test_one_target(test, &mut ir_analysis, solver, cfg))
        .collect()
}

fn resolve_reference_bitcode_paths(cfg: &Config, cve: &Cve) -> (String, String) {
    let project_dir = format!("{}/{}", cfg.bitcode_dir, cve.project);
    let candidates = [
        (
            format!("{}/{}_vuln.bc", project_dir, cve.id),
            format!("{}/{}_patch.bc", project_dir, cve.id),
        ),
        (
            format!("{}/{}_{}_vuln.bc", project_dir, cve.id, cve.commit),
            format!("{}/{}_{}_patch.bc", project_dir, cve.id, cve.commit),
        ),
    ];

    for (vuln_path, patch_path) in candidates {
        if Path::new(&vuln_path).exists() && Path::new(&patch_path).exists() {
            return (vuln_path, patch_path);
        }
    }

    (
        format!("{}/{}_vuln.bc", project_dir, cve.id),
        format!("{}/{}_patch.bc", project_dir, cve.id),
    )
}

fn update_confusion(confusion: &mut Confusion, ground_truth: State, result: State) {
    match (ground_truth, result) {
        (State::Vuln, State::Vuln) => confusion.tp += 1,
        (State::Patch, State::Vuln) => confusion.fp += 1,
        (State::Vuln, State::Patch) => confusion.fn_count += 1,
        (State::Patch, State::Patch) => confusion.tn += 1,
        _ => confusion.unknown += 1,
    }
}

fn confusion_metrics(confusion: &Confusion) -> SummaryMetrics {
    let precision = if confusion.tp + confusion.fp == 0 {
        1.0
    } else {
        confusion.tp as f64 / (confusion.tp + confusion.fp) as f64
    };
    let recall = if confusion.tp + confusion.fn_count == 0 {
        1.0
    } else {
        confusion.tp as f64 / (confusion.tp + confusion.fn_count) as f64
    };
    let f1 = if precision == 0.0 && recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    let total = confusion.tp + confusion.fp + confusion.fn_count + confusion.tn + confusion.unknown;
    let accuracy = if total == 0 {
        1.0
    } else {
        (confusion.tp + confusion.tn) as f64 / total as f64
    };

    SummaryMetrics {
        total,
        tp: confusion.tp,
        fp: confusion.fp,
        fn_count: confusion.fn_count,
        tn: confusion.tn,
        unknown: confusion.unknown,
        precision,
        recall,
        f1,
        accuracy,
    }
}

fn dump_detailed_results(results: &[TestResult], output_path: &str) -> Result<()> {
    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);
    for test_result in results {
        let row = DetailedResultRow {
            project: test_result.test.project.to_string(),
            cve: test_result.test.cve.clone(),
            commit: test_result.test.commit.clone(),
            file: test_result.test.file.clone(),
            ground_truth: test_result.test.ground_truth,
            result: test_result.result,
            correct: test_result.test.ground_truth == test_result.result,
        };
        serde_json::to_writer(&mut writer, &row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn dump_detailed_summary(results: &[TestResult], output_path: &str) -> Result<()> {
    let mut overall = Confusion::default();
    let mut by_cve_raw: BTreeMap<String, Confusion> = BTreeMap::new();

    for test_result in results {
        let cve_confusion = by_cve_raw.entry(test_result.test.cve.clone()).or_default();
        update_confusion(
            &mut overall,
            test_result.test.ground_truth,
            test_result.result,
        );
        update_confusion(
            cve_confusion,
            test_result.test.ground_truth,
            test_result.result,
        );
    }

    let by_cve = by_cve_raw
        .into_iter()
        .map(|(cve, confusion)| (cve, confusion_metrics(&confusion)))
        .collect();

    let summary = DetailedSummary {
        positive_label: "vuln",
        negative_label: "patch",
        overall: confusion_metrics(&overall),
        by_cve,
    };

    let file = File::create(output_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &summary)?;
    Ok(())
}

fn main() {
    if fs::metadata(LOG_FILE).is_ok() {
        fs::remove_file(LOG_FILE).unwrap();
    }
    let args = Args::parse();
    let cfg = Config::new(&args.dataset);
    let cve_infos = read_cves(&cfg.cve_info).unwrap();
    let mut tests = read_tests(&cfg.test).unwrap();
    tests.sort_by(|a, b| a.0.cmp(&b.0));
    let mut sovler: Smt = init_ctx().unwrap();
    let test_results = tests.iter();
    let test_results = test_results
        .filter_map(|(cve, tests)| {
            if let Some(exclude) = &args.exclude {
                if cve.contains(exclude) {
                    return None;
                }
            }
            if args.cve.is_none() || cve.contains(args.cve.as_ref().unwrap()) {
                let cve_info = cve_infos.get(cve).unwrap();
                let results =
                    test_each_cve(cve_info, tests, args.test, &args.binary, &mut sovler, &cfg);
                let (p, r, f1, cov) = precision_recall_f1(&results);
                println!("{}: P={:.3} R={:.3} F1={:.3} Cov={:.3}", cve, p, r, f1, cov);
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(LOG_FILE)
                    .unwrap();
                file.write_fmt(format_args!(
                    "{} {}: P={:.3} R={:.3} F1={:.3} Cov={:.3}\n",
                    cve_info.project, cve, p, r, f1, cov
                ))
                .unwrap();
                Some((cve, results))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    // calculate metrics for the whole dataset
    let results = test_results
        .into_iter()
        .flat_map(|(_, results)| results)
        .collect::<Vec<_>>();
    let (p, r, f1, cov) = precision_recall_f1(&results);
    let unknown_count = results
        .iter()
        .filter(|r| r.result == State::Unknown)
        .count();
    println!(
        "all: P={:.3} R={:.3} F1={:.3} Cov={:.3} ({} unknown out of {})",
        p,
        r,
        f1,
        cov,
        unknown_count,
        results.len()
    );
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .unwrap();
    file.write_fmt(format_args!(
        "all: P={:.3} R={:.3} F1={:.3} Cov={:.3} ({} unknown out of {})\n",
        p,
        r,
        f1,
        cov,
        unknown_count,
        results.len()
    ))
    .unwrap();
    // calculate for each compile: gcc, clang and O0, O1, O2, O3 combination
    let mut rq2 = HashMap::new();
    for compiler in ["gcc", "clang"] {
        for opt in ["O0", "O1", "O2", "O3"] {
            rq2.insert((compiler.to_string(), opt.to_string()), Vec::new());
        }
    }
    for test in &results {
        let (compiler, opt) = test.compiler_opt();
        rq2.get_mut(&(compiler, opt)).unwrap().push(test.clone());
    }
    for ((compiler, opt), tests) in rq2 {
        let (p, r, f1, cov) = precision_recall_f1(&tests);
        println!(
            "{} {}: P={:.3} R={:.3} F1={:.3} Cov={:.3}",
            compiler, opt, p, r, f1, cov
        );
    }

    if let Err(err) = dump_detailed_results(&results, &args.detail_result) {
        let _ = writeln!(
            io::stderr(),
            "failed to write detailed results to {}: {}",
            args.detail_result,
            err
        );
    } else {
        println!("detailed results written to {}", args.detail_result);
    }

    if let Err(err) = dump_detailed_summary(&results, &args.detail_summary) {
        let _ = writeln!(
            io::stderr(),
            "failed to write detailed summary to {}: {}",
            args.detail_summary,
            err
        );
    } else {
        println!("detailed summary written to {}", args.detail_summary);
    }
}
