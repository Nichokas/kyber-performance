import csv
import json
import os
import statistics
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

SAMPLE_COUNT = 20
BENCH_TARGETS = ("kyber_bench", "SECP384R1_bench", "rsa_bench")
BENCHMARKS_PER_ROUND = 9
RESULTS = Path("target/bench-results")


def run(*command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def record_environment(commands):
    with (RESULTS / "environment.txt").open("a") as metadata:
        for command in commands:
            output = run(*command, stdout=subprocess.PIPE).stdout
            block = f"$ {' '.join(command)}\n{output}\n"
            print(block, end="", flush=True)
            metadata.write(block)


def build_benchmarks():
    args = ["cargo", "bench", "--locked", "--no-run", "--message-format=json-render-diagnostics"]
    for target in BENCH_TARGETS:
        args.extend(("--bench", target))
    output = run(*args, stdout=subprocess.PIPE).stdout
    binaries = {}
    for line in output.splitlines():
        message = json.loads(line)
        if message["reason"] == "compiler-artifact" and message["executable"]:
            name = message["target"]["name"]
            binaries[name] = Path(message["executable"]).resolve()
    return [binaries[target] for target in BENCH_TARGETS]


def measure(sample, work_dir, binaries):
    print(f"Starting sample {sample}/{SAMPLE_COUNT}", flush=True)
    sample_dir = work_dir / str(sample)
    sample_dir.mkdir()
    fixture = sample_dir / "rsa.der"
    output_dir = sample_dir / "gungraun"
    env = os.environ | {
        "GUNGRAUN_HOME": str(output_dir),
        "GUNGRAUN_WORKSPACE_ROOT": str(Path.cwd()),
        "KYBER_BENCH_RSA_KEY": str(fixture),
    }
    log_path = RESULTS / f"callgrind-{sample:02d}.log"
    with log_path.open("w") as log:
        run(
            "openssl", "genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:7680", "-outform", "DER", "-out", str(fixture),
            stdout=log, stderr=subprocess.STDOUT,
        )
        for binary in binaries:
            run(binary, "--save-summary=json", env=env, stdout=log, stderr=subprocess.STDOUT)

    metrics = {}
    raw_dir = RESULTS / "gungraun" / f"{sample:02d}"
    raw_dir.mkdir(parents=True)
    for path in sorted(output_dir.rglob("summary.json")):
        summary = json.loads(path.read_text())
        if summary["version"] != "7":
            raise ValueError(f"Unexpected Gungraun summary version in {path}")
        benchmark = summary["function_name"]
        (profile,) = [item for item in summary["profiles"] if item["tool"] == "Callgrind"]
        cycles = profile["data"]["total"]["metrics"]["EstimatedCycles"]["values"]["new"]
        if type(cycles) is not int or cycles <= 0 or benchmark in metrics:
            raise ValueError(f"Invalid or duplicate Estimated Cycles for {benchmark}")
        metrics[benchmark] = cycles
        copyfile(path, raw_dir / f"{benchmark}.json")
    if len(metrics) != BENCHMARKS_PER_ROUND:
        raise ValueError(f"Expected {BENCHMARKS_PER_ROUND} benchmarks, received {len(metrics)}")
    print(f"Finished sample {sample}/{SAMPLE_COUNT}", flush=True)
    return metrics


def collect_samples(binaries):
    observations = defaultdict(list)
    failures = []
    workers = min(2, len(os.sched_getaffinity(0)))
    with (
        TemporaryDirectory(prefix="kyber-bench-", dir=os.environ["RUNNER_TEMP"]) as temp,
        (RESULTS / "samples.csv").open("w", newline="") as sample_file,
        ThreadPoolExecutor(max_workers=workers) as pool,
    ):
        writer = csv.writer(sample_file)
        writer.writerow(("sample", "benchmark", "estimated_cycles"))
        rounds = {
            pool.submit(measure, sample, Path(temp), binaries): sample
            for sample in range(1, SAMPLE_COUNT + 1)
        }
        for completed in as_completed(rounds):
            sample = rounds[completed]
            try:
                metrics = completed.result()
            except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
                failures.append(sample)
                print(f"::error::Sample {sample} failed: {error}", flush=True)
                continue
            for benchmark, cycles in metrics.items():
                observations[benchmark].append(cycles)
                writer.writerow((sample, benchmark, cycles))
            sample_file.flush()
    return observations, failures


def publish_summary(observations):
    lines = [
        "### Benchmark statistics (Estimated Cycles)",
        "",
        "| Benchmark | Samples | Mean | Median | Range (min–max) |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for benchmark, values in sorted(observations.items()):
        lines.append(
            f"| `{benchmark}` | {len(values)} | {statistics.mean(values):,.2f} | "
            f"{statistics.median(values):,.2f} | {min(values):,}–{max(values):,} |"
        )
    summary = "\n".join(lines) + "\n"
    print(summary)
    (RESULTS / "summary.md").write_text(summary)
    Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(summary)


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    os.environ["LC_ALL"] = "C"
    record_environment([
        ("git", "rev-parse", "HEAD"), ("uname", "-a"), ("cat", "/etc/os-release"), ("lscpu",),
    ])
    if os.uname().machine != os.environ["EXPECTED_ARCH"]:
        raise SystemExit(f"Unexpected runner architecture: {os.uname().machine}")

    run("sudo", "apt-get", "update")
    run(
        "sudo", "apt-get", "install", "-y", "--no-install-recommends",
        "build-essential", "clang", "cmake", "libclang-dev", "openssl", "perl", "pkg-config", "valgrind",
    )
    os.environ["RUSTUP_TOOLCHAIN"] = "1.99.1"
    run("rustup", "toolchain", "install", os.environ["RUSTUP_TOOLCHAIN"], "--profile", "minimal")
    run("cargo", "install", "--locked", "gungraun-runner", "--version", "0.20.0")
    record_environment([
        ("rustc", "-Vv"), ("cargo", "-V"), ("valgrind", "--version"),
        ("gungraun-runner", "--version"), ("openssl", "version"),
        ("cargo", "tree", "--locked", "-p", "oqs-sys", "-p", "openssl-sys", "-p", "openssl-src", "--depth", "0"),
    ])

    observations, failures = collect_samples(build_benchmarks())
    publish_summary(observations)
    if failures or len(observations) != BENCHMARKS_PER_ROUND or any(
        len(values) != SAMPLE_COUNT for values in observations.values()
    ):
        raise SystemExit("Incomplete benchmark results")


if __name__ == "__main__":
    main()
