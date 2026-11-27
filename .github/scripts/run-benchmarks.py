import argparse
import csv
import difflib
import json
import os
import re
import statistics
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

BENCH_TARGETS = ("kyber_bench", "SECP384R1_bench", "rsa_bench")
BENCHMARKS_PER_ROUND = 9
RESULTS = Path("target/bench-results")
DISPATCH_SYMBOL = re.compile(
    r"^(?:PQCP_MLKEM_NATIVE_MLKEM768_(?:X86_64|AARCH64|C)_(?:keypair|enc|dec)(?:_derand)?"
    r"|_*(?:Keccak[PF]1600|SHA3_absorb|ossl_keccak)\w*"
    r"|(?:ossl_ec_GFp_nistp384_points_mul|ossl_ec_wNAF_mul|ec_wNAF_mul)"
    r"|_*(?:bn_(?:mul|sqr)\w*_(?:mont|internal)\w*|bn_power5|bn_post4x_internal)"
    r"|(?:ossl_)?(?:rsaz|RSAZ)_(?!\w*_eligible$)\w+"
    r"|sha256_block(?:_data_order)?(?:_\w+)?|sha256_block_neon"
    r"|sha2::sha256::(?:x86_sha|aarch64_sha2|soft\w*)::(?:\w+::)*\w+"
    r"|(?:aesni|aes_v8|aes_hw|vpaes|bsaes|AES)_(?:ctr32_encrypt_blocks|ecb_encrypt|set_encrypt_key))$"
)


def run(*command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def record_environment(commands):
    with (RESULTS / "environment.txt").open("a") as metadata:
        for command in commands:
            output = run(*command, stdout=subprocess.PIPE).stdout
            block = f"$ {' '.join(command)}\n{output}\n"
            print(block, end="", flush=True)
            metadata.write(block)


def build_executables(*args):
    output = run(
        "cargo", *args, "--locked", "--message-format=json-render-diagnostics",
        stdout=subprocess.PIPE,
    ).stdout
    binaries = {}
    for line in output.splitlines():
        message = json.loads(line)
        if message["reason"] == "compiler-artifact" and message["executable"]:
            name = message["target"]["name"]
            binaries[name] = Path(message["executable"]).resolve()
    return binaries


def record_cpu_dispatch():
    copyfile("/proc/cpuinfo", RESULTS / "cpuinfo.txt")
    binary = build_executables("build", "--profile", "bench", "--bin", "cpu-dispatch")["cpu-dispatch"]
    outputs = {}
    for name, command in (
        ("native", (binary,)),
        ("callgrind", ("valgrind", "--tool=callgrind", "--callgrind-out-file=/dev/null", binary)),
    ):
        output = run(*command, stdout=subprocess.PIPE).stdout
        (RESULTS / f"cpu-{name}.txt").write_text(output)
        outputs[name] = output
    differences = "".join(difflib.unified_diff(
        outputs["native"].splitlines(keepends=True),
        outputs["callgrind"].splitlines(keepends=True),
        fromfile="native", tofile="callgrind",
    ))
    (RESULTS / "cpu-native-vs-callgrind.diff").write_text(differences)
    print(differences, end="", flush=True)


def observed_dispatch(profile_dir):
    symbols = set()
    profiles = sorted(profile_dir.glob("callgrind.*.out"))
    if not profiles:
        raise ValueError(f"No Callgrind profile in {profile_dir}")
    for profile in profiles:
        symbol = ""
        positions = 1
        call_cost = False
        with profile.open() as stream:
            for line in stream:
                if line.startswith("positions:"):
                    positions = len(line.split()) - 1
                elif line.startswith("fn="):
                    # Callgrind appends apostrophe-number suffixes to distinguish identical names.
                    symbol = line[3:].strip().split("'", 1)[0]
                    call_cost = False
                elif line.startswith("calls="):
                    call_cost = True
                elif line[0] in "0123456789+-*":
                    fields = line.split()
                    if not call_cost and DISPATCH_SYMBOL.fullmatch(symbol) and int(fields[positions]):
                        symbols.add(symbol)
                    call_cost = False
    if not symbols:
        raise ValueError(f"No cryptographic dispatch symbols in {profile_dir}")
    return sorted(symbols)


def measure(sample, work_dir, binaries):
    print(f"Starting sample {sample}", flush=True)
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
        summaries = set()
        for binary in binaries:
            # Cargo normally adds --bench; these executables run directly to parallelize samples.
            run(binary, "--bench", "--save-summary=json", env=env, stdout=log, stderr=subprocess.STDOUT)
            updated = set(output_dir.rglob("summary.json"))
            if updated == summaries:
                raise ValueError(f"{binary.name} produced no new summaries; see {log_path}")
            summaries = updated

    metrics = {}
    raw_dir = RESULTS / "gungraun" / f"{sample:02d}"
    raw_dir.mkdir(parents=True)
    for path in sorted(summaries):
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
        paths = observed_dispatch(path.parent)
        (raw_dir / f"{benchmark}.dispatch.json").write_text(json.dumps(paths) + "\n")
    if len(metrics) != BENCHMARKS_PER_ROUND:
        raise ValueError(f"Expected {BENCHMARKS_PER_ROUND} benchmarks, received {len(metrics)}")
    print(f"Finished sample {sample}", flush=True)
    return metrics


def collect_samples(binaries, sample_ids):
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
            for sample in sample_ids
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


def publish_summary(observations, output_dir):
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
    (output_dir / "summary.md").write_text(summary)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as job_summary:
        job_summary.write(summary + "\n")


def merge_shards(output_dir, first_shard, second_shard):
    observations = defaultdict(dict)
    dispatches = []
    for path, expected_ids in (
        (first_shard, set(range(1, 11))),
        (second_shard, set(range(11, 21))),
    ):
        shard_samples = defaultdict(set)
        shard_dispatch = defaultdict(set)
        with path.open(newline="") as sample_file:
            for row in csv.DictReader(sample_file):
                benchmark = row["benchmark"]
                sample = int(row["sample"])
                cycles = int(row["estimated_cycles"])
                if sample not in expected_ids or sample in shard_samples[benchmark] or cycles <= 0:
                    raise ValueError(f"Invalid or duplicate sample {sample} for {benchmark} in {path}")
                shard_samples[benchmark].add(sample)
                observations[benchmark][sample] = cycles
                trace_path = path.parent / "gungraun" / f"{sample:02d}" / f"{benchmark}.dispatch.json"
                trace = json.loads(trace_path.read_text())
                if not trace:
                    raise ValueError(f"Empty dispatch trace in {trace_path}")
                shard_dispatch[benchmark].update(trace)
        if len(shard_samples) != BENCHMARKS_PER_ROUND or any(
            samples != expected_ids for samples in shard_samples.values()
        ):
            raise ValueError(f"Incomplete samples in {path}")
        dispatches.append(shard_dispatch)
    if len(observations) != BENCHMARKS_PER_ROUND:
        raise ValueError("Shards contain different benchmarks")
    first_dispatch, second_dispatch = dispatches
    for name in sorted(observations):
        if first_dispatch[name] != second_dispatch[name]:
            raise ValueError(
                f"Different Callgrind paths for {name}: "
                f"shard 1 only {sorted(first_dispatch[name] - second_dispatch[name])}; "
                f"shard 2 only {sorted(second_dispatch[name] - first_dispatch[name])}"
            )
    first_cpu, second_cpu = (
        (path.parent / "cpu-callgrind.txt").read_text()
        for path in (first_shard, second_shard)
    )
    if first_cpu != second_cpu:
        warning = "Callgrind CPU capabilities differ between shards with matching observed symbols."
        print(f"::warning::{warning}")
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as job_summary:
            job_summary.write(f"> **Warning:** {warning}\n\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "samples.csv").open("w", newline="") as sample_file:
        writer = csv.writer(sample_file)
        writer.writerow(("sample", "benchmark", "estimated_cycles"))
        for benchmark, samples in sorted(observations.items()):
            for sample, cycles in sorted(samples.items()):
                writer.writerow((sample, benchmark, cycles))
    publish_summary({name: list(samples.values()) for name, samples in observations.items()}, output_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--merge", nargs=3, type=Path, metavar=("OUTPUT", "SHARD_1", "SHARD_2"))
    args = parser.parse_args()
    if args.merge:
        merge_shards(*args.merge)
        return

    sample_start = int(os.environ["SAMPLE_START"])
    sample_count = int(os.environ["SAMPLE_COUNT"])
    if sample_start < 1 or sample_count < 1:
        raise SystemExit("SAMPLE_START and SAMPLE_COUNT must be positive")

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

    sample_ids = range(sample_start, sample_start + sample_count)
    record_cpu_dispatch()
    args = [arg for target in BENCH_TARGETS for arg in ("--bench", target)]
    executables = build_executables("bench", "--no-run", *args)
    observations, failures = collect_samples([executables[target] for target in BENCH_TARGETS], sample_ids)
    publish_summary(observations, RESULTS)
    if failures or len(observations) != BENCHMARKS_PER_ROUND or any(
        len(values) != sample_count for values in observations.values()
    ):
        raise SystemExit("Incomplete benchmark results")


if __name__ == "__main__":
    main()
