#!/usr/bin/env python3
import csv
import sys
from typing import List, Dict, Callable, Tuple, Optional, Any

CSV_FILE = "Table.csv"

#Column resolution tools 

def norm(s: str):
    """Normalize a column name: lowercase, remove non-alphanumeric characters."""
    return "".join(ch.lower() for ch in s if ch.isalnum())


def resolve_columns(fieldnames: List[str]):
    """
    Map logical column names to actual CSV headers using normalized matching.
    Returns a dict with keys like 'name', 'security', 'block_size', etc.
    """
    header_map = {norm(fn): fn for fn in fieldnames}

    def get(label: str):
        key = norm(label)
        if key not in header_map:
            print(f"Could not find column for logical name: {label}")
            print("CSV columns are:", fieldnames)
            sys.exit(1)
        return header_map[key]

    return {
        "name": get("NAME"),
        "structure": get("STRUCTURE"),
        "key_sizes": get("KEY SIZE (bits)"),
        "security": get("SECURITY/STRENGTH LEVEL"),
        "common_use": get("COMMON USE"),
        "processing": get("PROCESSING TIME"),
        "block_size": get("BLOCK SIZE (bits)"),
        "standardized": get("Is it standardized?"),
        "low_power": get("Suitability for low power or constrained devices?"),
        "tls": get("Suitable for TLS and VPN"),
        "storage": get("Suitable for storage"),
        "stream": get("Suitable for high throughput streaming"),
        "ha": get("Hardware acceleration"),
        "vuln": get("Common vulnerabilities / attacks"),
    }

# Parsing helpers

def parse_key_sizes(s: str):
    if not s:
        return []
    result: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            result.append(int(part))
        except ValueError:
            
            pass
    return result


def parse_block_size(s: str):
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def max_key_size(row: Dict[str, str], cols: Dict[str, str]):
    sizes = parse_key_sizes(row[cols["key_sizes"]])
    return max(sizes) if sizes else 0



class State:
    def __init__(self):
        self.constraints: List[Tuple[Callable[[Dict[str, str]], bool], str]] = []
        self.answers: Dict[str, Any] = {}
        self.constraint_descriptions: List[str] = []

    def add_constraint(self, predicate: Callable[[Dict[str, str]], bool], desc: str):
        self.constraints.append((predicate, desc))
        self.constraint_descriptions.append(desc)

    def apply_constraints(self, rows: List[Dict[str, str]]):
        result: List[Dict[str, str]] = []
        for row in rows:
            ok = True
            for pred, _ in self.constraints:
                if not pred(row):
                    ok = False
                    break
            if ok:
                result.append(row)
        return result


class Question:
    def __init__(
        self,
        qid: str,
        prompt: str,
        options: List[str],
        bucket_func: Callable[[Dict[str, str], Dict[str, str]], int],
        apply_answer: Callable[[int, State, Dict[str, str]], None],):
        self.qid = qid
        self.prompt = prompt
        self.options = options
        self.bucket_func = bucket_func
        self.apply_answer = apply_answer
        self.asked = False


def sec_numeric(sec: str):
    sec = sec.strip()
    if sec == "High":
        return 3
    if sec == "Medium":
        return 2
    if sec == "Low":
        return 1
    return 0


def speed_numeric(speed: str):
    speed = speed.strip()
    if speed == "Fast":
        return 3
    if speed == "Medium":
        return 2
    if speed == "Slow":
        return 1
    return 0


def yes_limited_no_numeric(val: str):
    val = val.strip()
    if val == "Yes":
        return 3
    if val == "Limited":
        return 2
    if val == "No":
        return 1
    return 0


def bool_yes_numeric(val: str):
    val = val.strip()
    if val == "Yes":
        return 1
    return 0


def preference_score(row: Dict[str, str],
                    cols: Dict[str, str],
                    state: State,):
    score = 0
    ans = state.answers

    security = row[cols["security"]].strip()
    block = parse_block_size(row[cols["block_size"]])
    key_max = max_key_size(row, cols)
    low_power = row[cols["low_power"]].strip()
    processing = row[cols["processing"]].strip()
    std = row[cols["standardized"]].strip()
    tls = row[cols["tls"]].strip()
    storage = row[cols["storage"]].strip()
    stream = row[cols["stream"]].strip()
    common_use = row.get(cols["common_use"], "").strip()
    common_use_lower = common_use.lower()

    # Security preferences
    sec_need = ans.get("security_need")
    if sec_need in ("strong", "long_term"):
        if security == "High":
            score += 1
        if sec_need == "long_term":
            if key_max >= 256:
                score += 1
    elif sec_need == "legacy":
        if "legacy" in common_use_lower:
            score += 1

    # Data volume preferences
    dv = ans.get("data_volume")
    if block is not None:
        if dv == "large":
            if block >= 128:
                score += 1
        elif dv == "medium":
            if block >= 128:
                score += 1

    # Device / environment preferences
    dev = ans.get("device_env")
    if dev == "tiny":
        if low_power == "Yes":
            score += 2
        elif low_power == "Limited":
            score += 1
    elif dev == "hw_accel":
        ha = row[cols["ha"]].strip()
        if ha == "High":
            score += 2
        elif ha == "Medium":
            score += 1

    # Performance importance
    perf = ans.get("perf_importance")
    if perf == "high":
        if processing == "Fast":
            score += 2
        elif processing == "Medium":
            score += 1
    elif perf == "medium":
        if processing in ("Fast", "Medium"):
            score += 1

    # Standardization
    std_need = ans.get("std_need")
    if std_need == "require":
        if std == "Yes":
            score += 1
    elif std_need == "nice":
        if std == "Yes":
            score += 1

    # Usage pattern
    usage = ans.get("usage_pattern")
    if usage == "storage":
        if storage == "Yes":
            score += 2
        elif storage == "Limited":
            score += 1
    elif usage == "transit":
        if tls == "Yes":
            score += 2
        elif tls == "Limited":
            score += 1
    elif usage == "stream":
        if stream == "Yes":
            score += 2
        elif stream == "Limited":
            score += 1
    elif usage == "mixed":
        count_good = 0
        if storage == "Yes":
            count_good += 1
        if tls == "Yes":
            count_good += 1
        if stream == "Yes":
            count_good += 1
        if count_good >= 2:
            score += 2
        elif count_good == 1:
            score += 1

    # Power vs speed tradeoff
    pvs = ans.get("power_vs_speed")
    if pvs == "battery":
        if low_power == "Yes":
            score += 2
        elif low_power == "Limited":
            score += 1
    elif pvs == "speed":
        if processing == "Fast":
            score += 2
        elif processing == "Medium":
            score += 1
    elif pvs == "both":
        if low_power == "Yes" and processing == "Fast":
            score += 3
        elif low_power == "Yes" or processing == "Fast":
            score += 1

    # Comfort with older / niche / lightweight algorithms
    comfort = ans.get("comfort_level")
    if comfort == "modern":
        if "modern" in common_use_lower or "storage" in common_use_lower:
            score += 1
    elif comfort == "legacy_ok":
        # Middle ground, no extra score
        pass
    elif comfort == "legacy_niche":
        if "legacy" in common_use_lower or "research" in common_use_lower:
            score += 1
    elif comfort == "light_iot":
        if ("lightweight" in common_use_lower
            or "iot" in common_use_lower
            or "embedded" in common_use_lower
            or "niche" in common_use_lower):
            score += 2

    return score


def ranking_key(row: Dict[str, str], cols: Dict[str, str], state: State,):
    """
    Return a tuple used to sort candidates.
    Higher is better on each component.
    """
    pref = preference_score(row, cols, state)

    sec = sec_numeric(row[cols["security"]])
    block = parse_block_size(row[cols["block_size"]]) or 0
    speed = speed_numeric(row[cols["processing"]])
    std = 1 if row[cols["standardized"]].strip() == "Yes" else 0
    lowp = yes_limited_no_numeric(row[cols["low_power"]])

    return (pref, sec, block, speed, std, lowp)


#  Question definitions 
def make_questions(cols: Dict[str, str]):
    questions: List[Question] = []

    # Q1: Security level and lifetime
    def q1_bucket(row: Dict[str, str], cols: Dict[str, str]):
        sec = row[cols["security"]].strip()
        if sec == "Low":
            return 0
        if sec == "Medium":
            return 1
        return 2

    def q1_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["security_need"] = "strong"

            def pred(row: Dict[str, str]) -> bool:
                return row[cols["security"]].strip() != "Low"

            state.add_constraint(pred, "Drop low-security ciphers for standard strong security.")
        elif ans_idx == 1:
            state.answers["security_need"] = "long_term"

            def pred1(row: Dict[str, str]) -> bool:
                return row[cols["security"]].strip() != "Low"

            def pred2(row: Dict[str, str]) -> bool:
                return max_key_size(row, cols) >= 128

            state.add_constraint(pred1, "Drop low-security ciphers for long-term security.")
            state.add_constraint(pred2, "Require key size of at least 128 bits for long-term security.")
        else:
            state.answers["security_need"] = "legacy"

    questions.append(
        Question(
            "security",
            "What kind of security do you need from this algorithm?",
            [
                "Normal modern security for typical applications, not extreme long-term protection.",
                "Very strong, long-term security (decades, very sensitive data).",
                "Mainly compatibility with older systems; maximum strength is less important.",
            ],
            q1_bucket,
            q1_apply,
        )
    )

    # Q2: Amount of data per key
    def q2_bucket(row: Dict[str, str], cols: Dict[str, str]):
        block = parse_block_size(row[cols["block_size"]]) or 0
        if block < 128:
            return 0
        return 1

    def q2_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["data_volume"] = "small"
        elif ans_idx == 1:
            state.answers["data_volume"] = "medium"
        else:
            state.answers["data_volume"] = "large"

            def pred(row: Dict[str, str]) -> bool:
                b = parse_block_size(row[cols["block_size"]]) or 0
                return b >= 128

            state.add_constraint(pred, "Require 128-bit block size for very large amounts of data.")

    questions.append(
        Question(
            "data_volume",
            "How much data will you encrypt under the same key for this use?",
            [
                "Only small amounts (messages, small files).",
                "Moderate amounts (a few gigabytes).",
                "Large amounts (long-running connections, big backups, disk volumes).",
            ],
            q2_bucket,
            q2_apply,
        )
    )

    # Q3: Environment and device type
    def q3_bucket(row: Dict[str, str], cols: Dict[str, str]):
        val = row[cols["low_power"]].strip()
        if val == "Yes":
            return 0
        if val == "Limited":
            return 1
        return 2

    def q3_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["device_env"] = "tiny"

            def pred(row: Dict[str, str]) -> bool:
                return row[cols["low_power"]].strip() != "No"

            state.add_constraint(pred, "Drop ciphers unsuitable for low-power or constrained devices.")
        elif ans_idx == 1:
            state.answers["device_env"] = "normal"
        else:
            state.answers["device_env"] = "hw_accel"

    questions.append(
        Question(
            "device_env",
            "Where will this algorithm run most of the time?",
            [
                "Very small, low-power device (sensor, badge, tiny controller).",
                "Normal computer or server (laptop, desktop, VM, small server).",
                "System with a hardware crypto accelerator (modern CPU with crypto engine, smart card, dedicated chip).",
            ],
            q3_bucket,
            q3_apply,
        )
    )

    # Q4: Performance importance
    def q4_bucket(row: Dict[str, str], cols: Dict[str, str]):
        speed = row[cols["processing"]].strip()
        if speed == "Fast":
            return 0
        if speed == "Medium":
            return 1
        return 2

    def q4_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["perf_importance"] = "high"
        elif ans_idx == 1:
            state.answers["perf_importance"] = "medium"
        else:
            state.answers["perf_importance"] = "low"

    questions.append(
        Question(
            "performance",
            "How important is performance (speed and latency) for you?",
            [
                "It is critical. I need it as fast as reasonably possible.",
                "It matters, but not more than security and other needs.",
                "It is not a big concern.",
            ],
            q4_bucket,
            q4_apply,
        )
    )

    # Q5: Standardization and compliance
    def q5_bucket(row: Dict[str, str], cols: Dict[str, str]):
        std = row[cols["standardized"]].strip()
        if std == "Yes":
            return 0
        return 1

    def q5_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["std_need"] = "require"

            def pred(row: Dict[str, str]) -> bool:
                return row[cols["standardized"]].strip() == "Yes"

            state.add_constraint(pred, "Require standardized or widely accepted algorithms.")
        elif ans_idx == 1:
            state.answers["std_need"] = "nice"
        else:
            state.answers["std_need"] = "dontcare"

    questions.append(
        Question(
            "standardization",
            "Do you need to use an algorithm that is standardized or widely accepted?",
            [
                "Yes, I need standardized or widely accepted algorithms.",
                "It is nice, but not mandatory.",
                "I do not care; I can use less common algorithms.",
            ],
            q5_bucket,
            q5_apply,
        )
    )

    # Q6: Data usage pattern
    def q6_bucket(row: Dict[str, str], cols: Dict[str, str]):
        storage = row[cols["storage"]].strip()
        tls = row[cols["tls"]].strip()
        stream = row[cols["stream"]].strip()
        if storage == "Yes":
            return 0
        if tls == "Yes":
            return 1
        if stream == "Yes":
            return 2
        return 3

    def q6_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["usage_pattern"] = "storage"

            def pred(row: Dict[str, str]):
                return row[cols["storage"]].strip() != "No"

            state.add_constraint(pred, "Drop ciphers unsuitable for storage use.")
        elif ans_idx == 1:
            state.answers["usage_pattern"] = "transit"

            def pred(row: Dict[str, str]):
                return row[cols["tls"]].strip() != "No"

            state.add_constraint(pred, "Drop ciphers unsuitable for protecting data in transit.")
        elif ans_idx == 2:
            state.answers["usage_pattern"] = "stream"

            def pred(row: Dict[str, str]):
                return row[cols["stream"]].strip() != "No"

            state.add_constraint(pred, "Drop ciphers unsuitable for high-throughput streaming.")
        else:
            state.answers["usage_pattern"] = "mixed"

            def pred(row: Dict[str, str]):
                st = row[cols["storage"]].strip()
                tl = row[cols["tls"]].strip()
                strem = row[cols["stream"]].strip()
                return not (st == "No" and tl == "No" and strem == "No")

            state.add_constraint(pred, "Require suitability for at least one of storage, TLS, or streaming.")

    questions.append(
        Question(
            "usage_pattern",
            "What describes your data usage best?",
            [
                "Mostly data at rest (files, backups, disks, database records).",
                "Mostly data in transit (messages between clients and servers).",
                "Continuous or high-rate data streams (video, audio, many packets).",
                "A mix of storage and communication.",
            ],
            q6_bucket,
            q6_apply,
        )
    )

    # Q7: Power versus speed tradeoff
    def q7_bucket(row: Dict[str, str], cols: Dict[str, str]):
        lowp = row[cols["low_power"]].strip()
        speed = row[cols["processing"]].strip()
        if lowp == "Yes" and speed == "Fast":
            return 0
        if lowp == "Yes" or speed == "Fast":
            return 1
        return 2

    def q7_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["power_vs_speed"] = "battery"
        elif ans_idx == 1:
            state.answers["power_vs_speed"] = "speed"
        elif ans_idx == 2:
            state.answers["power_vs_speed"] = "both"
        else:
            state.answers["power_vs_speed"] = "none"

    questions.append(
        Question(
            "power_vs_speed",
            "If you had to choose, what matters more for your device?",
            [
                "Saving battery or power is more important than raw speed.",
                "Raw speed is more important than saving power.",
                "I care about both speed and power roughly equally.",
                "Neither of them matters much for me.",
            ],
            q7_bucket,
            q7_apply,
        )
    )

    # Q8: Comfort with older, niche, or lightweight algorithms
    def q8_bucket(row: Dict[str, str], cols: Dict[str, str]):
        cu = row.get(cols["common_use"], "").strip().lower()
        if "modern" in cu or "storage" in cu:
            return 0      
        if "legacy" in cu:
            return 1      
        if "research" in cu:
            return 2      
        if (
            "lightweight" in cu
            or "iot" in cu
            or "telecom" in cu
            or "mobile" in cu
            or "embedded" in cu
            or "niche" in cu
        ):
            return 3     
        return 4

    def q8_apply(ans_idx: int, state: State, cols: Dict[str, str]):
        if ans_idx == 0:
            state.answers["comfort_level"] = "modern"

        elif ans_idx == 1:
            state.answers["comfort_level"] = "legacy_ok"

        elif ans_idx == 2:
            state.answers["comfort_level"] = "legacy_niche"

            def pred(row: Dict[str, str]):
                cu = row.get(cols["common_use"], "").strip().lower()
                return ("legacy" in cu) or ("research" in cu)

            state.add_constraint(
                pred,
                "Require algorithms whose common use is legacy or research."
            )

        else:
            state.answers["comfort_level"] = "light_iot"

            def pred_light(row: Dict[str, str]):
                cu = row.get(cols["common_use"], "").strip().lower()
                return (
                    "lightweight" in cu
                    or "iot" in cu
                    or "embedded" in cu
                    or "niche" in cu
                )

            state.add_constraint(
                pred_light,
                "Require algorithms whose common use is lightweight, IoT, embedded, or niche."
            )

    questions.append(
        Question(
            "comfort",
            "What is your comfort level with older or less common algorithms?",
            [
                "I prefer widely used modern algorithms.",
                "I am ok with some older or niche algorithms.",
                "I specifically want legacy or research algorithms (for compatibility or curiosity).",
                "I want a lightweight, IoT, or niche algorithm for constrained or embedded devices.",
            ],
            q8_bucket,
            q8_apply,
        )
    )

    return questions

# Adaptive question selection 

def ask_choice(prompt: str, options: List[str]):
    print()
    print(prompt)
    for i, opt in enumerate(options, start=1):
        print(f"{i}) {opt}")
    while True:
        choice = input("Enter choice: ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        print("Invalid choice, try again.")


def choose_best_question(questions: List[Question],
                            candidates: List[Dict[str, str]],
                            cols: Dict[str, str],) :
    best_q: Optional[Question] = None
    best_worst_bucket: Optional[int] = None

    for q in questions:
        if q.asked:
            continue

        bucket_counts: Dict[int, int] = {}
        for row in candidates:
            b = q.bucket_func(row, cols)
            bucket_counts[b] = bucket_counts.get(b, 0) + 1

        if not bucket_counts:
            continue

        max_bucket = max(bucket_counts.values())

        if len(bucket_counts) == 1:
            pass

        if best_worst_bucket is None or max_bucket < best_worst_bucket:
            best_worst_bucket = max_bucket
            best_q = q

    return best_q

# For CLI
def main():
    try:
        with open(CSV_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames
    except FileNotFoundError:
        print(f"Could not open {CSV_FILE}. Make sure it is in the same folder as this script.")
        sys.exit(1)

    if not rows or not fieldnames:
        print("CSV appears to be empty or has no headers.")
        sys.exit(1)

    cols = resolve_columns(fieldnames)

    state = State()
    questions = make_questions(cols)
    candidates = rows[:]

    print("Block Cipher Selection Assistant (Adaptive DT)")
    print()

    max_questions_to_ask = 7
    asked_count = 0

    while True:
        candidates = state.apply_constraints(candidates)

        if len(candidates) == 0:
            print()
            print("Based on your answers, there is no cipher in the table that satisfies all of these conditions at the same time.")
            if state.constraint_descriptions:
                print("The hard requirements you set were:")
                for desc in state.constraint_descriptions:
                    print(f" - {desc}")
            else:
                print("No hard constraints recorded, which means something unexpected happened.")
            print("You may need to relax at least one requirement.")
            return

        if len(candidates) <= 3 or asked_count >= max_questions_to_ask:
            break

        q = choose_best_question(questions, candidates, cols)
        if q is None:
            break

        ans_idx = ask_choice(q.prompt, q.options)
        q.apply_answer(ans_idx, state, cols)
        q.asked = True
        asked_count += 1

    candidates_sorted = sorted(
        candidates,
        key=lambda row: ranking_key(row, cols, state),
        reverse=True,
    )

    #  to see the full list 
    print("\n Final candidate list after all hard filters (sorted):")
    for row in candidates_sorted:
        name = row[cols["name"]].strip()
        pref = preference_score(row, cols, state)
        print(f" - {name} (preference match score {pref})")
    print(" End of candidate list\n")

    print("Recommended ciphers based on your answers:")
    print("------------------------------------------")
    top_n = min(3, len(candidates_sorted))
    for rank in range(top_n):
        row = candidates_sorted[rank]
        name = row[cols["name"]].strip()
        sec = row[cols["security"]].strip()
        block = row[cols["block_size"]].strip()
        key_sizes = row[cols["key_sizes"]].strip()
        std = row[cols["standardized"]].strip()
        lowp = row[cols["low_power"]].strip()
        tls = row[cols["tls"]].strip()
        storage = row[cols["storage"]].strip()
        stream = row[cols["stream"]].strip()
        processing = row[cols["processing"]].strip()
        common_use = row.get(cols["common_use"], "").strip()
        ha = row[cols["ha"]].strip()
        vuln = row[cols["vuln"]].strip()

        pref = preference_score(row, cols, state)

        print(f"{rank + 1}. {name} (preference match score {pref})")
        print(f"   Security level: {sec}, block size: {block} bits, key sizes: {key_sizes}")
        print(f"   Common use: {common_use}, standardized: {std}")
        print(f"   Processing time: {processing}, low power suitability: {lowp}, hardware acceleration: {ha}")
        print(f"   TLS/VPN suitability: {tls}, storage suitability: {storage}, streaming suitability: {stream}")
        if vuln:
            print(f"   Notes on known attacks: {vuln}")
        print()

    if top_n == 0:
        print("Unexpectedly, no candidates remain after ranking. This should not happen if constraints were applied correctly.")

#main()

# Used for website
def compute_step(user_answers: Dict[str, int]):

    try:
        with open(CSV_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames
    except FileNotFoundError:
        raise RuntimeError(f"Could not open {CSV_FILE}.")

    if not rows or not fieldnames:
        raise RuntimeError("CSV appears to be empty or has no headers.")

    cols = resolve_columns(fieldnames)

    state = State()
    questions = make_questions(cols)
    candidates = rows[:]

    for q in questions:
        if q.qid in user_answers:
            ans_idx = user_answers[q.qid]
            q.apply_answer(ans_idx, state, cols)
            q.asked = True

    candidates = state.apply_constraints(candidates)

    if len(candidates) == 0:
        return {
            "done": True,
            "results": [],
            "all_candidates": [],
            "constraints": state.constraint_descriptions,}

    max_questions_to_ask = 7
    asked_count = sum(1 for q in questions if q.asked)


    if len(candidates) <= 3 or asked_count >= max_questions_to_ask:
        candidates_sorted = sorted(
            candidates,
            key=lambda row: ranking_key(row, cols, state),
            reverse=True,)

        top_n = min(3, len(candidates_sorted))
        top_results = []
        for i in range(top_n):
            row = candidates_sorted[i]
            top_results.append({
                "name": row[cols["name"]].strip(),
                "security": row[cols["security"]].strip(),
                "block_size": row[cols["block_size"]].strip(),
                "key_sizes": row[cols["key_sizes"]].strip(),
                "standardized": row[cols["standardized"]].strip(),
                "low_power": row[cols["low_power"]].strip(),
                "tls": row[cols["tls"]].strip(),
                "storage": row[cols["storage"]].strip(),
                "stream": row[cols["stream"]].strip(),
                "processing": row[cols["processing"]].strip(),
                "common_use": row.get(cols["common_use"], "").strip(),
                "ha": row[cols["ha"]].strip(),
                "vuln": row[cols["vuln"]].strip(),
                "pref_score": preference_score(row, cols, state),
            })

        other_candidates = [{"name": row[cols["name"]].strip(),
                            "pref_score": preference_score(row, cols, state)}
                            for row in candidates_sorted[top_n:]]

        print("DEBUG: other candidates:", [c["name"] for c in other_candidates])

        return {
            "done": True,
            "results": top_results,
            "all_candidates": other_candidates,
            "constraints": state.constraint_descriptions,}


    # Ask the next question
    next_q = choose_best_question(questions, candidates, cols)

    # No more useful questions
    if next_q is None:
        candidates_sorted = sorted(
            candidates,
            key=lambda row: ranking_key(row, cols, state),
            reverse=True,
        )

        # TOP 3 - Full Details
        top_n = min(3, len(candidates_sorted))
        top_results = []
        for i in range(top_n):
            row = candidates_sorted[i]
            top_results.append({
                "name": row[cols["name"]].strip(),
                "security": row[cols["security"]].strip(),
                "block_size": row[cols["block_size"]].strip(),
                "key_sizes": row[cols["key_sizes"]].strip(),
                "standardized": row[cols["standardized"]].strip(),
                "low_power": row[cols["low_power"]].strip(),
                "tls": row[cols["tls"]].strip(),
                "storage": row[cols["storage"]].strip(),
                "stream": row[cols["stream"]].strip(),
                "processing": row[cols["processing"]].strip(),
                "common_use": row.get(cols["common_use"], "").strip(),
                "ha": row[cols["ha"]].strip(),
                "vuln": row[cols["vuln"]].strip(),
                "pref_score": preference_score(row, cols, state),})

        # All other candidates
        other_candidates = [{"name": row[cols["name"]].strip(),
                            "pref_score": preference_score(row, cols, state)}
                            for row in candidates_sorted[top_n:]]
        
        print("DEBUG: other candidates:", [c["name"] for c in other_candidates])

        return {
            "done": True,
            "results": top_results,
            "all_candidates": other_candidates,
            "constraints": state.constraint_descriptions,}

    
    # return next question
    return {
        "done": False,
        "next_question": {
            "qid": next_q.qid,
            "prompt": next_q.prompt,
            "options": next_q.options,},
        "constraints": state.constraint_descriptions,
        "candidate_count": len(candidates),}
