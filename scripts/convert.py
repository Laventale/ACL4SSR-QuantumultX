#!/usr/bin/env python3
"""Synchronize ACL4SSR Online Full and translate its Clash rules for Quantumult X.

No third-party conversion service. Input comes exclusively from the official
ACL4SSR GitHub raw content. All files are published only after validation.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

RAW_PREFIX = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/"
TEMPLATE_URL = RAW_PREFIX + "config/ACL4SSR_Online_Full.ini"
SUPPORTED_RULES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "USER-AGENT"}
# ACL4SSR sources are written for Clash. These rule types do not have a safe,
# equivalent Quantumult X filter rule. Never invent a broader matching rule.
# Skips are recorded in conversion-warnings.txt; all OTHER unknown types fail.
UNSUPPORTED_QX_RULES = {
    "PROCESS-NAME": "Quantumult X cannot match a process by name",
    "PROCESS-PATH": "Quantumult X cannot match a process path",
    "URL-REGEX": "Quantumult X filter rules cannot match a full URL regular expression",
    "DOMAIN-REGEX": "no proven equivalent Quantumult X domain regex rule",
    "SRC-IP-CIDR": "no proven equivalent source-IP filter rule",
    "SRC-PORT": "no proven equivalent source-port filter rule",
    "DST-PORT": "no proven equivalent destination-port filter rule",
}
DEFAULT_TIMEOUT = 35


class ConversionError(Exception):
    pass


@dataclass(frozen=True)
class RuleSource:
    group: str
    url: str
    relative: Path


def fetch_text(url: str, attempts: int = 3) -> str:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "acl4ssr-qx-sync/1.0", "Accept": "text/plain"})
            with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
                data = response.read(12 * 1024 * 1024 + 1)
            if len(data) > 12 * 1024 * 1024:
                raise ConversionError(f"File larger than 12 MiB: {url}")
            return data.decode("utf-8-sig")
        except (OSError, UnicodeError, urllib.error.URLError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(2 * (attempt + 1))
    raise ConversionError(f"Unable to download {url}: {last}")


def parse_template(text: str) -> tuple[list[RuleSource], bool, bool]:
    sources: list[RuleSource] = []
    has_geoip_cn = False
    has_final = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or not line.startswith("ruleset="):
            continue
        body = line[len("ruleset="):]
        if "," not in body:
            raise ConversionError(f"Template line {lineno}: invalid ruleset format")
        group, target = (value.strip() for value in body.split(",", 1))
        if not group:
            raise ConversionError(f"Template line {lineno}: missing policy group")
        if target.startswith("[]"):
            builtin = target[2:].upper().replace(" ", "")
            if builtin == "GEOIP,CN":
                has_geoip_cn = True
            elif builtin == "FINAL":
                has_final = True
            else:
                raise ConversionError(f"Unknown inline rule at template line {lineno}: {target}")
            continue
        if not target.startswith(RAW_PREFIX):
            raise ConversionError(f"Untrusted/non-official rule URL at template line {lineno}: {target}")
        path_str = target[len(RAW_PREFIX):]
        p = Path(path_str)
        if p.is_absolute() or ".." in p.parts or p.suffix.lower() != ".list" or not p.parts:
            raise ConversionError(f"Unsafe rule path: {path_str}")
        sources.append(RuleSource(group, target, p))
    if len(sources) < 25 or not has_final or not has_geoip_cn:
        raise ConversionError("Template appears incomplete: expected >=25 lists, GEOIP CN, FINAL")
    if len({str(source.relative) for source in sources}) != len(sources):
        raise ConversionError("Template has duplicate source paths")
    return sources, has_geoip_cn, has_final


def validate_pattern(text: str, wildcard: bool) -> None:
    if not text or any(ch.isspace() for ch in text) or "," in text or "/" in text or "\\" in text:
        raise ConversionError(f"Suspicious domain pattern: {text!r}")
    if not wildcard and ("*" in text or "?" in text):
        raise ConversionError(f"Unconverted wildcard in domain pattern: {text!r}")
    if not re.fullmatch(r"[A-Za-z0-9._*?+-]+", text):
        raise ConversionError(f"Unknown domain pattern characters: {text!r}")


def convert_line(line: str, source: str, index: int) -> tuple[str | None, str | None] | None:
    value = line.strip()
    if not value or value.startswith(("#", ";", "//")):
        return None
    # Reject embedded rule comments if they cannot be unambiguously parsed.
    fields = [x.strip() for x in value.split(",")]
    if len(fields) < 2:
        raise ConversionError(f"{source}:{index}: invalid Clash rule: {line}")
    kind, target = fields[0].upper(), fields[1]
    extra = fields[2:]
    if kind in UNSUPPORTED_QX_RULES:
        # Do not convert PROCESS-NAME to a domain rule: that would change the
        # meaning and could route much more traffic than the upstream intended.
        reason = UNSUPPORTED_QX_RULES[kind]
        return None, f"{source}:{index}: SKIPPED {kind} ({reason}): {line}"
    if kind not in SUPPORTED_RULES:
        raise ConversionError(f"{source}:{index}: unknown rule type {kind!r}: {line}")
    if any(x.lower() != "no-resolve" for x in extra):
        raise ConversionError(f"{source}:{index}: unsupported rule modifiers: {line}")
    warning = None
    if kind == "USER-AGENT":
        if not target or any(ch in target for ch in ("\r", "\n", ",")) or extra:
            raise ConversionError(f"{source}:{index}: invalid USER-AGENT: {line}")
        return f"user-agent, {target}", None
    if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
        if extra:
            raise ConversionError(f"{source}:{index}: unexpected modifier on domain: {line}")
        if kind == "DOMAIN-SUFFIX" and target.startswith("+."):
            target = target[2:]
        if kind == "DOMAIN-SUFFIX" and target.startswith("*.") and target.count("*") == 1 and "?" not in target:
            # Preserve the wildcard's intent instead of leaking '*' into host-suffix.
            qtype = "host-wildcard"
        elif "*" in target or "?" in target:
            qtype = "host-wildcard"
            if kind == "DOMAIN-KEYWORD":
                target = f"*{target}*" if not (target.startswith("*") and target.endswith("*")) else target
        else:
            qtype = {"DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword", "DOMAIN-WILDCARD": "host-wildcard"}[kind]
        validate_pattern(target, wildcard=qtype == "host-wildcard")
        if kind == "DOMAIN-WILDCARD":
            qtype = "host-wildcard"
        return f"{qtype}, {target}", None
    if kind in ("IP-CIDR", "IP-CIDR6"):
        try:
            parsed = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ConversionError(f"{source}:{index}: invalid CIDR {target}") from exc
        if (kind == "IP-CIDR" and parsed.version != 4) or (kind == "IP-CIDR6" and parsed.version != 6):
            raise ConversionError(f"{source}:{index}: wrong address family: {target}")
        if extra:
            warning = f"{source}:{index}: dropped Clash-only 'no-resolve' for {target}"
        return f"{'ip-cidr' if parsed.version == 4 else 'ip6-cidr'}, {target}", warning
    if kind == "IP-ASN":
        if not target.isdigit() or extra:
            raise ConversionError(f"{source}:{index}: invalid IP-ASN: {line}")
        return f"ip-asn, {target}", None
    if kind == "GEOIP":
        if not target.isalpha() or extra:
            raise ConversionError(f"{source}:{index}: invalid GEOIP: {line}")
        return f"geoip, {target.lower()}", None
    raise AssertionError(kind)


def convert_list(source_text: str, name: str) -> tuple[list[str], list[str]]:
    converted: list[str] = []
    warnings: list[str] = []
    for n, line in enumerate(source_text.splitlines(), 1):
        result = convert_line(line, name, n)
        if result is None:
            continue
        rule, warning = result
        if rule is not None:
            converted.append(rule)
        if warning:
            warnings.append(warning)
    if not converted:
        raise ConversionError(f"No compatible Quantumult X rules remain in {name}; refusing to publish an empty list")
    return converted, warnings


def make_remote_snippet(sources: list[RuleSource], repo: str, branch: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ConversionError(f"Invalid GitHub repo value: {repo}")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", branch) or ".." in branch:
        raise ConversionError(f"Invalid branch value: {branch}")
    base = f"https://raw.githubusercontent.com/{repo}/{branch}/Rules"
    lines = ["; Generated from ACL4SSR official Online Full template; preserve order.",
             "; Replace only the existing [filter_remote] CONTENT with these lines.",
             "; DO NOT upload your private .conf file or proxy credentials to GitHub."]
    for source in sources:
        name = source.relative.stem
        # Names stable and familiar to prior generated QX profile.
        tag = f"ACL_{name}"
        url = base + "/" + source.relative.as_posix()
        lines.append(f"{url}, tag={tag}, force-policy={source.group}, update-interval=86400, opt-parser=false, enabled=true")
    lines.append("FILTER_REGION, tag=ACL_GeoIP_CN, force-policy=🎯 全球直连, enabled=true")
    return "\n".join(lines) + "\n"


def run(root: Path, repo: str, branch: str, template_url: str = TEMPLATE_URL) -> dict:
    if template_url != TEMPLATE_URL:
        raise ConversionError("Only the official Online Full template is allowed")
    original_template = fetch_text(template_url)
    sources, _, _ = parse_template(original_template)
    all_outputs: dict[Path, str] = {}
    meta: list[dict] = []
    warnings: list[str] = []
    grand_total = 0
    for source in sources:
        original = fetch_text(source.url)
        converted, local_warnings = convert_list(original, source.relative.as_posix())
        grand_total += len(converted)
        warnings.extend(local_warnings)
        output = "# Generated from ACL4SSR official: " + source.relative.as_posix() + "\n"
        # With force-policy in QX config, a policy isn't necessary in the remote .list.
        # Three-field rules work as standalone rule lists too.
        output += "\n".join(f"{rule}, {source.group}" for rule in converted) + "\n"
        all_outputs[source.relative] = output
        skipped = sum("SKIPPED " in warning for warning in local_warnings)
        meta.append({"path": str(source.relative), "policy": source.group,
                     "rules": len(converted), "skipped": skipped,
                     "upstream_sha256": hashlib.sha256(original.encode()).hexdigest()})
    if grand_total < 1000:
        raise ConversionError(f"Too few rules ({grand_total}); refusing to publish")
    snippet = make_remote_snippet(sources, repo, branch)
    manifest = {"upstream": TEMPLATE_URL, "template_sha256": hashlib.sha256(original_template.encode()).hexdigest(),
                "list_count": len(sources), "rule_count": grand_total, "files": meta,
                "skipped_rules": sum(item["skipped"] for item in meta),
                "notes": "Clash-only rules not supported by QX were skipped and logged; IP-CIDR no-resolve is omitted. See conversion-warnings.txt"}
    # Stage all outputs, then copy only after successful conversion of every source.
    with tempfile.TemporaryDirectory(prefix="acl4ssr-stage-") as tmp:
        stage = Path(tmp)
        stage_rules = stage / "Rules"
        for rel, content in all_outputs.items():
            output = stage_rules / rel
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
        (stage / "filter_remote.snippet").write_text(snippet, encoding="utf-8")
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "conversion-warnings.txt").write_text("\n".join(warnings) + ("\n" if warnings else ""), encoding="utf-8")
        root.mkdir(parents=True, exist_ok=True)
        output_rules = root / "Rules"
        if output_rules.exists():
            shutil.rmtree(output_rules)
        shutil.copytree(stage_rules, output_rules)
        for item in ("filter_remote.snippet", "manifest.json", "conversion-warnings.txt"):
            shutil.copy2(stage / item, root / item)
    return {"sources": len(sources), "rules": grand_total, "warnings": len(warnings)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="GitHub owner/repository")
    parser.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", "main"))
    parser.add_argument("--output", default=".", help="Repository root directory")
    args = parser.parse_args()
    if not args.repo:
        parser.error("Provide --repo YOURNAME/ACL4SSR-QuantumultX (or use GitHub Actions)")
    try:
        summary = run(Path(args.output), args.repo, args.branch)
        print(f"OK: {summary['sources']} files, {summary['rules']} rules, {summary['warnings']} notices")
    except ConversionError as exc:
        print("SYNC FAILED: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
