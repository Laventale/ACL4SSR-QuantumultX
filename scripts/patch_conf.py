#!/usr/bin/env python3
"""Locally replace only Quantumult X [filter_remote] (never upload your profile)."""
import argparse
import re
from pathlib import Path


def replace_remote(profile: str, snippet: str) -> str:
    # An exact section boundary stops accidental edits in large private .conf files.
    pattern = r'(?im)^\[filter_remote\][ \t]*\r?\n[\s\S]*?(?=^\[[^\]\r\n]+\][ \t]*\r?$|\Z)'
    matched = list(re.finditer(pattern, profile))
    if len(matched) != 1:
        raise ValueError('Expected exactly one [filter_remote] section')
    if not snippet.strip() or re.search(r'(?im)^\s*\[filter_remote\]\s*$', snippet):
        raise ValueError('Provide generated filter_remote.snippet CONTENT, without header')
    if 'raw.githubusercontent.com/' not in snippet:
        raise ValueError('Snippet looks incomplete or invalid')
    block = '[filter_remote]\n' + snippet.strip() + '\n\n'
    return profile[:matched[0].start()] + block + profile[matched[0].end():]


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('private_profile', type=Path)
    cli.add_argument('filter_remote_snippet', type=Path)
    cli.add_argument('--output', type=Path)
    args = cli.parse_args()
    if args.output is None:
        args.output = args.private_profile.with_name(args.private_profile.stem + '_selfhosted.conf')
    if args.output.resolve() == args.private_profile.resolve():
        cli.error('Do not overwrite your original configuration')
    profile = args.private_profile.read_text(encoding='utf-8-sig')
    snippet = args.filter_remote_snippet.read_text(encoding='utf-8-sig')
    merged = replace_remote(profile, snippet)
    args.output.write_text(merged, encoding='utf-8')
    print('Saved local private profile:', args.output)
    print('This file contains your proxy credentials. NEVER publish it to GitHub.')


if __name__ == '__main__':
    main()
