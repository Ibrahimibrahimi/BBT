#!/usr/bin/env python3
"""
Crypter — an interactive CLI that runs a string through every
encoding/encryption/hash method it can find and prints the results
in a friendly, colorful table.

Methods are loaded dynamically from the `methods/` folder — see
loader.py and methods/base.py. Drop a new file in methods/ that
defines a BaseMethod subclass and it shows up automatically, no
code changes needed here.
"""

import argparse
import csv
import io
import json
import re
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich import box

from loader import load_methods

console = Console()
no_color = False

# One color per category, cycled if more categories appear later
CATEGORY_COLORS = {
    "Encoding": "cyan",
    "Hash": "magenta",
    "Cipher": "yellow",
}
DEFAULT_COLOR = "green"


def category_color(category: str) -> str:
    return CATEGORY_COLORS.get(category, DEFAULT_COLOR)


def format_results_json(results: list[dict]) -> str:
    return json.dumps(results, indent=2)


def format_results_csv(results: list[dict]) -> str:
    if not results:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)
    return buf.getvalue()


def print_banner():
    banner = Text()
    banner.append("  ▄████▄   ██▀███ ▓██   ██▓ ██▓███  ▄▄▄█████▓▓█████  ██▀███  \n", style="bold cyan")
    banner.append(" ▒██▀ ▀█  ▓██ ▒ ██▒▒██  ██▒▓██░  ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒\n", style="bold cyan")
    banner.append(" ▒▓█    ▄ ▓██ ░▄█ ▒ ▒██ ██░▓██░ ██▓▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒\n", style="bold blue")
    banner.append(" ▒▓▓▄ ▄██▒▒██▀▀█▄   ░ ▐██▓░▒██▄█▓▒ ▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  \n", style="bold blue")
    banner.append(" ▒ ▓███▀ ░░██▓ ▒██▒ ░ ██▒▓░▒██▒ ░  ░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒\n", style="bold white")
    banner.append("  string  ->  encode / encrypt / hash  ->  all at once", style="dim italic")
    console.print(Panel(banner, border_style="cyan", box=box.DOUBLE))


def list_methods(methods_list):
    table = Table(title="Available Methods", box=box.SIMPLE_HEAVY, header_style="bold white")
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")

    for i, m in enumerate(methods_list, start=1):
        color = category_color(m.category)
        table.add_row(str(i), Text(m.name, style=color), Text(m.category, style=color), m.description)

    console.print(table)


def run_methods(text: str, methods_list, check_match: str = None):
    """
    Run every method on `text`. If `check_match` is given, each result is
    also tested for a case-insensitive substring match against it (handy
    for matching a partial/truncated hash or encoded value) and matching
    rows are highlighted.
    """
    title = f'Results for: "{text}"'
    if check_match:
        title += f'  —  matching against: "{check_match}"'

    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold white",
        show_lines=False,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Method", style="bold", min_width=12)
    table.add_column("Category", min_width=10)
    table.add_column("Result", overflow="fold")
    if check_match:
        table.add_column("Match", justify="center", width=7)

    ok_count = 0
    fail_count = 0
    matches = []  # list of (method_name, result) that matched

    needle = check_match.lower() if check_match else None

    for i, m in enumerate(methods_list, start=1):
        color = category_color(m.category)
        try:
            result = m.encode(text)
            is_match = needle is not None and needle in result.lower()

            row_style = "bold on dark_green" if is_match else None
            row = [
                str(i),
                Text(m.name, style=color if not is_match else "bold black"),
                Text(m.category, style=color if not is_match else "bold black"),
                Text(result, style=None if not is_match else "bold black"),
            ]
            if check_match:
                row.append(Text("✔ MATCH", style="bold green") if is_match else Text("—", style="dim"))

            table.add_row(*row, style=row_style)
            ok_count += 1
            if is_match:
                matches.append((m.name, result))
        except Exception as exc:  # noqa: BLE001
            row = [
                str(i),
                Text(m.name, style=color),
                Text(m.category, style=color),
                Text(f"[failed: {exc}]", style="bold red"),
            ]
            if check_match:
                row.append(Text("—", style="dim"))
            table.add_row(*row)
            fail_count += 1

    console.print(table)
    summary = f"[green]{ok_count} succeeded[/green]"
    if fail_count:
        summary += f"  •  [red]{fail_count} failed[/red]"
    summary += f"  •  [dim]{len(methods_list)} methods total[/dim]"
    console.print(Panel(summary, border_style="dim", box=box.MINIMAL))

    if check_match:
        if matches:
            names = ", ".join(f"[bold green]{n}[/bold green]" for n, _ in matches)
            console.print(
                Panel(
                    f'[bold]"{check_match}"[/bold] found in {len(matches)} result(s): {names}',
                    border_style="green",
                    box=box.HEAVY,
                )
            )
        else:
            console.print(
                Panel(
                    f'[bold]"{check_match}"[/bold] was [red]not found[/red] in any result.',
                    border_style="red",
                    box=box.HEAVY,
                )
            )

    return matches


def run_methods_raw(text: str, methods_list) -> list[dict]:
    """Run every method and return a list of result dicts (for JSON/CSV output)."""
    results = []
    for m in methods_list:
        try:
            result = m.encode(text)
            results.append({"method": m.name, "category": m.category, "result": result, "error": None})
        except Exception as exc:  # noqa: BLE001
            results.append({"method": m.name, "category": m.category, "result": None, "error": str(exc)})
    return results


def filter_methods(
    methods_list,
    names: list[str] | None = None,
    category: str | None = None,
    pattern: str | None = None,
) -> list:
    """Return a filtered subset of methods based on the given criteria."""
    filtered = methods_list
    if names:
        name_set = {n.lower() for n in names}
        filtered = [m for m in filtered if m.name.lower() in name_set]
    if category:
        cat_lower = category.lower()
        filtered = [m for m in filtered if cat_lower in m.category.lower()]
    if pattern:
        regex = re.compile(pattern, re.IGNORECASE)
        filtered = [m for m in filtered if regex.search(m.name) or regex.search(m.description)]
    return filtered


def interactive_loop(methods_list):
    print_banner()
    console.print(
        f"[dim]Loaded [bold]{len(methods_list)}[/bold] method(s) from the methods/ folder. "
        f"Type [bold]:list[/bold] to see them, [bold]:q[/bold] to quit.[/dim]\n"
    )

    while True:
        try:
            text = Prompt.ask("[bold cyan]crypter[/bold cyan] [dim]>[/dim]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Bye![/dim]")
            break

        if not text.strip():
            continue

        if text.strip() in (":q", ":quit", ":exit"):
            console.print("[dim]Bye![/dim]")
            break

        if text.strip() == ":list":
            list_methods(methods_list)
            continue

        if text.strip() == ":help":
            console.print(
                "[bold]Commands:[/bold]\n"
                "  :list          show all loaded methods\n"
                "  :help          show this help\n"
                "  :q / :quit     exit\n"
                "  <any text>     run all methods on that text\n"
            )
            continue

        console.print()
        run_methods(text, methods_list)
        console.print()


def main():
    global no_color

    parser = argparse.ArgumentParser(
        description="Crypter — encode/encrypt/hash a string using every method found in methods/"
    )
    parser.add_argument("text", nargs="?", help="Text to encode. If omitted, launches interactive mode.")
    parser.add_argument(
        "-t", "--target",
        dest="target",
        help='Text to encode (alternative to positional arg), e.g. --target "hi this is a text"',
    )
    parser.add_argument(
        "-c", "--check-match",
        dest="check_match",
        metavar="VALUE",
        help="Check whether VALUE appears (case-insensitive substring) in any of the results, "
             'e.g. --check-match "ef59d". Useful for matching a partial/truncated hash.',
    )
    parser.add_argument("-l", "--list", action="store_true", help="List all loaded methods and exit.")

    # --- new flags ---
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        dest="output_format",
        help="Output results as JSON or CSV instead of the default Rich table.",
    )
    parser.add_argument(
        "--methods",
        nargs="+",
        metavar="NAME",
        help="Only run methods whose name matches one of the given names (case-insensitive).",
    )
    parser.add_argument(
        "--category",
        metavar="CAT",
        help="Only run methods whose category contains CAT (case-insensitive substring).",
    )
    parser.add_argument(
        "--pattern",
        metavar="REGEX",
        help="Only run methods whose name or description matches the given regex.",
    )
    parser.add_argument(
        "--input-encoding",
        dest="input_encoding",
        default="utf-8",
        metavar="ENCODING",
        help="Encoding of the input text (default: utf-8). E.g. latin-1, ascii, cp1252.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable Rich color/formatting output.",
    )
    args = parser.parse_args()

    no_color = args.no_color
    if no_color:
        global console
        console = Console(no_color=True)

    methods_list = load_methods()

    if not methods_list:
        console.print("[bold red]No methods found in methods/ folder.[/bold red]")
        sys.exit(1)

    # Apply method filters
    methods_list = filter_methods(methods_list, names=args.methods, category=args.category, pattern=args.pattern)

    if not methods_list:
        console.print("[bold red]No methods matched the given filters.[/bold red]")
        sys.exit(1)

    if args.list:
        print_banner()
        list_methods(methods_list)
        return

    # --target takes priority, but the positional arg still works too
    target_text = args.target if args.target is not None else args.text

    # Re-encode target text if a non-UTF-8 input encoding was specified
    if target_text and args.input_encoding.lower() != "utf-8":
        raw = target_text.encode("utf-8")
        try:
            target_text = raw.decode(args.input_encoding)
        except (UnicodeDecodeError, LookupError) as exc:
            console.print(f"[bold red]Input encoding error: {exc}[/bold red]")
            sys.exit(1)

    if target_text:
        if args.output_format:
            results = run_methods_raw(target_text, methods_list)
            if args.output_format == "json":
                print(format_results_json(results))
            elif args.output_format == "csv":
                print(format_results_csv(results))
            if args.check_match:
                needle = args.check_match.lower()
                matches = [r for r in results if r["result"] and needle in r["result"].lower()]
                sys.exit(0 if matches else 1)
        else:
            print_banner()
            matches = run_methods(target_text, methods_list, check_match=args.check_match)
            if args.check_match:
                sys.exit(0 if matches else 1)
        return

    interactive_loop(methods_list)


if __name__ == "__main__":
    main()
