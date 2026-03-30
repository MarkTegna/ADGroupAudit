"""DC Replication Checker for AD Group Audit.

Queries group membership across all domain controllers in a domain
and reports discrepancies. Useful for diagnosing replication lag.

Usage:
  dc-repl-check.exe "CN=GroupName,OU=Groups,DC=domain,DC=com"
  dc-repl-check.exe --config myconfig.ini "CN=GroupName,..."
  dc-repl-check.exe --domain tgna.tegna.com "CN=GroupName,..."

Author: Mark Oldham
"""

import argparse
import os
import subprocess
from datetime import datetime

from ldap3 import ALL, KERBEROS, NTLM, SASL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from ad_group_audit.config_manager import ConfigManager
from ad_group_audit.version import __author__, __compile_date__, __version__

DEFAULT_INI = "ad_group_audit.ini"


def parse_args(args=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="dc-repl-check",
        description=(
            f"DC Replication Checker v{__version__} - "
            "Compare group membership across all domain controllers.\n"
            f"Author: {__author__} | Compiled: {__compile_date__}"
        ),
    )
    parser.add_argument(
        "group_dn",
        help="Distinguished name of the group to check",
    )
    parser.add_argument(
        "--config", default=DEFAULT_INI,
        help=f"Path to INI config file (default: {DEFAULT_INI})",
    )
    parser.add_argument(
        "--domain",
        help="Domain to check (default: first domain in config)",
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Print version info and exit",
    )
    return parser.parse_args(args)


def discover_domain_controllers(domain: str) -> list:
    """Discover all DCs for a domain using DNS SRV records via nslookup."""
    dcs = []
    try:
        result = subprocess.run(
            ["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if "svr hostname" in stripped.lower():
                # Format: "svr hostname   = dc01.domain.com"
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    hostname = parts[1].strip().rstrip(".")
                    if hostname:
                        dcs.append(hostname)
    except Exception as e:
        print(f"  [FAIL] DNS SRV lookup failed: {e}")

    if not dcs:
        # Fallback: try nltest
        try:
            result = subprocess.run(
                ["nltest", f"/dclist:{domain}"],
                capture_output=True, text=True, timeout=15,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if "." in line and not line.startswith("Get"):
                    # Lines like "DC01.domain.com [DS] Site: Default"
                    hostname = line.split()[0].strip().rstrip(".")
                    if hostname:
                        dcs.append(hostname)
        except Exception as e:
            print(f"  [FAIL] nltest fallback failed: {e}")

    return sorted(set(dc.lower() for dc in dcs))


def query_dc_members(dc_hostname: str, group_dn: str,
                     username: str = "", password: str = "") -> dict:
    """Query a single DC for group membership.

    Returns dict with 'members' (set of DNs), 'error' (str or None).
    """
    conn = None
    try:
        server = Server(dc_hostname, get_info=ALL, connect_timeout=10)
        if username:
            conn = Connection(
                server, user=username, password=password,
                authentication=NTLM, auto_bind=True,
                receive_timeout=30,
            )
        else:
            conn = Connection(
                server, authentication=SASL,
                sasl_mechanism=KERBEROS, auto_bind=True,
                receive_timeout=30,
            )

        conn.search(
            search_base=group_dn,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=["member"],
        )

        members = set()
        if conn.entries:
            entry = conn.entries[0]
            if hasattr(entry, "member") and entry.member:
                members = {str(m) for m in entry.member}

        return {"members": members, "error": None}

    except LDAPException as e:
        return {"members": set(), "error": str(e)}
    except Exception as e:
        return {"members": set(), "error": str(e)}
    finally:
        if conn:
            try:
                conn.unbind()
            except Exception:
                pass


def build_report(group_dn: str, dc_results: dict, domain: str) -> list:
    """Build the comparison report as a list of lines."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"DC Replication Check - {timestamp}",
        f"Domain: {domain}",
        f"Group:  {group_dn}",
        "=" * 70,
    ]

    # Separate successful and failed DCs
    successful = {dc: r for dc, r in dc_results.items() if r["error"] is None}
    failed = {dc: r for dc, r in dc_results.items() if r["error"] is not None}

    if failed:
        lines.append(f"\n  Unreachable DCs ({len(failed)}):")
        for dc, r in sorted(failed.items()):
            lines.append(f"    [FAIL] {dc}: {r['error']}")

    if not successful:
        lines.append("\n  No DCs responded successfully. Cannot compare.")
        return lines

    # Show member counts per DC
    lines.append(f"\n  Member counts ({len(successful)} DCs responded):")
    for dc in sorted(successful.keys()):
        count = len(successful[dc]["members"])
        lines.append(f"    {dc}: {count} members")

    # Find the consensus (most common member set)
    all_members = set()
    for r in successful.values():
        all_members |= r["members"]

    # Check for discrepancies
    discrepancies = []
    for member_dn in sorted(all_members):
        present_on = []
        missing_from = []
        for dc in sorted(successful.keys()):
            if member_dn in successful[dc]["members"]:
                present_on.append(dc)
            else:
                missing_from.append(dc)
        if missing_from:
            discrepancies.append({
                "member": member_dn,
                "present_on": present_on,
                "missing_from": missing_from,
            })

    if not discrepancies:
        lines.append(
            f"\n  [OK] All {len(successful)} DCs agree on membership "
            f"({len(all_members)} members)."
        )
    else:
        lines.append(f"\n  [WARN] {len(discrepancies)} discrepancies found:")
        lines.append("-" * 70)
        for d in discrepancies:
            lines.append(f"\n  Member: {d['member']}")
            lines.append(
                f"    Present on  ({len(d['present_on'])}): "
                f"{', '.join(d['present_on'])}"
            )
            lines.append(
                f"    Missing from ({len(d['missing_from'])}): "
                f"{', '.join(d['missing_from'])}"
            )

    lines.append("\n" + "=" * 70)
    return lines


def write_report(lines: list, output_dir: str = "logs") -> str:
    """Write report lines to a timestamped text file.

    Returns the output file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H-%M")
    filename = f"dc-repl-check-{timestamp}.txt"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return filepath


def main(args=None) -> int:
    """Entry point for DC replication checker."""
    parsed = parse_args(args)

    if parsed.version:
        print(f"DC Replication Checker v{__version__}")
        print(f"Author: {__author__}")
        print(f"Compile Date: {__compile_date__}")
        return 0

    # Load config for credentials
    config_mgr = ConfigManager(parsed.config)
    config = config_mgr.load()

    # Determine which domain to use
    domain_config = None
    if parsed.domain:
        for d in config.domains:
            if d.name.lower() == parsed.domain.lower():
                domain_config = d
                break
        if not domain_config:
            print(f"Error: Domain '{parsed.domain}' not found in config.")
            return 1
    elif config.domains:
        domain_config = config.domains[0]
    else:
        print("Error: No domains configured.")
        return 1

    domain = domain_config.name
    group_dn = parsed.group_dn

    print(f"Discovering domain controllers for {domain}...")
    dcs = discover_domain_controllers(domain)

    if not dcs:
        print(f"Error: No domain controllers found for {domain}")
        return 1

    print(f"Found {len(dcs)} domain controllers: {', '.join(dcs)}")
    print("Querying group membership on each DC...")

    dc_results = {}
    for dc in dcs:
        print(f"  Querying {dc}...", end=" ", flush=True)
        result = query_dc_members(
            dc, group_dn,
            username=domain_config.ldap_username,
            password=domain_config.ldap_password,
        )
        if result["error"]:
            print(f"[FAIL] {result['error']}")
        else:
            print(f"[OK] {len(result['members'])} members")
        dc_results[dc] = result

    report_lines = build_report(group_dn, dc_results, domain)
    print("\n".join(report_lines))

    filepath = write_report(report_lines)
    print(f"\nReport saved to: {filepath}")
    return 0


if __name__ == "__main__":
    rc = main()
    # Force exit to prevent ldap3/Kerberos background threads from hanging
    os._exit(rc)
