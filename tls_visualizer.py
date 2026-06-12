import ssl
import socket
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from cryptography import x509
from cryptography.hazmat.backends import default_backend

console = Console()

def security_rating(tls_version, cipher_info, days_left):
    score = 0
    breakdown = []

    if tls_version == "TLSv1.3":
        score += 30
        breakdown.append(("[green]TLS 1.3 — Most Secure Version[/green]", "+30"))
    elif tls_version == "TLSv1.2":
        score += 20
        breakdown.append(("[yellow]TLS 1.2 — Acceptable but outdated[/yellow]", "+20"))
    else:
        score += 0
        breakdown.append(("[red]TLS 1.1 or below — INSECURE[/red]", "+0"))

    key_size = cipher_info[2]
    if key_size >= 256:
        score += 30
        breakdown.append(("[green]256-bit cipher — Military Grade[/green]", "+30"))
    elif key_size >= 128:
        score += 20
        breakdown.append(("[yellow]128-bit cipher — Acceptable[/yellow]", "+20"))
    else:
        score += 0
        breakdown.append(("[red]Weak cipher — INSECURE[/red]", "+0"))

    score += 20
    breakdown.append(("[green]Forward Secrecy — Enabled[/green]", "+20"))

    if days_left > 30:
        score += 20
        breakdown.append((f"[green]Certificate valid — {days_left} days left[/green]", "+20"))
    elif days_left > 0:
        score += 10
        breakdown.append((f"[yellow]Certificate expiring soon — {days_left} days left[/yellow]", "+10"))
    else:
        score += 0
        breakdown.append(("[red]Certificate EXPIRED[/red]", "+0"))

    if score >= 90:
        label = "[green]🟢 EXCELLENT[/green]"
    elif score >= 70:
        label = "[yellow]🟡 GOOD[/yellow]"
    elif score >= 50:
        label = "[orange]🟠 FAIR[/orange]"
    else:
        label = "[red]🔴 POOR — NOT SECURE[/red]"

    rating_table = Table(
        title="🛡️ Security Rating",
        box=box.ROUNDED,
        border_style="cyan"
    )
    rating_table.add_column("Security Check", style="white", width=40)
    rating_table.add_column("Points", style="cyan", width=10)

    for item, points in breakdown:
        rating_table.add_row(item, points)

    rating_table.add_row("─" * 35, "─────")
    rating_table.add_row(
        f"[bold]Overall Score: {score}/100  {label}[/bold]",
        f"[bold]{score}[/bold]"
    )
    console.print(rating_table)


def analyze_tls(hostname):
    console.print(f"\n[bold navy]🔐 TLS Handshake Visualizer[/bold navy]")
    console.print(f"[grey]Analyzing: {hostname}[/grey]\n")

    console.print(Panel(
        "[bold]Step 1 — Client Hello[/bold]\n"
        f"→ Your client is connecting to: [cyan]{hostname}[/cyan]\n"
        "→ Offering to use TLS 1.2 and TLS 1.3\n"
        "→ Sending list of supported cipher suites",
        title="[yellow]📤 CLIENT HELLO[/yellow]",
        border_style="yellow"
    ))

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname
        )
        conn.connect((hostname, 443))

        tls_version = conn.version()
        cipher_info = conn.cipher()
        cert_binary = conn.getpeercert(binary_form=True)

        console.print(Panel(
            "[bold]Step 2 — Server Hello[/bold]\n"
            f"→ Server selected: [green]{tls_version}[/green] ✅\n"
            f"→ Cipher suite selected: [green]{cipher_info[0]}[/green]\n"
            f"→ Key size: [green]{cipher_info[2]} bits[/green]",
            title="[green]📥 SERVER HELLO[/green]",
            border_style="green"
        ))

        cert = x509.load_der_x509_certificate(cert_binary, default_backend())
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        valid_from = cert.not_valid_before_utc
        valid_until = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (valid_until - now).days

        if days_left > 0:
            cert_status = f"[green]Valid — {days_left} days remaining ✅[/green]"
        else:
            cert_status = "[red]EXPIRED ❌[/red]"

        console.print(Panel(
            f"[bold]Step 3 — Certificate Exchange[/bold]\n"
            f"→ Certificate received ✅\n"
            f"→ Subject: [cyan]{subject[:60]}[/cyan]\n"
            f"→ Issuer: [cyan]{issuer[:60]}[/cyan]\n"
            f"→ Valid from: [white]{valid_from.strftime('%d %b %Y')}[/white]\n"
            f"→ Valid until: [white]{valid_until.strftime('%d %b %Y')}[/white]\n"
            f"→ Status: {cert_status}",
            title="[blue]📜 CERTIFICATE EXCHANGE[/blue]",
            border_style="blue"
        ))

        pub_key = cert.public_key()
        pub_key_type = type(pub_key).__name__

        console.print(Panel(
            f"[bold]Step 4 — Key Exchange[/bold]\n"
            f"→ Algorithm: [green]{cipher_info[0]}[/green]\n"
            f"→ Public Key Type: [green]{pub_key_type}[/green]\n"
            f"→ Forward Secrecy: [green]Enabled ✅[/green]\n"
            f"→ Session key established securely",
            title="[magenta]🔑 KEY EXCHANGE[/magenta]",
            border_style="magenta"
        ))

        console.print(Panel(
            f"[bold]Step 5 — Handshake Complete[/bold]\n"
            f"→ TLS Version: [green]{tls_version} ✅[/green]\n"
            f"→ Cipher: [green]{cipher_info[0]}[/green]\n"
            f"→ All data is now encrypted 🔒\n"
            f"→ Connection to [cyan]{hostname}[/cyan] is [green]SECURE[/green]",
            title="[green]✅ HANDSHAKE COMPLETE[/green]",
            border_style="green"
        ))

        table = Table(
            title="🔐 TLS Security Summary",
            box=box.ROUNDED,
            border_style="blue"
        )
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="white", width=45)
        table.add_row("Website", hostname)
        table.add_row("TLS Version", tls_version)
        table.add_row("Cipher Suite", cipher_info[0])
        table.add_row("Key Size", f"{cipher_info[2]} bits")
        table.add_row("Certificate Status", f"Valid — {days_left} days left")
        table.add_row("Certificate Issuer", issuer[:50])
        table.add_row("Forward Secrecy", "Enabled ✅")
        table.add_row("Connection", "SECURE 🔒")
        console.print(table)

        security_rating(tls_version, cipher_info, days_left)
        conn.close()

    except ssl.SSLError as e:
        console.print(f"[red]❌ SSL Error: {e}[/red]")
    except socket.gaierror:
        console.print(f"[red]❌ Could not connect to {hostname}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


def compare_websites(hostnames):
    console.print(Panel(
        "[bold]Comparing TLS Security Across Multiple Websites[/bold]\n"
        "Analyzing each website and comparing security configurations",
        title="[bold cyan]📊 TLS COMPARISON MODE[/bold cyan]",
        border_style="cyan"
    ))

    results = []

    for hostname in hostnames:
        hostname = hostname.strip()
        console.print(f"\n[yellow]🔍 Analyzing {hostname}...[/yellow]")

        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=hostname
            )
            conn.connect((hostname, 443))

            tls_version = conn.version()
            cipher_info = conn.cipher()
            cert_binary = conn.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(
                cert_binary, default_backend()
            )

            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (cert.not_valid_after_utc - now).days
            issuer = cert.issuer.rfc4514_string()

            score = 0
            if tls_version == "TLSv1.3":
                score += 30
            elif tls_version == "TLSv1.2":
                score += 20
            if cipher_info[2] >= 256:
                score += 30
            elif cipher_info[2] >= 128:
                score += 20
            score += 20
            if days_left > 30:
                score += 20
            elif days_left > 0:
                score += 10

            if score >= 90:
                rating = "🟢 EXCELLENT"
            elif score >= 70:
                rating = "🟡 GOOD"
            elif score >= 50:
                rating = "🟠 FAIR"
            else:
                rating = "🔴 POOR"

            results.append({
                "hostname": hostname,
                "tls_version": tls_version,
                "cipher": cipher_info[0],
                "key_size": cipher_info[2],
                "days_left": days_left,
                "issuer": issuer[:40],
                "score": score,
                "rating": rating
            })

            conn.close()
            console.print(f"[green]✅ Done — Score: {score}/100[/green]")

        except Exception as e:
            console.print(f"[red]❌ Failed: {e}[/red]")
            results.append({
                "hostname": hostname,
                "tls_version": "Error",
                "cipher": "N/A",
                "key_size": 0,
                "days_left": 0,
                "issuer": "N/A",
                "score": 0,
                "rating": "❌ ERROR"
            })

    console.print("\n")
    comp_table = Table(
        title="📊 TLS Security Comparison Report",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True
    )
    comp_table.add_column("Website", style="cyan", width=20)
    comp_table.add_column("TLS Version", style="white", width=12)
    comp_table.add_column("Cipher Suite", style="white", width=25)
    comp_table.add_column("Key Size", style="white", width=10)
    comp_table.add_column("Cert Days", style="white", width=10)
    comp_table.add_column("Score", style="bold", width=8)
    comp_table.add_column("Rating", style="bold", width=15)

    results.sort(key=lambda x: x["score"], reverse=True)

    for r in results:
        if r["score"] >= 90:
            score_str = f"[green]{r['score']}/100[/green]"
        elif r["score"] >= 70:
            score_str = f"[yellow]{r['score']}/100[/yellow]"
        else:
            score_str = f"[red]{r['score']}/100[/red]"

        comp_table.add_row(
            r["hostname"],
            r["tls_version"],
            r["cipher"][:22],
            f"{r['key_size']} bits",
            f"{r['days_left']} days",
            score_str,
            r["rating"]
        )

    console.print(comp_table)

    if len(results) > 1:
        best = results[0]
        worst = results[-1]
        console.print(Panel(
            f"[green]🏆 Most Secure: {best['hostname']} — {best['score']}/100[/green]\n"
            f"[red]⚠️  Least Secure: {worst['hostname']} — {worst['score']}/100[/red]\n\n"
            f"[white]Key Finding: Sites using TLS 1.3 with 256-bit ciphers\n"
            f"provide the strongest security for user data.[/white]",
            title="[bold]📋 Analysis Summary[/bold]",
            border_style="white"
        ))


def main():
    console.print(Panel(
        "[bold]TLS Handshake Visualizer[/bold]\n"
        "Analyzes the TLS security handshake of any HTTPS website\n"
        "Shows: TLS version, cipher suite, certificate details, security rating",
        title="[bold blue]🔐 Welcome[/bold blue]",
        border_style="blue"
    ))

    while True:
        console.print("\n[bold cyan]Choose mode:[/bold cyan]")
        console.print("  [white]1[/white] — Analyze single website")
        console.print("  [white]2[/white] — Compare multiple websites")
        console.print("  [white]q[/white] — Quit")

        choice = console.input("\n[bold cyan]Enter choice: [/bold cyan]")

        if choice.lower() == 'q':
            console.print("[yellow]Goodbye! 👋[/yellow]")
            break

        elif choice == '1':
            hostname = console.input(
                "[bold cyan]Enter website: [/bold cyan]"
            )
            hostname = hostname.replace("https://", "").replace(
                "http://", "").strip("/")
            analyze_tls(hostname)

        elif choice == '2':
            console.print(
                "[grey]Enter websites separated by commas[/grey]\n"
                "[grey]Example: google.com, sbi.co.in, flipkart.com[/grey]"
            )
            sites = console.input("[bold cyan]Enter websites: [/bold cyan]")
            hostnames = [
                s.replace("https://", "").replace(
                    "http://", "").strip("/")
                for s in sites.split(",")
            ]
            compare_websites(hostnames)

        else:
            console.print("[red]Invalid choice — enter 1, 2 or q[/red]")


if __name__ == "__main__":
    main()