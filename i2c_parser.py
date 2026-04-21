import argparse
import pandas as pd
import re
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
register_map = defaultdict(set)

def extract_hex(value):
  if pd.isna(value):
    return None
  
  match = re.search(r"0x([0-9A-Fa-f]+)", str(value))
  if match:
    return int(match.group(1), 16)
  
  return None

def get_transactions(df):
  transactions = []

  for packet_id, group in df.groupby("packet_id"):
    group = group.sort_values("time")
    
    addr = None
    rw = None
    data_bytes = []
    
    for _, row in group.iterrows():
      if addr is None:
        addr = row["address"]
        rw = row["rw"]
      
      if row["data"] is not None:
        data_bytes.append(row["data"])
    
    transactions.append({
      "packet_id": packet_id,
      "address": addr,
      "rw": rw,
      "data": data_bytes
    })
  return transactions

def get_reads(transactions):
  reads = []

  for i in range(len(transactions) - 1):
    t1 = transactions[i]
    t2 = transactions[i + 1]
    
    if t1["rw"] == "WRITE" and t2["rw"] == "READ":
      if t1["address"] == t2["address"]:
        if len(t1["data"]) >= 1:
          reg = t1["data"][0]
          real_reg = reg & 0x7F if reg & 0x80 else reg

          reads.append({
            "device": t1["address"],
            "register": real_reg,
            "raw_register": reg,
            "data": t2["data"]
          })
  return reads

def parse_file(file_path, address=None, register=None, transaction=None):
  console.print(f"[bold cyan]Loading file:[/bold cyan] {file_path}")

  df = pd.read_csv(file_path)
  
  df.columns = [c.strip().lower() for c in df.columns]

  df = df.rename(columns={
      "time [s]": "time",
      "packet id": "packet_id",
      "read/write": "rw",
      "ack/nak": "ack"
  })

  df["address"] = df["address"].apply(extract_hex)
  df["data"] = df["data"].apply(extract_hex)
  df["rw"] = df["rw"].str.strip().str.upper()

  transactions = get_transactions(df=df)
  
  reads = get_reads(transactions=transactions)

  if address:
    address = int(address, 16) if isinstance(address, str) else address
    reads = [r for r in reads if r["device"] == address]

  if register:
    register = int(register, 16) if isinstance(register, str) else register
    reads = [r for r in reads if r["register"] == register]

  if transaction:
    transaction = transaction.upper()
    if transaction == "R":
      reads = [r for r in reads if len(r["data"]) > 0]
    elif transaction == "W":
      reads = []

  if not address and not register and not transaction:
    devices = sorted(set(t["address"] for t in transactions if t["address"] is not None))

    summary = Table(title="Detected Devices", show_lines=True)
    summary.add_column("Device (HEX)", style="cyan")
    summary.add_column("Device (DEC)", style="magenta")

    for d in devices:
      summary.add_row(f"0x{d:02X}", str(d))

    console.print(summary)
    console.print(f"[bold green]Total devices:[/bold green] {len(devices)}\n")

  table = Table(title="I2C Register Reads", show_lines=True)

  table.add_column("Device", style="cyan", justify="center")
  table.add_column("Register", style="yellow", justify="center")
  table.add_column("Raw Reg", style="dim", justify="center")
  table.add_column("Data", style="green")

  for r in reads[:10]:
    data_str = " ".join(f"{b:02X}" for b in r["data"])
    table.add_row(
      f"0x{r['device']:02X}",
      f"0x{r['register']:02X}",
      f"0x{r['raw_register']:02X}",
      data_str
    )

  console.print(table)
  console.print(f"[bold blue]Total showing {len(reads[:10])} of:[/bold blue] {len(reads)}\n")

  if not address and not register and not transaction:
    for r in reads:
      register_map[r["device"]].add(r["register"])

    reg_table = Table(title="Register Map", show_lines=True)
    reg_table.add_column("Device", style="cyan")
    reg_table.add_column("Registers", style="yellow")

    for dev, regs in register_map.items():
      reg_list = ", ".join(f"0x{r:02X}" for r in sorted(regs))
      reg_table.add_row(f"0x{dev:02X}", reg_list)

    console.print(reg_table)


def main():
  parser = argparse.ArgumentParser(description="I2C Logic Analyzer Parser")

  parser.add_argument("file_path")
  parser.add_argument("-a", "--address", help="Filter by device address (e.g. 0x19)")
  parser.add_argument("-r", "--register", help="Filter by register (e.g. 0x0C)")
  parser.add_argument("-t", "--transaction", choices=["r", "w"], help="Filter by transaction type")

  args = parser.parse_args()

  parse_file(
    args.file_path,
    address=args.address,
    register=args.register,
    transaction=args.transaction
  )


if __name__ == "__main__":
  main()