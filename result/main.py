from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import messagebox, simpledialog


@dataclass(frozen=True)
class NetworkAdapter:
    name: str
    description: str
    guid: str
    mac_address: str
    ipv4_addresses: tuple[str, ...]

    @property
    def display_name(self) -> str:
        addresses = ", ".join(self.ipv4_addresses)
        return f"{self.name} | {self.description} | {addresses}"

    @property
    def npcap_name(self) -> str:
        guid = self.guid.strip("{}")
        return rf"\Device\NPF_{{{guid}}}"


@dataclass
class ArpScanData:
    network: str
    interface: str
    command: list[str] = field(default_factory=list)
    devices: dict[str, set[str]] = field(default_factory=dict)
    conflicts: dict[str, set[str]] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    output_file: Path | None = None


class ArpScanner:
    _RESULT_PATTERN = re.compile(
        r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})$"
    )

    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or Path(__file__).with_name("ArpScan.exe")

    @staticmethod
    def list_adapters() -> list[NetworkAdapter]:
        script = (
            "$ErrorActionPreference = 'Stop'; "
            "$adapters = @(Get-NetAdapter | "
            "Where-Object Status -eq 'Up' | Sort-Object ifIndex | ForEach-Object { "
            "$adapter = $_; "
            "$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex "
            "-AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object AddressState -eq 'Preferred' | "
            "ForEach-Object { $_.IPAddress }); "
            "if ($addresses.Count -gt 0 -and $adapter.MacAddress) { "
            "[PSCustomObject]@{ Name = $adapter.Name; "
            "Description = $adapter.InterfaceDescription; "
            "Guid = $adapter.InterfaceGuid.ToString(); "
            "MacAddress = $adapter.MacAddress; IPv4Addresses = $addresses } } }); "
            "$adapters | ConvertTo-Json -Compress -Depth 3"
        )
        completed = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
        if completed.returncode != 0:
            error = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(f"读取网卡失败：{error}")

        raw_adapters = json.loads(completed.stdout or "[]")
        if isinstance(raw_adapters, dict):
            raw_adapters = [raw_adapters]

        adapters = []
        for item in raw_adapters:
            addresses = item.get("IPv4Addresses", [])
            if isinstance(addresses, str):
                addresses = [addresses]
            adapters.append(
                NetworkAdapter(
                    name=item["Name"],
                    description=item["Description"],
                    guid=item["Guid"],
                    mac_address=item["MacAddress"],
                    ipv4_addresses=tuple(addresses),
                )
            )
        return adapters

    def scan(self, network: str, adapter: NetworkAdapter) -> ArpScanData:
        try:
            parsed_network = ipaddress.ip_network(network, strict=False)
        except ValueError as error:
            raise ValueError("请输入有效的 IPv4 CIDR 网段") from error
        if parsed_network.version != 4:
            raise ValueError("仅支持 IPv4 网段")
        if not self.executable.is_file():
            raise FileNotFoundError(f"未找到扫描程序：{self.executable}")

        normalized_network = str(parsed_network)
        command = [
            str(self.executable),
            f"--interface={adapter.npcap_name}",
            "--plain",
            "--quiet",
            "--numeric",
            "--format=${ip}\\t${mac}",
            normalized_network,
        ]
        data = ArpScanData(
            network=normalized_network,
            interface=adapter.npcap_name,
            command=command,
        )

        completed = subprocess.run(
            command,
            cwd=self.executable.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
        data.stdout = completed.stdout
        data.stderr = completed.stderr
        data.return_code = completed.returncode

        if completed.returncode != 0:
            raise RuntimeError(
                f"ArpScan 扫描失败，退出代码 {completed.returncode}："
                f"{completed.stderr.strip()}"
            )

        for line in completed.stdout.splitlines():
            match = self._RESULT_PATTERN.fullmatch(line.strip())
            if match is None:
                continue
            ip = match.group("ip")
            mac = match.group("mac").lower()
            data.devices.setdefault(ip, set()).add(mac)

        data.conflicts = {
            ip: macs for ip, macs in data.devices.items() if len(macs) > 1
        }
        return data

    @staticmethod
    def write_conflicts(data: ArpScanData, output_file: Path) -> None:
        conflicts = sorted(
            data.conflicts.items(),
            key=lambda item: ipaddress.ip_address(item[0]),
        )
        lines = [f"{ip} {', '.join(sorted(macs))}" for ip, macs in conflicts]
        output_file.write_text(
            "\n".join(lines) + ("\n" if lines else ""),
            encoding="utf-8",
        )
        data.output_file = output_file


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    scanner = ArpScanner()

    try:
        network = simpledialog.askstring(
            "IP 冲突扫描",
            "请输入 IPv4 网段（例如 172.168.10.0/24）：",
            parent=root,
        )
        if network is None:
            return

        try:
            parsed_network = ipaddress.ip_network(network.strip(), strict=False)
        except ValueError:
            messagebox.showerror("错误", "请输入有效的 IPv4 CIDR 网段", parent=root)
            return
        if parsed_network.version != 4:
            messagebox.showerror("错误", "仅支持 IPv4 网段", parent=root)
            return

        adapters = scanner.list_adapters()
        if not adapters:
            messagebox.showerror("错误", "未找到具有 IPv4 地址的活动网卡", parent=root)
            return

        adapter_list = "\n".join(
            f"{index}. {adapter.display_name}"
            for index, adapter in enumerate(adapters, start=1)
        )
        selection = simpledialog.askstring(
            "选择网卡",
            f"请输入网卡序号：\n\n{adapter_list}",
            parent=root,
        )
        if selection is None:
            return

        try:
            adapter_index = int(selection.strip())
            if not 1 <= adapter_index <= len(adapters):
                raise ValueError
            adapter = adapters[adapter_index - 1]
        except ValueError:
            messagebox.showerror("错误", "请输入有效的网卡序号", parent=root)
            return

        data = scanner.scan(str(parsed_network), adapter)
        output_file = Path.cwd() / "冲突IP.txt"
        scanner.write_conflicts(data, output_file)
        if data.conflicts:
            status = f"扫描完成，发现 {len(data.conflicts)} 个冲突 IP"
        else:
            status = "扫描完成，未发现冲突 IP"
        messagebox.showinfo(
            "扫描完成",
            f"{status}\n结果已写入：{output_file}",
            parent=root,
        )
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        messagebox.showerror("扫描失败", str(error), parent=root)
    finally:
        root.destroy()


if __name__ == "__main__":
    main()
