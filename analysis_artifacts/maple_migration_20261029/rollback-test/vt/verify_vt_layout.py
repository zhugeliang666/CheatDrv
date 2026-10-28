from __future__ import annotations

import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VT = ROOT / "vt"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"[FAIL] {message}")
    print(f"[OK] {message}")


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def macro_number(source: str, name: str) -> int:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+(0x[0-9A-Fa-f]+|[0-9]+)(?:ul|ull)?$", source, re.M)
    require(match is not None, f"macro {name} exists")
    return int(match.group(1), 0)


expected = {
    "VtHypervisor": "VtHypervisor.vcxproj",
    "VtResidentPayload": "VtResidentPayload.vcxproj",
    "VtBootstrapDriver": "VtBootstrapDriver.vcxproj",
}
for directory, project in expected.items():
    require((VT / directory).is_dir(), f"directory {directory}")
    require((VT / directory / project).is_file(), f"project {directory}/{project}")

obsolete_names = (
    "vtcall" + "-driver-main",
    "vt-call" + "-pyaload-main",
    "vt-call" + "-mapdriver-main",
)
for obsolete in obsolete_names:
    require(not (VT / obsolete).exists(), f"obsolete directory removed: {obsolete}")

solution = text(ROOT / "Machenike.sln")
for directory, project in expected.items():
    require(f'"{directory}", "vt\\{directory}\\{project}"' in solution,
            f"Machenike.sln references {directory}")

standalone = text(VT / "VtHypervisor" / "VtHypervisor.sln")
require('= "VtHypervisor", "VtHypervisor.vcxproj"' in standalone,
        "standalone solution/project names match VtHypervisor.sys")
require(("Test" + "Driver.vcxproj") not in standalone, "stale TestDriver project name removed")

bootstrap_project = text(VT / "VtBootstrapDriver" / "VtBootstrapDriver.vcxproj")
require("..\\VtHypervisor\\VtHypervisor.vcxproj" in bootstrap_project,
        "bootstrap references VtHypervisor")
require("..\\VtResidentPayload\\VtResidentPayload.vcxproj" in bootstrap_project,
        "bootstrap references VtResidentPayload")

loader_main = text(ROOT / "loader" / "main.cpp")
loader_header = text(ROOT / "loader" / "vt_loader.h")
loader_common = text(ROOT / "loader" / "loader_common.h")
driver_common = text(ROOT / "Core" / "Common.h")
bootstrap_main = text(VT / "VtBootstrapDriver" / "main.cpp")
require("#define ENABLE_VT_FRAMEWORK 1" in loader_common,
        "loader VT framework is enabled")
require("#define ENABLE_VT_FRAMEWORK 1" in driver_common,
        "Machenike VT framework is enabled")
require("#define VT_STAGE12_SKIP_MACHENIKE 0" in loader_main,
        "final profile enables Machenike")
require("ValidateRuntimeForMachenike" in loader_header,
        "pre-Machenike runtime gate is compiled")
require("ValidateMachenikeLoaded" in loader_header,
        "post-Machenike runtime gate is compiled")
require("mapdriver_amd_svm_resident_ready" in bootstrap_main,
        "AMD resident-VMRUN migration gate is compiled")
require("onekey AMD resident transfer" in bootstrap_main,
        "AMD resident transfer completion is observable")
require("bool const amdLegacyReleased" in loader_header and
        "bool const amdLegacyRetained" in loader_header and
        "amdLegacyReleased || amdLegacyRetained" in loader_header and
        "st.test_unloaded != 0" in loader_header and
        "st.test_quarantined != 0" in loader_header,
        "AMD final gate accepts released or retained-quarantine legacy image")
require("VT_AMD_RELEASE_LEGACY_IMAGE_AFTER_HANDOFF 1" in
        (VT / "common" / "vt_config.h").read_text(encoding="utf-8-sig"),
        "AMD automatic legacy-image release is enabled by default")
require("AMD legacy image retained after resident handoff" in bootstrap_main,
        "AMD retained-image stabilization branch is observable")
require("PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE" in loader_header,
        "AMD final gate requires complete legacy detach")
runtime_gate = loader_header[
    loader_header.index("static bool ValidateRuntimeForMachenike"):
    loader_header.index("static bool ValidateMachenikeLoaded")
]
common_gate = runtime_gate[
    runtime_gate.index("bool const commonOk"):
    runtime_gate.index("bool const amd")
]
require("vmexit_target" not in common_gate and "vmexit_bridge_target" not in common_gate,
        "backend-neutral gate does not require legacy VM-exit targets")
require("check.payload.vmexit_target == 0" in runtime_gate and
        "check.payload.vmexit_bridge_target == 0" in runtime_gate,
        "AMD final gate requires released legacy VM-exit targets")
require("bool const intelTargetsReady" in runtime_gate and
        "check.payload.vmexit_target != 0" in runtime_gate and
        "check.payload.vmexit_bridge_target != 0" in runtime_gate,
        "Intel final gate retains nonzero resident-bridge targets")
build_path_token = 'L"%svt\\\\VtBootstrapDriver.sys"'
compat_path_token = 'L"%sVtBootstrapDriver.sys"'
require(build_path_token in loader_header,
        "loader knows canonical bin/vt bootstrap output")
require(loader_header.index(build_path_token) < loader_header.index(compat_path_token),
        "loader prefers canonical bin/vt bootstrap output")
require("RemoveLegacyBootstrapAliases" in bootstrap_project,
        "bootstrap build removes stale root aliases")

outputs = {
    "VtHypervisor": ROOT / "bin" / "vt" / "VtHypervisor.sys",
    "VtResidentPayload": ROOT / "bin" / "vt" / "VtResidentPayload.sys",
    "VtBootstrapDriver": ROOT / "bin" / "vt" / "VtBootstrapDriver.sys",
    "Machenike": ROOT / "bin" / "mswsk.sys",
    "loader": ROOT / "bin" / "loader.exe",
}
for name, path in outputs.items():
    require(path.is_file() and path.stat().st_size > 0, f"output exists: {name}")
    require(path.read_bytes()[:2] == b"MZ", f"output is PE: {name}")

hypervisor = outputs["VtHypervisor"].read_bytes()
hypervisor_hash = hashlib.sha256(hypervisor).hexdigest().upper()
hypervisor_header = text(VT / "VtBootstrapDriver" / "common" / "hypervisor_payload.h")
embedded_hash = re.search(r'^#define\s+HYPERVISOR_PAYLOAD_SHA256\s+"([0-9A-F]{64})"$', hypervisor_header, re.M)
require(embedded_hash is not None, "embedded VtHypervisor SHA-256 exists")
require(embedded_hash.group(1) == hypervisor_hash, "embedded VtHypervisor SHA-256 matches final SYS")
require(macro_number(hypervisor_header, "HYPERVISOR_PAYLOAD_UNPACKED_SIZE") == len(hypervisor),
        "embedded VtHypervisor size matches final SYS")

payload = outputs["VtResidentPayload"].read_bytes()
payload_hash = hashlib.sha256(payload).hexdigest().upper()
payload_header = text(VT / "VtBootstrapDriver" / "common" / "resident_payload.h")
payload_embedded_hash = re.search(r'^#define\s+PAYLOAD_IMAGE_SOURCE_PE_SHA256\s+"([0-9A-F]{64})"$', payload_header, re.M)
require(payload_embedded_hash is not None, "embedded VtResidentPayload SHA-256 exists")
require(payload_embedded_hash.group(1) == payload_hash, "embedded VtResidentPayload SHA-256 matches final SYS")
require(macro_number(payload_header, "PAYLOAD_IMAGE_SOURCE_PE_SIZE") == len(payload),
        "embedded VtResidentPayload source size matches final SYS")

machenike = outputs["Machenike"].read_bytes()
machenike_hash = hashlib.sha256(machenike).hexdigest().upper()
machenike_header = text(VT / "VtBootstrapDriver" / "common" / "machenike_payload.h")
machenike_embedded_hash = re.search(r'^#define\s+MACHENIKE_SYS_SHA256\s+"([0-9A-F]{64})"$', machenike_header, re.M)
require(machenike_embedded_hash is not None, "embedded Machenike SHA-256 exists")
require(machenike_embedded_hash.group(1) == machenike_hash, "embedded Machenike SHA-256 matches final SYS")
require(macro_number(machenike_header, "MACHENIKE_SYS_UNPACKED_SIZE") == len(machenike),
        "embedded Machenike size matches final SYS")

print("[PASS] VT final integration layout and embedded-image checks completed")
