from pathlib import Path
import sys
import os
import subprocess


# Root de sandbox 
SANDBOX_ROOT = Path(__file__).resolve().parents[2] / "sandbox"

def ensure_sandbox_exists():
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    (SANDBOX_ROOT / "in").mkdir(exist_ok=True)
    (SANDBOX_ROOT / "out").mkdir(exist_ok=True)
    (SANDBOX_ROOT / "keys").mkdir(exist_ok=True)

def ensure_in_sandbox(path_like):
   
    p = Path(path_like)
   
    try:
        p_resolved = p.resolve()
    except Exception:
        p_resolved = (Path.cwd() / p).resolve()
    sandbox_root = SANDBOX_ROOT.resolve()
    if not str(p_resolved).startswith(str(sandbox_root)):
        print(f"[ERROR] Ruta fuera de sandbox detectada: {p_resolved}")
        sys.exit(2)
    return p_resolved

def is_in_sandbox(path_like):
    try:
        p_resolved = Path(path_like).resolve()
    except Exception:
        p_resolved = (Path.cwd() / Path(path_like)).resolve()
    return str(p_resolved).startswith(str(SANDBOX_ROOT.resolve()))

def test_block_out_of_sandbox():
   
    outside = Path("outside.tmp")
    outside.write_bytes(b"data")
    r = subprocess.run([sys.executable, "-m", "src.cli", "encrypt",
                        "--infile", str(outside), 
                        "--outfile", "sandbox/out/x.enc",
                        "--keyfile", "sandbox/keys/secret.key"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "fuera de sandbox" in r.stdout.lower() or "ruta fuera de sandbox" in r.stdout.lower()
