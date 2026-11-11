import argparse
from pathlib import Path
from get_platform import get_platform
import zipfile
import io
import requests
import stat
import tarfile

root_path = Path(__file__).parent.parent


platform = get_platform()
if platform is None:
    exit(1)


parser = argparse.ArgumentParser()
parser.add_argument("tool")
parser.add_argument("tag")
parser.add_argument("--path", type=Path, required=True)
args = parser.parse_args()


def binutils_url(tag: str) -> str:
    # MIPS binutils (no Allegrex or VFPU: tools/vfpu_words.py)
    ext = "zip" if platform.system == "windows" else "tar.gz"
    return (f"https://github.com/decompals/binutils-mips-ps2-decompals/releases/download/{tag}/"
            f"binutils-mips-ps2-decompals-{platform.system}-x86-64.{ext}")


def wibo_url(tag: str) -> str:
    # Map platform to wibo binary name
    if platform.system == "darwin":
        binary = "wibo-macos"
    elif platform.machine == "i686" or platform.machine == "i386":
        binary = "wibo-i686"
    else:  # x86_64
        binary = "wibo-x86_64"
    return f"https://github.com/decompals/wibo/releases/download/{tag}/{binary}"


def objdiff_url(tag: str) -> str:
    return f"https://github.com/encounter/objdiff/releases/download/{tag}/objdiff-cli-{platform.system}-{platform.machine}{platform.exe}"


def compiler_url(tag: str) -> str:
    # decomp.me compiler archives; the tag is the compiler id (pspsnc_1.2.7503.0)
    return f"https://github.com/decompme/compilers/releases/download/compilers/{tag}.tar.gz"


TOOLS = {
    "binutils": binutils_url,
    "compiler": compiler_url,
    "wibo": wibo_url,
    "objdiff": objdiff_url,
}


download_url = TOOLS[args.tool](args.tag)
print(f"\nDownloading {args.tool} {args.tag}...")
response = requests.get(download_url)
response.raise_for_status()
if download_url.endswith(".zip"):
    zip_file = zipfile.ZipFile(io.BytesIO(response.content))
    zip_file.extractall(args.path)
elif download_url.endswith(".tar.gz"):
    with tarfile.open(fileobj=io.BytesIO(response.content)) as tar:
        tar.extractall(args.path, filter="data")
    if args.tool == "compiler" and platform.system == "windows":
        # Metrowerks compilers wait on the FLEXlm license window when run natively
        from lmgr_patch import patch_folder
        patch_folder(args.path)
else:
    out_path: Path = args.path
    with out_path.open("wb") as f:
        f.write(response.content)
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
