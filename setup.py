import os
import platform
import shutil
import tarfile
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

from setuptools import setup
from setuptools.command.build import build

CPYTHON_NEAR_VERSION = os.environ.get("CPYTHON_NEAR_VERSION", "v3.13.5-near")

BINARYEN_VERSION = os.environ.get("BINARYEN_VERSION", "123")
BINARYEN_PLATFORM_MAP = {
    "linux": ("x86_64-linux", "tar.gz"),
    "macos_x86_64": ("x86_64-macos", "tar.gz"),
    "macos_arm64": ("arm64-macos", "tar.gz"),
    "windows": ("x86_64-windows", "tar.gz"),
}


class CustomBuild(build):
    def run(self):
        bin_dir = Path("src/cpython_near_wasm_opt/bin")
        lib_dir = Path("src/cpython_near_wasm_opt/lib")
        for dir in (bin_dir, lib_dir):
            if dir.exists():
                shutil.rmtree(dir)
            dir.mkdir(parents=True, exist_ok=True)

        self.download_binaryen(bin_dir, lib_dir)
        self.download_cpython(lib_dir)

        super().run()

    def download_binaryen(self, bin_dir, lib_dir):
        build_platform = os.environ.get("BUILD_PLATFORM")
        if build_platform:
            system = build_platform.lower()
        else:
            system = platform.system().lower()
            if system == "darwin":
                system = f"macos_{platform.machine().lower()}"
            elif system == "windows":
                system = "windows"
            else:
                system = "linux"

        build_dir = Path("build")
        if build_dir.exists():
            shutil.rmtree(build_dir)

        if system not in BINARYEN_PLATFORM_MAP:
            raise RuntimeError(f"Unsupported platform: {system}")

        platform_name, ext = BINARYEN_PLATFORM_MAP[system]
        url = f"https://github.com/WebAssembly/binaryen/releases/download/version_{BINARYEN_VERSION}/binaryen-version_{BINARYEN_VERSION}-{platform_name}.{ext}"

        archive_path = f"binaryen.{ext}"
        print(f"Downloading {url}...")
        urlretrieve(url, archive_path)

        binary_name_suffixes = (
            "wasm-dis",
            "wasm-as",
            "wasm-opt",
            "wasm-dis.exe",
            "wasm-as.exe",
            "wasm-opt.exe",
        )
        if ext == "tar.gz":
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(binary_name_suffixes):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, bin_dir)
                    if member.name.endswith("libbinaryen.dylib"):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, lib_dir)
        elif ext == "zip":
            with zipfile.ZipFile(archive_path, "r") as zip_file:
                for name in zip_file.namelist():
                    if name.endswith(binary_name_suffixes):
                        with (
                            zip_file.open(name) as src,
                            open(bin_dir / os.path.basename(name), "wb") as dst,
                        ):
                            shutil.copyfileobj(src, dst)

        if system not in ["windows"]:
            for binary in bin_dir.glob("wasm-*"):
                binary.chmod(0o755)

        os.remove(archive_path)

    def download_cpython(self, lib_dir):
        url = f"https://github.com/past-hypothesis/cpython-near/releases/download/{CPYTHON_NEAR_VERSION}/python-wasm-near-{CPYTHON_NEAR_VERSION}.zip"

        archive_path = f"python-wasm-near-{CPYTHON_NEAR_VERSION}.zip"
        print(f"Downloading {url}...")
        urlretrieve(url, archive_path)

        with zipfile.ZipFile(archive_path, "r") as zip_file:
            for name in zip_file.namelist():
                with (
                    zip_file.open(name) as src,
                    open(lib_dir / os.path.basename(name), "wb") as dst,
                ):
                    shutil.copyfileobj(src, dst)

        os.remove(archive_path)


setup(
    cmdclass={"build": CustomBuild},
)
