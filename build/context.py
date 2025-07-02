#!/usr/bin/env python3
"""
Build context dataclass to hold all build state
"""

import time
import sys
from pathlib import Path
from dataclasses import dataclass
from utils import log_info, log_error, log_success, log_warning


@dataclass
class BuildContext:
    """Simple dataclass to hold all build state"""

    root_dir: Path
    chromium_src: Path = Path()
    out_dir: str = "out/Default"
    architecture: str = "arm64"
    build_type: str = "debug"
    apply_patches: bool = False
    sign_package: bool = False
    package: bool = False
    build: bool = False
    chromium_version: str = ""
    nxtscape_version: str = ""
    nxtscape_chromium_version: str = ""
    start_time: float = 0.0

    # App names
    CHROMIUM_APP_NAME: str = "Chromium.app"
    NXTSCAPE_APP_NAME: str = "BrowserOS.app"

    # Third party
    SPARKLE_VERSION: str = "2.7.0"

    def __post_init__(self):
        """Load version files and set architecture-specific out_dir"""
        # Set architecture-specific output directory
        self.out_dir = f"out/Default_{self.architecture}"

        version_dict = {}

        if not self.chromium_version:
            # Read from VERSION file
            version_file = self.root_dir / "CHROMIUM_VERSION"
            if version_file.exists():
                # Parse VERSION file format: MAJOR=137\nMINOR=0\nBUILD=7151\nPATCH=69
                for line in version_file.read_text().strip().split("\n"):
                    key, value = line.split("=")
                    version_dict[key] = value

                # Construct chromium_version as MAJOR.MINOR.BUILD.PATCH
                self.chromium_version = f"{version_dict['MAJOR']}.{version_dict['MINOR']}.{version_dict['BUILD']}.{version_dict['PATCH']}"

        if not self.nxtscape_version:
            # Read from NXTSCAPE_VERSION file
            version_file = self.root_dir / "build" / "config" / "NXTSCAPE_VERSION"
            if version_file.exists():
                self.nxtscape_version = version_file.read_text().strip()

        # Set nxtscape_chromium_version as chromium version with BUILD + nxtscape_version
        if self.chromium_version and self.nxtscape_version and version_dict:
            # Calculate new BUILD number by adding nxtscape_version to original BUILD
            new_build = int(version_dict["BUILD"]) + int(self.nxtscape_version)
            self.nxtscape_chromium_version = f"{version_dict['MAJOR']}.{version_dict['MINOR']}.{new_build}.{version_dict['PATCH']}"

        # Determine chromium source directory
        if self.chromium_src and self.chromium_src.exists():
            log_warning(f"📁 Using provided Chromium source: {self.chromium_src}")
        else:
            log_warning(f"⚠️  Provided path does not exist: {self.chromium_src}")
            self.chromium_src = self.root_dir / "chromium_src"
            if not self.chromium_src.exists():
                log_error(
                    f"⚠️  Default Chromium source path does not exist: {self.chromium_src}"
                )
                raise FileNotFoundError(
                    f"Chromium source path does not exist: {self.chromium_src}"
                )

        self.start_time = time.time()

    # Path getter methods
    def get_config_dir(self) -> Path:
        """Get build config directory"""
        return self.root_dir / "build" / "config"

    def get_gn_config_dir(self) -> Path:
        """Get GN config directory"""
        return self.get_config_dir() / "gn"

    def get_gn_flags_file(self) -> Path:
        """Get GN flags file for current build type"""
        return self.get_gn_config_dir() / f"flags.macos.{self.build_type}.gn"

    def get_copy_resources_config(self) -> Path:
        """Get copy resources configuration file"""
        return self.get_config_dir() / "copy_resources.yaml"

    def get_patches_dir(self) -> Path:
        """Get patches directory"""
        return self.root_dir / "patches"

    def get_nxtscape_patches_dir(self) -> Path:
        """Get Nxtscape specific patches directory"""
        return self.get_patches_dir() / "nxtscape"

    def get_sparkle_dir(self) -> Path:
        """Get Sparkle directory"""
        return self.chromium_src / "third_party" / "sparkle"

    def get_sparkle_url(self) -> str:
        """Get Sparkle download URL"""
        return f"https://github.com/sparkle-project/Sparkle/releases/download/{self.SPARKLE_VERSION}/Sparkle-{self.SPARKLE_VERSION}.tar.xz"

    def get_resources_dir(self) -> Path:
        """Get resources directory"""
        return self.root_dir / "resources"

    def get_resources_files_dir(self) -> Path:
        """Get resources files directory"""
        return self.get_resources_dir() / "files"

    def get_resources_gen_dir(self) -> Path:
        """Get generated resources directory"""
        return self.get_resources_dir() / "gen"

    def get_chrome_resources_dir(self) -> Path:
        """Get Chrome browser resources directory"""
        return self.chromium_src / "chrome" / "browser" / "resources"

    def get_chrome_theme_dir(self) -> Path:
        """Get Chrome theme directory"""
        return self.chromium_src / "chrome" / "app" / "theme" / "chromium"

    def get_chrome_app_dir(self) -> Path:
        """Get Chrome app directory"""
        return self.chromium_src / "chrome" / "app"

    def get_entitlements_dir(self) -> Path:
        """Get entitlements directory"""
        return self.root_dir / "resources" / "entitlements"

    def get_dmg_dir(self) -> Path:
        """Get DMG output directory"""
        return self.chromium_src / self.out_dir / "dmg"

    def get_pkg_dmg_path(self) -> Path:
        """Get pkg-dmg tool path"""
        return self.chromium_src / "chrome" / "installer" / "mac" / "pkg-dmg"

    def get_app_path(self) -> Path:
        """Get built app path"""
        return self.chromium_src / self.out_dir / self.NXTSCAPE_APP_NAME

    def get_chromium_app_path(self) -> Path:
        """Get original Chromium app path"""
        return self.chromium_src / self.out_dir / self.CHROMIUM_APP_NAME

    def get_gn_args_file(self) -> Path:
        """Get GN args file path"""
        return self.chromium_src / self.out_dir / "args.gn"

    def get_notarization_zip(self) -> Path:
        """Get notarization zip path"""
        return self.chromium_src / self.out_dir / "notarize.zip"

    def get_dmg_name(self, signed=False) -> str:
        """Get DMG filename with architecture suffix"""
        if self.architecture == "universal":
            if signed:
                return f"BrowserOS_{self.nxtscape_chromium_version}_universal_signed.dmg"
            return f"BrowserOS_{self.nxtscape_chromium_version}_universal.dmg"
        else:
            if signed:
                return f"BrowserOS_{self.nxtscape_chromium_version}_{self.architecture}_signed.dmg"
            return f"BrowserOS_{self.nxtscape_chromium_version}_{self.architecture}.dmg"

    # Extension names
    def get_ai_extensions(self) -> list[str]:
        """Get list of AI extension names"""
        return ["ai_side_panel"]

    # Bundle identifiers
    def get_bundle_identifier(self) -> str:
        """Get main bundle identifier"""
        return "com.browseros.BrowserOS"

    def get_base_identifier(self) -> str:
        """Get base identifier for components"""
        return "com.browseros"
