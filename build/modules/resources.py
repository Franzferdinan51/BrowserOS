#!/usr/bin/env python3
"""
Resource management module for Nxtscape build system
"""

import sys
import glob
import shutil
import yaml
from pathlib import Path
from context import BuildContext
from utils import log_info, log_success, log_error, log_warning


def copy_resources(ctx: BuildContext) -> bool:
    """Copy AI extensions and icons based on YAML configuration"""
    log_info("\n📦 Copying resources...")

    # Load copy configuration
    copy_config_path = ctx.get_copy_resources_config()
    if not copy_config_path.exists():
        log_error(f"Copy configuration file not found: {copy_config_path}")
        raise FileNotFoundError(f"Copy configuration file not found: {copy_config_path}")

    with open(copy_config_path, "r") as f:
        config = yaml.safe_load(f)

    if "copy_operations" not in config:
        log_info("⚠️  No copy_operations defined in configuration")
        return True

    # Process each copy operation
    for operation in config["copy_operations"]:
        name = operation.get("name", "Unnamed operation")
        source = operation["source"]
        destination = operation["destination"]
        op_type = operation.get("type", "directory")
        build_type_condition = operation.get("build_type")

        # Skip operation if build_type condition doesn't match
        if build_type_condition and build_type_condition != ctx.build_type:
            log_info(
                f"  ⏭️  Skipping {name} (build_type: {build_type_condition}, current: {ctx.build_type})"
            )
            continue

        # Resolve paths
        src_path = ctx.root_dir / source
        dst_base = ctx.chromium_src / destination

        log_info(f"  • {name}")

        try:
            if op_type == "directory":
                # Copy entire directory
                if src_path.exists() and src_path.is_dir():
                    dst_path = dst_base
                    dst_path.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                    log_info(f"    ✓ Copied directory: {source} → {destination}")
                else:
                    log_warning(f"    Source directory not found: {source}")

            elif op_type == "files":
                # Copy files matching pattern
                files = glob.glob(str(ctx.root_dir / source))
                if files:
                    dst_base.mkdir(parents=True, exist_ok=True)
                    for file_path in files:
                        file_path = Path(file_path)
                        if file_path.is_file():
                            shutil.copy2(file_path, dst_base)
                    log_info(f"    ✓ Copied {len(files)} files: {source} → {destination}")
                else:
                    log_warning(f"    No files found matching: {source}")

            elif op_type == "file":
                # Copy single file
                if src_path.exists() and src_path.is_file():
                    dst_base.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_path, dst_base)
                    log_info(f"    ✓ Copied file: {source} → {destination}")
                else:
                    log_warning(f"    Source file not found: {source}")

        except Exception as e:
            log_error(f"    Error: {e}")

    log_success("Resources copied")

