#!/usr/bin/env python3
"""
Universal binary merge module for Nxtscape Browser
Provides CLI to merge two architecture builds into a universal binary
"""

import os
import sys
import shutil
import click
from pathlib import Path
from typing import List
from context import BuildContext
from utils import run_command, log_info, log_error, log_success, log_warning


def merge_architectures(
    arch1_path: Path,
    arch2_path: Path,
    output_path: Path,
    universalizer_script: Path = None
) -> bool:
    """
    Merge two architecture builds into a universal binary
    
    Args:
        arch1_path: Path to first architecture .app bundle
        arch2_path: Path to second architecture .app bundle  
        output_path: Path where universal .app bundle should be created
        universalizer_script: Path to universalizer script (optional)
    
    Returns:
        True if successful, False otherwise
    """
    log_info("🔄 Merging architecture builds into universal binary...")
    
    # Validate input paths
    if not arch1_path.exists():
        log_error(f"Architecture 1 app not found: {arch1_path}")
        return False
    
    if not arch2_path.exists():
        log_error(f"Architecture 2 app not found: {arch2_path}")
        return False
    
    log_info(f"📱 Input 1: {arch1_path}")
    log_info(f"📱 Input 2: {arch2_path}")
    log_info(f"🎯 Output: {output_path}")
    
    # Find universalizer script
    if universalizer_script is None:
        # Try to find it relative to this module
        current_dir = Path(__file__).parent.parent
        universalizer_script = current_dir / "universalizer_patched.py"
    
    if not universalizer_script.exists():
        log_error(f"Universalizer script not found: {universalizer_script}")
        return False
    
    # Create output directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove existing output if present
    if output_path.exists():
        log_info(f"Removing existing output: {output_path}")
        shutil.rmtree(output_path)
    
    try:
        # Run universalizer
        cmd = [
            sys.executable,
            str(universalizer_script),
            str(arch1_path),
            str(arch2_path),
            str(output_path)
        ]
        
        log_info(f"Running universalizer...")
        log_info(f"Command: {' '.join(cmd)}")
        run_command(cmd)
        
        if output_path.exists():
            log_success(f"Universal binary created: {output_path}")
            return True
        else:
            log_error("Universal binary creation failed - output not found")
            return False
            
    except Exception as e:
        log_error(f"Failed to create universal binary: {e}")
        return False


def create_minimal_context(app_path: Path, architecture: str = "universal") -> BuildContext:
    """Create a minimal BuildContext for signing/packaging operations"""
    
    # Determine paths from app location
    # app_path should be like: /path/to/build/src/out/Default_universal/Nxtscape.app
    out_dir_path = app_path.parent  # out/Default_universal
    chromium_src = out_dir_path.parent.parent  # build/src
    root_dir = chromium_src.parent  # build parent
    
    ctx = BuildContext(
        root_dir=root_dir,
        chromium_src=chromium_src,
        architecture=architecture,
        build_type="release",  # Assume release for universal builds
        apply_patches=False,
        sign_package=True,
        package=True,
        build=False,
    )
    
    # Override out_dir to match the actual location
    ctx.out_dir = out_dir_path.name
    
    return ctx


def merge_sign_package(
    arch1_path: Path,
    arch2_path: Path,
    output_path: Path,
    sign: bool = True,
    package: bool = True,
    universalizer_script: Path = None
) -> bool:
    """
    Complete workflow: merge, sign, and package universal binary
    
    Args:
        arch1_path: Path to first architecture .app bundle
        arch2_path: Path to second architecture .app bundle
        output_path: Path where universal .app bundle should be created
        sign: Whether to sign the universal binary
        package: Whether to create DMG package
        universalizer_script: Path to universalizer script (optional)
    
    Returns:
        True if successful, False otherwise
    """
    log_info("=" * 70)
    log_info("🚀 Starting merge, sign, and package workflow...")
    log_info("=" * 70)
    
    # Step 1: Merge architectures
    if not merge_architectures(arch1_path, arch2_path, output_path, universalizer_script):
        return False
    
    # Step 2: Sign (if requested)
    if sign:
        log_info("\n" + "=" * 70)
        log_info("🔏 Signing universal binary...")
        log_info("=" * 70)
        
        try:
            from modules.sign import sign_app
            
            ctx = create_minimal_context(output_path)
            if not sign_app(ctx, create_dmg=False):
                log_error("Failed to sign universal binary")
                return False
            
            log_success("Universal binary signed successfully!")
            
        except ImportError as e:
            log_error(f"Could not import signing module: {e}")
            return False
        except Exception as e:
            log_error(f"Signing failed: {e}")
            return False
    
    # Step 3: Package (if requested)
    if package:
        log_info("\n" + "=" * 70)
        log_info("📦 Creating DMG package...")
        log_info("=" * 70)
        
        try:
            from modules.package import create_dmg
            
            ctx = create_minimal_context(output_path)
            
            # Create DMG in parent directory
            dmg_dir = ctx.root_dir / "dmg"
            dmg_dir.mkdir(parents=True, exist_ok=True)
            
            dmg_name = f"Nxtscape_{ctx.nxtscape_chromium_version}_universal.dmg"
            if sign:
                dmg_name = dmg_name.replace(".dmg", "_signed.dmg")
            
            dmg_path = dmg_dir / dmg_name
            pkg_dmg_path = ctx.get_pkg_dmg_path()
            
            if create_dmg(output_path, dmg_path, "Nxtscape", pkg_dmg_path):
                log_success(f"DMG created: {dmg_name}")
            else:
                log_error("Failed to create DMG")
                return False
                
        except ImportError as e:
            log_error(f"Could not import packaging module: {e}")
            return False
        except Exception as e:
            log_error(f"Packaging failed: {e}")
            return False
    
    log_info("\n" + "=" * 70)
    log_success("Merge, sign, and package workflow completed successfully!")
    log_info("=" * 70)
    
    return True


@click.command()
@click.option(
    "--arch1", "-1",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to first architecture .app bundle"
)
@click.option(
    "--arch2", "-2", 
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to second architecture .app bundle"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    required=True,
    help="Path where universal .app bundle should be created"
)
@click.option(
    "--universalizer", "-u",
    type=click.Path(exists=True, path_type=Path),
    help="Path to universalizer script (auto-detected if not provided)"
)
@click.option(
    "--sign/--no-sign", "-s/-S",
    default=True,
    help="Sign the universal binary (default: true)"
)
@click.option(
    "--package/--no-package", "-p/-P",
    default=True,
    help="Create DMG package (default: true)"
)
@click.option(
    "--merge-only", "-m",
    is_flag=True,
    default=False,
    help="Only merge architectures, skip signing and packaging"
)
def main(arch1, arch2, output, universalizer, sign, package, merge_only):
    """
    Merge two architecture builds into a universal binary.
    
    This tool merges two single-architecture Nxtscape.app bundles into a single
    universal binary, optionally signs it, and creates a DMG package.
    
    Examples:
    
    \b
    # Merge, sign, and package (full workflow)
    python -m modules.merge -1 out/Default_x86_64/Nxtscape.app -2 out/Default_arm64/Nxtscape.app -o out/Default_universal/Nxtscape.app
    
    \b
    # Merge only, no signing or packaging
    python -m modules.merge -1 out/Default_x86_64/Nxtscape.app -2 out/Default_arm64/Nxtscape.app -o out/Default_universal/Nxtscape.app --merge-only
    
    \b
    # Merge and sign, but don't package
    python -m modules.merge -1 out/Default_x86_64/Nxtscape.app -2 out/Default_arm64/Nxtscape.app -o out/Default_universal/Nxtscape.app --no-package
    """
    
    if merge_only:
        # Only merge, skip signing and packaging
        success = merge_architectures(arch1, arch2, output, universalizer)
    else:
        # Full workflow
        success = merge_sign_package(arch1, arch2, output, sign, package, universalizer)
    
    if not success:
        log_error("Merge workflow failed!")
        sys.exit(1)
    else:
        log_success("Merge workflow completed successfully!")


if __name__ == "__main__":
    main()