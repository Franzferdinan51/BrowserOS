#!/usr/bin/env python3
"""
Windows packaging module for Nxtscape Browser
Based on ungoogled-chromium-windows packaging approach
"""

import sys
import shutil
import zipfile
from pathlib import Path
from typing import Optional, List
from context import BuildContext
from utils import run_command, log_info, log_error, log_success, log_warning, join_paths


def package(ctx: BuildContext) -> bool:
    """Create Windows packages (installer and portable zip)"""
    log_info("\n📦 Creating Windows packages...")
    
    # Create both installer and portable zip
    success = True
    
    if create_installer(ctx):
        log_success("Installer created successfully")
    else:
        log_error("Failed to create installer")
        success = False
    
    if create_portable_zip(ctx):
        log_success("Portable ZIP created successfully")
    else:
        log_error("Failed to create portable ZIP")
        success = False
    
    return success


def create_installer(ctx: BuildContext) -> bool:
    """Create Windows installer (mini_installer.exe)"""
    log_info("\n🔧 Creating Windows installer...")
    
    # Get paths
    build_output_dir = join_paths(ctx.chromium_src, ctx.out_dir)
    mini_installer_path = build_output_dir / "mini_installer.exe"
    
    if not mini_installer_path.exists():
        log_warning(f"mini_installer.exe not found at: {mini_installer_path}")
        log_info("To build the installer, run: autoninja -C out\\Default_x64 mini_installer")
        return False
    
    # Create output directory
    output_dir = ctx.root_dir / "dist"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate installer filename with version and architecture
    installer_name = f"{ctx.get_app_base_name()}_{ctx.get_nxtscape_version()}_{ctx.architecture}_installer.exe"
    installer_path = output_dir / installer_name
    
    # Copy mini_installer to final location
    try:
        shutil.copy2(mini_installer_path, installer_path)
        log_success(f"Installer created: {installer_name}")
        return True
    except Exception as e:
        log_error(f"Failed to create installer: {e}")
        return False


def create_portable_zip(ctx: BuildContext) -> bool:
    """Create ZIP of just the installer for easier distribution"""
    log_info("\n📦 Creating installer ZIP package...")
    
    # Get paths
    build_output_dir = join_paths(ctx.chromium_src, ctx.out_dir)
    mini_installer_path = build_output_dir / "mini_installer.exe"
    
    if not mini_installer_path.exists():
        log_warning(f"mini_installer.exe not found at: {mini_installer_path}")
        log_info("To build the installer, run: autoninja -C out\\Default_x64 mini_installer")
        return False
    
    # Create output directory
    output_dir = ctx.root_dir / "dist"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate ZIP filename with version and architecture
    zip_name = f"{ctx.get_app_base_name()}_{ctx.get_nxtscape_version()}_{ctx.architecture}_installer.zip"
    zip_path = output_dir / zip_name
    
    # Create ZIP file containing just the installer
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add mini_installer.exe to the zip
            installer_name = f"{ctx.get_app_base_name()}_{ctx.get_nxtscape_version()}_{ctx.architecture}_installer.exe"
            zipf.write(mini_installer_path, installer_name)
            
            # Get file size for logging
            file_size = mini_installer_path.stat().st_size
            log_info(f"Added installer to ZIP ({file_size // (1024*1024)} MB)")
                    
        log_success(f"Installer ZIP created: {zip_name}")
        return True
    except Exception as e:
        log_error(f"Failed to create installer ZIP: {e}")
        return False


def sign_binaries(ctx: BuildContext, certificate_name: Optional[str] = None) -> bool:
    """Sign Windows binaries using signtool"""
    log_info("\n🔏 Signing Windows binaries...")
    
    if not certificate_name:
        log_warning("No certificate specified, skipping signing")
        return True
    
    # Get paths to sign
    build_output_dir = join_paths(ctx.chromium_src, ctx.out_dir)
    chrome_exe = build_output_dir / "chrome.exe"
    
    if not chrome_exe.exists():
        log_error(f"chrome.exe not found at: {chrome_exe}")
        return False
    
    # Check if signtool is available
    signtool_path = shutil.which("signtool")
    if not signtool_path:
        # Try to find it in Windows SDK locations
        sdk_paths = [
            Path("C:/Program Files (x86)/Windows Kits/10/bin"),
            Path("C:/Program Files/Windows Kits/10/bin"),
        ]
        
        for sdk_path in sdk_paths:
            if sdk_path.exists():
                # Look for signtool in architecture-specific subdirectories
                for arch_dir in sdk_path.glob("*/x64"):
                    potential_signtool = arch_dir / "signtool.exe"
                    if potential_signtool.exists():
                        signtool_path = str(potential_signtool)
                        break
            if signtool_path:
                break
    
    if not signtool_path:
        log_error("signtool.exe not found. Please install Windows SDK.")
        return False
    
    # Sign the main executable
    try:
        # Basic signing command - can be extended with timestamp server etc.
        cmd = [
            signtool_path,
            "sign",
            "/n", certificate_name,  # Certificate name
            "/t", "http://timestamp.digicert.com",  # Timestamp server
            "/fd", "sha256",  # File digest algorithm
            str(chrome_exe)
        ]
        
        run_command(cmd)
        log_success("Binary signed successfully")
        
        # Verify signature
        verify_cmd = [signtool_path, "verify", "/pa", str(chrome_exe)]
        run_command(verify_cmd)
        log_success("Signature verified successfully")
        
        return True
    except Exception as e:
        log_error(f"Failed to sign binary: {e}")
        return False


def package_universal(contexts: List[BuildContext]) -> bool:
    """Windows doesn't support universal binaries like macOS"""
    log_warning("Universal binaries are not supported on Windows")
    log_info("Consider creating separate packages for each architecture")
    return True


def get_target_cpu(build_output_dir: Path) -> str:
    """Get target CPU architecture from build configuration"""
    args_gn_path = build_output_dir / "args.gn"
    
    if not args_gn_path.exists():
        return "x64"  # Default
    
    try:
        args_gn_content = args_gn_path.read_text(encoding='utf-8')
        for cpu in ('x64', 'x86', 'arm64'):
            if f'target_cpu="{cpu}"' in args_gn_content:
                return cpu
    except Exception:
        pass
    
    return "x64"  # Default


def create_files_cfg_package(ctx: BuildContext) -> bool:
    """Create package using Chromium's FILES.cfg approach (alternative method)"""
    log_info("\n📦 Creating FILES.cfg-based package...")
    
    build_output_dir = join_paths(ctx.chromium_src, ctx.out_dir)
    files_cfg_path = ctx.chromium_src / "chrome" / "tools" / "build" / "win" / "FILES.cfg"
    
    if not files_cfg_path.exists():
        log_error(f"FILES.cfg not found at: {files_cfg_path}")
        return False
    
    # This would require implementing the filescfg module functionality
    # from ungoogled-chromium, which is quite complex
    log_warning("FILES.cfg packaging not yet implemented")
    return False