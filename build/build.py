#!/usr/bin/env python3
"""
Main build orchestrator for Nxtscape Browser
"""

import sys
import time
import click
from pathlib import Path
from typing import Optional

# Import shared components
from context import BuildContext
from utils import load_config, log_info, log_warning, log_error, log_success

# Import modules
from modules.clean import clean
from modules.git import setup_git, setup_sparkle
from modules.patches import apply_patches
from modules.resources import copy_resources
from modules.chromium_replace import replace_chromium_files, add_file_to_replacements
from modules.configure import configure
from modules.compile import build
from modules.sign import sign, sign_universal
from modules.package import package, package_universal
from modules.postbuild import run_postbuild
from modules.slack import (
    notify_build_started,
    notify_build_step,
    notify_build_success,
    notify_build_failure,
    notify_build_interrupted,
)


def build_main(
    config_file: Optional[Path] = None,
    clean_flag: bool = False,
    git_setup_flag: bool = False,
    apply_patches_flag: bool = False,
    chromium_replace_flag: bool = False,
    sign_flag: bool = False,
    package_flag: bool = False,
    build_flag: bool = False,
    arch: str = "arm64",
    build_type: str = "debug",
    chromium_src_dir: Optional[Path] = None,
    slack_notifications: bool = False,
):
    """Main build orchestration"""
    log_info("🚀 Nxtscape Build System")
    log_info("=" * 50)

    # Setup context
    root_dir = Path(__file__).parent.parent

    # Initialize chromium_src as None - will be set from CLI or config
    chromium_src = None

    # Load config if provided
    config = None
    gn_flags_file = None
    architectures = [arch]  # Default to single architecture
    universal = False
    if config_file:
        config = load_config(config_file)
        log_info(f"📄 Loaded config from: {config_file}")

        # Override parameters from config
        if "build" in config:
            build_type = config["build"].get("type", build_type)
            arch = config["build"].get("architecture", arch)
            # Check for multi-architecture builds
            if "architectures" in config["build"]:
                architectures = config["build"]["architectures"]
            universal = config["build"].get("universal", False)

        if "steps" in config:
            clean_flag = config["steps"].get("clean", clean_flag)
            git_setup_flag = config["steps"].get("git_setup", git_setup_flag)
            apply_patches_flag = config["steps"].get(
                "apply_patches", apply_patches_flag
            )
            chromium_replace_flag = config["steps"].get("chromium_replace", chromium_replace_flag)
            build_flag = config["steps"].get("build", build_flag)
            sign_flag = config["steps"].get("sign", sign_flag)
            package_flag = config["steps"].get("package", package_flag)

        # Override slack notifications from config if not explicitly set via CLI
        if "notifications" in config:
            slack_notifications = config["notifications"].get(
                "slack", slack_notifications
            )

        if "gn_flags" in config and "file" in config["gn_flags"]:
            gn_flags_file = Path(config["gn_flags"]["file"])

        # Get chromium_src from config (only if not provided via CLI)
        if (
            not chromium_src_dir
            and "paths" in config
            and "chromium_src" in config["paths"]
        ):
            config_chromium_src = Path(config["paths"]["chromium_src"])
            chromium_src = config_chromium_src
            log_info(f"📁 Using Chromium source from config: {chromium_src}")

    # CLI takes precedence over config
    if chromium_src_dir:
        chromium_src = chromium_src_dir
        log_info(f"📁 Using Chromium source from CLI: {chromium_src}")

    # Enforce chromium_src requirement
    if not chromium_src:
        log_error("Chromium source directory is required!")
        log_error(
            "Provide it via --chromium-src CLI option or paths.chromium_src in config YAML"
        )
        log_error("Example: python build.py --chromium-src /path/to/chromium/src")
        raise ValueError("chromium_src is required but not provided")

    # Validate chromium_src path exists
    if not chromium_src.exists():
        log_error(f"Chromium source directory does not exist: {chromium_src}")
        log_error("Please provide a valid chromium source path")
        raise FileNotFoundError(f"Chromium source directory not found: {chromium_src}")

    # Display build configuration
    log_info(f"📍 Root: {root_dir}")
    log_info(f"📍 Chromium source: {chromium_src}")
    log_info(f"📍 Architectures: {architectures}")
    log_info(f"📍 Universal build: {universal}")
    log_info(f"📍 Build type: {build_type}")

    # Start time for overall build
    start_time = time.time()

    # Notify build started (if enabled)
    if slack_notifications:
        notify_build_started(build_type, str(architectures))

    # Run build steps
    try:
        built_contexts = []

        # Build each architecture separately
        for arch_name in architectures:
            log_info(f"\n{'='*60}")
            log_info(f"🏗️  Building for architecture: {arch_name}")
            log_info(f"{'='*60}")

            ctx = BuildContext(
                root_dir=root_dir,
                chromium_src=chromium_src,
                architecture=arch_name,
                build_type=build_type,
                apply_patches=apply_patches_flag,
                sign_package=sign_flag,
                package=package_flag,
                build=build_flag,
            )

            log_info(f"📍 Chromium: {ctx.chromium_version}")
            log_info(f"📍 Nxtscape: {ctx.nxtscape_version}")
            log_info(f"📍 Output directory: {ctx.out_dir}")

            # Clean (only for first architecture to avoid conflicts)
            if clean_flag and arch_name == architectures[0]:
                clean(ctx)
                if slack_notifications:
                    notify_build_step("Completed cleaning build artifacts")

            # Git setup (only once for first architecture)
            if git_setup_flag and arch_name == architectures[0]:
                setup_git(ctx)
                if slack_notifications:
                    notify_build_step("Completed Git setup and Chromium source")

            # Apply patches (only once for first architecture)
            if apply_patches_flag and arch_name == architectures[0]:
                setup_sparkle(ctx)
                apply_patches(ctx)
                copy_resources(ctx)
                if slack_notifications:
                    notify_build_step(
                        "Completed applying patches and copying resources"
                    )

            # Replace chromium files (only once for first architecture)
            if chromium_replace_flag and arch_name == architectures[0]:
                replace_chromium_files(ctx)
                if slack_notifications:
                    notify_build_step("Completed replacing chromium files")

            # Build for this architecture
            if build_flag:
                if slack_notifications:
                    notify_build_step(f"Started building for {arch_name}")
                configure(ctx, gn_flags_file)
                build(ctx)

                # Run post-build tasks
                run_postbuild(ctx)

                if slack_notifications:
                    notify_build_step(f"Completed building for {arch_name}")

            # Sign and package immediately after building each architecture
            if sign_flag:
                log_info(f"\n🔏 Signing {ctx.architecture} build...")
                if slack_notifications:
                    notify_build_step(f"[{ctx.architecture}] Started signing")
                sign(ctx)
                if slack_notifications:
                    notify_build_step(f"[{ctx.architecture}] Completed signing")

            if package_flag:
                log_info(f"\n📦 Packaging {ctx.architecture} build...")
                if slack_notifications:
                    notify_build_step(f"[{ctx.architecture}] Started DMG creation")
                package(ctx)
                if slack_notifications:
                    notify_build_step(f"[{ctx.architecture}] Completed DMG creation")

            built_contexts.append(ctx)

        # Handle universal build if requested
        if len(architectures) > 1 and universal:
            # Universal build: merge, sign and package
            log_info(f"\n{'='*60}")
            log_info("🔄 Creating universal binary...")
            log_info(f"{'='*60}")

            # Import merge function
            from modules.merge import merge_architectures
            import shutil

            # Get paths for the built apps
            arch1_app = built_contexts[0].get_app_path()
            arch2_app = built_contexts[1].get_app_path()

            # Clean up old universal output directory if it exists
            universal_dir = built_contexts[0].chromium_src / "out/Default_universal"
            if universal_dir.exists():
                log_info("🧹 Cleaning up old universal output directory...")
                shutil.rmtree(universal_dir)

            # Create fresh universal output path
            universal_dir.mkdir(parents=True, exist_ok=True)
            universal_app_path = universal_dir / built_contexts[0].NXTSCAPE_APP_NAME

            # Find universalizer script
            universalizer_script = root_dir / "build" / "universalizer_patched.py"

            # Merge the architectures
            if not merge_architectures(
                arch1_app, arch2_app, universal_app_path, universalizer_script
            ):
                raise RuntimeError(
                    "Failed to merge architectures into universal binary"
                )

            if slack_notifications:
                notify_build_step(
                    "Completed merging architectures into universal binary"
                )

            if sign_flag:
                if slack_notifications:
                    notify_build_step("[Universal] Started signing and notarization")
                sign_universal(built_contexts)
                if slack_notifications:
                    notify_build_step("[Universal] Completed signing and notarization")

            if package_flag:
                if slack_notifications:
                    notify_build_step("[Universal] Started DMG package creation")
                package_universal(built_contexts)
                if slack_notifications:
                    notify_build_step("[Universal] Completed DMG package creation")

        # Summary
        elapsed = time.time() - start_time
        mins = int(elapsed / 60)
        secs = int(elapsed % 60)

        log_info("\n" + "=" * 60)
        log_success(
            f"Build completed for {len(architectures)} architecture(s) in {mins}m {secs}s"
        )
        if universal and len(architectures) > 1:
            log_success("Universal binary created successfully!")
        log_info("=" * 60)

        # Notify build success (if enabled)
        if slack_notifications:
            notify_build_success(mins, secs)

    except KeyboardInterrupt:
        log_warning("\nBuild interrupted")
        if slack_notifications:
            notify_build_interrupted()
        sys.exit(130)
    except Exception as e:
        log_error(f"\nBuild failed: {e}")
        if slack_notifications:
            notify_build_failure(str(e))
        sys.exit(1)


@click.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Load configuration from YAML file",
)
@click.option("--clean", "-C", is_flag=True, default=False, help="Clean before build")
@click.option("--git-setup", "-g", is_flag=True, default=False, help="Git setup")
@click.option(
    "--apply-patches", "-p", is_flag=True, default=False, help="Apply patches"
)
@click.option(
    "--chromium-replace", "-r", is_flag=True, default=False, help="Replace chromium files"
)
@click.option(
    "--sign", "-s", is_flag=True, default=False, help="Sign and notarize the app"
)
@click.option(
    "--arch",
    "-a",
    type=click.Choice(["arm64", "x64"]),
    default="arm64",
    help="Architecture",
)
@click.option(
    "--build-type",
    "-t",
    type=click.Choice(["debug", "release"]),
    default="debug",
    help="Build type",
)
@click.option("--package", "-P", is_flag=True, default=False, help="Create DMG package")
@click.option("--build", "-b", is_flag=True, default=False, help="Build")
@click.option(
    "--chromium-src",
    "-S",
    type=click.Path(exists=False, path_type=Path),
    help="Path to Chromium source directory",
)
@click.option(
    "--slack-notifications",
    "-n",
    is_flag=True,
    default=False,
    help="Enable Slack notifications",
)
@click.option(
    "--merge",
    nargs=2,
    type=click.Path(path_type=Path),
    metavar="ARCH1_APP ARCH2_APP",
    help="Merge two architecture builds: --merge path/to/arch1.app path/to/arch2.app",
)
@click.option(
    "--add-replace",
    type=click.Path(exists=True, path_type=Path),
    help="Add a file to chromium_src replacement directory: --add-replace /path/to/chromium/src/file --chromium-src /path/to/chromium/src",
)
def main(
    config,
    clean,
    git_setup,
    apply_patches,
    chromium_replace,
    sign,
    arch,
    build_type,
    package,
    build,
    chromium_src,
    slack_notifications,
    merge,
    add_replace,
):
    """Simple build system for Nxtscape Browser"""

    # Validate chromium-src for commands that need it
    if add_replace or merge or (not config and chromium_src is None):
        if not chromium_src:
            if add_replace:
                log_error("--add-replace requires --chromium-src to be specified")
                log_error(
                    "Example: python build.py --add-replace /path/to/chromium/src/chrome/file.cc --chromium-src /path/to/chromium/src"
                )
            elif merge:
                log_error("--merge requires --chromium-src to be specified")
                log_error(
                    "Example: python build.py --merge app1.app app2.app --chromium-src /path/to/chromium/src"
                )
            else:
                log_error("--chromium-src is required when not using a config file")
                log_error("Example: python build.py --chromium-src /path/to/chromium/src")
            sys.exit(1)

        # Validate chromium_src path exists
        if not chromium_src.exists():
            log_error(f"Chromium source directory does not exist: {chromium_src}")
            sys.exit(1)

    # Handle add-replace command
    if add_replace:
        # Get root directory
        root_dir = Path(__file__).parent.parent
        
        # Call the function from chromium_replace module
        if add_file_to_replacements(add_replace, chromium_src, root_dir):
            sys.exit(0)
        else:
            sys.exit(1)

    # Handle merge command
    if merge:
        from modules.merge import handle_merge_command

        arch1_path, arch2_path = merge
        
        if handle_merge_command(arch1_path, arch2_path, chromium_src, sign, package):
            sys.exit(0)
        else:
            sys.exit(1)

    # Regular build workflow
    build_main(
        config_file=config,
        clean_flag=clean,
        git_setup_flag=git_setup,
        apply_patches_flag=apply_patches,
        chromium_replace_flag=chromium_replace,
        sign_flag=sign,
        package_flag=package,
        build_flag=build,
        arch=arch,
        build_type=build_type,
        chromium_src_dir=chromium_src,
        slack_notifications=slack_notifications,
    )


if __name__ == "__main__":
    main()
