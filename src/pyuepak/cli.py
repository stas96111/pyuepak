import click, sys
from pathlib import Path
from pyuepak import PakFile, PakVersion


def common_options(func):
    func = click.pass_context(func)
    return func


@click.group()
@click.version_option("0.2.0", prog_name="pyuepak")
@click.option("--aes", type=str, help="AES key (hex string).")
@click.pass_context
def cli(ctx: click.Context, aes):
    """🗂️  pyuepak — a Python library for working with Unreal Engine .pak files."""
    ctx.ensure_object(dict)
    ctx.obj["aes"] = aes


@cli.command("info", help="📄 Display information about the given .pak file.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to the .pak file.",
)
@common_options
def info(ctx: click.Context, path):
    try:
        aes_key = ctx.obj.get("aes")
        pak = PakFile()
        if aes_key:
            pak.set_key(aes_key)
        pak.read(path)
        click.secho(f"➡️ Mount point: {pak.mount_point}", fg="green")
        click.secho(f"📦 Pak version: {pak.version.name}", fg="green")
        click.secho(f"📝 Entries count: {len(pak.list_files())}", fg="green")
        click.secho(f"🔒 Encrypted index: {pak._footer.is_encrypted}", fg="green")
        click.secho(
            f"🔑 Encrytion guid: {pak._footer.encryption_key.hex()}", fg="green"
        )
    except Exception as e:
        click.secho(f"❌ Failed to read .pak file: {e}", err=True, fg="red")


@cli.command("list", help="📄 Returns all paths in the pack.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to the .pak file.",
)
@common_options
def list(ctx: click.Context, path):
    try:
        aes_key = ctx.obj.get("aes")
        pak = PakFile()
        if aes_key:
            pak.set_key(aes_key)
        pak.read(path)
        for path in pak.list_files():
            click.secho(path)
    except Exception as e:
        click.secho(f"❌ Failed to read .pak file: {e}", err=True, fg="red")


@cli.command("unpack", help="📄 Unpack all files.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the .pak file.",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=False),
    required=False,
    help="Output folder path (default: same as .pak file).",
)
@common_options
def unpack(ctx: click.Context, path, out=None):
    try:
        aes_key = ctx.obj.get("aes")
        pak_path = Path(path)
        out_dir = (
            Path(out) if out else pak_path.with_suffix("")
        )  # default folder = pak name

        pak = PakFile()
        if aes_key:
            pak.set_key(aes_key)
        pak.read(str(pak_path))

        for file_path in pak.list_files():
            out_path = out_dir / Path(file_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)

            # Read data and write file
            data = pak.read_file(str(file_path))
            out_path.write_bytes(data)

        click.secho(
            f"✅ Unpacked {len(pak.list_files())} files to '{out_dir}'", fg="green"
        )
    except Exception as e:
        click.secho(f"❌ Failed to pack files: {e}", err=True, fg="red")


@cli.command("pack", help="📦 Pack all files into a .pak archive.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False),
    required=True,
    help="Input folder path to pack.",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(dir_okay=False),
    required=False,
    help="Output .pak file path (default: same name as input folder).",
)
@click.option(
    "--ver",
    "-v",
    type=click.STRING,
    required=False,
    help="Pak version (number or name. 11 or V11). Default: V11.",
)
@click.option(
    "--mount_point",
    "-m",
    type=click.STRING,
    required=False,
    help="Mount point path. Default: ../../../",
)
def pack(input, out=None, ver: str = PakVersion.V11, mount_point="../../../"):
    try:
        input_dir = Path(input)
        out_file = Path(out) if out else input_dir.with_suffix(".pak")

        if ver.isdigit():
            num_ver = int(ver)
            num_ver = num_ver + 1 if num_ver > 8 else num_ver
            ver = PakVersion(num_ver)
        else:
            ver = PakVersion[ver]

        if not ver:
            click.secho(f"❌ Version not found.", err=True, fg="yellow")

        pak = PakFile()
        pak.set_version(mount_point)
        pak.set_mount_point(mount_point)

        # Collect all files
        files = [f for f in input_dir.rglob("*") if f.is_file()]

        for file_path in files:
            rel_path = file_path.relative_to(input_dir)
            with open(file_path, "rb") as f:
                pak.add_file(str(rel_path.as_posix()), f.read())

        pak.write(out_file)

        click.secho(f"✅ Packed {len(files)} files into '{out_file}'", fg="green")

    except Exception as e:
        click.secho(f"❌ Failed to pack files: {e}", err=True, fg="red")


@cli.command("extract", help="📤 Extract a single file.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the .pak file.",
)
@click.option(
    "--file",
    "-f",
    type=str,
    required=True,
    help="Path inside the .pak to extract (use forward slashes).",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=False),
    required=False,
    help="Output folder (default: next to .pak file).",
)
@common_options
def extract(ctx: click.Context, path, file, out=None):
    try:
        aes_key = ctx.obj.get("aes")
        pak_path = Path(path)
        out_dir = (
            Path(out) if out else pak_path.parent.with_suffix("")
        )  # e.g. game.pak → game/

        pak = PakFile()
        if aes_key:
            pak.set_key(aes_key)
        pak.read(str(pak_path.as_posix()))

        # Get the file data
        data = pak.read_file(file)

        # Recreate original path inside the output folder
        out_path = out_dir / Path(file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)

        click.secho(f"✅ Extracted '{file}' to '{out_path}'", fg="green")

    except Exception as e:
        click.secho(f"❌ Failed to extract file: {e}", err=True, fg="red")


@cli.command("read", help="📖 Read a single file from a .pak and write to stdout.")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the .pak file.",
)
@click.option(
    "--file",
    "-f",
    type=str,
    required=True,
    help="Path inside the .pak to read (use forward slashes).",
)
@common_options
def read(ctx: click.Context, path, file):
    """Read one file from the .pak and write raw bytes to stdout."""
    try:
        aes_key = ctx.obj.get("aes")

        pak = PakFile()
        if aes_key:
            pak.set_key(aes_key)
        pak.read(path)

        data = pak.read_file(file)

        # Write raw bytes to stdout (not text!)
        sys.stdout.buffer.write(data)

    except Exception as e:
        click.echo(f"❌ Failed to read file from .pak: {e}", err=True)
