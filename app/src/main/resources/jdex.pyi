from typing import Any


class _Node:
    descriptor: str
    def rename(self, new_name: str | None) -> None:
        """Rename this node in the project (persisted). Pass None or '' to clear the rename."""
        ...
    def xrefs_to(self) -> list[Class | Method | Field]:
        """Nodes that reference this one (callers, field accesses, type uses)."""
        ...


class Class(_Node):
    """A class, identified by its smali descriptor e.g. 'Lcom/foo/Bar;'."""
    name: str
    package: str
    def methods(self) -> list[Method]:
        """Methods declared by this class."""
        ...
    def fields(self) -> list[Field]:
        """Fields declared by this class."""
        ...
    def java(self) -> str:
        """Decompiled Java source for this class (top-level parent for inner classes)."""
        ...
    def smali(self) -> str:
        """Disassembled smali/bytecode listing for this class."""
        ...
    def super_class(self) -> Class | None:
        """The superclass as a Class, or None."""
        ...
    def interfaces(self) -> list[Class]:
        """Implemented interfaces as Class objects."""
        ...
    def offset_at_line(self, line: int) -> int | None:
        """Bytecode offset (code units) for a 1-based decompiled-Java line, or None."""
        ...
    def strings(self) -> list[str]:
        """Distinct string literals referenced by this class's methods, in first-seen order."""
        ...
    def info(self) -> dict[str, Any] | None:
        """Structured metadata dict: descriptor, name, package, super, interfaces, access_flags, modifiers."""
        ...


class Method(_Node):
    """A method, identified as 'Lcom/foo/Bar;->name(args)ret'."""
    declaring_class: Class
    signature: str
    name: str
    def smali(self) -> str | None:
        """Disassembled smali/bytecode listing for just this method."""
        ...
    def instructions(self) -> list[dict[str, Any]] | None:
        """Structured bytecode rows, each a dict: offset, addr, line, mnemonic, operands, comment, resource."""
        ...
    def info(self) -> dict[str, Any] | None:
        """Structured metadata dict: descriptor, name, signature, return_type, arg_types, access_flags, modifiers, registers."""
        ...


class Field(_Node):
    """A field, identified as 'Lcom/foo/Bar;->name'."""
    declaring_class: Class
    name: str
    def info(self) -> dict[str, Any] | None:
        """Structured metadata dict: descriptor, name, type, access_flags, modifiers."""
        ...
    def reads(self) -> list[Method]:
        """Methods that read this field (IGET/SGET)."""
        ...
    def writes(self) -> list[Method]:
        """Methods that write this field (IPUT/SPUT)."""
        ...


class Dex:
    """A dex file jadx could not load, identified by the SHA-256 of its original bytes."""
    sha: str
    name: str
    problems: list[str]
    malformed: bool
    def bytes(self) -> bytes:
        """Current (patched) dex bytes."""
        ...
    def source_bytes(self) -> bytes:
        """Original unpatched dex bytes."""
        ...
    def validate(self, data: bytes | None = ...) -> list[str]:
        """Validation problems for the current bytes, or for `data` if given."""
        ...
    def repair(self) -> bool:
        """Auto-fix the dex header, save the fix as a patch, reload. Returns True if now valid."""
        ...
    def save(self, data: bytes) -> None:
        """Save hand-fixed `data` as the dex patch and reload (for fixes beyond the header)."""
        ...


class _Ui:
    """Interaction with the jdex window: dialogs and navigation."""
    def message(self, text: str) -> None:
        """Show an information dialog."""
        ...
    def error(self, text: str) -> None:
        """Show an error dialog."""
        ...
    def ask(self, prompt: str, default: str = "") -> str | None:
        """Prompt for a line of text; returns the entered string, or None if cancelled."""
        ...
    def confirm(self, text: str) -> bool:
        """Yes/No dialog; returns True if the user chose Yes."""
        ...
    def goto_offset(self, offset: int) -> None:
        """Reveal a file offset (int) in the bytecode view."""
        ...
    def open(self, node: _Node | str) -> None:
        """Reveal a Class, Method or Field (or a raw descriptor string) in the bytecode view."""
        ...


class _Jdex:
    """Top-level scripting facade, bound as `jdex`."""
    ui: _Ui
    def files(self) -> list[str]:
        """Names of every file entry inside the loaded APK (or the dex name for a bare dex)."""
        ...
    def read_file(self, path: str) -> bytes:
        """Raw bytes of one APK entry by name; empty bytes if absent."""
        ...
    def import_dex(self, name: str, data: bytes) -> None:
        """Add a dex (bytes) to the project under `name`, then re-analyze."""
        ...
    def classes(self) -> list[Class]:
        """All classes including inner classes."""
        ...
    def get_class(self, name: str) -> Class | None:
        """Look up a class by descriptor ('Lcom/foo/Bar;') or dotted name ('com.foo.Bar'); None if absent."""
        ...
    def find_classes(self, pattern: str) -> list[Class]:
        """Classes whose descriptor or simple name matches the regex `pattern`."""
        ...
    def find_methods(self, pattern: str) -> list[Method]:
        """Methods across all classes whose descriptor matches the regex `pattern`."""
        ...
    def find_fields(self, pattern: str) -> list[Field]:
        """Fields across all classes whose descriptor matches the regex `pattern`."""
        ...
    def strings(self) -> list[dict[str, Any]]:
        """Every string literal across all classes as dicts {value, method}. Expensive: scans all bytecode."""
        ...
    def search_code(self, pattern: str, limit: int = 1000) -> list[dict[str, Any]]:
        """Bytecode lines matching regex `pattern`, as dicts {method, offset, text}. Expensive full scan, capped at `limit`."""
        ...
    def manifest(self) -> str:
        """Decoded AndroidManifest.xml text, '' if none."""
        ...
    def permissions(self) -> list[str]:
        """Requested permission names from <uses-permission>."""
        ...
    def components(self, kind: str = "activity") -> list[str]:
        """Declared component names for a manifest tag: activity, service, receiver or provider."""
        ...
    def app_package(self) -> str | None:
        """Application package id, or None."""
        ...
    def main_activity(self) -> str | None:
        """Launcher activity class name, or None."""
        ...
    def malformed_dexes(self) -> list[Dex]:
        """Dex files jadx could not load, as Dex objects you can inspect and repair."""
        ...
    def jadx(self) -> Any:
        """The raw jadx JadxDecompiler, for anything the facade does not cover."""
        ...


jdex: _Jdex
