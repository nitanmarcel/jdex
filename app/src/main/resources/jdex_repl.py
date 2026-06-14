import ast as _ast
import sys as _sys
import inspect as _inspect
import traceback as _traceback
import rlcompleter as _rlcompleter


def _head(expr, obj):
    try:
        sig = str(_inspect.signature(obj))
    except (TypeError, ValueError):
        sig = ""
    return (getattr(obj, "__name__", expr.rsplit(".", 1)[-1]) + sig).strip()


def _signature(expr):
    try:
        obj = eval(expr, globals())
    except BaseException:
        return ""
    head = _head(expr, obj)
    doc = (getattr(obj, "__doc__", "") or "").strip()
    return "%s — %s" % (head, doc.split("\n", 1)[0].strip()) if doc else head


def _doc(expr):
    try:
        obj = eval(expr, globals())
    except BaseException:
        return ""
    head = _head(expr, obj)
    doc = (getattr(obj, "__doc__", "") or "").strip()
    return "%s\n\n%s" % (head, doc) if doc else head

_COMPOUND = (
    _ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef, _ast.If, _ast.For,
    _ast.AsyncFor, _ast.While, _ast.With, _ast.AsyncWith, _ast.Try,
)
if hasattr(_ast, "Match"):
    _COMPOUND = _COMPOUND + (_ast.Match,)

_INCOMPLETE_MARKERS = (
    "unexpected EOF", "was never closed", "expected an indented block",
    "incomplete input", "unterminated",
)


def _run(src):
    try:
        mod = _ast.parse(src)
    except SyntaxError:
        for line in _traceback.format_exception_only(*_sys.exc_info()[:2]):
            _sys.stderr.write(line)
        return
    try:
        body = mod.body
        if body and isinstance(body[-1], _ast.Expr):
            exec(compile(_ast.Module(body[:-1], type_ignores=[]), "<repl>", "exec"), globals())
            exec(compile(_ast.Interactive([body[-1]]), "<repl>", "single"), globals())
        else:
            exec(compile(mod, "<repl>", "exec"), globals())
    except SystemExit:
        raise
    except BaseException as e:
        exc_type, exc, tb = _sys.exc_info()
        try:
            _traceback.print_exception(exc_type, exc, tb.tb_next if tb is not None else None)
        except BaseException:
            _sys.stderr.write("%s\n" % (exc if exc is not None else e))


def _incomplete(src):
    if not src.strip():
        return False
    try:
        tree = _ast.parse(src)
    except SyntaxError as e:
        msg = str(e)
        return any(marker in msg for marker in _INCOMPLETE_MARKERS)
    return bool(tree.body) and isinstance(tree.body[-1], _COMPOUND) and "\n" in src


class _Repl:
    def __init__(self):
        self.buffer = []

    def feed(self, line):
        blank = line.strip() == ""
        if blank and not self.buffer:
            return False
        if not blank:
            self.buffer.append(line)
        src = "\n".join(self.buffer)
        if blank or not _incomplete(src):
            self.buffer = []
            _run(src)
            return False
        return True


_repl = _Repl()
_complete = _rlcompleter.Completer(globals()).complete
_signature_of = _signature
_doc_of = _doc
