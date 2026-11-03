"""Monitores por regra: analisam um evento e devolvem alertas.

Cada regra e uma funcao pura (evento -> Finding | None), o que facilita testar.
Os monitores apenas DETECTAM; nao bloqueiam nada (isso fica para uma fase futura).
"""
import os
import re
import shlex
from dataclasses import dataclass
from enum import IntEnum
from urllib.parse import urlparse


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str


DEFAULT_ALLOWED_DOMAINS = {
    "github.com", "githubusercontent.com", "pypi.org", "pythonhosted.org",
    "npmjs.org", "npmjs.com", "yarnpkg.com", "localhost", "127.0.0.1",
}


def allowed_domains() -> set:
    """Dominios confiaveis. Extras via AGENTWATCH_ALLOWED_DOMAINS (separados por virgula)."""
    extra = os.environ.get("AGENTWATCH_ALLOWED_DOMAINS", "")
    return DEFAULT_ALLOWED_DOMAINS | {d.strip().lower() for d in extra.split(",") if d.strip()}


# ---------------------------------------------------------------- utilidades

_SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\|")
_WRAPPERS = {"sudo", "doas", "command", "time", "nohup"}


def _bash_command(event):
    if event.get("tool_name") != "Bash":
        return None
    return event.get("command") or None


def _segments(command: str):
    return [s.strip() for s in _SEGMENT_SPLIT.split(command) if s.strip()]


def _words(segment: str):
    """Divide o segmento em palavras e remove sudo/VAR=x. Retorna (palavras, usou_sudo)."""
    try:
        words = shlex.split(segment)
    except ValueError:
        words = segment.split()
    sudo = False
    while words and (
        words[0] in _WRAPPERS
        or re.match(r"^\w+=", words[0])
        or (sudo and words[0].startswith("-"))
    ):
        if words[0] in {"sudo", "doas"}:
            sudo = True
        words = words[1:]
    return words, sudo


def _host(url: str):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_allowed(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed_domains())


# ------------------------------------------------------------------ regras

def force_push(event):
    command = _bash_command(event)
    if not command:
        return None
    lease = False
    for seg in _segments(command):
        words, _ = _words(seg)
        if not words or words[0] != "git" or "push" not in words[1:4]:
            continue
        for w in words[words.index("push") + 1:]:
            hard = (
                w == "--force"
                or w == "-f"
                or (w.startswith("-") and not w.startswith("--") and "f" in w[1:])
                or (w.startswith("+") and len(w) > 1)
            )
            if hard:
                return Finding("force-push", Severity.HIGH,
                               "git push forcado pode sobrescrever o historico remoto")
            if w.startswith("--force-with-lease"):
                lease = True
    if lease:
        return Finding("force-push", Severity.MEDIUM,
                       "git push --force-with-lease reescreve historico remoto")
    return None


_SENSITIVE_FILES = re.compile(
    r"""(?ix)
    (?:^|[\s/"'=:])
    (?:
        \.env(?:\.(?!example\b|sample\b|template\b)[\w-]+)?
      | id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)
      | \.netrc | \.pypirc | \.npmrc | \.git-credentials | \.pgpass
      | [\w.-]+\.(?:pem|p12|pfx|key)
    )
    (?=$|[\s"';|&)])
    """
)
_SENSITIVE_DIRS = re.compile(
    r"(?:^|[\s/\"'=:])\.(?:ssh|aws|gnupg|kube)/(?!\S*\.pub)", re.IGNORECASE
)


def sensitive_file(event):
    targets = [event.get("file_path"), _bash_command(event)]
    for text in targets:
        if not text:
            continue
        match = _SENSITIVE_FILES.search(text) or _SENSITIVE_DIRS.search(text)
        if match:
            return Finding("sensitive-file", Severity.HIGH,
                           f"acesso a arquivo sensivel: {match.group(0).strip(' /\"\'=:')}")
    return None


_SYSTEM_ROOTS = {"/", "/*", "/etc", "/usr", "/var", "/bin", "/sbin", "/boot",
                 "/lib", "/home", "/root", "/opt", "/sys", "/dev"}
_HOME_ROOTS = {"~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "${HOME}/*"}
_WIPE_CWD = {".", "./", "*", "./*", ".*"}


def _rm_target_severity(target: str, cwd):
    stripped = target.rstrip("/") or "/"
    if target in _HOME_ROOTS or stripped in _SYSTEM_ROOTS or target == "/*":
        return Severity.CRITICAL
    if target in _WIPE_CWD or target.startswith(".."):
        return Severity.HIGH
    if target.startswith(("~", "$HOME", "${HOME}")):
        return Severity.HIGH
    if target.startswith("/"):
        if cwd:
            norm, base = os.path.normpath(target), os.path.normpath(cwd)
            if norm == base or norm.startswith(base + os.sep):
                return None
        return Severity.HIGH
    return None


def destructive_rm(event):
    command = _bash_command(event)
    if not command:
        return None
    worst = None
    for seg in _segments(command):
        words, _ = _words(seg)
        if not words or words[0] != "rm":
            continue
        flags = [w for w in words[1:] if w.startswith("-")]
        recursive = any(
            w == "--recursive" or (not w.startswith("--") and ("r" in w[1:] or "R" in w[1:]))
            for w in flags
        )
        if not recursive:
            continue
        for target in (w for w in words[1:] if not w.startswith("-")):
            sev = _rm_target_severity(target, event.get("cwd"))
            if sev and (worst is None or sev > worst[0]):
                worst = (sev, target)
    if worst:
        return Finding("destructive-rm", worst[0],
                       f"remocao recursiva em alvo perigoso: {worst[1]}")
    return None


_UPLOAD_FLAGS_CURL = {"-T", "--upload-file", "-F", "--form", "--json"}
_UPLOAD_FLAGS_WGET = {"--post-data", "--post-file", "--body-data", "--body-file"}


def _is_upload(words):
    for w in words[1:]:
        if w in _UPLOAD_FLAGS_CURL or w in _UPLOAD_FLAGS_WGET:
            return True
        if w.startswith("--data") or w.startswith("--form"):
            return True
        if w.startswith("-d") and not w.startswith("--"):
            return True
    return False


def network_unknown_host(event):
    command = _bash_command(event)
    if not command:
        return None
    worst = None
    for seg in _segments(command):
        words, _ = _words(seg)
        if not words or words[0] not in {"curl", "wget"}:
            continue
        upload = _is_upload(words)
        for w in words[1:]:
            if not re.match(r"^https?://", w):
                continue
            host = _host(w)
            if not host or _host_allowed(host):
                continue
            sev = Severity.HIGH if upload else Severity.MEDIUM
            msg = ("possivel exfiltracao: envio de dados para " if upload
                   else "download de dominio fora da lista confiavel: ") + host
            if worst is None or sev > worst[0]:
                worst = (sev, msg)
    if worst:
        return Finding("network-unknown-host", worst[0], worst[1])
    return None


_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)


def remote_script_exec(event):
    command = _bash_command(event)
    if command and _PIPE_TO_SHELL.search(command):
        return Finding("remote-script-exec", Severity.CRITICAL,
                       "execucao de script remoto sem inspecao (curl | sh)")
    return None


_PIP_SKIP_VALUE = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                   "-i", "--index-url", "--extra-index-url", "--trusted-host",
                   "--target", "-t", "--prefix"}
_PIP_INDEX_FLAGS = ("--index-url", "--extra-index-url", "--trusted-host")


def _is_url_or_git(arg: str) -> bool:
    return arg.startswith(("git+", "github:", "http://", "https://")) or arg.endswith(".tgz")


def package_install(event):
    command = _bash_command(event)
    if not command:
        return None
    worst = None

    def bump(sev, msg):
        nonlocal worst
        if worst is None or sev > worst[0]:
            worst = (sev, msg)

    for seg in _segments(command):
        words, sudo = _words(seg)
        if len(words) >= 3 and words[0] in {"python", "python3"} and words[1:3] == ["-m", "pip"]:
            words = ["pip"] + words[3:]
        elif len(words) >= 2 and words[0] == "uv" and words[1] == "pip":
            words = ["pip"] + words[2:]
        if len(words) < 2:
            continue

        if words[0] in {"pip", "pip3"} and words[1] == "install":
            args, packages, skip = words[2:], [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in _PIP_SKIP_VALUE:
                    skip = True
                    continue
                if a.startswith("-"):
                    continue
                packages.append(a)
            if any(a.startswith(_PIP_INDEX_FLAGS) or a == "-i" for a in args) or \
                    any(_is_url_or_git(p) for p in packages):
                bump(Severity.HIGH, "instalacao de pacote por URL/git ou indice alternativo")
            elif sudo:
                bump(Severity.MEDIUM, "instalacao de pacote com sudo")
            elif packages:
                bump(Severity.LOW, f"instalacao de pacote: {' '.join(packages[:3])}")

        elif words[0] in {"npm", "pnpm", "yarn"} and words[1] in {"install", "i", "add"}:
            args = words[2:]
            packages = [a for a in args if not a.startswith("-")]
            is_global = "-g" in args or "--global" in args
            if any(_is_url_or_git(p) for p in packages):
                bump(Severity.HIGH, "instalacao de pacote por URL/git")
            elif is_global or sudo:
                bump(Severity.MEDIUM, "instalacao global ou com sudo")
            elif packages:
                bump(Severity.LOW, f"instalacao de pacote: {' '.join(packages[:3])}")

    if worst:
        return Finding("package-install", worst[0], worst[1])
    return None


RULES = (
    force_push,
    sensitive_file,
    destructive_rm,
    network_unknown_host,
    remote_script_exec,
    package_install,
)


def analyze(event: dict) -> list:
    """Roda todas as regras e devolve os alertas, do mais grave para o menos grave."""
    findings = [f for f in (rule(event) for rule in RULES) if f]
    return sorted(findings, key=lambda f: f.severity, reverse=True)
