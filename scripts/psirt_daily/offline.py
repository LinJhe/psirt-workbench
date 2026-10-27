"""Process-wide tripwire for accidental network or subprocess use in fixture runs."""
import sys

_installed = False


def install_offline_guard():
    """Block socket/DNS and child processes; intentionally lasts for this process.

    This is an accident-prevention guard, not a sandbox for hostile Python code.
    The fixture is parsed as JSON only; no plugins or commands are executed.
    """
    global _installed
    if _installed:
        return

    def deny(event, args):
        if (event.startswith("socket.") or event.startswith("subprocess.")
                or event in {"os.system", "os.posix_spawn", "os.fork", "os.forkpty",
                             "os.exec", "os.spawn", "pty.spawn"}):
            raise PermissionError("Gate1OfflineOnly")

    sys.addaudithook(deny)
    _installed = True
