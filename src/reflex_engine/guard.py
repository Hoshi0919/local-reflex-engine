import inspect
import functools
from typing import Callable, Optional, Union, Any

from .engine import ReflexEngine
from .schema import SafetyLevel, Tier, Verdict

# Global lazily-initialized engine instance for decorator reuse
_DEFAULT_ENGINE: Optional[ReflexEngine] = None

def get_default_engine() -> ReflexEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = ReflexEngine()
    return _DEFAULT_ENGINE

class CommandBlockedError(PermissionError):
    """Raised when a command is rejected by Local Reflex Engine."""
    def __init__(self, verdict: Verdict, command: str):
        self.verdict = verdict
        self.command = command
        reason_str = "; ".join(verdict.reasons) if verdict.reasons else "Safety violation"
        msg = (
            f"[LRE BLOCKED] Command '{command}' was rejected ({verdict.level.value}, "
            f"{verdict.tier.value}, score={verdict.score:.2f}, {verdict.latency_us:.1f}µs): {reason_str}"
        )
        super().__init__(msg)

def _extract_command(command_arg: Union[int, str], args: tuple, kwargs: dict) -> str:
    if isinstance(command_arg, int):
        if len(args) > command_arg:
            val = args[command_arg]
            if isinstance(val, (list, tuple)):
                return " ".join(str(x) for x in val)
            return str(val)
        # Fallback check kwargs
        for candidate in ("command", "cmd", "line"):
            if candidate in kwargs:
                val = kwargs[candidate]
                if isinstance(val, (list, tuple)):
                    return " ".join(str(x) for x in val)
                return str(val)
    elif isinstance(command_arg, str):
        if command_arg in kwargs:
            val = kwargs[command_arg]
            if isinstance(val, (list, tuple)):
                return " ".join(str(x) for x in val)
            return str(val)
        if len(args) > 0:
            return str(args[0])
    return ""

def guard(
    fn: Optional[Callable] = None,
    *,
    engine: Optional[ReflexEngine] = None,
    allow_suspicious: bool = False,
    on_blocked: str = "raise",
    command_arg: Union[int, str] = 0,
    fallback: Optional[Callable[..., Any]] = None
):
    """
    Guard decorator / wrapper for terminal execution functions.
    Inspects command using ReflexEngine (<50µs) before calling the target function.
    
    Args:
        fn: Target function to wrap.
        engine: Optional ReflexEngine instance (default: shared engine).
        allow_suspicious: If True, execute commands classified as SUSPICIOUS.
        on_blocked: Action when blocked: 'raise', 'return_verdict', or 'return_none'.
        command_arg: Index (int) or kwarg key (str) of the command parameter.
        fallback: Optional callback called when Tier.TIER_FALLBACK is triggered:
                  fallback(verdict, *args, **kwargs).
    """
    def decorator(target: Callable) -> Callable:
        is_async = inspect.iscoroutinefunction(target)
        eng = engine or get_default_engine()

        def _evaluate_and_check(args: tuple, kwargs: dict):
            cmd = _extract_command(command_arg, args, kwargs)
            verdict = eng.judge(cmd)

            # 1. Tier Fallback
            if verdict.tier == Tier.TIER_FALLBACK and fallback is not None:
                return "fallback", verdict

            # 2. Dangerous -> Block
            if verdict.level == SafetyLevel.DANGEROUS:
                return "block", verdict

            # 3. Suspicious
            if verdict.level == SafetyLevel.SUSPICIOUS:
                if allow_suspicious:
                    return "pass", verdict
                return "block", verdict

            # 4. Safe -> Pass
            return "pass", verdict

        def _handle_block(verdict: Verdict, args: tuple, kwargs: dict):
            cmd = _extract_command(command_arg, args, kwargs)
            if on_blocked == "raise":
                raise CommandBlockedError(verdict, cmd)
            elif on_blocked == "return_verdict":
                return verdict
            elif on_blocked == "return_none":
                return None
            else:
                raise ValueError(f"Unknown on_blocked mode: {on_blocked}")

        if is_async:
            @functools.wraps(target)
            async def async_wrapper(*args, **kwargs):
                action, verdict = _evaluate_and_check(args, kwargs)
                if action == "pass":
                    return await target(*args, **kwargs)
                elif action == "fallback":
                    if inspect.iscoroutinefunction(fallback):
                        return await fallback(verdict, *args, **kwargs)
                    return fallback(verdict, *args, **kwargs)
                else:
                    return _handle_block(verdict, args, kwargs)
            return async_wrapper
        else:
            @functools.wraps(target)
            def sync_wrapper(*args, **kwargs):
                action, verdict = _evaluate_and_check(args, kwargs)
                if action == "pass":
                    return target(*args, **kwargs)
                elif action == "fallback":
                    return fallback(verdict, *args, **kwargs)
                else:
                    return _handle_block(verdict, args, kwargs)
            return sync_wrapper

    if fn is not None:
        return decorator(fn)
    return decorator
