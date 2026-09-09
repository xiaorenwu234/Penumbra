#!/usr/bin/env python3
"""Outcome classification and infrastructure-error signalling for RQ2.

Every measurement in RQ2 must land in exactly one of four buckets. Conflating
them is what made earlier runs report "0 violations" while whole subsystems
were silently down:

  PASS         the target operation completed AND the safety property held.
  VIOLATION    the target operation completed BUT the safety property failed.
  INFRA_ERROR  the experiment could not be carried out: a daemon, socket,
               FUSE mount, cgroup, epoch, probe or policy installation failed.
               This is NEVER a pass and must make the run exit non-zero.
  SKIPPED      the test is explicitly not applicable in this configuration
               (e.g. a probe binary that does not exist on this kernel).
               Requires a reason; it does not enter the denominator.

Lifecycle calls -- begin_epoch, commit, rollback, policy installation, freeze,
drain, probe startup -- raise :class:`InfrastructureError` on failure instead of
being wrapped in ``except Exception: pass``.
"""

from typing import Optional

# Trial outcome buckets (values are serialized into the JSON reports).
PASS = "pass"
VIOLATION = "violation"
INFRA_ERROR = "infra_error"
SKIPPED = "skipped"

# Trial record statuses used by MetricsCollector.
STATUS_COMPLETED = "completed"
STATUS_SKIPPED = "skipped"
STATUS_INFRA_ERROR = "infra_error"


class InfrastructureError(RuntimeError):
    """A lifecycle/infrastructure step failed, so no security claim can be made.

    ``stage`` names the step that failed (e.g. ``begin_epoch``, ``freeze``,
    ``policy_install``, ``probe_spawn``, ``fuse_mount``) so reports can group
    infrastructure failures by cause.
    """

    def __init__(self, stage: str, message: str,
                 cause: Optional[BaseException] = None):
        self.stage = stage
        self.cause = cause
        full = f"[INFRA:{stage}] {message}"
        if cause is not None:
            full += f" (caused by {type(cause).__name__}: {cause})"
        super().__init__(full)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "message": str(self),
            "cause": f"{type(self.cause).__name__}: {self.cause}"
                     if self.cause is not None else None,
        }


def infra(stage: str, message: str,
          cause: Optional[BaseException] = None) -> InfrastructureError:
    """Build an :class:`InfrastructureError` (readable at the raise site)."""
    return InfrastructureError(stage, message, cause)


def reraise_as_infra(stage: str, exc: BaseException) -> InfrastructureError:
    """Wrap any exception from a lifecycle call as an infrastructure error."""
    if isinstance(exc, InfrastructureError):
        return exc
    return InfrastructureError(stage, str(exc), exc)
