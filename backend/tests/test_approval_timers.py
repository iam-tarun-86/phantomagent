"""Approval countdown lifecycle.

Each critical threat spawns a task that sleeps APPROVAL_TIMEOUT_SECONDS and then
auto-contains. Previously nothing cancelled it when a human answered first, so the task
lingered until it woke to find the threat already resolved.
"""

import asyncio

import pytest

from backend.main import state


@pytest.fixture(autouse=True)
def clean_state():
    state.approval_timers.clear()
    state.pending_approvals.clear()
    yield
    for task in state.approval_timers.values():
        task.cancel()
    state.approval_timers.clear()
    state.pending_approvals.clear()


async def test_cancel_stops_a_running_timer():
    async def long_sleep():
        await asyncio.sleep(60)

    task = asyncio.create_task(long_sleep())
    state.approval_timers["T1"] = task

    state.cancel_approval_timer("T1")
    await asyncio.sleep(0)

    assert task.cancelled() or task.done()
    assert "T1" not in state.approval_timers


async def test_cancelling_an_unknown_id_is_safe():
    state.cancel_approval_timer("NOPE")  # must not raise


async def test_cancel_is_idempotent():
    async def long_sleep():
        await asyncio.sleep(60)

    state.approval_timers["T2"] = asyncio.create_task(long_sleep())
    state.cancel_approval_timer("T2")
    state.cancel_approval_timer("T2")


async def test_completed_timer_is_not_recancelled():
    async def done_now():
        return None

    task = asyncio.create_task(done_now())
    await task
    state.approval_timers["T3"] = task

    state.cancel_approval_timer("T3")
    assert not task.cancelled()


async def test_timers_do_not_leak_across_threats():
    async def long_sleep():
        await asyncio.sleep(60)

    for i in range(5):
        state.approval_timers[f"T{i}"] = asyncio.create_task(long_sleep())

    for i in range(5):
        state.cancel_approval_timer(f"T{i}")

    assert state.approval_timers == {}
