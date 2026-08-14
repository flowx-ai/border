---
title: Tiers
description: What a tier decides, what it does not, and what a full scan costs.
group: Concepts
order: 3
---

# Tiers

Every detector sits in a tier. A tier decides **when** a detector runs and whether a
policy may switch it off.

| Tier | Rule |
|---|---|
| `T0` | Always runs. Cannot be disabled. |
| `T1` | Runs on the standard path. |
| `T2` | Runs on the standard path. May be disabled by policy. |
| `T3` | Runs only when a lower tier flags, or when the policy sets `always: true`. |

## A tier is not a cost

This is the part that is easy to get wrong. Every model-backed detector in the set
is the same XLM-RoBERTa base, so at the same input length they all cost the same.
They share one budget rather than splitting into a fast tier and a slow one.

`gibberish` is T1 because unreadable input should short circuit the tiers above it
rather than be scored by them, not because it is cheaper. It is not.

## What a full scan costs

Cost is per token and close to linear **within a window**, about 1.66 ms per token on
one thread, and it steps at each window boundary. A window holds 94 content tokens,
so 94 tokens is one forward pass and 95 is two: the step is about 33 ms for one more
token. A document of n tokens costs roughly `ceil(n / 94)` passes, which is
proportional rather than catastrophic, and that is the property worth relying on.

A full output-side scan with every detector wired would be one rule check plus seven
encoder passes, roughly 360 ms at the reference input.

Keeping that off the common path is the entire job of the tier system, and it is a
scheduling property rather than a cost one.

This said "about 0.6 ms per token" until 2026-08-14. That rate belonged to `piiguard`'s
published 266 MB INT8 export, withdrawn on 2026-08-12 for losing an entity entirely on
13 of 120 texts, and it also averaged a slope across the window boundary, so it was
wrong twice in the same direction. See `benchmarks/latency_sweep.py`, which records the
sweep and refuses to run on a busy machine.

## Threads

Measured at the 87-token reference input: 157.32 ms on one thread, 79.50 on two, 42.99
on four, 25.63 on eight. The default stays at one. A library that quietly commandeers
the machine it is embedded in is worse than one that is honestly slower, and a policy
can raise it deliberately.

These read 54.7, 29.8, 17.8 and 12.4 at 96 tokens until 2026-08-14, on the same
withdrawn export. 96 tokens is also two windows, so that table measured parallelism
across two passes, one of them 19 tokens long, which is not the shape anyone wanted to
know about.
