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

Cost is per token and close to linear, about 0.6 ms per token on one thread. A full
output-side scan with every detector wired would be one rule check plus seven
encoder passes, roughly 360 ms at the reference input.

Keeping that off the common path is the entire job of the tier system, and it is a
scheduling property rather than a cost one.

## Threads

Measured at 96 tokens: 54.7 ms on one thread, 29.8 on two, 17.8 on four, 12.4 on
eight. The default stays at one. A library that quietly commandeers the machine it
is embedded in is worse than one that is honestly slower, and a policy can raise it
deliberately.
