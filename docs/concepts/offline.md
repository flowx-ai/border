---
title: Offline and determinism
description: What "no network at scan time" means exactly, and what is asserted rather than promised.
group: Concepts
order: 5
---

# Offline and determinism

## No network at scan time

Model weights are fetched once, at install or on first load, and cached. After
that, `scan_input` and `scan_output` work with the network interface down.

This is asserted rather than promised. The test suite patches `socket.socket` to
raise and runs the default suite against it. If a change makes a test need the
network, the change is wrong, not the test.

Nothing is sent anywhere. No telemetry, no usage counters, no crash reports. The
evidence record stays on your infrastructure.

## What that costs

CPU is the reference target rather than a fallback, so every detector has to be
usable on a CPU within its budget. GPU is an optimisation, never a requirement.
That constrains what the models can be, and it is the reason the classifiers are
encoders rather than anything generative.

## Determinism

Given the same inputs and the same model revisions, a scan returns the same
decision and the same record. No sampling, no temperature, no clock-dependent
behaviour inside a scan.

The timestamp in the record is the one thing that changes between runs, and it is
deliberately outside the signed comparison you would make when reproducing a
decision: hash the inputs and the policy, not the record as a whole.
