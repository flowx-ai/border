---
title: Introduction
description: What border is, what it returns, and what it deliberately does not do.
group: Getting started
order: 1
---

# Introduction

`flowx-border` is an embeddable Python library. It inspects the text going into and
coming out of an LLM and returns a structured decision plus an audit-grade evidence
record.

It is not a gateway, not a proxy, and not an agent framework. It does not wrap your
model call. You call two functions and decide what to do with what they return.

## The shape of it

```python
from flowx_border import scan_input, scan_output, load_policy

policy = load_policy("border-code.yaml")

crossing = scan_input(user_text, policy)
if crossing.verdict == "block":
    return refuse(crossing.evidence.record_id)

answer = your_model.complete(crossing.text)

out = scan_output(answer, policy)
archive(out.evidence)
return out.text
```

Three imports is the whole public surface. If something appears to need a fourth,
that is a design question rather than a missing feature.

## What you get back

Every scan returns a `Decision`: a verdict, the text (possibly redacted), the
findings that produced the verdict, and an `EvidenceRecord`.

The evidence record is the part most libraries do not have. It names which
detectors ran, which model revision and weight hash each used, the hash of the
resolved policy, and a hash of the input text. It never contains the text itself.
That is what makes it archivable next to a decision rather than becoming a second
copy of the thing you were trying to protect.

## What it will not do

It will not make anyone compliant with any regulation. It produces an auditable
record of which checks ran and what they found, which supports the evidence
requirements of a governance process you run yourself. The obligations under any
law that applies to your system sit with you as its provider or deployer.

It will not silently pass. A detector whose model is not available raises an error
naming what is missing rather than returning an empty result, because a check that
quietly passes is worse than one that is absent.

It will not call out. After the weights are cached, a scan works with the network
interface down, and the test suite asserts it by making socket calls raise.
