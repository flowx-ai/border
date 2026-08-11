---
title: The two functions
description: Why the API is two calls, what a Decision contains, and which text to use afterwards.
group: Concepts
order: 1
---

# The two functions

`scan_input` inspects text on its way to the model. `scan_output` inspects it on
the way back. They take the same arguments and return the same shape.

```python
def scan_input(text: str, policy: Policy, ctx: Context | None = None) -> Decision
def scan_output(text: str, policy: Policy, ctx: Context | None = None) -> Decision
```

The direction is not a flag on one function because the two sides run different
detectors. `secrets` only makes sense on the way in; `disclosure` and
`groundedness` only make sense on the way out. Splitting them means the policy can
describe each side honestly and the evidence record can say which direction it
describes.

## Nothing wraps your model call

There is no client to construct and no gateway to run. Between the two calls you do
whatever you already do. That is deliberate: a library that wraps the model call
owns your retries, your streaming and your error handling, and becomes very hard to
remove.

The consequence is that if border stops working, your application still runs. It
stops producing evidence, which is a different and more visible failure than
silently stopping checking.

## Use the text it gives back

```python
crossing = scan_input(user_text, policy)
answer = your_model.complete(crossing.text)   # not user_text
```

`Decision.text` is the text after any redaction or rewrite. `Decision.original_text`
is what you passed in. Passing the original onward after a redaction is the most
common way to make the library look like it is not working.

## Verdicts

| Verdict | Meaning |
|---|---|
| `allow` | Nothing fired. |
| `flag` | Something fired and was recorded. The text is unchanged. |
| `redact` | The text was modified. Use `Decision.text`. |
| `block` | Do not send this onward. |

A verdict is the strongest action any finding produced, not a separate judgement.
