# Key records entered the log late (2026-11-20)

## What a reader of the log will see

Leaves 194 to 198 carry the prefix `kb` (key records). They were appended on 2026-11-20 at 04:30 UTC and are in `leaves/194-198.jsonl`. Each carries an `issued_at` from July, August or September 2026, which is months earlier than the first signed tree head that covers it, `sth/199.json`, signed 2026-11-20. The head before it is `sth/194.json`, signed 2026-10-29.

## Why

The log's table was created with a rule that named six kinds of record and did not name `kb`. Key records were added to the product afterward, and the rule was not widened. The database refused each key record every night, so none of them was appended.

The gap was found on 2026-11-19 by reading this mirror and counting every public record against the log. Every other kind was complete: no transcript, course, item, wall or signature was missing.

## What this means for a verifier

- A key record's `issued_at` is the day the operator says the key was established. For these five records the log does not corroborate that day.
- What the log does show is that each of these records existed by 2026-11-20, the day of the first signed tree head that covers it.
- Nothing already in the log changed. Leaves 0 to 193, their order and every earlier signed head are as they were, and the consistency between the head of size 194 and the head of size 199 can be checked in the ordinary way.
- A key record made after 2026-11-19 enters the log the night it is made, like every other record.

## What was fixed

The rule now names `kb`. The nightly job now counts every record the log refuses and says so in its own answer, and the repository has a test that fails if the code names a kind of record the table would refuse.
