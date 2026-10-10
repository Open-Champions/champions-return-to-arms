# Two-client validation protocol

**Status: proposed; not executed.** This document records no successful connection,
reproduced desync, or verified fix. The evidence labels in [FINDINGS.md](../FINDINGS.md)
remain unchanged. Use two legally obtained game copies and a working two-client network
session; launching two offline instances does not test lockstep or prediction.

## Prepare one repeatable setup

1. Label clients A and B. Record the game region/version, executable SHA-256, emulator
   version/build, host OS, player slots and session host. The target in this repository
   is US `SLUS_209.73` v2.00, SHA-256
   `292f6f48e3609c0026def2307d76c222cd5b389303d53b89b0e107d7b1dcd675`.
   Stop comparison if executable identity differs.
2. Match emulator CPU/timing, frame-limit, audio, graphics and game settings for the
   initial experiment. Disable unrelated patches, cheats and speed changes on both
   clients. Record every relevant setting and patch-file hash; keep them fixed across
   each baseline/treatment pair.
3. Preserve an untouched copy of each client's starting save locally. Record save
   hashes, characters, equipment, skills, difficulty, progression and initial player
   slots. Restore that same per-client starting state before every trial. Do not
   replace both characters with one shared character or load a save state into only
   one member of an active session. Restart both clients and establish a fresh session
   for each trial.
4. Write a short input script with relative simulation-frame checkpoints where
   practical: movement, attacks, dialog advances, menu actions and waiting. Repeat it
   for both conditions and record deviations. Prefer a supported input replay when
   available; manual actions are approximate and must be described as such.
5. Verify both players can exchange inputs and progress together before the target
   scene. Record normal ping/loss and any existing out-of-sync indication. If a
   working network session cannot be established, report that blocker; it is not a
   pass or failure of either gameplay hypothesis.

For each trial, start an individual A and B record containing trial ID, condition,
start-state hashes, patch status, event checkpoints, first divergence if any, end
state and any departure from the script. Keep wall-clock times for correlation, but
compare simulation observations at the **same confirmed frame**, not equal elapsed
seconds or display frames. A prediction copy can legitimately differ from the other
client's confirmed player.

Where debugger/watch support permits, collect only the small numeric observations
needed: confirmed frame, shared seed `0x404464`, corresponding real players' integer
positions, local prediction-copy flag `0x20000`, and relevant counters described below.
Record how each observation was captured. Sampling after prediction restores shared
state avoids treating its temporary seed changes as committed divergence. Independent
breakpoints can change timing; classify such trials separately from uninterrupted
runs. If frame-aligned observations are unavailable, report visible symptoms only;
do not claim the first mismatching hash was identified.

## DRUNARE ending: baseline versus audio patch

The hypothesis is D8/D10. D19 also records an important limitation: the inspected
speaker paths do not establish a route to the shared hash during this particular
ending. Animation drift alone therefore does not prove the arena desync's cause.

| Condition | Configuration on both clients |
|---|---|
| A: baseline | All patches disabled; verify original instruction at `0x199448` if a debugger is available |
| B: audio treatment | Only `patches/SLUS-20973_4028A55F.pnach` enabled, with its cutscene-audio section enabled; verify the intended instruction at `0x199448` was applied |

Do not infer application from the filename or checkbox alone. Use the emulator's
patch report and, where available, an instruction readback. Record unavailable
verification explicitly. Keep both clients on the same condition for a trial.

1. From the preserved pre-arena state, follow the same evil-path fight and ending
   inputs. Mark the fourth knight's defeat, avatar defeat, ending start, first dialog,
   each wait, ending completion and level transition.
2. D18's nominal timeline places dialog near 13.4 seconds and waits near 27.06, 35.18
   and 49.57 seconds. These are scene checkpoints, not wall-clock deadlines; network
   waits can extend the observed duration. Continue through the transition and at
   least 600 confirmed simulation frames afterwards, if the next scene permits.
3. Record any out-of-sync indication, stall, crash, incorrect transition or audio/lip
   mismatch on each client. With instrumentation, additionally compare speaker
   animation progress and private seed at matching confirmed frames, separately from
   shared seed/player-position comparisons.
4. Run at least **three baseline and three treatment trials**, interleaving A/B from
   restored starts. Do not add another patch while testing this one. If investigating
   different audio settings or network delay later, change one variable per new
   series and reproduce the entire baseline/treatment comparison.

A treatment result supports the narrow hypothesis when a reproducible baseline
failure disappears across matched treatment trials without a new progression failure.
Describe it as “not reproduced in three treatment trials,” not “fixed everywhere.”
If baseline does not reproduce, the experiment is **inconclusive about a fix**, even
when treatment completes. If only animation timing changes, it supports patch behavior
but not causation of shared-state divergence. Failure despite the patch means this
change was insufficient under the recorded conditions; it does not automatically
identify a different cause.

## PvP prediction-copy death

This tests G9/G10 separately. **No PvP fix patch is supplied in the current patch
folder.** The audio patch is not a treatment for this hypothesis; keep it disabled.

1. Exercise each of the two PvP modes separately, identifying which mode flag is
   active (`0x4f711c` or `0x4f7120`). Preserve starting health, mana, score, equipment,
   character levels and positions. Use the same attack sequence to bring the victim
   near death, then deliver the lethal event with a documented input sequence.
2. First record ordinary deaths under normal network conditions. Then, if needed,
   use a supported, reproducible network-delay control to create unconfirmed frames.
   Record its exact configuration and apply the same network condition to every
   trial being compared. A laggy display or ordinary death alone does not establish
   prediction-copy death.
3. If instrumentation is available, establish that `Player_processDamage` at
   `0x1b2cc0` receives the local copy (flag `0x20000`) during prediction and reaches
   the PvP tail after `0x1b3504`. Log the victim identity, confirmed/unconfirmed frame
   relationship, killer mana, score, orb creation count and shared seed before and
   after the prediction pass. Compare corresponding committed state on both clients
   at the same confirmed frame. This distinguishes a transient prediction result
   from an un-restored side effect.
4. Run at least **three attempts per mode with A as victim**, then **three per mode
   with B as victim**. Report how many actually reached the instrumented trigger.
   Record session-host assignment; swap that role only as a separate controlled
   series. Continue each death through respawn or match end and 600 further confirmed
   frames when possible.
5. If a reviewed PvP patch is subsequently added, rerun the same matrix with only
   that patch enabled on both clients. It must prevent prediction-only side effects
   while preserving the intended reward/score/orb behavior for one confirmed death.
   Record the patch revision and whether the lethal prediction trigger still occurs.

A confirmed reproduction requires both the prediction-copy trigger and the claimed
persistent side effect or committed divergence. A visible out-of-sync message alone
is a symptom with an unresolved cause. If the trigger was not observed, report
**inconclusive**, even if all attempts stayed synchronized. A future fix is supported
only by matched triggered trials plus preserved confirmed-death behavior.

## Report and retain evidence

Publish an original summary with setup identity, condition, attempts, confirmed
trigger count, failure count, first known confirmed frame, affected clients and
limitations. Include a small table of numeric observations and the exact patch
revision. Distinguish **completed without observed failure**, **reproduced**,
**treatment supported**, **inconclusive**, and **blocked**; none implies universal
correctness.

Keep saves, save states, game executable/disc, extracted assets, raw memory dumps and
full debugger/decompiler output local and untracked, as required by
[CONTRIBUTING.md](../CONTRIBUTING.md). Share only sanitized test metadata, selected
numeric traces and descriptions written in your own words. Do not upload game text,
raw game code or assets as supporting logs. Remove account/network identifiers from
any emulator-log excerpts. A full emulator log or screenshot is not required for the
public report. Retain local evidence under ignored `work/` or another private test
location and cite its local trial IDs in the summary.
