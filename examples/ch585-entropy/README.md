# CH585 entropy measurement (S0)

Measures the physical noise available on a CH585 board and proves the
controller's `HCI_LE_Rand` path is seeded from it. The image never initializes
the RF block, so the probe may read RAM at any time.

## What it does

1. HAL init from the on-board 32 MHz HSE (60 MHz core).
2. Phase A: 1024 repetitions of one fixed workload, recording the SysTick
   delta (clock/pipeline jitter).
3. Phase B: 512 samples of the internal ADC temperature channel, recording the
   raw value and each conversion's SysTick duration. The first 256 values are
   printed for offline analysis.
4. Feeds everything through `wchble::rand::EntropyPool`; refuses to seed when
   the ADC looks stuck (fewer than 64 samples, range < 2, or < 4 distinct
   values).
5. Seeds a `SoftRunner` DRBG and sends two `HCI_LE_Rand` (0x2018) commands
   through the soft HCI transport, logging both replies.
6. Parks with RF never started.

The measured result and its limits are recorded in
`local-docs/research/ch585-s0-entropy-results.md` (not in the repo's published
docs): the ADC low bits carry roughly 2 bits of min-entropy per sample;
SysTick jitter was constant on this setup and is not counted.

## Console markers

`entropy start`, `jitter n=… min=… max=… mean=… distinct=… zero=…`,
`adc n=… min=… max=… distinct=… ticks=…/…/… err=…`,
`health ok=… adc_range=… raw_range=…`, `seed <hex>`, `drbg seeded=…`,
`le rand {0,1} <16 hex>`, `entropy done`.

The console and `STATS[32]` (`magic 0x45303538`, version 1, stage 9 when
complete) are in RAM; see the RF smoke README for the probe-read pattern.

## Run

```bash
cd examples/ch585-entropy
cargo build --release
cd ../..
python3 examples/ch585-entropy/tools/run.py --out local-docs/results/s0-entropy-01
```

`run.py` archives the ELF, hashes it, flashes through `tools/ch585-preflight`
(halt → engine stop → two zero acknowledgements → verified download), waits,
reads `LOG` and `STATS`, and writes `console.txt`, `result.json`,
`stats.words.txt` and `symbols.txt`. The probe is fixed to
`1a86:8010:F93D8F067E10`; failures are archived and never retried.

Because the image never starts RF, no smoke restore is performed. Re-run on
any new board or series before trusting the entropy numbers.
