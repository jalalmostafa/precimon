# precimon

PRECIse MONitor: Nigel's MONitor (NMON) for more accurate computations

## How is this different from njmon

- Correct JSON Format (fix structure)
- Handles SIGTERM... ends on next cycle
- High Time Resolution (sleep and get time)
- always run on instance (pid lock)
- P option if has args (PIDs - comma separated), shows only specified processes
