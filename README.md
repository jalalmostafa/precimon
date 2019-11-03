# precimon

PRECIse MONitor: Nigel's MONitor (NMON) for more accurate computations

## How is this different from njmon

- [x] Correct JSON Format (fix structure)
- [x] Graceful Exit: Handles SIGTERM... ends on next cycle
- [x] High Time Resolution (sleep and get time). Monotonic clock. Absolute Time.
- [x] always run on instance (pid lock)
- [ ] output timers using `-T` option
- [ ] P option if has args (PIDs - comma separated), shows only specified processes
- [x] print config to file
