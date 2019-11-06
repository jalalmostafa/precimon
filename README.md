# Precimon

PRECIse MONitor (precimon - pronounced pre-simon) is an opinionated system monitoring tool for Linux based on Nigel Griffiths' tool [njmon](http://nmon.sourceforge.net/pmwiki.php?n=Site.Njmon). Being time-accurate, precimon is suitable to monitor systems running real-time or time-sensitive application e.g. control systems.

## Commandline tool

### precimon

The tool samples `/proc` every N seconds then prints them to stdout or selected file. By default, N is 60 seconds. It also provide the following options:

- `-s` seconds   : seconds between snapshots of data (default 60 seconds)
- `-c` count     : number of snapshots (default forever)
- `-m` directory : Program will cd to the directory before output
- `-f`           : Output to file (not stdout). Data file:  `hostname_<year><month><day>_<hour><minutes>.json`. Error file `hostname_<year><month><day>_<hour><minutes>.err`
- `-P`           : Add process stats (take CPU cycles and large stats volume)
- `-I percent`   : Set ignore process percent threshold (default 0.01%)
- `-C`           : Output precimon configuration to the JSON file
- `-T`           : Output snapshot timers e.g. sleep time, execution time

Examples:

- `./precimon -s 10` runs a precimon instance that takes snapshots every 10 seconds forever
- `./precimon -s 10 -c 50` runs a precimon instance that takes snapshots every 10 seconds for 50 cycles
- `./precimon -f -s 10` runs precimon instance that takes snapshots every 10 seconds forever and print them to files instead of stdout

The tool can also send the collected data through network using precimon collector. Run Precimon Collector on a different machine and use the following options to configure the connection:

- `-i ip`        : IP address or hostname of the precimon central collector
- `-p port`      : port number on collector host
- `-X secret`    : Set the remote collector secret or use shell PRECIMON_SECRET

Example:

- `./precimon -s 10 -c 50 -i monitoring-machine.com -p 8888 -X password` runs a precimon instance that takes snapshots every 10 seconds for 50 cycles and sends data to `monitoring-machine.com:8888` using the secret `password`

### precimon collector

Collect precimon data from network using precimon collector.

Example: precimon_collector -p 8181 -d /home/nigel
Example: precimon_collector -p 8181 -d /home/sally -i -X abcd1234

By default, collector saves the data to a file named hostname+date+time.json to the supplied directory.

- `-d`                      Directory to save JSON file.
- `-p`                      TCP port to listen for connections on.
- `-X`                      Connection password. Or set this to the PRECIMON_SECRET shell variable.
- `-a <collector.conf>`     Use configuration file instead of options. Do not mix this option with other command line options.

collector.conf contents should be like this:

```conf
port=8181
directory=/home/nag/precimondata
secret=abc123
json=1
```

Note: 1=on and 0=off

## How is this different from njmon

### v0.1

#### High Time Resolution

Precimon uses `clock_gettime(CLOCK_MONOTONIC, ...)` and `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)` to do time
operations. Both functions use high resolution clocks (nanoseconds). Precimon also uses monotonic clocks (counting
time from system start) instead of real-time clocks to avoid time change problems caused by NTP server
time-change, daylight time-saving, etc...
An example problem is [Cloudflare's RRDNS problem - How and why the leap second affected cloudflare dns](https://blog.cloudflare.com/how-and-why-the-leap-second-affected-cloudflare-dns/).

#### Graceful Exit

Precimon outputs JSON data. To ensure it preserve the correct format, precimon handles the following signals: `SIGTERM`,
`SIGINT` and `SIGQUIT`. When a signal is received, a flag is set for a graceful exit. On the next precimon cycle, it pushs
all buffered data to the output file, completes the JSON format then exits.

#### Minor Additions

- Use `-T` option to print timers for each snapshot e.g. sleeping time, execution time
- Use `-C` option to print precimon running configurations
- Better JSON structure
- Single process instance using pid file locks `/tmp/precimon.pid`

### vNext

Hopefully, we want to include these features in vNext:

- Metrics Alerts e.g. when total CPU percentage > 60%, alert using email
- Single process monitoring e.g. `-P 1500` to output metrics of process whose pid is 1500
- Database Injection Support for collector

## License

precimon and precimon collector are both forked from Nigel Griffiths njmon and njmon collector, and licensed under GPLv3.
No warranty is implied or guaranteed.

(C) Copyright 2019 Jalal Mostafa.
