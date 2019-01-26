# deswappify-auto

Automatically swap-in pages when enough memory is available.

The code is inspired by https://gist.github.com/WGH-/91260f6d65db88be2c847053c49be5ae and the discussion on  https://unix.stackexchange.com/questions/45673/how-can-swapoff-be-that-slow.

It is ment to use as a daemon on linux. It continuously scans the memory and load situation and performs a deswap operation when there the situation allows (enough available memory and not too many active processes). This might be seen as a workaround for high swap usages after resume from hibernation, even if there is enough physical memory available.

The script has been developed in python 3.5 (it might run also with python 2.7).

Recommended python packages are systemd (for logging) and psutil (for setting an appropriate ionice level). If these packages are not installed, the functionality is slightly limited.

Help is available via deswappify_auto.py -h:

```
Usage: deswappify_auto.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v VERBOSE, --verbose=VERBOSE
                        set verbosity to one of error, warning, info or dump
                        [default: warning]
  -m MEM_THRESHOLD, --mem_threshold=MEM_THRESHOLD
                        set minimal amount of extra memory which should be
                        available after deswapping. Sizes can be suffixed with
                        k,M,G and T (for bytes) and with % (for percentage of
                        physical memory). [default: 25%]
  -s MAX_ACCEPTED_SWAP_SIZE, --max_accepted_swap_size=MAX_ACCEPTED_SWAP_SIZE
                        set maximum amount of swap size which is acceptable
                        before leaving idle state. Sizes can be suffixed with
                        k,M,G and T (for bytes) and with % (for percentage of
                        physical memory). [default: 100M]
  -p POLL_PROC_SWAP_INTERVAL, --poll_proc_swap_interval=POLL_PROC_SWAP_INTERVAL
                        minimum number of seconds between two polls of the
                        /proc directory for swap information. [default: 60]
  -P POLL_PROC_ACTIVE_INTERVAL, --poll_proc_active_interval=POLL_PROC_ACTIVE_INTERVAL
                        minimum number of seconds between two polls of the
                        /proc directory for active process information.
                        [default: 3]
  -b IDLE_AFTER_BUSY, --idle_after_busy=IDLE_AFTER_BUSY
                        number of seconds to sleep after system busy
                        detection. [default: 5]
  -c IDLE_AFTER_COMPLETED, --idle_after_completed=IDLE_AFTER_COMPLETED
                        number of seconds to sleep after successful
                        deswappify. [default: 60]
  -a MAX_ACTIVE_PROCESSES, --max_active_processes=MAX_ACTIVE_PROCESSES
                        maximum number of active processes for system idle
                        detection. [default: 4]
  -n, --avoid_renicing  avoid renicing this process.
  -l, --systemd_logger  use systemd logger instead of python stream logger.
```
