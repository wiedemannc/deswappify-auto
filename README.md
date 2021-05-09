# deswappify-auto

## Automatically fetch swapped pages to physical memory when enough memory is available.

The code is inspired by https://gist.github.com/WGH-/91260f6d65db88be2c847053c49be5ae and the discussion on  https://unix.stackexchange.com/questions/45673/how-can-swapoff-be-that-slow.

It is ment to be used as a daemon on linux. It continuously scans the memory and load situation and performs a deswap operation when there the situation allows (enough available memory and not too many active processes). This might be seen as a workaround for high swap usages after resume from hibernation, even if there is enough physical memory available.

## Dependencies

The script has been developed in python 3.5 (it might run also with python 2.7).

Recommended python packages are `systemd` (for logging) and `psutil` (for setting an appropriate ionice level). If these packages are not installed, the functionality is slightly limited.

The script expects the linux commands `free`, `swapoff` and `swapon` to be in PATH, the latter two are optional and only used if -e option is set.

Obviously, the script has to be run with root privileges.

## Help

Help is available via deswappify_auto.py -h:

```
usage: deswappify_auto [-h] [--version] [-v {error,warning,info,dump}]
                       [-m MEM_THRESHOLD] [-s MAX_ACCEPTED_SWAP_SIZE]
                       [-p POLL_PROC_SWAP_INTERVAL]
                       [-P POLL_PROC_ACTIVE_INTERVAL] [-b IDLE_AFTER_BUSY]
                       [-c IDLE_AFTER_COMPLETED] [-a MAX_ACTIVE_PROCESSES]
                       [-n] [-l] [-e] [-j NUM_PARALLEL] [-t SPAWN_TIMEOUT]
                       [-d] [--pc_during_deswap PC_DURING_DESWAP]
                       [--pc_during_idle PC_DURING_IDLE]
                       [pids [pids ...]]

positional arguments:
  pids                  If pids are specified, the program is run in one-shot
                        mode. Otherwise it's run as a daemon. (default: [])

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v {error,warning,info,dump}, --verbose {error,warning,info,dump}
                        set verbosity (default: warning)
  -m MEM_THRESHOLD, --mem_threshold MEM_THRESHOLD
                        set minimal amount of extra memory which should be
                        available after deswapping. Sizes can be suffixed with
                        k,M,G and T for bytes and with % for percentage of
                        physical memory. (default: 25%)
  -s MAX_ACCEPTED_SWAP_SIZE, --max_accepted_swap_size MAX_ACCEPTED_SWAP_SIZE
                        set maximum amount of swap size which is acceptable
                        before leaving idle state. Sizes can be suffixed with
                        k,M,G and T for bytes and with % for percentage of
                        physical memory. (default: 100M)
  -p POLL_PROC_SWAP_INTERVAL, --poll_proc_swap_interval POLL_PROC_SWAP_INTERVAL
                        minimum number of seconds between two polls of the
                        /proc directory for swap information. (default: 60)
  -P POLL_PROC_ACTIVE_INTERVAL, --poll_proc_active_interval POLL_PROC_ACTIVE_INTERVAL
                        minimum number of seconds between two polls of the
                        /proc directory for active process information.
                        (default: 3)
  -b IDLE_AFTER_BUSY, --idle_after_busy IDLE_AFTER_BUSY
                        number of seconds to sleep after system busy
                        detection. (default: 5)
  -c IDLE_AFTER_COMPLETED, --idle_after_completed IDLE_AFTER_COMPLETED
                        number of seconds to sleep after successful
                        deswappify. (default: 60)
  -a MAX_ACTIVE_PROCESSES, --max_active_processes MAX_ACTIVE_PROCESSES
                        maximum number of active processes for system idle
                        detection. (default: 4)
  -n, --avoid_renicing  avoid renicing this process. (default: False)
  -l, --systemd_logger  use systemd logger instead of python stream logger.
                        (default: False)
  -e, --swapoffon       if given, a swapoff -a followed by a swapon -a will be
                        issued after successfully completing a deswapping.
                        (default: False)
  -j NUM_PARALLEL, --num_parallel NUM_PARALLEL
                        Number of parallel readers. In theory, more readers
                        should be more efficient on HDD's because the parallel
                        accesses can be sorted. (default: 1)
  -t SPAWN_TIMEOUT, --spawn_timeout SPAWN_TIMEOUT
                        Timeout for spawned processes. Only available in
                        python3. (default: 0)
  -d, --develop         use in development mode, after a possible bug is
                        detected, the application exits. (default: False)
  --pc_during_deswap PC_DURING_DESWAP
                        Optimize swap read-ahead in /proc/sys/vm/page-cluster
                        during deswap operation. This is the value to be used
                        during deswappifying. The actual number of bytes can
                        be calculated by pagesize*2^value. For page sizes of 4
                        kB, the default value of 16 is 256 MB. Use negative
                        sizes to not modify the value stored in
                        /proc/sys/vm/page-cluster. (default: 16)
  --pc_during_idle PC_DURING_IDLE
                        Optimize swap read-ahead in /proc/sys/vm/page-cluster
                        during deswap operation. This is the value to be used
                        during idle operation. Use negative arguments to
                        return to the original value stored in
                        /proc/sys/vm/page-cluster. (default: -1)
```
