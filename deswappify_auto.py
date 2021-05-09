#!/usr/bin/env python3

# deswappify-auto
# Copyright (C) 2019 wiedemannc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function, division, with_statement
import sys
import time
import glob
import re
import os
import subprocess
import argparse
import logging
import struct
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed

class SmapsFile(object):
    """
    this class can be used to iterate over a smaps file. In non-detailed mode, the swap sizes of 
    the individual chunks are reported. In detailed mode, also the start and end adresses are reported.
    """
    swapre = re.compile(r"Swap:\s+([0-9]+)\skB")
    rangere = re.compile(r"([0-9a-f]+)\s*-\s*([0-9a-f]+)\s")#re.compile("([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s")

    def __init__(self, pid=None, detailed=False):
        self.f = []
        if pid is not None:
            try:
                self.f = open("/proc/%d/smaps" % pid, "r")
            except IOError:
                pass
        self.detailed = detailed
        self.valid_start_chars = set("S0123456789abcdef") if detailed else set("SA")
        
    def bytes_swapped(self):
        assert not self.detailed
        return sum(self)
    
    def __iter__(self):
        lastRange = None
        for l in self.f:
            if l[0] in self.valid_start_chars:
                if self.detailed:
                    M = self.rangere.search(l)
                    if M is not None:
                        lastRange = M.groups()
                M = self.swapre.search(l)
                if M is not None:
                    cswap = int(M.group(1))
                    if cswap > 0:
                        if self.detailed:
                            r = (int(lastRange[0], base=16), 
                                    int(lastRange[1], base=16), 
                                    cswap*1024,)
                            yield r
                        else:
                            yield cswap*1024
                
class SmapsFileWrapper(object):
    """
    Small wrapper around SmapsFile to predict iteration-end conditions. 
    These can be checked with the exhausted() method.
    """
    def __init__(self, *args, **kw):
        self.smaps = SmapsFile(*args, **kw)
        self.it = iter(self.smaps)
        try:
            self.nextItem = next(self.it)
        except StopIteration:
            self.nextItem = None
        
    def __iter__(self):
        while self.nextItem is not None:
            n = self.nextItem
            try:
                self.nextItem = next(self.it)
            except StopIteration:
                self.nextItem = None
            yield n
        
    def exhausted(self):
        return self.nextItem is None
    
        
class Deswappifier(object):
    """
    Main class for automatic deswappifying.
    """
    SCAN_PROC_SWAP_DETAILS = 1
    SCAN_PROC_ACTIVE = 2
    
    STATE_WAIT_IDLE = 0
    STATE_DESWAP = 1
    STATE_DONE = 2
    
    DESWAP_PARENT = 0
    DESWAP_CHILD = 1
    
    LOG_PREFIX = ["[error]", "[warn ]", "[info ]", "[dump ]"]
    
    def __init__(self, **kw):
        # configuration
        self.mem_threshold = kw.get("mem_threshold")
        self.max_accepted_swap_size = kw.get("max_accepted_swap_size")
        self.poll_proc_swap_interval = kw.get("poll_proc_swap_interval")
        self.poll_proc_active_interval = kw.get("poll_proc_active_interval")
        self.idle_after_system_busy = kw.get("idle_after_busy")
        self.idle_after_completed = kw.get("idle_after_completed")
        self.proc_threshold = kw.get("max_active_processes")
        self.perform_swap_off = kw.get("swapoffon")
        self.num_workers = kw.get("num_parallel")
        self.develop_mode = kw.get("develop")
        self.spawn_timeout = kw.get("spawn_timeout")
        self.pc_during_deswap = kw.get("pc_during_deswap")
        self.pc_during_idle = kw.get("pc_during_idle")
        verbose = kw.get("verbose")
        systemdlog = kw.get("systemd_logger")

        # create logger
        self.logger = logging.getLogger(__name__)
        if systemdlog:
            from systemd.journal import JournalHandler
            handler = JournalHandler()
        else:
            handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.handlers = []
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.ERROR if verbose == "error" else
                             logging.WARNING if verbose == "warning" else
                             logging.INFO if verbose == "info" else
                             logging.DEBUG if verbose == "dump" else
                             logging.NOTSET)
        
        if os.geteuid() != 0:
            self.logerror("It seems that this application is not run as root. Exiting.")
            sys.exit(1)
        
        for d in kw:
            self.logdump("Option %s value %s (type %s)", d, kw[d], str(type(kw[d])))
        if not kw.get("avoid_renicing", False):
            os.nice(20)
            self.loginfo("set nice value to 20")
            try:
                import psutil
                p = psutil.Process(os.getpid())
                p.ionice(psutil.IOPRIO_CLASS_IDLE)
                self.loginfo("set io nice value to idle")
            except ImportError:
                self.logwarning("Cannot import psutil, ionice value will not be modified.")
        
        if self.spawn_timeout > 0 and sys.version_info.major < 3:
            self.logerror("option spawn_timeout not available in python 2")
            sys.exit(1)

        if self.pc_during_idle < 0 and self.pc_during_deswap >= 0:
            self.pc_during_idle = self.pageCluster(-1)
            if self.pc_during_idle >= 0:
                sys.argv.extend(["--pc_during_idle", str(self.pc_during_idle)])

        if self.pc_during_idle >= 0 and self.pc_during_deswap < 0:
            self.logerror("pc_during_idle is set (>=0) but pc_during_deswap is not set (<0). This is not supported.")
            sys.exit(1)
            
        # state
        self.state = self.STATE_DESWAP
        self.current_process = None
        self.f_memory = None
        self.remaining_items = SmapsFileWrapper()
        self.remaining_items_iter = iter(self.remaining_items)
        self.total_amount_to_deswap = 0
        self.current_process_swapsize = 0
        
        # cache
        self.lastNumActiveProcs = None
        self.lastProcScan = {}
        
        # regexes
        self.condense_smap = re.compile(r"^(Swap:.*)|(([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s.*)$", re.MULTILINE)
        self.freere = re.compile(r"Mem:.*\s([0-9]+)$")
        self.swapusedre = re.compile(r"Swap:\s+[0-9]+\s+([0-9]+)\s")
        self.statere = re.compile(r"State:\s*([A-Z])")
        self.namere = re.compile(r"Name:\s*(.*)")
        
        # initialize
        self.scan_proc(self.SCAN_PROC_ACTIVE|self.SCAN_PROC_SWAP_DETAILS)
        self.executor = ThreadPoolExecutor(max_workers = self.num_workers)
        self.futures_pending = set()

    @staticmethod
    def get_active_pids():
        dirs = glob.glob("/proc/[0-9]*")
        for d in dirs:
            yield int(d[d.rfind("/")+1:])

    def pageCluster(self, newvalue):
        try:
            with open("/proc/sys/vm/page-cluster", "r") as f:
                v = int(f.read())
            if newvalue < 0:
                return v
            if v != newvalue:
                self.loginfo("Modifying page-cluster from %d to %d.", v, newvalue)
                with open("/proc/sys/vm/page-cluster", "w") as f:
                    f.write("%d" % newvalue)
            return newvalue
        except Exception as e:
            self.logger.exception("exception during modifying /proc/sys/vm/page-cluster (ignored)")
            return -1

    def log(self, verbosity, msg, *args):
        if verbosity <= self.verbose:
            print(self.LOG_PREFIX[verbosity], msg % args)
            
    def logerror(self, *args):
        self.logger.error(*args)
    
    def logwarning(self, *args):
        self.logger.warning(*args)
        
    def loginfo(self, *args):
        self.logger.info(*args)
        
    def logdump(self, *args):
        self.logger.debug(*args)
        
    def scan_proc(self, mode):
        # iterate over all processes listed in /proc/<pid> and gather information according to given mode
        # results are cached for a certain amount of time
        cached = True
        if mode & self.SCAN_PROC_SWAP_DETAILS:
            if (self.SCAN_PROC_SWAP_DETAILS not in self.lastProcScan or
                time.time() - self.lastProcScan[self.SCAN_PROC_SWAP_DETAILS][0] > self.poll_proc_swap_interval):
                cached = False
        if mode & self.SCAN_PROC_ACTIVE:
            if (self.SCAN_PROC_ACTIVE not in self.lastProcScan or
                time.time() - self.lastProcScan[self.SCAN_PROC_ACTIVE][0] > self.poll_proc_active_interval):
                cached = False
        if not cached:
            tstart = time.time()
            swap_size = {}
            proc_names = {}
            n_active = 0
            for m in [self.SCAN_PROC_SWAP_DETAILS,self.SCAN_PROC_ACTIVE]: 
                if mode & m and m in self.lastProcScan:
                    del self.lastProcScan[m]
            for pid in self.get_active_pids():
                if mode & self.SCAN_PROC_SWAP_DETAILS:
                    swap_size[pid] = SmapsFile(pid, detailed=False).bytes_swapped()
                if mode & self.SCAN_PROC_ACTIVE:
                    # parse status file and scan for process state and name
                    try:
                        state = None
                        for l in open("/proc/%d/status"%pid, "r"):
                            M = self.statere.search(l)
                            if M is not None:
                                state = M.group(1)
                            M = self.namere.search(l)
                            if M is not None:
                                proc_names[pid] = M.group(1)
                        if state is None:
                            self.logwarning("Cannot determine process state (%s). Process probably already died.", d)
                        n_active += state != "S" and state != "I" # sleep or idle
                    except IOError:
                        pass
            tend = time.time()
            self.logdump("Scanning proc mode=%d took %.1f seconds", mode, tend-tstart)
            if mode & self.SCAN_PROC_SWAP_DETAILS:
                self.lastProcScan[self.SCAN_PROC_SWAP_DETAILS] = (
                    time.time(), 
                    [swap_size])
                self.total_amount_to_deswap = sum(swap_size.values())
            if mode & self.SCAN_PROC_ACTIVE:
                self.lastProcScan[self.SCAN_PROC_ACTIVE] = (
                    time.time(),
                    [n_active, proc_names])
        result = []
        result += (self.lastProcScan[self.SCAN_PROC_SWAP_DETAILS][1] 
                    if mode & self.SCAN_PROC_SWAP_DETAILS
                    else [])
        result += (self.lastProcScan[self.SCAN_PROC_ACTIVE][1] 
                    if mode & self.SCAN_PROC_ACTIVE
                    else [])
        return tuple(result)
    
    def select_new_process(self, selected_pid = None):
        # select a new process to be de-swapped
        while 1:
            self.current_process = None
            self.f_memory = None
            self.remaining_items = SmapsFileWrapper()
            self.remaining_items_iter = iter(self.remaining_items)
            self.current_process_swapsize = 0
            # get scan information
            swap_size, _, proc_names = self.scan_proc(self.SCAN_PROC_SWAP_DETAILS|self.SCAN_PROC_ACTIVE)
            # filter valid directories (i.e. processes)
            valid_pids = [pid for pid in swap_size.keys() if swap_size[pid] > 0]
            if len(valid_pids) == 0:
                # no more processes to deswap, we are finished.
                if selected_pid is None:
                    self.loginfo("no processes found.")
                else:
                    self.loginfo("pid %d: process not found or already deswapped.", selected_pid)
                return
            if selected_pid is None:
                # process is parent (controller)
                # find pids with largest swap memories
                pids = sorted([(swap_size[pid],pid) for pid in valid_pids])[::-1]
                i = 0
                T = 100*1024*1024 # threshold 100M total
                s = 0
                while s < T and i < len(pids):
                    s += pids[i][0]
                    i += 1
                pids = pids[:i]
                # spawn a subprocess which will execute the deswapping for the specified
                # pids. Without spawning, the memory footprint of this script grows to quite large
                # numbers, like 100M or so. Reason for this is unknown and difficult to debug.
                # With spawning, the memory footprint of the parent stays reasonable small.
                self.loginfo("Spawning process: swap total: %.3f MB (%d processes)", 
                            self.total_amount_to_deswap/(1024.*1024.),
                            len(valid_pids))
                self.setState(self.STATE_DESWAP)
                if self.spawn_timeout > 0:
                    # if a timeout is given (recommended), the child is respawned after the timeout until the given work is finished.
                    try:
                        # use same arguments, add an "avoid renicing" (because the nice value will be inherited) and the pids
                        subprocess.check_call([sys.executable] + sys.argv + ["-n"] + [str(p[1]) for p in pids], timeout=self.spawn_timeout)
                    except subprocess.TimeoutExpired:
                        # avoid updating cache. Usually, we rescan right afterwards
                        pids = [] 
                else:
                    # otherwsie we are just waiting for the child to complete
                    subprocess.check_call([sys.executable] + sys.argv + ["-n"] + [str(p[1]) for p in pids])
                
                # update cache
                for css, pid in pids:
                    self.total_amount_to_deswap -= css
                    del swap_size[pid]
                return True
            else:
                # process is child (called with specific pid)
                if not selected_pid in swap_size or swap_size[selected_pid] == 0:
                    self.loginfo("pid %d not found or no swap size" % selected_pid)
                    return
                largest_pid = selected_pid
                largest = swap_size[selected_pid]
                try:
                    # open memory mapping and set object state 
                    self.f_memory = [open("/proc/%d/mem" % largest_pid, "rb", 0) for i in range(self.num_workers)]
                    self.remaining_items = SmapsFileWrapper(largest_pid, detailed=True)
                    self.remaining_items_iter = iter(self.remaining_items)
                    self.current_process = largest_pid
                    self.current_process_swapsize = largest
                    name = proc_names.get(self.current_process, "<unknown>")
                    self.loginfo("deswappifying %d [%s] (%.3f MB)" % 
                                (largest_pid, name, largest/(1024.*1024.)))
                    # remove from cache, don't select this process again
                    del swap_size[self.current_process]
                    return
                except IOError as e:
                    # this might happen if the processes died before we get here or on permission errors
                    del swap_size[largest_pid]
                    self.loginfo("process died in between (%s).", str(e))
        
    def deswappify_parent(self):
        # check if we still have something to do, otherwise fetch new task
        work_done = False
        if self.remaining_items.exhausted():
            work_done = self.select_new_process()
        if not work_done and self.remaining_items.exhausted():
            if self.state != self.STATE_DONE:
                # perform a new scan and check if we are still done
                self.lastProcScan = {}
                work_done = self.select_new_process()
                if work_done or not self.remaining_items.exhausted():
                    # there is more work to do...
                    return
                self.lastProcScan = {}
                gc.collect()
            if self.perform_swap_off:
                try:
                    self.loginfo("executing 'swapoff -a'")
                    subprocess.check_call(["swapoff", "-a"])
                    self.loginfo("executing 'swapon -a'")
                    subprocess.check_call(["swapon", "-a"])
                except Exception as e:
                    self.logger.exception("executing swapoff / swapon failed.")
            self.setState(self.STATE_DONE)
            time.sleep(self.idle_after_completed)
            return

    def deswappify_child(self):
        if not self.remaining_items.exhausted():
            # get next work package
            self.setState(self.STATE_DESWAP)
            # following is only executed in child processes
            
            # we are reading in parallel with multiple threads
            # wait for future results if necessary (all workers busy)
            self.wait_for_futures()
            # get next task
            start,end,cswap = next(self.remaining_items_iter)
            size = end - start
            self.logdump("%x - %x (%d kB)", start, end, size//1024)
            # fetch a free file descriptor
            f = self.f_memory.pop()
            # submit work to workers
            fut = self.executor.submit(self.read, f, start, end, size, cswap)
            # store future result for further processing
            self.futures_pending.add(fut)
        if self.remaining_items.exhausted():
            # after the whole process is deswapped, wait for all remaining future results and clean up executor stuff
            self.wait_for_futures()
            self.current_process = None
            self.f_memory = None
            self.remaining_items = SmapsFileWrapper()
            self.remaining_items_iter = iter(self.remaining_items)
            self.executor.shutdown(wait=True)
            self.executor = ThreadPoolExecutor(max_workers = self.num_workers)

    def deswappify_pid(self, pid):
        """
        deswappify a specific process
        """
        self.select_new_process(pid)
        while self.current_process is pid:
            self.step(self.DESWAP_CHILD)

    def wait_for_futures(self):
        """
        wait for threads to finish reading, if necessary
        """
        if len(self.f_memory) == 0 or self.remaining_items.exhausted():
            # wait for futures
            for fut in as_completed(self.futures_pending):
                self.futures_pending.remove(fut)
                read, f, size,start,end,cswap,exc_info = fut.result()
                self.f_memory.append(f)
                if exc_info is not None:
                    self.logwarning(*exc_info)
                else:
                    self.logdump("read %d bytes of %d bytes (%x - %x)" % (read, size, start, end))
                self.total_amount_to_deswap -= cswap
                if not self.remaining_items.exhausted():
                    break
        assert len(self.f_memory) > 0
        assert not self.remaining_items.exhausted() or len(self.futures_pending) == 0

    @staticmethod
    def read(f, start, end, size, cswap):
        """
        read memory of a process from file descriptor
        """
        try:
            # seek for the requested offset
            f.seek(start)
            read = 0
            # read the data chunk
            while read < size:
                r = len(f.read(size-read))
                if r == 0:
                    break
                read += r
            return (read, f, size, start, end, cswap, None)
        except IOError as e:
            return (0, f, size, start, end, cswap, ("cannot read memory mapping, process died or memory layout changed meanwhile (%s)", str(e)))
            
    def get_non_sleeping_processes(self):
        """
        get number of active processes
        """
        n,_ = self.scan_proc(self.SCAN_PROC_ACTIVE)
        return n
    
    def get_mem_info(self):
        # use linux free tool to check for available memory
        free_mem = 0
        try:
            o = subprocess.check_output("free -b", shell=True, universal_newlines=True)
            o = o.split("\n")
            if len(o) > 1:
                memline = o[1]
            else:
                memline = o[-1]
                
            M = self.freere.search(memline)
            if M is not None:
                free_mem = int(M.group(1))
            else:
                self.loginfo("memline: %s", memline)
                self.logerror("cannot determine available memory. (regex not matching)")            
        except Exception as e:
            self.logerror("cannot determine available memory. (%s)", str(e))
        return free_mem
    
    def sys_busy(self):
        # check whether system is busy or available memory is too small (in this case
        # the tool is not trying to deswap processes, it wouldn't make sense)
        free_mem = self.get_mem_info()
        num_active_procs = self.get_non_sleeping_processes()
        sys_busy = (num_active_procs >= self.proc_threshold 
                    or free_mem < self.current_process_swapsize + self.mem_threshold)
        if sys_busy and self.state == self.STATE_DESWAP:
            self.loginfo("Suspending: available memory: %.3f MB swap: %s (missing %.3f MB)",
                         free_mem / (1024.*1024.),
                         "%.3f MB" % (self.total_amount_to_deswap/(1024.*1024.)),
                         max(0, self.current_process_swapsize + self.mem_threshold - free_mem)/(1024.*1024.),
                         )
            self.loginfo("            num active procs: %d (delta: %d)", 
                         num_active_procs,
                         max(0, num_active_procs + 1 - self.proc_threshold),
                        )
        return sys_busy
    
    def setState(self, state):
        if state != self.state:
            self.state = state
            if state == self.STATE_DESWAP:
                self.pageCluster(self.pc_during_deswap)
            else:
                self.pageCluster(self.pc_during_idle)
            self.loginfo("State transition to %s", ["WAIT_IDLE", "DESWAP", "DONE"][self.state])
    
    def step(self, who_am_i):
        try:
            if self.state == self.STATE_DONE:
                self.scan_proc(self.SCAN_PROC_SWAP_DETAILS)
                if self.total_amount_to_deswap > self.max_accepted_swap_size:
                    self.setState(self.STATE_DESWAP)
                else:
                    if self.total_amount_to_deswap > 0:
                        self.loginfo("%.3f MB not sufficient for deswap initiation.", self.total_amount_to_deswap/(1024.*1024.))
                    time.sleep(self.idle_after_completed)
            else:
                # perform a deswapping step
                if self.sys_busy():
                    self.setState(self.STATE_WAIT_IDLE)
                    time.sleep(self.idle_after_system_busy)
                else:
                    if who_am_i is self.DESWAP_PARENT:
                        self.deswappify_parent()
                    elif who_am_i is self.DESWAP_CHILD:
                        self.deswappify_child()
        except Exception as e:
            self.logger.exception("Application triggered possible bug. Please report back the following information so it can be fixed.")
            if self.develop_mode:
                raise e
            
def parseSize(s):
    """
    convert size string s to bytes
    """
    f = 1
    if s[-1] == "k":
        s = s[:-1]
        f = 1024
    elif s[-1] == "M":
        s = s[:-1]
        f = 1024*1024
    elif s[-1] == "G":
        s = s[:-1]
        f = 1024*1024*1024
    elif s[-1] == "T":
        s = s[:-1]
        f = 1024*1024*1024*1024
    elif s[-1] == "%":
        s = s[:-1]
        mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        f = mem_bytes/100.
    v = int(int(s)*f)
    return v

def main():
    """
    main function
    """
    parser = argparse.ArgumentParser(prog="deswappify_auto", 
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version="deswappify_auto 0.1")
    parser.add_argument("-v", "--verbose", 
                      choices=["error", "warning", "info", "dump"], 
                      default="warning", 
                      help="set verbosity")
    parser.add_argument("-m", "--mem_threshold",
                      type=parseSize,
                      default=("25%"),
                      help="set minimal amount of extra memory which should be available after deswapping. Sizes can be suffixed with k,M,G and T for bytes and with %% for percentage of physical memory.")
    parser.add_argument("-s", "--max_accepted_swap_size",
                      type=parseSize,
                      default=("100M"),
                      help="set maximum amount of swap size which is acceptable before leaving idle state. Sizes can be suffixed with k,M,G and T for bytes and with %% for percentage of physical memory.")
    parser.add_argument("-p", "--poll_proc_swap_interval", 
                      type=int,
                      default=60,
                      help="minimum number of seconds between two polls of the /proc directory for swap information.")
    parser.add_argument("-P", "--poll_proc_active_interval", 
                      type=int,
                      default=3,
                      help="minimum number of seconds between two polls of the /proc directory for active process information.")
    parser.add_argument("-b", "--idle_after_busy",
                      type=int,
                      default=5,
                      help="number of seconds to sleep after system busy detection.")
    parser.add_argument("-c", "--idle_after_completed",
                      type=int,
                      default=60,
                      help="number of seconds to sleep after successful deswappify.")
    parser.add_argument("-a", "--max_active_processes",
                      type=int,
                      default=4,
                      help="maximum number of active processes for system idle detection.")
    parser.add_argument("-n", "--avoid_renicing",
                      action="store_true",
                      help="avoid renicing this process.")
    parser.add_argument("-l", "--systemd_logger",
                      action="store_true",
                      help="use systemd logger instead of python stream logger.")
    parser.add_argument("-e", "--swapoffon",
                      action="store_true",
                      help="if given, a swapoff -a followed by a swapon -a will be issued after successfully completing a deswapping.")
    parser.add_argument("-j", "--num_parallel",
                      default=1,
                      type=int,
                      help="Number of parallel readers. In theory, more readers should be more efficient on HDD's because the parallel accesses can be sorted.")
    parser.add_argument("-t", "--spawn_timeout",
                      default=0,
                      type=int,
                      help="Timeout for spawned processes. Only available in python3.")
    parser.add_argument("-d", "--develop",
                      action="store_true",
                      help="use in development mode, after a possible bug is detected, the application exits.")
    parser.add_argument("--pc_during_deswap",
                        type=int,
                        default=16,
                        help="Optimize swap read-ahead in /proc/sys/vm/page-cluster during deswap operation. This is the value to be used during deswappifying. The actual number of bytes can be calculated by pagesize*2^value. For page sizes of 4 kB, the default value of 16 is 256 MB. Use negative sizes to not modify the value stored in /proc/sys/vm/page-cluster.")
    parser.add_argument("--pc_during_idle",
                        type=int,
                        default=-1,
                        help="Optimize swap read-ahead in /proc/sys/vm/page-cluster during deswap operation. This is the value to be used during idle operation. Use negative arguments to return to the original value stored in /proc/sys/vm/page-cluster.")
    parser.add_argument("pids", metavar="pids", type=int, nargs='*', default=[],
                        help="If pids are specified, the program is run in one-shot mode. Otherwise it's run as a daemon.")
    args = parser.parse_args()
    
    os.environ["LC_ALL"] = "C"
    t0 = time.time()
    ds = Deswappifier(**args.__dict__)
    if len(args.pids) == 0:
        while 1:
            ds.step(ds.DESWAP_PARENT)
    else:
        for pid in args.pids:
            ds.deswappify_pid(int(pid))
    
if __name__ == "__main__":
    main()
