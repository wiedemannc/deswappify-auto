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

from __future__ import print_function, division
import sys
import time
import glob
import re
import os
import subprocess
import optparse
import logging

class Deswappifier(object):
    SCAN_PROC_SWAP_DETAILS = 1
    SCAN_PROC_ACTIVE = 2
    
    STATE_WAIT_IDLE = 0
    STATE_DESWAP = 1
    STATE_DONE = 2
    
    LOG_PREFIX = ["[error]", "[warn ]", "[info ]", "[dump ]"]
    
    def __init__(self, **kw):
        # configuration
        self.mem_threshold = kw.get("mem_threshold", 500*1024*1024)
        self.max_accepted_swap_size = kw.get("max_accepted_swap_size", 100*1024*1024)
        self.poll_proc_swap_interval = kw.get("poll_proc_swap_interval", 60)
        self.poll_proc_active_interval = kw.get("poll_proc_active_interval", 5)
        self.idle_after_system_busy = kw.get("idle_after_busy", 5)
        self.idle_after_completed = kw.get("idle_after_completed", 300)
        self.proc_threshold = kw.get("max_active_processes", 4)
        verbose = kw.get("verbose", "error")
        systemdlog = kw.get("systemd_logger")

        # create logger
        self.logger = logging.getLogger(__name__)
        if systemdlog:
            from systemd.journal import JournalHandler
            handler = JournalHandler()
        else:
            handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
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
            self.loginfo("Option %s value %s (type %s)", d, kw[d], str(type(kw[d])))
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
        
        # state
        self.state = self.STATE_DESWAP
        self.current_process = None
        self.f_memory = None
        self.remaining_items = []
        self.total_amount_to_deswap = 0
        
        # cache
        self.lastNumActiveProcs = None
        self.lastProcScan = {}
        
        # regexes
        self.condense_smap = re.compile(r"^(Swap:.*)|(([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s.*)$", re.MULTILINE)
        self.swapre = re.compile(r"Swap((?:Pss)?):\s+([0-9]+)\skB")
        self.rangere = re.compile(r"([0-9a-f]+)\s*-\s*([0-9a-f]+)\s")#re.compile("([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s")
        self.freere = re.compile(r"Mem:.*\s([0-9]+)$")
        self.swapusedre = re.compile(r"Swap:\s+[0-9]+\s+([0-9]+)\s")
        self.statere = re.compile(r"State:\s*([A-Z])")
        self.namere = re.compile(r"Name:\s*(.*)")
        
        # initialize
        self.scan_proc(self.SCAN_PROC_ACTIVE|self.SCAN_PROC_SWAP_DETAILS)
        
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
            dirs = glob.glob("/proc/[0-9]*")
            swap_size = {}
            mem_swapped = {}
            proc_names = {}
            n_active = 0
            valid_start_chars = set("S0123456789abcdef")
            for d in dirs:
                if mode & self.SCAN_PROC_SWAP_DETAILS:
                    # parse smaps files for swapped data segments (i.e. having a Swap: entry with more than 0 kB)
                    # note that this operation is quite expensive, so caching is important for not wasting too much CPU
                    s = 0
                    spss = 0
                    ranges = []
                    lastRange = None
                    try:
                        for l in open(d + "/smaps"):
                            if l[0] in valid_start_chars: # optimization for avoiding the regex matches on a lot of lines
                                M = self.swapre.search(l)
                                if M is not None:
                                    cswap = int(M.group(2))
                                    pss = M.group(1) == "Pss"
                                    if cswap > 0:
                                        if not pss:
                                            s += cswap
                                            dec = cswap*1024
                                        else:
                                            spss += cswap
                                            dec = 0
                                        assert lastRange is not None
                                        r = [int(lastRange[0], base=16), 
                                             int(lastRange[1], base=16), 
                                             dec,]
                                        if len(ranges) == 0 or ranges[-1][:2] != r[:2]:
                                            ranges.append(r)
                                        elif dec > 0 and ranges[-1][:2] == r[:2] and ranges[-1][2] == 0:
                                            ranges[-1][2] = dec
                                M = self.rangere.search(l)
                                if M is not None:
                                    lastRange = (M.group(1),M.group(2))
                        if s > 0:
                            swap_size[d] = s
                            mem_swapped[d] = ranges
                    except IOError:
                        pass
                    self.logdump("%s: %d %d", d, s, spss)
                if mode & self.SCAN_PROC_ACTIVE:
                    # parse status file and scan for process state and name
                    try:
                        state = None
                        for l in open(d + "/status", "r"):
                            M = self.statere.search(l)
                            if M is not None:
                                state = M.group(1)
                            M = self.namere.search(l)
                            if M is not None:
                                proc_names[d] = M.group(1)
                        if state is None:
                            self.logwarning("Cannot determine process state (%s). Process probably already died.", d)
                        n_active += state != "S"
                    except IOError:
                        pass
            tend = time.time()
            self.logdump("Scanning proc mode=%d took %.1f seconds", mode, tend-tstart)
            if mode & self.SCAN_PROC_SWAP_DETAILS:
                self.lastProcScan[self.SCAN_PROC_SWAP_DETAILS] = (
                    time.time(), 
                    [swap_size, mem_swapped])
                self.total_amount_to_deswap = sum(swap_size.values())*1024
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
    
    def select_new_process(self):
        # select a new process to be de-swapped
        while 1:
            self.current_process = None
            self.f_memory = None
            self.remaining_items = []
            # get scan information
            swap_size, mem_swapped, _, proc_names = self.scan_proc(self.SCAN_PROC_SWAP_DETAILS|self.SCAN_PROC_ACTIVE)
            # filter valid directories (i.e. processes)
            valid_dirs = [d for d in swap_size.keys() if len(mem_swapped[d]) > 0 and swap_size[d] > 0]
            if len(valid_dirs) == 0:
                # no more processes to deswap, we are finished.
                self.loginfo("no processes found (len(swap_size)==%d len(mem_swapped)==%d len(valid_dirs)==%d.",
                             len(swap_size), len(mem_swapped), len(valid_dirs))
                return
            # find the process with largest swap
            largest = max([swap_size[d] for d in valid_dirs])
            largest_dir = [d for d in valid_dirs if swap_size[d] == largest][0]
            self.loginfo("swap total: %.3f MB (%d processes)", 
                        self.total_amount_to_deswap/(1024.*1024.),
                        len(valid_dirs))
            try:
                # open memory mapping and set object state 
                self.f_memory = open(largest_dir + "/mem", "rb")
                self.remaining_items = mem_swapped[largest_dir]
                self.current_process = largest_dir
                name = proc_names.get(self.current_process, "<unknown>")
                self.loginfo("deswappifying %s[%s] (%.3f MB, %d chunks)" % 
                            (largest_dir, name, largest/1024., len(self.remaining_items)))
                # remove from cache
                del swap_size[self.current_process]
                del mem_swapped[self.current_process]
                return
            except IOError as e:
                # this might happen if the processes died before we get here or on permission errors
                del swap_size[largest_dir]
                del mem_swapped[largest_dir]
                self.loginfo("process died in between (%s).", str(e))
        
    def deswappify(self):
        # check if we still have something to do, otherwise fetch new task
        if len(self.remaining_items) == 0:
            self.select_new_process()
        if len(self.remaining_items) == 0:
            self.setState(self.STATE_DONE)
            time.sleep(self.idle_after_completed)
            return
        # get next work package
        self.setState(self.STATE_DESWAP)
        start,end,cswap = self.remaining_items.pop()
        size = end - start
        self.logdump("%x - %x (%d kB)", start, end, size//1024)
        try:
            # seek for the requested offset
            self.f_memory.seek(start)
            read = 0
            # read the data chunk
            while read < size:
                r = len(self.f_memory.read(size-read))
                if r == 0:
                    break
                read += r
        except IOError as e:
            self.logwarning("cannot read memory mapping, process died or memory layout changed meanwhile (%s)", str(e))
        self.logdump("read %d bytes of %d bytes (%x - %x)" % (read, size, start, end))
        self.total_amount_to_deswap -= cswap

    def get_non_sleeping_processes(self):
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
                    or free_mem < self.total_amount_to_deswap + self.mem_threshold)
        if sys_busy and self.state == self.STATE_DESWAP:
            self.loginfo("Suspending: available memory: %.3f MB swap: %s (missing %.3f MB)",
                         free_mem / (1024.*1024.),
                         "%.3f MB" % (self.total_amount_to_deswap/(1024.*1024.)),
                         max(0, self.total_amount_to_deswap + self.mem_threshold - free_mem)/(1024.*1024.),
                         )
            self.loginfo("            num active procs: %d (delta: %d)", 
                         num_active_procs,
                         max(0, num_active_procs - self.proc_threshold),
                        )
        return sys_busy
    
    def setState(self, state):
        if state != self.state:
            self.state = state
            self.loginfo("State transition to %s", ["WAIT_IDLE", "DESWAP", "DONE"][self.state])
    
    def step(self):
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
                    self.deswappify()
        except Exception as e:
            self.logger.exception("Application triggered possible bug. Please report back the following information so it can be fixed.")
            
def parseSize(s):
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

def sizeCallback(option, opt_str, value, parser):
    try:
        setattr(parser.values, option.dest, parseSize(value))
    except Exception as e:
        raise optparse.OptionValueError(str(e))
    
def main():
    parser = optparse.OptionParser(version="deswappify_auto 0.0")
    parser.add_option("-v", "--verbose", 
                      choices=["error", "warning", "info", "dump"], 
                      default="warning", 
                      help="set verbosity to one of error, warning, info or dump [default: %default]")
    parser.add_option("-m", "--mem_threshold",
                      action="callback", callback = sizeCallback,
                      default=parseSize("25%"),
                      type=str,
                      help="set minimal amount of extra memory which should be available after deswapping. Sizes can be suffixed with k,M,G and T (for bytes) and with % (for percentage of physical memory). [default: 25%]")
    parser.add_option("-s", "--max_accepted_swap_size",
                      action="callback", callback = sizeCallback,
                      default=parseSize("100M"),
                      type=str,
                      help="set maximum amount of swap size which is acceptable before leaving idle state. Sizes can be suffixed with k,M,G and T (for bytes) and with % (for percentage of physical memory). [default: 100M]")
    parser.add_option("-p", "--poll_proc_swap_interval", 
                      type=int,
                      default=60,
                      help="minimum number of seconds between two polls of the /proc directory for swap information. [default: %default]")
    parser.add_option("-P", "--poll_proc_active_interval", 
                      type=int,
                      default=3,
                      help="minimum number of seconds between two polls of the /proc directory for active process information. [default: %default]")
    parser.add_option("-b", "--idle_after_busy",
                      type=int,
                      default=5,
                      help="number of seconds to sleep after system busy detection. [default: %default]")
    parser.add_option("-c", "--idle_after_completed",
                      type=int,
                      default=60,
                      help="number of seconds to sleep after successful deswappify. [default: %default]")
    parser.add_option("-a", "--max_active_processes",
                      type=int,
                      default=4,
                      help="maximum number of active processes for system idle detection. [default: %default]")
    parser.add_option("-n", "--avoid_renicing",
                      action="store_true",
                      help="avoid renicing this process.")
    parser.add_option("-l", "--systemd_logger",
                      action="store_true",
                      help="use systemd logger instead of python stream logger.")
    option, args = parser.parse_args()
    ds = Deswappifier(**option.__dict__)
    while 1:
        ds.step()
    
if __name__ == "__main__":
    main()
