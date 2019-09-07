#coding: utf-8
import threading
import queue
import os
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from WebshellInspector import WebshellInspector
from WebshellKiller import WebshellKiller

'''
1> after monitor mode started, call WebshellInspector to inpsector each file changed(
   especially uploaded), make this decision to decrease the error rate.
   
2> when working in hand mode, call WebshellKiller to detect all the specified files(
   or directory)
   
3> however, you could always use these shit code by yourself without any limination.

4> thanks `WatchDog` anyway.
'''

MONITOR_TYPELIST = ['*.JSP', '*.JSPX', '*.ASHX', '*.ASPX', '*.PHP'] 
MONITOR_INTERVAL = 3 #To ignore the file change event repeatly with this interval 
SLEEP_INTERVAL_S = 0.01
MONITOR_CACHESIZE = 1024

class WebshellMonitor(threading.Thread):
    
    # monitor_directory: no need to explain it
    # monitor_level    : 0 means we would call WebshellInspector to detect otherwise
    # call WebshellKiller to detect if set 1
    
    def __init__(self, monitor_directory, monitor_level=1):
        super().__init__()
        self.monitor_directory = monitor_directory
        self.monitor_container = queue.Queue(1024) 
        self.monitor_observer  = self._init_observer();
        self.monitor_executive = self._init_executive(monitor_level);
        self.mointor_terminate = False
        self._init_cache_manager()
    
    def _init_cache_manager(self):
        self.cache = dict()
    
    def flush_cache(self, monitor_item):
        file_path, last_time = monitor_item
        curr_time = time.time()
        if file_path in self.cache: 
            interval = curr_time - last_time
            if interval < MONITOR_INTERVAL:
                return False
        if len(self.cache) > MONITOR_CACHESIZE: #update cache
            limitation = curr_time - 3600 * 24
            self.cache = {k:v for k, v in self.cache.items() if v > limitation}
        self.cache[file_path] = curr_time
        return True
        
    def _init_executive(self, monitor_level=1):
        if monitor_level == 1: 
            self.JExecutive = self._init_killer('Java')
            self.AExecutive = self._init_killer('Aspx')
            self.PExecutive = self._init_killer('Php')
        else: 
            self.JExecutive = self._init_inspector('Java')
            self.AExecutive = self._init_inspector('Aspx')
            self.PExecutive = self._init_inspector('Php')
        monitor_executive = {
            'J': self.JExecutive, 'A': self.AExecutive, 'P': self.PExecutive}
        return monitor_executive
     
    def _init_killer(self, magic_head):
        logger_fpath = "../Log/Webshell.log"
        config_fpath = "../Config/{0}WebshellKiller.yar".format(magic_head)
        return WebshellKiller(config_fpath, logger_fpath)
    
    def _init_inspector(self, magic_head):
        logger_fpath = "../Log/Webshell.log"
        config_fpath = '../Config/{0}WebshellInspector.json'.format(magic_head)
        return WebshellInspector(config_fpath, logger_fpath)
    
    def _init_observer(self):
        observer = Observer()
        event_handler = MonitorEventHandler(self.monitor_container)     
        observer.schedule(event_handler, self.monitor_directory, recursive=True)
        return observer
    
    def detect(self, monitor_item):
        if self.flush_cache(monitor_item): 
            #DON'T detect the file until the cache has been flushed.
            file_path, event_time = monitor_item
            file_extension = os.path.splitext(file_path)[-1]
            indicator = file_extension[1].upper()
            executive = self.monitor_executive[indicator]
            while True:
                detect_result = executive.detect(file_path)
                if not detect_result:
                    time.sleep(SLEEP_INTERVAL_S)
                else:
                    break
        
    def run(self):
        if not self.monitor_executive:
            return
        self.monitor_observer.start()
        while not self.mointor_terminate:
            monitor_item = self.monitor_container.get()
            self.detect(monitor_item)    
            self.monitor_container.task_done()
        self.monitor_observer.join()     
        self.monitor_observer.stop()
    
    def stop(self):
        self.mointor_terminate = True
        
class MonitorEventHandler(PatternMatchingEventHandler):
    def __init__(self, monitor_container):
        super().__init__(patterns=MONITOR_TYPELIST)
        self.monitor_container = monitor_container
    
    def on_any_event(self, event):
        pass
    
    #actually we just need to monitor the action of file `modified` and `moved` 
    def on_modified(self, event):
        monitor_item = (event.src_path, time.time())
        self.monitor_container.put(monitor_item)
 
    def on_moved(self, event):
        monitor_item = (event.dest_path, time.time())
        self.monitor_container.put(monitor_item)

if __name__ == '__main__':
    monitor = WebshellMonitor('..\\Test', monitor_level=1)
    monitor.start()
    monitor.join()
    
    
