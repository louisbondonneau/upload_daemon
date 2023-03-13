

# !/opt/python3/bin/python3
# -*- coding: utf-8 -*-
import sys
import traceback
import os
import re
import time
import psutil
import shutil
import signal
from datetime import datetime
import subprocess
import socket
import numpy as np

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

from pathlib import Path
import threading

Version = "00.02.00"
DEBUG = False  # !!! the simple print in DEBUG cause crash after closing session
Host_name = socket.gethostname()
Deamon_name = 'Deamon_' + Host_name
DEFAULT_PATH = os.path.dirname(os.path.realpath(__file__)) + '/'
CONFIG_FILE = DEFAULT_PATH + 'upload_daemon.conf'

if(Host_name[:10] == 'undysputed'):
    Host_nb = int(Host_name.split("undysputedbk")[-1])
    Host_name = "undysputedbk"
else:
    Host_nb = 0


class Log_class():
    def __init__(self, logname=None, logdir=None):
        if logname is None:
            time_now = datetime.now().isoformat()
            logname = 'deamon_' + time_now.isot.replace('-', '').replace(':', '').replace('T', '_').split('.')[0]
        self.logname = logname.split('.')[0]
        if logdir is None:
            self.dir = ''  # current dir if error at start
        else:
            self.dir = logdir
            self.check_directory_validity(self.dir)
        self.length = 20
        self.stdlog = self.dir + self.logname + '.log'

    def set_dir(self, directory):

        if(directory[-1] != '/'):
            directory = directory + '/'
        self.dir = str(directory)
        self.check_directory_validity(self.dir)
        self.stdlog = self.dir + self.logname + '.log'

    def __string_formating(self, msg, objet='LOG', timing=True):
        msg = msg.strip('\r').strip('\n').split('\n')
        string = []
        if timing is True:
            time_string = self.__timing_string()
        for imsg in range(len(msg)):
            if timing is True:
                msg[imsg] = time_string + ' ' + msg[imsg]
            string_tmp = "%s: %" + str(self.length - len(objet) + len(msg[imsg])) + "s"
            string.append(string_tmp % (objet, msg[imsg]))
        return string

    def log(self, msg, objet='LOG', timing=True):
        string = self.__string_formating(msg, objet=objet, timing=timing)
        with open(self.dir + self.logname + '.log', 'a') as log_file:
            for istring in string:
                print(istring, file=log_file)
                # if(DEBUG):
                #     print('LOG: ' + istring)

    def warning(self, msg, objet='WARNING', timing=True):
        string = self.__string_formating(msg, objet=objet, timing=timing)
        with open(self.dir + self.logname + '.warning', 'a') as warning_file:
            for istring in string:
                print(istring, file=warning_file)
                # if(DEBUG):
                #     print('WAR: ' + istring)

    def error(self, msg, objet='ERROR', timing=True):
        string = self.__string_formating(msg, objet=objet, timing=timing)
        with open(self.dir + self.logname + '.error', 'a') as error_file:
            for istring in string:
                print(istring, file=error_file)
                # if(DEBUG):
                #     print('ERR: ' + istring)

    def __timing_string(self):
        time_string = datetime.now()
        mili = time_string.strftime("%f")[:3]
        time_string = time_string.strftime("%Y-%m-%d %H:%M:%S.") + mili
        return time_string

    def filter(self, msg, objet='Filter', timing=True):
        msg = msg.strip('\r').strip('\n')
        if (re.search(' e:', msg.lower())) or (re.search('err', msg.lower())):
            self.error(msg, objet=objet, timing=timing)
        elif (re.search(' w:', msg.lower())) or (re.search('warn', msg.lower())):
            self.warning(msg, objet=objet, timing=timing)
        else:
            self.log(msg, objet=objet, timing=timing)

    def check_file_validity(self, file_):
        ''' Check whether the a given file exists, readable and is a file '''
        if not os.access(file_, os.F_OK):
            self.error("File '%s' does not exist" % (file_))
            raise NameError(0, "File '%s' does not exist" % (file_))
        if not os.access(file_, os.R_OK):
            self.error("File '%s' not readable" % (file_))
            raise NameError(1, "File '%s' not readable" % (file_))
        if os.path.isdir(file_):
            self.error("File '%s' is a directory" % (file_))
            raise NameError(2, "File '%s' is a directory" % (file_))

    def check_directory_validity(self, dir_):
        ''' Check whether the a given file exists, readable and is a file '''
        if not os.access(dir_, os.F_OK):
            self.error("Directory '%s' does not exist" % (dir_))
            raise NameError(3, "Directory '%s' does not exist" % (dir_))
        if not os.access(dir_, os.R_OK):
            self.error("Directory '%s' not readable" % (dir_))
            raise NameError(4, "Directory '%s' not readable" % (dir_))
        if not os.path.isdir(dir_):
            self.error("'%s' is not a directory" % (dir_))
            raise NameError(5, "'%s' is not a directory" % (dir_))

    def copyfile(self, file_, target):
        ''' Check whether the a given file exists, readable and is a file '''
        self.check_file_validity(file_)
        self.check_directory_validity(os.path.dirname(target))
        shutil.copyfile(file_, target)
        self.check_file_validity(target)

    def movefile(self, file_, target):
        ''' Check whether the a given file exists, readable and is a file '''
        if (target[-1] != '/'):
            target = target + '/'
        self.check_file_validity(file_)
        if os.path.isdir(target):
            self.check_directory_validity(target)
            target = target + os.path.basename(file_)
        elif os.path.isfile(target):
            self.check_file_validity(target)
        # self.log("move file from %s to %s" % (file_, target), objet=Deamon_name)
        shutil.move(file_, target)
        self.check_file_validity(target)

    def attach_file(self, msg, nom_fichier):
        if os.path.isfile(nom_fichier):
            piece = open(nom_fichier, "rb")
            part = MIMEBase('application', 'octet-stream')
            part.set_payload((piece).read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', "piece; filename= %s" % os.path.basename(nom_fichier))
            msg.attach(part)

    def sendMail(self, mail, subject, text, files=[]):
        try:
            msg = MIMEMultipart()
            msg['From'] = socket.gethostname() + '@obs-nancay.fr'
            msg['To'] = mail
            msg['Subject'] = subject
            msg.attach(MIMEText(text))
            if (len(files) > 0):
                for ifile in range(len(files)):
                    self.attach_file(msg, files[ifile])
                    # print(files[ifile])
            mailserver = smtplib.SMTP('localhost')
            # mailserver.set_debuglevel(1)
            mailserver.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
            mailserver.quit()
            self.log('Send a mail: \"%s\"" to %s' % (subject, mail), objet=Deamon_name)
        except:
            self.traceback_toerror(objet=Deamon_name)

    def traceback_tomail(self, mail, objet=Deamon_name):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_print = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for tb in traceback_print:
            self.error(tb, objet=objet, timing=True)
        self.sendMail(mail, "Error while running %s" % Deamon_name,
                      "An error occure while running %s" % Deamon_name,
                      [self.dir + self.logname + '.log',
                       self.dir + self.logname + '.warning',
                       self.dir + self.logname + '.error'])

    def traceback_toerror(self, objet=Deamon_name):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_print = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for tb in traceback_print:
            self.error(tb, objet=objet, timing=True)

    def traceback_towarning(self, objet=Deamon_name):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_print = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for tb in traceback_print:
            self.warning(tb, objet=objet, timing=True)


class Daemon(object):
    """
    Usage: - create your own a subclass Daemon class and override the run() method. Run() will be periodically the calling inside the infinite run loop
           - you can receive reload signal from self.isReloadSignal and then you have to set back self.isReloadSignal = False
    """

    def __init__(self):
        self.ver = Version
        self.restartPause = 1    # 0 means without a pause between stop and start during the restart of the daemon
        self.waitToHardKill = 3600  # when terminate a process, wait until kill the process with SIGTERM signal
        self.isReloadSignal = False
        self._canDaemonRun = True
        self.SLOW = True
        self.FAST = True
        self.processName = os.path.basename(sys.argv[0])
        self.log = Log_class(logname=self.processName, logdir=DEFAULT_PATH)
        self.stdin = self.log.stdlog
        self.stdout = self.log.stdlog
        self.stderr = self.log.stdlog
        self.__init_config__()

    def __init_config__(self):
        def clean_dirname(string_tmp):
            if(string_tmp[-1] != '/'):
                string_tmp = string_tmp + '/'
            return string_tmp

        self.config = CONFIG_READER(CONFIG_FILE, log_obj=self.log)
        self.logdir = self.config.get_config('UPLOAD', 'logdir')
        self.log.set_dir(self.logdir)
        self.pauseRunLoop = self.config.get_config('UPLOAD', 'UPDATE_TIME')
        self.script_dir = clean_dirname(self.config.get_config('UPLOAD', 'script_dir'))
        if (self.script_dir == '/'):
            self.log.error("script_dir in the configuration file should not be empty or root.", objet='DAEMON_CONF')

        self.script_logdir = clean_dirname(self.config.get_config('UPLOAD', 'script_logdir'))
        if (self.script_logdir == '/'):
            self.log.warning("script_logdir in the configuration file should not be empty or root. (default is logdir)", objet='DAEMON_CONF')
            self.script_logdir = self.logdir

        self.script_dir_finish = clean_dirname(self.config.get_config('UPLOAD', 'script_dir_finish'))
        self.script_dir_error = clean_dirname(self.config.get_config('UPLOAD', 'script_dir_error'))

        # self.id = self.config.get_config('UPLOAD', 'id_prog')

        self.script_timeout = int(self.config.get_config('UPLOAD', 'script_timeout'))
        self.parallel_slow = int(self.config.get_config('UPLOAD', 'parallel_slow'))
        self.parallel_fast = int(self.config.get_config('UPLOAD', 'parallel_fast'))

        self.mail_error = str(self.config.get_config('UPLOAD', 'mail_error'))

    def _sigterm_handler(self, signum, frame):
        self._canDaemonRun = False

    def _reload_handler(self, signum, frame):
        self.isReloadSignal = True

    def _makeDaemon(self):
        """
        Make a daemon, do double-fork magic.
        """
        try:
            pid = os.fork()
            if pid > 0:
                # Exit first parent.
                sys.exit(0)
        except OSError as e:
            m = "Fork #1 failed"
            self.log.error(m, objet=Deamon_name)
            sys.exit(1)
        # Decouple from the parent environment.
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # Do second fork.
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent.
                sys.exit(0)
        except OSError as e:
            m = "Fork #2 failed"
            self.log.error(m, objet=Deamon_name)
            sys.exit(1)
        m = "The daemon process is going to background."
        self.log.log(m, objet=Deamon_name)
        # Redirect standard file descriptors.
        sys.stdout.flush()
        sys.stderr.flush()

    def _getProces(self, processName=None):
        if processName is None:
            processName = self.processName
        procs = []
        tbavoid = ['sleep', 'wakeup']
        for p in psutil.process_iter():
            if (self.processName in [part.split('/')[-1] for part in p.cmdline()]):
                # Skip  the current process
                process_tbavoided = False
                for avoid_string in tbavoid:
                    if (avoid_string in [part.split('/')[-1] for part in p.cmdline()]):
                        process_tbavoided = True
                        break
                if (process_tbavoided):
                    continue
                if p.pid != os.getpid():
                    procs.append(p)
                    # children_procs = p.children(recursive=True)
                    # for f in children_procs:
                    #     procs.insert(0, f)
                    continue
        return procs

    def script_from_cmdline(self, cmdline):
        if (len(cmdline) > 1):
            return os.path.basename(cmdline[1])
        else:
            return ''

    def speed_from_cmdline(self, cmdline):
        if (len(cmdline) > 2):
            if (os.path.basename(cmdline[2]) == 'fast'):
                return "fast"
            elif (os.path.basename(cmdline[2]) == 'slow'):
                return "slow"
            else:
                self.log.warning("Can not understand the script option \"%s\" (default is fast)" % os.path.basename(cmdline[2]), objet=Deamon_name)
                return "fast"
        else:
            return None

    def status_translation(self, status):
        if (status == 'sleeping') or (status == 'running') or (status == 'disk-sleep'):  # running can be see as sleeping
            return 'running'
        elif (status == 'stopped'):  # sleeping is see as stopped
            return 'sleeping'
        else:
            return 'stopped'

    def get_script_liste(self):

        # ZENITH_TRANSIT_CHECK_CLIM_20191116_215936.script-postobs-rsync
        # GJ_1151_TRACKING_20220531_150036.script-postobs-rsync
        # SUN_TRACKING_20220531_091036.script-postobs-rsync
        # GJ_486_TRACKING_20220607_180036.script-postobs-rsync
        # GJ_486_TRACKING_20220607_180036.script-postobs-rsyncfast

        # B2217+47_D20211205T1704_59553_251751_0075_BEAM1_script.sh
        # JUPITER_1242.undysputedbk1.2021-11-03T15:49:10.000_script.sh
        # J0139+3310_D20220607T0901_59737_252135_0071_BEAM1_script.sh
        # J0139+3310_D20220607T0901_59737_252135_0071_BEAM1_script_fast.sh

        # catch the liste of script in script_dir and sort it by date (FIFO)
        liste_in_script_dir = sorted([str(i) for i in Path(self.script_dir).iterdir()], key=os.path.getmtime)
        file_liste = []
        for file_or_dir in liste_in_script_dir:
            if(Path(file_or_dir).is_file()):
                file_liste.append(str(file_or_dir))
        return file_liste

    def get_script_status(self, script_liste):
        try:
            self.process_dico = {"%s_pid%s" % (str(p.name()), str(p.pid)): {'pid': p.pid,
                                                                            'status': p.status(),
                                                                            'cmdline': p.cmdline(),
                                                                            'obj': p} for p in psutil.process_iter()}
        except psutil.NoSuchProcess:
            try:
                self.process_dico = {"%s_pid%s" % (str(p.name()), str(p.pid)): {'pid': p.pid,
                                                                                'status': p.status(),
                                                                                'cmdline': p.cmdline(),
                                                                                'obj': p} for p in psutil.process_iter()}
            except psutil.NoSuchProcess:
                self.log.warning('Something went wrong with psutil, will pass this loop', objet=Deamon_name)
                return
        # current_process = list(key.split('_pid')[0] for key in self.process_dico.keys())
        current_process_info = list(self.process_dico.values())
        current_scripts = list((self.script_from_cmdline(dico['cmdline'])) for dico in current_process_info)
        # current_speed = list((self.speed_from_cmdline(dico['cmdline'])) for dico in current_process_info)

        self.nFAST = 0
        self.nSLOW = 0
        self.target_scripts = {}
        for process in script_liste:
            self.target_scripts[process] = {'status': None, 'pid': None, 'speed': None, 'obj': None}

        for process, process_info in self.target_scripts.items():
            if (os.path.basename(process) in current_scripts):
                index = np.where(np.asarray(current_scripts) == os.path.basename(process))[0]
                if (len(index) > 1):
                    status = []
                    pid = []
                    speed = []
                    obj = []
                    for i in index:
                        status.append(self.status_translation(current_process_info[i]['status']))
                        pid.append(current_process_info[i]['pid'])
                        speed.append(self.speed_from_cmdline(current_process_info[i]['cmdline']))
                        obj.append(current_process_info[i]['obj'])
                        children_procs = current_process_info[i]['obj'].children(recursive=True)
                        for f in children_procs:
                            obj.insert(0, f)
                        self.log.warning("duplicate process %s is now in \"%s\" on PID %s" % (process, status, str(pid)), objet=Deamon_name)
                    if 'running' in status:
                        status = 'running'
                    else:
                        status = 'sleeping'
                    # maybe need some clever way to find the corresponding process
                    pid = pid[0]
                    speed = speed[0]
                    obj = obj
                else:
                    index = index[0]
                    status = self.status_translation(current_process_info[index]['status'])
                    pid = current_process_info[index]['pid']
                    speed = self.speed_from_cmdline(current_process_info[index]['cmdline'])
                    obj = [current_process_info[index]['obj']]
                    try:
                        children_procs = current_process_info[index]['obj'].children(recursive=True)
                    except psutil.NoSuchProcess:
                        m = "Fail Sending SIGHUP signal into the process %s with PID." % (self.processName, str(current_process_info[index]['obj'].pid))
                        self.log.warning(m, objet=Deamon_name)
                    for f in children_procs:
                        obj.insert(0, f)
                    # self.log.log("process %s is now in \"%s\" on PID %s" % (process, status, str(pid)), objet=Deamon_name)
            else:
                status = 'stopped'
                pid = None
                speed = None
                obj = None
                # self.log.log("process %s is \"stopped\"" % (process), objet=Deamon_name)
            self.target_scripts[process]['status'] = status
            self.target_scripts[process]['pid'] = pid
            self.target_scripts[process]['speed'] = speed
            self.target_scripts[process]['obj'] = obj
            if (speed == 'fast'):
                self.nFAST += 1
            elif(speed == 'slow'):
                self.nSLOW += 1

    def launch_script(self, script, mode=""):
        try:
            log_script = Log_class(logname=os.path.basename(script), logdir=self.script_logdir)
            log_script.check_file_validity(script)
            cmd = "bash %s %s &" % (script, mode)
            script_out = log_script.dir + log_script.logname + '.log'
            script_err = log_script.dir + log_script.logname + '.error'
            with open(script_out, "a") as out, open(script_err, "a") as err:
                proc = subprocess.Popen(cmd.split(' '), start_new_session=True, stdout=out, stderr=err)
                try:
                    # self.log.log('Start Command: [%s]' % (cmd), objet='rsync')
                    stdout_data, stderr_data = proc.communicate(timeout=self.script_timeout)
                    if (proc.returncode == 0):
                        proc_success = True
                    elif (proc.returncode == 1):
                        proc_success = True
                    elif (proc.returncode != 0):
                        proc_success = False
                        log_script.error(
                            "%r failed, status code %s stdout %r stderr %r" % (
                                cmd, proc.returncode,
                                stdout_data, stderr_data), objet='launch_script')
                    log_script.log('script success: [%s]' % (cmd), objet='launch_script')
                except subprocess.TimeoutExpired as e:
                    proc_success = False
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    log_script.error('script TimeoutExpired: [%s]' % e, objet='launch_script')
                except subprocess.SubprocessError as e:
                    proc_success = False
                    # os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    log_script.error('script SubprocessError: [%s]' % e, objet='launch_script')
            self.log.log("%s STOP %s" % (script, mode.upper()), objet=Deamon_name)

            # delete the .error file if empty
            if (proc_success):
                try:
                    os.remove(script_err)
                except:
                    pass
                log_script.movefile(script, self.script_dir_finish)
                log_script.movefile(script_out, self.script_logdir)
            else:
                self.log.sendMail(self.mail_error, Deamon_name + " error %s" % os.path.basename(script),
                                  "An error ocure durring the execution of %s " % os.path.basename(script),
                                  [script, script_out, script_err])
                log_script.movefile(script, self.script_dir_error)
                log_script.movefile(script_out, self.script_dir_error)
                log_script.movefile(script_err, self.script_dir_error)
        except:
            log_script.traceback_tomail(self.mail_error, objet=Deamon_name)

    def start(self):
        """
        Start daemon.
        """
        # Handle signals
        signal.signal(signal.SIGINT, self._sigterm_handler)  # interuption ctrl + c
        signal.signal(signal.SIGTERM, self._sigterm_handler)  # terminer
        signal.signal(signal.SIGHUP, self._reload_handler)  # initialiser (decoupl du terminal)
        # Check if the daemon is already running.
        procs = self._getProces()
        if procs:
            for p in procs:
                m = "Find a previous daemon processes %s with PIDs %s. Is not already the daemon running?" % (self.processName, str(p.pid))
                self.log.warning(m, objet=Deamon_name)
            sys.exit(1)
        else:
            m = "Start the daemon version %s" % (str(self.ver))
            self.log.log(m, objet=Deamon_name)
        # Daemonize the main process
        self._makeDaemon()
        # Start a infinitive loop that periodically runs run() method
        self._infiniteLoop()

    def version(self):
        m = "The daemon version %s" % str(self.ver)
        self.log.log(m, objet=Deamon_name)

    def status(self):
        """
        Get status of the daemon.
        """
        procs = self._getProces()
        if procs:
            for p in procs:
                try:
                    m = "The daemon %s is %s with PID %s." % (self.processName, str(p.status()), str(p.pid))
                    self.log.log(m, objet=Deamon_name)
                except psutil.NoSuchProcess:
                    m = "The daemon %s is stopped" % (self.processName)
                    self.log.log(m, objet=Deamon_name)
        else:
            m = "The daemon is not running!"
            self.log.log(m, objet=Deamon_name)

        script_liste = self.get_script_liste()
        self.get_script_status(script_liste)

        # sys.stdin = open(self.log.dir + self.log.logname + '.log', 'r')
        for process, script_info in self.target_scripts.items():
            self.log.log("Script %s status is %s" % (process, script_info['status']), objet=Deamon_name)
        # sys.stdin.flush()
        # sys.stdin = open(os.devnull, 'w')

    def reload(self):
        """
        Reload the daemon.
        """
        procs = self._getProces()
        if procs:
            for p in procs:
                try:
                    os.kill(p.pid, signal.SIGHUP)
                    if(DEBUG):
                        m = "Send SIGHUP signal into the daemon process %s with PID." % (self.processName, str(p.pid))
                        self.log.log(m, objet=Deamon_name)
                except psutil.NoSuchProcess:
                    m = "Fail Sending SIGHUP signal into the process %s with PID." % (self.processName, str(p.pid))
                    self.log.warning(m, objet=Deamon_name)
        else:
            m = "The daemon is not running!"
            self.log.log(m, objet=Deamon_name)

    def sleep(self, sleep_time=None):
        """
        Sleeping running scripts and the daemon.
        """
        self.FAST = False
        self.SLOW = False
        # procs = self._getProces()

        # sleeping running scripts
        script_liste = self.get_script_liste()
        self.get_script_status(script_liste)
        for script, script_info in self.target_scripts.items():
            # print("Script %s status is %s" % (script, script_info['status']))
            if (script_info['status'] == "running"):
                self.log.log("%s SLEEP" % script, objet=Deamon_name)
                for p in script_info['obj']:
                    try:
                        os.kill(p.pid, signal.SIGSTOP)
                        if(DEBUG):
                            m = "Send SIGSTOP signal into the script %s from %s with PID %s." % (script, str(p.name()), str(p.pid))
                            self.log.log(m, objet=Deamon_name)
                    except psutil.NoSuchProcess:
                        m = "Fail Sending SIGSTOP signal into the script %s from %s with PID %s: NoSuchProcess." % (script, str(p.name()), str(p.pid))
                        self.log.warning(m, objet=Deamon_name)
                if sleep_time is not None:
                    if (int(sleep_time) >= 0):
                        try:
                            pid = os.fork()
                            if pid > 0:
                                # Exit from second parent.
                                sys.exit(0)
                        except OSError as e:
                            m = "sleep Fork failed"
                            self.log.error(m, objet=Deamon_name)
                            sys.exit(1)
                        m = "The daemon child processes is asleep for %s sec." % str(sleep_time)
                        self.log.log(m, objet=Deamon_name)
                        time.sleep(int(sleep_time))
                        self.log.log("%s WAKEUP" % script, objet=Deamon_name)
                        for p in script_info['obj']:
                            try:
                                if (p.status() == "stopped"):
                                    try:
                                        os.kill(p.pid, signal.SIGCONT)
                                        m = "Send SIGCONT signal into the script %s from %s with PID %s." % (script, str(p.name()), str(p.pid))
                                        self.log.log(m, objet=Deamon_name)
                                    except psutil.NoSuchProcess:
                                        m = "Fail Sending SIGCONT signal into the script %s from %s with PID %s: NoSuchProcess." % (
                                            script, str(p.name()), str(p.pid))
                                        self.log.warning(m, objet=Deamon_name)
                                else:
                                    m = "The script %s with PID %s is already awake." % (script, str(p.pid))
                            except psutil.NoSuchProcess:
                                m = "The script %s with PID %s is already vanished." % (script, str(p.pid))
                            self.log.log(m, objet=Deamon_name)
                        sys.exit(0)

        # sleeping the daemon
        procs = self._getProces()
        if procs:
            for p in procs:
                try:
                    os.kill(p.pid, signal.SIGSTOP)
                    if(DEBUG):
                        m = "Send SIGSTOP signal into the daemon process %s/%s/%s with PID %s." % (
                            str(p.name()), str(p.cmdline()), self.processName, str(p.pid))
                        self.log.log(m, objet=Deamon_name)
                except psutil.NoSuchProcess:
                    m = "Fail Sending SIGSTOP signal into the daemon process %s with PID %s: NoSuchProcess." % (self.processName, str(p.pid))
                    self.log.warning(m, objet=Deamon_name)

            if sleep_time is not None:
                if (int(sleep_time) > 0):
                    try:
                        pid = os.fork()
                        if pid > 0:
                            # Exit from second parent.
                            sys.exit(0)
                    except OSError as e:
                        m = "sleep Fork failed"
                        self.log.error(m, objet=Deamon_name)
                        sys.exit(1)
                    m = "The daemon himself is asleep for %s sec." % str(sleep_time)
                    self.log.log(m, objet=Deamon_name)
                    time.sleep(int(sleep_time))
                    for p in procs:
                        try:
                            if (p.status() == "stopped"):
                                os.kill(p.pid, signal.SIGCONT)  # todo verif status "stopped"
                                m = "Send SIGCONT signal into the daemon process %s with PID %s." % (self.processName, str(p.pid))
                                self.log.log(m, objet=Deamon_name)
                            else:
                                m = "The daemon process %s with PID %s is already awake." % (self.processName, str(p.pid))
                                self.log.log(m, objet=Deamon_name)
                        except psutil.NoSuchProcess:
                            m = "Fail Sending SIGCONT signal into the daemon process %s with PID %s: NoSuchProcess." % (self.processName, str(p.pid))
                            self.log.warning(m, objet=Deamon_name)
                    sys.exit(0)
        else:
            m = "The daemon is not running!"
            self.log.warning(m, objet=Deamon_name)

    def stop(self):
        """
        Stop the daemon.
        """
        self.FAST = False
        self.SLOW = False
        self._canDaemonRun = False

        def on_terminate(process):
            m = "The daemon process with PID %s has ended correctly." % (str(process.pid))
            self.log.log(m, objet=Deamon_name)
        # waiting scripts to terminate

        # stop the daemon

        # for thread_i in self.all_thread:
        #     thread_i.join()

        procs = self._getProces()
        self._makeDaemon()
        if procs:
            for p in procs:
                m = "Waiting %d sec daemon process %s with PID %s to terminate" % (int(self.waitToHardKill), self.processName, str(p.pid))
                self.log.log(m, objet=Deamon_name)
                p.terminate()
            gone, alive = psutil.wait_procs(procs, timeout=self.waitToHardKill, callback=on_terminate)
            for p in alive:
                m = "The daemon process %s with PID %s was killed with SIGTERM!" % (self.processName, str(p.pid))
                self.log.log(m, objet=Deamon_name)
                p.kill()
            m = "The daemon process %s is stopped" % (self.processName)
            self.log.log(m, objet=Deamon_name)
        else:
            m = "Cannot find some daemon process, I will do nothing."
            self.log.warning(m, objet=Deamon_name)

    def kill(self):
        """
        Kill the daemon and current scripts.
        """
        self._canDaemonRun = False
        self.FAST = False
        self.SLOW = False

        # wakeup sleeping scripts
        script_liste = self.get_script_liste()
        self.get_script_status(script_liste)
        for script, script_info in self.target_scripts.items():
            if(script_info['status'] == "sleeping") or (script_info['status'] == "running"):
                self.log.log("%s KILL" % script, objet=Deamon_name)
                for p in script_info['obj']:
                    try:
                        os.kill(p.pid, signal.SIGKILL)
                        if(DEBUG):
                            m = "Send SIGKILL signal into the script %s from %s with PID %s." % (script, str(p.name()), str(p.pid))
                            self.log.log(m, objet=Deamon_name)
                    except psutil.NoSuchProcess:
                        m = "Fail Sending SIGKILL signal into the script %s from %s with PID %s: NoSuchProcess." % (script, str(p.name()), str(p.pid))
                        self.log.warning(m, objet=Deamon_name)
        self.waitToHardKill = 10
        self.stop()

    def restart(self):
        """
        Restart the daemon.
        """
        self.stop()
        if self.restartPause:
            time.sleep(self.restartPause)
        self.__init__()
        self.start()

    def wakeup(self):
        """
        Wakeup the sleeping the daemon.
        """
        self.FAST = True
        self.SLOW = True

        # wakeup sleeping scripts
        script_liste = self.get_script_liste()
        self.get_script_status(script_liste)
        for script, script_info in self.target_scripts.items():
            if(script_info['status'] == "sleeping"):
                self.log.log("%s WAKEUP" % script, objet=Deamon_name)
                for p in script_info['obj']:
                    try:
                        os.kill(p.pid, signal.SIGCONT)
                        m = "Send SIGCONT signal into the script %s from %s with PID %s." % (script, str(p.name()), str(p.pid))
                        self.log.log(m, objet=Deamon_name)
                    except psutil.NoSuchProcess:
                        m = "Fail Sending SIGCONT signal into the script %s from %s with PID %s: NoSuchProcess." % (script, str(p.name()), str(p.pid))
                        self.log.warning(m, objet=Deamon_name)

        # wakeup the daemon
        procs = self._getProces()
        if procs:
            for p in procs:
                try:
                    os.kill(p.pid, signal.SIGCONT)  # todo verif status "stopped"
                    m = "Send SIGCONT signal into the daemon process %s from %s  with PID %s." % (str(p.name()), self.processName, str(p.pid))
                    self.log.log(m, objet=Deamon_name)
                except psutil.NoSuchProcess:
                    m = "Fail Sending SIGCONT signal into the daemon process %s from %s with PID %s: NoSuchProcess." % (
                        str(p.name()), self.processName, str(p.pid))
                    self.log.warning(m, objet=Deamon_name)
        else:
            m = "The daemon is not launched!"
            self.log.warning(m, objet=Deamon_name)

    def slow(self, sleep_time=None):
        """
        sleep the fast daemon.
        """
        self.FAST = False
        self.SLOW = True

        script_liste = self.get_script_liste()
        self.get_script_status(script_liste)

        # procs = self._getProces()

        for process, script_info in self.target_scripts.items():
            process = os.path.basename(process)
            # script_info['status']  # 'running' 'sleeping' 'stopped'
            # script_info['pid']
            # script_info['speed']  # 'fast' 'slow' None
            # script_info['obj']  # liste of psutil object for master and childrens

            if (script_info['status'] == 'running') and (script_info['speed'] == 'fast'):
                self.log.log("%s SLEEP" % process, objet=Deamon_name)
                for p in script_info['obj']:
                    try:
                        os.kill(p.pid, signal.SIGSTOP)
                        if(DEBUG):
                            m = "Send SIGSTOP signal into the process %s from %s with PID %s." % (process, str(p.name()), str(p.pid))
                            self.log.log(m, objet=Deamon_name)
                    except psutil.NoSuchProcess:
                        m = "Fail Sending SIGSTOP signal into the process %s from %s with PID %s: NoSuchProcess." % (process, str(p.name()), str(p.pid))
                        self.log.warning(m, objet=Deamon_name)
                if sleep_time is not None:
                    if (int(sleep_time) >= 0):
                        try:
                            pid = os.fork()
                            if pid > 0:
                                # Exit from second parent.
                                sys.exit(0)
                        except OSError as e:
                            m = "sleep Fork failed"
                            self.log.error(m, objet=Deamon_name)
                            sys.exit(1)
                        m = "The daemon sleeping process is going to background for %s sec." % str(sleep_time)
                        self.log.log(m, objet=Deamon_name)
                        time.sleep(int(sleep_time))
                        self.log.log("%s WAKEUP" % process, objet=Deamon_name)
                        for p in script_info['obj']:
                            if (p.status() == "stopped"):
                                try:
                                    os.kill(p.pid, signal.SIGCONT)  # todo verif status "stopped"
                                    if(DEBUG):
                                        m = "Send SIGCONT signal into the process %s from %s with PID %s." % (process, str(p.name()), str(p.pid))
                                        self.log.log(m, objet=Deamon_name)
                                except psutil.NoSuchProcess:
                                    m = "Fail Sending SIGCONT signal into the process %s from %s with PID %s: NoSuchProcess." % (
                                        process, str(p.name()), str(p.pid))
                                    self.log.warning(m, objet=Deamon_name)
                            else:
                                m = "The process %s with PID %s from %s is already awake." % (process, str(p.name()), str(p.pid))
                            self.log.log(m, objet=Deamon_name)
                        sys.exit(0)
            else:
                m = "The script %s is not running" % process
                self.log.log(m, objet=Deamon_name)

    def _infiniteLoop(self):
        self.i = 0
        try:
            if self.pauseRunLoop:
                self.t0 = time.time()
                self.t0 = self.t0 - (self.t0 % self.pauseRunLoop)
                while self._canDaemonRun:
                    self.i += 1
                    delta = (self.t0 + self.pauseRunLoop * float(self.i)) - time.time()
                    if delta > 0:
                        time.sleep(delta)
                    self.run()
            else:
                while self._canDaemonRun:
                    self.run()
        except Exception:
            self.log.traceback_tomail(self.mail_error, objet=Deamon_name)
            sys.exit(1)
    # this method you have to override

    def run(self):
        pass
# ----------------------------------------------------------------------------------------------------
# an example of a custom run method where you can set your useful python code


class UploadScript(Daemon):
    def __init__(self):
        super().__init__()
        self.host = socket.gethostname()
        self.last_update_time = time.time()
        self.last_script_liste = []
        self.all_thread = []

    def run(self):
        # for p in psutil.process_iter():
        #    print(p)
        #    print(p.cmdline())
        # print(self.processName)
        if (self.isReloadSignal):
            self.log.log("Receved reload signal", objet='UploadDeamon')
            self.isReloadSignal = False
            self.__init__()

        self.new_script_liste = self.get_script_liste()
        self.get_script_status(self.new_script_liste)
        # print(self.target_scripts)

        # self._getProcess(self, processName=None)

        self.diff_script_liste = [item for item in self.new_script_liste if item not in self.last_script_liste]
        for ifile in self.diff_script_liste:
            self.log.log("New script detected: %s" % ifile, objet=Deamon_name)
        self.last_script_liste = self.new_script_liste

        for process, script_info in self.target_scripts.items():
            # print(script_info['status'], self.nFAST, self.nSLOW)
            # script_info['status']  # 'running' 'sleeping' 'stopped'
            # script_info['pid']
            # script_info['speed']  # 'fast' 'slow' None
            # script_info['obj']  # liste of psutil object for master and childrens

            if(script_info['status'] == 'stopped') and (script_info['pid'] is None):
                if (self.nFAST < self.parallel_fast):
                    new_thread = Thread(self.launch_script, args=(process,), kwargs={'mode': 'fast'}, name=process)
                    new_thread.start()
                    self.all_thread.append(new_thread)
                    self.nFAST += 1
                    self.log.log("%s START FAST" % process, objet=Deamon_name)
                elif (self.nSLOW < self.parallel_slow):
                    new_thread = Thread(self.launch_script, args=(process,), kwargs={'mode': 'slow'}, name=process)
                    new_thread.start()
                    self.all_thread.append(new_thread)
                    self.nSLOW += 1
                    self.log.log("%s START SLOW" % process, objet=Deamon_name)

    def script_from_cmdline(self, cmdline):
        if (len(cmdline) > 1):
            return os.path.basename(cmdline[1])
        else:
            return ''


class CONFIG_READER():
    def __init__(self, config_file, log_obj=None):
        if log_obj is None:
            self.log = Log_class()
        else:
            self.log = log_obj
        self.log.check_file_validity(config_file)
        self.log.log('Read configuration from :%s' % (config_file), objet='CONFIG_READER')
        self.config_file = config_file
        self.dico = {}
        config_file_obj = open(self.config_file, "r")
        for line in config_file_obj:
            if not re.search('^;', line):
                if re.search('^\[', line):
                    last_sector = line.strip('\n').strip(' ').strip('[').rstrip(']')
                    self.dico[last_sector] = {}
                elif re.search("=", line):
                    line = line.strip('\n').strip(' ').split('=')
                    obj = line[0]
                    result = line[1]
                    self.dico[last_sector][obj] = result
                else:
                    self.log.error("do not understand :\"" + line + '\"', objet='CONFIG_READER')
        config_file_obj.close()

    def get_config(self, sector, obj):  # dico['MR']['LOG_FIRE']
        '''  get an object from CONFIG_FILE
        Arguments:
            object = PREFIX PREFIX_DATA LOG_FIRE IP PORT
            sector = PATH LOG BACKEND MR POINTAGE_AUTO_SERVICE
                     BACKEND_AUTO_SERVICE POINTAGE_LISTEN_SERVICE'''

        try:
            int(self.dico[sector][obj])
            return int(self.dico[sector][obj])
        except ValueError:
            pass

        try:
            float(self.dico[sector][obj])
            return float(self.dico[sector][obj])
        except ValueError:
            pass

        if (self.dico[sector][obj] == 'True'):
            return True
        elif (self.dico[sector][obj] == 'False'):
            return False
        if (self.dico[sector][obj] == 'None'):
            return None
        return str(self.dico[sector][obj])


class Thread (threading.Thread):
    def __init__(self, func, args=((),), kwargs={}, name=None):
        threading.Thread.__init__(self)  # init mother class
        self.func2thread = func
        self.args = args
        self.kwargs = kwargs
        self.name = name

    def run(self):
        self.func2thread(*self.args, **self.kwargs)


# ----------------------------------------------------------------------------------------------------
# the main section
if __name__ == "__main__":
    daemon = UploadScript()
    usageMessage = "Usage: %s (start|stop|kill|sleep N|wakeup|slow N|restart|status|reload|version)" % sys.argv[0]
    choice = sys.argv[1]
    if (len(sys.argv) == 2):
        if choice == "start":
            daemon.start()
        elif choice == "stop":
            daemon.stop()
        elif choice == "kill":
            daemon.kill()
        elif choice == "sleep":
            daemon.sleep()
        elif choice == "wakeup":
            daemon.wakeup()
        elif choice == "slow":
            daemon.slow()
        elif choice == "status":
            daemon.status()
        elif choice == "restart":
            daemon.restart()
        elif choice == "reload":
            daemon.reload()
        elif choice == "version":
            daemon.version()
        else:
            print("Unknown command \"%s\"." % choice)
            print(usageMessage)
            sys.exit(1)
    elif (len(sys.argv) == 3):
        if choice == "sleep":
            try:
                daemon.sleep(sys.argv[2])
            except IndexError:
                daemon.sleep()
        if choice == "slow":
            try:
                daemon.slow(sys.argv[2])
            except IndexError:
                daemon.slow()
        else:
            print("Unknown command \"%s\" + \"%s\"." % (choice, sys.argv[2]))
            print(usageMessage)
            sys.exit(1)
    else:
        print("Too many options to be valid.")
        print(usageMessage)
        sys.exit(1)

    sys.exit(0)
