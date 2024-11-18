#!/usr/bin/python2
###!/usr/libexec/platform-python
# version 0.1.2
import argparse
import sys
import os
import logging
from logging.handlers import SysLogHandler
import bz2
import pwd
import time
if sys.version_info[0] == 2:
    import ConfigParser as configparser
else:
    import configparser
    import resource

logger = logging.getLogger()

#add ArgumentParser error logging
class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        logging.getLogger().info(message)
        super(ArgumentParser, self).error(message)

class ScriptConfig:
    def __init__(self, cfg = None, base_cfg_filename=''):
        self.logger = logging.getLogger()
        self.section = 'DEFAULT'
        self.config = configparser.RawConfigParser(defaults=cfg)
        self.config.optionxform = str
        cfg_files = self.list_config_files(base_cfg_filename)
        self.config.read(cfg_files)

    def get_username_by_uid(self, uid=None):
        username = ""
        if uid is not None:
            try:
                user_pwd = pwd.getpwuid(uid)
                username = user_pwd.pw_name
            except KeyError:
                self.logger.warning('User with uid %d not found.', uid)
        return username

    def set_cfg_section_name(self, uid=None):
        proc_owner_username = self.get_username_by_uid(uid)
        if proc_owner_username:
            secname = 'user:' + proc_owner_username
            if self.config.has_section(secname):
                self.section = secname

    @staticmethod
    def list_config_files(base_name):
        cfgfilelist = [base_name]
        dropin = base_name + '.d'
        if os.path.isdir(dropin):
            for confile in os.listdir(dropin):
                full_f = os.path.join(dropin, confile)
                if full_f.endswith('.conf') and os.path.isfile(full_f):
                    cfgfilelist.append(os.path.join(dropin, confile))
        cfgfilelist.sort()
        return cfgfilelist

    def get(self, option):
        return self.config.get(self.section, option)

    def getint(self, option):
        return self.config.getint(self.section, option)

    def getboolean(self, option):
        return self.config.getboolean(self.section, option)

_SCRIPT_CONFIG = None
def get_config(base_cfg_filename='/etc/ccdc.conf'):
    global _SCRIPT_CONFIG
    if _SCRIPT_CONFIG is None:
        cfg = {
            'save_core_dir': '/var/crash/coredump',
            'max_file_size_bytes': -1,
            'min_fs_free_perc': 15,
            'min_fs_free_bytes': -1,
            'compression': 2,
            'ignore_soft_limit': 'False'
            }
        _SCRIPT_CONFIG = ScriptConfig(cfg, base_cfg_filename)
    return _SCRIPT_CONFIG

def check_dir(dirpname):
    ret_full_size = -1
    ret_avail_size = -1
    if os.path.exists(dirpname):
        path = os.path.realpath(dirpname)
        if os.path.isdir(path):
            ret_full_size = os.statvfs(path).f_blocks * os.statvfs(path).f_bsize
            ret_avail_size = os.statvfs(path).f_bfree * os.statvfs(path).f_bsize
        else:
            logger.error("Path " + path + " does not look like directory.")
    else:
        logger.error("Path " + dirpname + " does not exist.")
    return ret_full_size, ret_avail_size

def get_max_allowed_zip_size():
    max_allowed_zip_size = 0
    cfg = get_config()
    save_core_dir = cfg.get('save_core_dir')
    full_size, free_size = check_dir(save_core_dir)
    if full_size > 0:
        spare_free_size = max(cfg.getint('min_fs_free_bytes'),
                              int(full_size * cfg.getint('min_fs_free_perc') / 100))
        max_allowed_zip_size = free_size - spare_free_size
        if cfg.getint('max_file_size_bytes') > 0:
            max_allowed_zip_size = min(cfg.getint('max_file_size_bytes'), max_allowed_zip_size)
    return max_allowed_zip_size

def is_chown_allowed(pid=None):
    proc_ug_ids = get_proc_id_info(pid)
    if proc_ug_ids['uid']['real'] == proc_ug_ids['uid']['effective'] \
    and proc_ug_ids['uid']['effective'] != -1 \
    and proc_ug_ids['gid']['real'] == proc_ug_ids['gid']['effective'] \
    and proc_ug_ids['gid']['effective'] != -1:
        return True
    return False

def get_proc_id_info(pid=None):
    types = ['real', 'effective', 'saved', 'filesystem']
    proc_data = {}
    if pid:
        status_file = os.path.join('/proc', str(pid), 'status')
        if os.path.isfile(status_file):
            with open(status_file, 'r') as statusfd:
                for line in statusfd:
                    if line.startswith('Uid:') or line.startswith('Gid:'):
                        words = line.split()
                        if len(words) == 5:
                            proc_data[words[0][:3].lower()] = dict(zip(types, words[1:]))
                        if len(proc_data) == 2:
                            break

    if 'gid' in proc_data:
        return proc_data

    return {k: {t: -1 for t in types} for k in ['uid', 'gid']}

def do_clean():
    logger.warning("Clean is not implemented yet")

def main(args):
    cfg = get_config()
    if args.clean:
        do_clean()
    else:
        chown_ok = is_chown_allowed(args.dumped_pid)
        #Use custom config in case of non-suid/sgid process
        if chown_ok:
            cfg.set_cfg_section_name(args.dumped_uid)
        logger.warning("Process crash has been caught: PID=" + str(args.dumped_pid) +
                       " RUID=" + str(args.dumped_uid) +
                       " EXE=" + args.dumped_comm +
                       " SIG=" + str(args.signal_num))
        do_coredump(args, chown_ok)

def get_core_hard_limit(pid):
    hard = 0
    if sys.version_info[0] > 2:
        _, hard = resource.prlimit(pid, resource.RLIMIT_CORE)
    else:
        limits_filepath = os.path.join('/proc', str(pid),'limits')
        if os.path.exists(limits_filepath):
            with open(limits_filepath, 'r') as limitsfd:
                for line in limitsfd:
                    if line.startswith('Max core file size'):
                        words = line.split()
                        if len(words) > 4:
                            if words[5] == 'unlimited':
                                hard = -1
                            else:
                                hard = int(words[5])
                            break
    return hard

def get_raw_core_size_limit(dumped_pid, core_limit, ignore_soft_limit):
    if ignore_soft_limit:
        logger.warning("Core soft limit of the process will be ignored")
        return get_core_hard_limit(dumped_pid)
    return core_limit

def do_coredump(args, chown_ok):
    cfg = get_config()
    max_raw_size = get_raw_core_size_limit(
        args.dumped_pid,
        args.core_limit,
        cfg.getboolean('ignore_soft_limit'))
    if max_raw_size == 0:
        logger.warning("PID " + str(args.dumped_pid) +
                     " not dumped because of core file size limit")
    else:
        save_core_dir = cfg.get('save_core_dir')
        max_allowed_zip_size = get_max_allowed_zip_size()
        if max_allowed_zip_size > 0:

            corename = '.'.join([
                'core',
                args.dumped_comm,
                str(args.dumped_uid),
                str(args.dumped_pid),
                str(args.unix_time),
                'bz2'
                ])

            coredumpfilepath = os.path.join(save_core_dir, corename)
            if os.path.exists(coredumpfilepath):
                logger.error("File " + coredumpfilepath + " already exists")
            else:

                inputstream = sys.stdin
                if sys.version_info[0] > 2:
                    inputstream = sys.stdin.buffer

                if do_writecore(
                    inputstream,
                    coredumpfilepath,
                    max_allowed_zip_size,
                    cfg.getint('compression'),
                    max_raw_size
                    ):
                    logger.warning("Core of PID " + str(args.dumped_pid) +
                                   " has been collected successfully")
                    if chown_ok:
                        os.chown(coredumpfilepath, args.dumped_uid, -1)
                else:
                    logger.warning("Collecting core of PID " + str(args.dumped_pid) +
                                   " has been failed")
                    if os.path.exists(coredumpfilepath):
                        logger.warning("Removing partially collected file " + coredumpfilepath)
                        os.remove(coredumpfilepath)
        else:
            logger.error("There is not enough free space in the " + save_core_dir +
                         " directory to start the saving process.")

def do_writecore(inputstream, targetfile_pathname, max_zip_size, compression=2, max_raw_size=-1):
    raw_oversize = False
    zip_oversize = False
    write_error = False

    def write_data(fd, data):
        try:
            fd.write(data)
        except:
            logger.error("Error writing data to " + targetfile_pathname, exc_info=True)
            return False
        return True

    zipfile = None
    oldumask = os.umask(0o0077)
    try:
        zipfile = open(targetfile_pathname, 'wb')
    except OSError:
        logger.error("Error opening " + targetfile_pathname, exc_info=True)

    if zipfile is not None:
        core_size_raw = 0
        core_size_zip = 0
        buffsize = 1024 * 1024
        compressor = bz2.BZ2Compressor(compression)
        with zipfile:
            while True:
                data = inputstream.read(buffsize)
                #no more data in input stream
                if not data:
                    break
                core_size_raw += len(data)
                #too much data in input stream
                if max_raw_size != -1 and core_size_raw > max_raw_size:
                    logger.warning(targetfile_pathname +
                                   " truncated due to process limits")
                    raw_oversize = True
                    break
                zip_data = compressor.compress(data)
                #error while writing data
                if not write_data(zipfile, zip_data):
                    write_error = True
                    break
                core_size_zip += len(zip_data)
                #compressed file is too big
                if max_zip_size != -1 and core_size_zip > max_zip_size:
                    logger.warning(targetfile_pathname +
                        " file truncated due to high filesystem usage or excessive file size")
                    zip_oversize = True
                    break
            if not write_error:
                write_error = not write_data(zipfile, compressor.flush())
    os.umask(oldumask)

    return not (raw_oversize or zip_oversize or write_error)

if __name__ == '__main__':

    #configure root logger
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(filename)s %(levelname)s: %(message)s")
    for lhdr in (logging.StreamHandler(sys.stderr),
                 SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_DAEMON)):
        lhdr.setFormatter(formatter)
        logger.addHandler(lhdr)

    parser = ArgumentParser(description='Customizable core dump collector',
                            conflict_handler='resolve')
    parser.add_argument('-P', '--dumped-pid',  dest='dumped_pid', type=int,
                        help='PID of dumped process, as seen in the initial PID namespace')
    parser.add_argument('-u', '--dumped-uid',  dest='dumped_uid', type=int,
                        help='Numeric real UID of dumped process')
    parser.add_argument('-g', '--dumped-gid',  dest='dumped_gid', type=int, default=-1,
                        help='Numeric real GID of dumped process')
    parser.add_argument('-s', '--signal-num',  dest='signal_num', type=int,
                        help='Number of signal causing dump')
    parser.add_argument('-t', '--unix-time',   dest='unix_time',  type=int,
                        default=int(time.time()),
                        help='Time of dump, expressed as seconds since the Epoch')
    parser.add_argument('-c', '--core-limit',  dest='core_limit', type=int, default=0,
                        help='Core file size soft resource limit of crashing process')
    parser.add_argument('-h', '--host-name',   dest='host_name',  type=str, default='',
                        help='Hostname')
    parser.add_argument('-e', '--dumped-exec', dest='dumped_comm', type=str, default='unknown',
                        help='Comm value of the dumped process or thread')
    parser.add_argument('-I', '--trigger-tid', dest='trigger_tid', type=int, default=-1,
                        help='Comm value of the dumped process or thread')
    parser.add_argument('-C', '--clean',       dest='clean',       action='store_true',
                        help='Clean savecore directories')
    parser.add_argument('-?', '--help', action='help',
                        help='Show help')
    arguments = parser.parse_args()

    if not arguments.clean:
        if arguments.dumped_pid is None \
        or arguments.dumped_uid is None \
        or arguments.signal_num is None:
            parser.error('Without -C, -P <pid>, -u <uid> and -s <signal> are required')

    main(arguments)
