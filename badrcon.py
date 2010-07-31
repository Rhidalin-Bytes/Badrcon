# B3 console.log parse, ipsec and hosts.deny or other OS command, perhaps email alert? Unsure of pipeing 
# multiple commands.
# command line(s) to query, add and delete IP bans (bancommand =, unbancommand =, listbancommand =)
# ------------ this is to allow for compatibility cross platform without hard coding commands
# ------------ as commands are different between windows versions, linux, etc
# Bad rcon from 192.168.1.100:-16347:
# Must make sure that mmpolicy and qmpolicy is created or exists
# Verification of OS ban to Database ban list needs written.
import b3, re, time, fileinput, sys, subprocess, os
import b3.events

class BadrconPlugin(b3.plugin.Plugin):
    _adminPlugin = None
    _interval = 0
    _cronTab = None
    info = None
    clog = None
    fileHandle = None
    eof = None
    # table = badrcon = index, ip, cnt, ban, modified_date, client
    _SELECT_QUERY = "SELECT ip, cnt, ban, client, immune FROM badrcon WHERE ip='%s'"
    _ADD_QUERY = "INSERT INTO badrcon (id , ip, cnt, ban, client, modified_date, immune) VALUES (NULL ,'%s','%s','%s','%s',CURRENT_TIMESTAMP,'%s')"
    _CNT_QUERY = "UPDATE badrcon SET cnt=cnt+1 WHERE badrcon.ip='%s'"
    _BAN_QUERY = "UPDATE badrcon SET ban='%s' WHERE badrcon.ip='%s'"
    _IMMUNE_QUERY = "UPDATE badrcon SET immune='%s' WHERE badrcon.ip='%s'"
    _IMMUNELIST_QUERY = "SELECT ip FROM badrcon WHERE immune=1"
    _BANLIST_QUERY = "SELECT ip FROM badrcon WHERE ban=1"
    
    def startup(self):
        """\
        Initialize plugin settings
        """
        self._adminPlugin = self.console.getPlugin('admin')
        if not self._adminPlugin:
            self.error('Could not find admin plugin')
            return False
        
        # register our commands (you can ignore this bit)
        if 'commands' in self.config.sections():
            for cmd in self.config.options('commands'):
                level = self.config.get('commands', cmd)
                sp = cmd.split('-')
                alias = None
                if len(sp) == 2:
                    cmd, alias = sp

                func = self.getCmd(cmd)
                if func:
                    self._adminPlugin.registerCommand(self, cmd, level, func, alias)

        # Get vars
        if 'settings' in self.config.sections():
            self.clog = self.config.get('settings', 'log')
            self._interval = self.config.getint('settings', 'interval')
            self.tp = self.config.get('settings','tp')
            self.grace = self.config.getint('settings', 'grace')
            self.bancommand = self.config.get('settings', 'bancommand')
            self.unbancommand = self.config.get('settings', 'unbancommand')
            self.listbancommand = self.config.get('settings', 'listbancommand')
            
        # Do we have a log file present?
        if os.path.isfile(self.clog):
            self.fileHandle = open (self.clog,"r")
            self.fileHandle.seek(0, os.SEEK_END)
            self.debug('Using Console log: %s' % self.clog)
        else:
            self.error('Error reading file %s', self.clog)
            raise SystemExit('Error reading file %s\n' % self.clog)
        
        # We can't leave that file open now can we?
        self.registerEvent(b3.events.EVT_EXIT)

        # Now we need to see that sql is functioning
        try:
            self.console.storage.query(self._SELECT_QUERY % '0.0.0.0')
        except:
            self.debug('Error loading SQL, did you install the table?')
            
        # Must stay on schedule
        self._cronTab = b3.cron.PluginCronTab(self, self.parseit, '*/%s' % self._interval)
        self.console.cron + self._cronTab        
        
        # Start it up
        self.debug('We made it through the little stuff now on with the show...')
        
    def getCmd(self, cmd):
        cmd = 'cmd_%s' % cmd
        if hasattr(self, cmd):
            func = getattr(self, cmd)
            return func
        return None

    def onEvent(self,  event):
        if event.type == b3.events.EVT_EXIT:
            self.closefile()
        
    def parseit(self):
        # Don't forget the white lists
        tpre = re.escape(self.tp)
        s1 = re.compile(r"(%s)." % tpre)
        s2 = re.compile((r"(%s)") % ("\.".join(['(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)']*4)))
        i = 0
        results = []
        while 1:
            line = self.fileHandle.readline()
            if not line:
                break
            else:
                while True:
                    m = s1.match(line)
                    if m:
                        mip = s2.search(line)
                        self.cmd_stickip(data = mip.group(1))
                        break
                    else:
                        break

    def closefile(self):
        self.file.close(fileHandle)
           
    def cmd_stickip(self, data, client=None, cmd=None):
        """\
        <ip> - add ip to perm ban list
        """
        ban = 0
        cnt = 0
        immune = 0
        if client:
            m = self._adminPlugin.parseUserCmd(data)
            if m:
                ip = ''
                for n in m:
                    ip = ip + n
                cnt = self.grace + 1
            else:        
                self.client('You must supply a valid IP')
                return False
        else:
            ip = data
        # Whether it's command or automation, we need to make sure IP exists
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            goat.close()
            cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, client, immune))
            cursor2.close()
            self.debug("ip %s added to sql" % ip)
        # Now we need to requery goat and check for cnt
        goat.close()
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        # ip, cnt, ban, client, immune
        recheck = goat.getRow()
        goat.close()
        if recheck['cnt'] >= self.grace and not recheck['immune']:
            ban = 1
            cursor2 = self.console.storage.query(self._BAN_QUERY % (ban, ip))
            cursor2.close()
            try:
                # We assume that no error value is returned on bancommand otherwise we assume it's done
                # Unix command must use silent flags because of windows silence on success not done passing
                # parameters to os.system, it's coming
                # stick IP into bancommand
                o = sys.platform
                bancommand = self.bancommand.replace('XXX', ip)
                p = subprocess.Popen(bancommand, stdout=subprocess.PIPE, close_fds=False, stderr=subprocess.PIPE, shell=(o), stdin=subprocess.PIPE)
                text = p.stdout
                for line in text:
                    self.debug('line is %s' % line)
                    if 'ERR' in line:
                        p.close()
                        raise
                p.close()
                if client:
                    client.message('%s has been banned for %s Bad Rcon tries'% ip, goat[1])
                else:
                    cmd.sayLoudOrPM(None, '%s has been banned for %s Bad Rcon tries' % ip, goat[1])
            except:
                try:
                    client.message('OS Error: %s is not bannned' % ip)
                except:
                    self.debug('OS Error: %s is not banned' % ip)
                return False
            return True
        # if it's immune and someone told me to do it, tell them we can't
        elif recheck['immune'] and client:
            client.message('The ip you entered is protected, see a server admin')
            goat.close()
            return False
        # if someone protected is making a mistake, forgive them.
        elif recheck['immune']:
            return
        # son of beach better quit while he's ahead
        else:
            goat.close()
            cursor2 = self.console.storage.query(self._CNT_QUERY % (ip))
            self.debug("ip %s hacking, count added" % ip)
            cursor2.close()
            self.console.say('B3 bot is watching!')
            return True
 
    def cmd_unstickip(self, data, client=None, cmd=None):
        """\
        <ip> - remove ip from ban list
        """        
        m = self._adminPlugin.parseUserCmd(data)
        if m:
            ip = ''
            for n in m:
                ip = ip + n
            cnt = self.grace + 1
        else:        
            self.client('You must supply a valid IP')
            return False
        # Lets see if it exists and is banned
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            client.message("%s does not exist in the database, please contact admins" % ip)
        else:
            try:
                cursor2 = self.console.storage.query(self._BAN_QUERY % (0, ip))
                cursor2.close()
                self.debug("%s ban lifted from database" % ip)
                o = sys.platform
                unbancommand = self.unbancommand.replace('XXX', ip)
                p = subprocess.Popen(unbancommand, stdout=subprocess.PIPE, close_fds=False, stderr=subprocess.PIPE, shell=(o), stdin=subprocess.PIPE)
                text = p.stdout, p.stderr
                for line in text:
                    self.debug('line is %s' % line)
                    if 'ERR' in line:
                        raise OSError
                client.message('%s unbanned' % ip)
                return True
            except OSError:
                if client:
                    client.message('%s not removed, contact tech support(OS)' % ip)
                else:
                    self.debug('%s not removed, contact tech support(OS)' % ip)
                return false
            except:
                if client:
                    client.message('%s not removed, contact tech support(DBOS)' % ip)
                else:
                    self.debug('%s not removed, contact tech support(DBOS)' % ip)
                
    def cmd_listips(self, data, client=None, cmd=None):
        """\
        list ip addresses in ban state
        """         
        cursor = self.console.storage.query(self._BANLIST_QUERY)
        if cursor.rowcount == 0:
            client.message("^7The list is empty.")
            cursor.close()
            return False
        ips = []
        while not cursor.EOF:
            r = cursor.getRow()
            self.debug('r is %s' % r)
            ips.append(r['ip'])
            cursor.moveNext()
        cursor.close()
        client.message('These IP addresses are banned')
        client.message(', '.join(ips))
        
    def cmd_ipsafe(self, data, client=None, cmd=None):
        """\
        make an IP immune to badrcon
        """         
        cnt = 0
        ban = 0
        immune = 1
        ip = ''
        m = self._adminPlugin.parseUserCmd(data)
        if m:
            for n in m:
                ip = ip + n
            self.debug('ip is %s' % ip)
        else:
            client.message('You must enter a valid IP address')
            return False
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, client.id, immune))
            cursor2.close()
            client.message('%s is now immune' % ip)
        elif goat.rowcount > 0:
            cursor2 = self.console.storage.query(self._IMMUNE_QUERY % (immune, ip))
            cursor2.close()
            client.message('%s is now immune' % ip)
        else:
            client.message('WARNING, there was a problem, %s is not immune' % ip)
        goat.close()
        return
        
    def cmd_ipunsafe(self, data, client=None, cmd=None):
        """\
        remove immunity from IP in badrcon
        """  
        cnt = 0
        ban = 0
        immune = 0
        ip = ''
        m = self._adminPlugin.parseUserCmd(data)
        for n in m:
            ip = ip + n
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        try:
            if goat.rowcount == 0:
                goat.close()
                cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, client, immune))
                cursor2.close()
            else:
                goat.close()
                cursor2 = self.console.storage.query(self._IMMUNE_QUERY % (immune, ip))
                cursor2.close()
            client.message('%s is no longer immune' % ip)
            return
        except:
            client.message('WARNING, there was a problem changing %s status' % ip)
            return

    def cmd_ipsafelist(self, data, client=None, cmd=None):
        """\
        Return IP's that are immune
        """  
        goat = self.console.storage.query(self._IMMUNELIST_QUERY)
        ips = []
        while not goat.EOF:
            r = goat.getRow()
            self.debug('r is %s' % r)
            ips.append(r['ip'])
            goat.moveNext()
        goat.close()
        client.message('These IP addresses are immune')
        client.message(', '.join(ips))
        
class OSError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
        