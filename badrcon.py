# B3 console.log parse, ipsec and hosts.deny
# command line(s) to query, add and delete IP bans (bancommand =, unbancommand =, listbancommand =)
# ------------ this is to allow for compatibility cross platform without hard coding commands
# ------------ as commands are different between windows versions, linux, etc
# Define Warning search eg. find player by IP, if player name and IP, then check warning or
# ban and add if not there. (hrm, stuck on this, find client @ by IP, if multiple clients do what?)
# Now we need to add this to B3 as a constantly running program (Use CRON)
# Bad rcon from 192.168.1.100:-16347:
# bancommand = netsh ipsec dynamic add rule srcaddr=192.168.100.100 mmpolicy=1
# ...qmpolicy=qmsec dstaddr=ANY mirrored=yes srcport=0 dstport=0 actioninbound=block actionoutbound=block
# unbancommand = netsh ipsec dynamic delete rule srcaddr=192.168.100.100 dstaddr=ANY mirror=yes srcport=0 
# ...dstport=0 proto=any conntype=all
# listbancommand = netsh ipsec dynamic show qmfilter Name = "87.0.0.0 - More Ripe crap"
# Must make sure that mmpolicy and qmpolicy is created or exists, also, must verify addition and removal, list
# bancommand is for all, perhaps change it to querybancommand, where srcaddr=%s and pass ALL for !ipbanlist
import b3, re, time, fileinput, os
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
    _SELECT_QUERY = "SELECT ip, cnt, ban, client, immune, modified_date FROM badrcon WHERE ip = '%s'"
    _ADD_QUERY = "INSERT INTO badrcon (ip, cnt, ban, client, immune, modified_date) VALUES ('%s',%s,%s,'%s',%s,NOW())"
    _CNT_QUERY = "UPDATE badrcon SET cnt=cnt+1 WHERE ip='%s'"
    _BAN_QUERY = "UPDATE badrcon SET ban=%s WHERE ip='%s'"
    _IMMUNE_QUERY = "UPDATE badrcon SET immune=%s WHERE ip='%s'"
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
        s2 = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
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
                        # Insert IP into sql and check it's counter for grace
                        #if cmd_stickip(ip=mip):                        
                        break
                    else:
                        break
        # Add possible cross reference IP to Client
            
    def closefile(self):
        self.file.close(fileHandle)
           
    def cmd_stickip(self, ip, client=None):
        """\
        <ip> - add ip to perm ban list
        """
        cnt = 0
        immune = 0
        autoban = 0
        if client:
            autoban = self.grace + 1
            if not ip:
                self.client('You must supply a valid IP')
                return false
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            goat.close()
            cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, immune, client))
            cursor2.close()
            self.debug("ip %s added to sql" % ip)
        else:
            if goat[1] >= (grace + autoban) and not (goat[4] > 0):
                cursor2 = self.console.storage.query(self._BAN_QUERY % ('1', ip))
                cursor2.close()
                try:
                    # We assume that no error value is returned on bancommand otherwise we assume it's done
                    # Unix command must use silent flags because of windows silence on success not done passing
                    # parameters to os.system, it's coming
                    os.system('%s', self.bancommand)
                    stdout_handle = os.popen(self.bancommand, "r")
                    text = stdout_handle.read()
                    if lines in text:
                        raise
                    admin.say('%s has been banned for %s Bad Rcon tries'% ip, goat[1])
                except:
                    goat.close()
                    admin.say('There was a problem adding %s with the OS ip ban')
                    return false
                return true
                #nothing more to do here, problem dealt with
            elif not goat[4] and client:
                admin.say('The ip you entered is protected, see a server admin')
                goat.close()
                return false
            else:
                goat.close()
                cursor2 = self.console.storage.query(self._CNT_QUERY % (ip))
                self.debug("ip %s exists, count added" % ip)
                cursor2.close()
                return true
 
    def cmd_unstickip(self, ip, client):
        """\
        <ip> - remove ip from ban list
        """        
        m = self._adminPlugin.parseUserCmd(data)
        if not m:
            client.message('^7Invalid parameters')
            return False
        ip = self._adminPlugin.findClientPrompt(m[0], client)
        try:
            cursor2 = self.console.storage.query(self._BAN_QUERY % 0, ip)
            cursor2.close()
            self.debug("IP removed from database")
            stdout_handle = os.popen(self.unbancommand, "r")
            text = stdout_handle.read()
            if lines in text:
                raise OSerror
            admin.say('%s has been unbanned' % ip)
            return true
        except OSerror:
            client.message("There was a problem, contact tech support(OS)")
            return false
        except:
            self.client('%s was not found, contact tech support(DB)')
        
    def cmd_listips(self, ip, client):
        stdout_handle = os.popen(self.banlistcommand, "r")
        text = stdout_handle.read()
        for lines in text:
            self.client('%s', line)
            return true
  
        """\
        list ip addresses in ban state
        """         
        cursor = self.console.storage.query(self._BANLIST_QUERY)
        if cursor.rowcount == 0:
            client.message("^7The list is empty.")
            cursor.close()
            return False

        while not cursor.EOF:
            r = cursor.getRow()
            cient.message('%s banned %s', ip, modified_date)
            cursor.moveNext()
        cursor.close()
        
    def cmd_ipsafe(self, ip, client):
        cnt = 0
        ban = 0
        immune = 1
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        try:
            if goat.rowcount == 0:
                goat.close()
                cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, immune, client))
                cursor2.close()
            else:
                cursor2 = self.console.storage.query(self._IMMUNE_QUERY % (immune, ip))
                curser2.close()
            client.message('%s is now immune')
        except:
            client.message('WARNING, there was a problem, %s is not immune' % ip)
            
    def cmd_ipunsafe(self, ip, client):
        cnt = 0
        ban = 0
        immune = 0
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        try:
            if goat.rowcount == 0:
                goat.close()
                cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, immune, client))
                cursor2.close()
            else:
                cursor2 = self.console.storage.query(self._IMMUNE_QUERY % (immune, ip))
                curser2.close()
            client.message('%s is no longer immune')
            return true
        except:
            client.message('WARNING, there was a problem changing %s status' % ip)
            return false
            
    def cmd_ipsafelist(self, client):
        goat = self.console.storage.query(self._IMMUNELIST_QUERY)
        client.message('These IP addresses are immune')
        for row in goat:
            client.message('%s')
        return true