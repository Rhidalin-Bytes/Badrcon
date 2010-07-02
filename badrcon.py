# B3 console parse, ipsec and hosts.deny
# Load config
# Config contains ----
# location of console file (log = hardpath+filename)
# Now we need to define a bad RCON (or what we search for) (tp for test phrase)
# Which WORD is the IP (IPP = 4)
# number of acceptable retries (grace = )
# command line(s) to query, add and delete IP bans (bancommand =, unbancommand =, listbancommand =)
# ------------ this is to allow for compatibility cross platform without hard coding commands
# ------------ as commands are different between windows versions, linux, etc
# Define query (also a command) sql for tracking
# Define add (also a command) sql for tracking
# Define delete (also a command) sql for tracking
# Define Warning search eg. find player by IP, if player name and IP, then check warning or
# ban and add if not there. (hrm, stuck on this, find client @ by IP, if multiple clients do what?)
# Now we need to add this to B3 as a constantly running program (Use CRON)
# On __Init__ (actual CRON logic)
#     On "Bad Rcon from Player, IP" (console.log)
#           If B3 Ban for player exists
#               client.count = client.count + maxRetries
#               return true
#           Return false
#     
#     On client.count > maxRetries - 1
#           system.cmd("ipsecadd", name, ip")
#           on errorlevel > 1
#               return false
#           else 
#               return true
#Bad rcon from 192.168.1.100:-16347:
#status
# DECLARED VARIABLES
# log = Z:\mp_console.log
# tp = "Bad Rcon"
# IPP = 4
# grace = 5
# bancommand = netsh ipsec dynamic add rule srcaddr=192.168.100.100 mmpolicy=1
# qmpolicy=qmsec dstaddr=ANY mirrored=yes srcport=0 dstport=0 actioninbound=block actionoutbound=block
# unbancommand = netsh ipsec dynamic delete rule srcaddr=192.168.100.100 dstaddr=ANY mirror=yes srcport=0 
# dstport=0 proto=any conntype=all
# listbancommand = netsh ipsec dynamic show qmfilter Name = "87.0.0.0 - More Ripe crap"
# Must make sure that mmpolicy and qmpolicy is created or exists, also, must verify addition and removal, list
# bancommand is for all, perhaps change it to querybancommand, where srcaddr=%s and pass ALL for !ipbanlist
# write in set run once for sql table creation for new plugin users, eg. if not table use build sql add to init

import b3, b3.plugin, re, time, re, fileinput

class BadrconPlugin(b3.plugin.Plugin):
    _lineFormat = re.compile('^([a-z ]+): (.*?)', re.IGNORECASE)

    _events = {}
    _eventNames = {}
    _commands = {}
    _messages = {}
    _timeStart = None

    _reColor = re.compile(r'\^[0-9a-z]')
    _cron = None

    info = None
    config = None
    # table = badrcon index, ip, cnt, ban, modified_date, client
    _SELECT_QUERY = "SELECT ip, cnt, ban, client, modified_date FROM badrcon WHERE ip = %s"
    _ADD_QUERY = "INSERT INTO badrcon (ip, cnt, ban, client, modified_date) VALUES ('%s','%s',%s,'%s',NOW())"
    _CNT_QUERY = "UPDATE badrcon SET cnt=cnt+1 WHERE ip='%s'"
    _BAN_QUERY = "UPDATE badrcon SET ban='%s' WHERE ip='%s'" 
    _LIST_QUERY = "SELECT ip FROM badrcon WHERE ban=true"
    
    def startup(self):

        if not self.loadConfig(config):
            print 'COULD NOT LOAD CONFIG'
            raise SystemExit(220)

        # set up logging and sql
        log = self.config('log', 'log')
        self.log = b3.output.getInstance(logfile, self.config.getint('b3', 'log_level'), log2console)
        # Do we have a log file present? variable log = mp_console.log
        if os.path.isfile(log):
            # open log file
            fileHandle = open (log,"r")
            eof = fileHandle.readlines()-1
            self.screen.write('Using Console log: %s\n' % log)
        else:
            self.error('Error reading file %s', f)
            raise SystemExit('Error reading file %s\n' % f)
            
        # Start it up
    def run(self):
        self.parseit()
        
    def loadConfig(self, config):
        """Set the config file to load"""

        if not config:
            return False

        self.config = config

        return True
    def parseit(self):
        IPC = ":"
        for line in fileinput.input(log):
            ip, IPC, tail = line[IPP].split(IPC)
            # Insert IP into sql and check it's counter for grace
            if stickip(ip, 1):
                self.debug('parsed and dealt with ip %s', ip)
            else:
                self.debug('unable to deal with ip %s', ip)
            # Add possible cross reference IP to Client
            
    def closefile(self):
        self.exit
           
    def linetest(line, tp):
        cnt = 0
        if cnt <= len(tp):
            if test(cnt) == tp(cnt):
                return true
            else:
                return false
        return false

    def osipban(self, ip, count, client=None):
        if ip:
            admin.say('%s has been banned for %s Bad Rcon tries', ip, count)
            os.system('%s', self.bancommand)
            return true
        else:
            self.client('You must supply a valid IP')
            return false
    
    def osipunban(self, ip, client=None):
        if ip:
            stdout_handle = os.popen(self.bancommand, "r")
            text = stdout_handle.read()
            for lines in text:
                self.debug('%s', line)
            return true
                #os.system('%s', self.unbancommand)
            admin.say('%s has been unbanned', ip)
            return true
        else:
            self.client('You must supply a valid IP')
            return 
           
    def osipbanlist(self, client=None):
        stdout_handle = os.popen(self.banlistcommand, "r")
        text = stdout_handle.read()
        for lines in text:
            self.client('%s', line)
            return true
            
    def stickip(self, ip, client=None):
        """\
        <ip> - add ip to perm ban list
        """
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            cursor2 = self.console.storage.query(self._ADD_QUERY % (ip, cnt, ban, client))
            cursor2.close()
            self.debug("ip added to sql")
        else:
            if goat[1] >= (grace - 1):
                if osipban(ip):
                    return true
                else:
                    self.debug("OS ip ban for %s failed",ip)
                    return false
                #nothing more to do here, problem dealt with
            else:            
                cursor2 = self.console.storage.query(self._CNT_QUERY % (ip))
                self.debug("ip %s exists, count added", ip)
                cursor2.close()
                return true
        cursor.close()

    def unstickip(self, ip, client):
        """\
        <ip> - remove ip from ban list
        """        
        m = self._adminPlugin.parseUserCmd(data)
        if not m:
            client.message('^7Invalid parameters')
            return False

        ip = self._adminPlugin.findClientPrompt(m[0], client)
        cursor = self.console.storage.query(self._BAN_QUERY % 0, ip)
        cursor.close()
        self.debug("IP removed from database")
        if osipunban(ip):
            client.message("^7%s ip ban removed.", ip)
        else:
            client.message("There was a problem, contact tech support")
        
    def listips(self, ip, client):

        """\
        list ip addresses in ban state
        """         
        cursor = self.console.storage.query(self._LIST_QUERY)
        if cursor.rowcount == 0:
            client.message("^7The list is empty.")
            cursor.close()
            return False

        while not cursor.EOF:
            r = cursor.getRow()
            cient.message('%s banned %s', ip, modified_date)
            cursor.moveNext()
        cursor.close()
        