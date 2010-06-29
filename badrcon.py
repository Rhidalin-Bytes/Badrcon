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

#Rcon from 192.168.1.100:-2899:
#status
#Rcon from 192.168.1.100:-2899:
#say
#Rcon from 192.168.1.100:-2899:
#status
#Sending heartbeat to cod2master.activision.com
#WARNING: Non-localized Game Message string is not allowed to have letters in it. Must be changed over to a localized string: "Welcome to another fine server running ^1WRM^7 - Wolfsbane's Realism Mod"
#Rcon from 192.168.1.100:-2899:
#status
#Rcon from 192.168.1.100:-2899:
#say
#WARNING: Non-localized Game Message string is not allowed to have letters in it. Must be changed over to a localized string: "For all your WRM inquiries, visit their forums at ^3www.1stsfss.org^7"
#Rcon from 192.168.1.100:-2899:
#status
#Rcon from 192.168.1.100:-2899:
#status
#Rcon from 192.168.1.100:-2899:
#say
#Bad rcon from 192.168.1.100:-16349:
#status
#Bad rcon from 192.168.1.100:-16348:
#status
#Bad rcon from 192.168.1.100:-16347:
#status
#
# ipsecpol –w REG –p "Packet Filter" –r "Inbound/outbound mail"
# -f *+131.107.1.1:110:TCP –f *+131.107.1.1:995:TCP
# -f *+131.107.1.1:143:TCP –f *+131.107.1.1:993:TCP
# -f *+131.107.1.1:25:TCP –f 131.107.1.1+*:25:TCP
# –n PASS
# Command for listed bad rcon would be 
# ipsecpol -w REG -p "Bad Rcon Traffic" -f 192.168.1.100:*:*+* -n BLOCK -x
# 
# problem with command line to research, how do we list and unban, removal isn't explicitly 
# stated for ipsecpol
# Possible solution is to use a table in sql for storage of IP's and their status. This would allow
# a page to be created for echelon to deal with checking on ban status. Haven't worked out how
# echelon would unban an ip. Possibly use the on map change event to trigger a "bancheck" of the 
# sql table.

# DECLARED VARIABLES
# log = Z:\mp_console.log
# tp = "Bad Rcon"
# IPP = 4
# grace = 5
# bancommand = 
# unbancommand = 
# listbancommand = 

# write in set run once for sql table creation for new plugin users, eg. if not table use built sql

import b3, b3.admin, re, time, re, fileinput
# Possible log parse

class Parser(object):
    _lineFormat = re.compile('^([a-z ]+): (.*?)', re.IGNORECASE)

    _events = {}
    _eventNames = {}
    _commands = {}
    _messages = {}
    _timeStart = None

    _reColor = re.compile(r'\^[0-9a-z]')
    _cron = None

    info = None
    
    _SELECT_QUERY = "SELECT ip, cnt, ban, modified FROM badrcon WHERE ip = %s"
    _ADD_QUERY = "INSERT INTO badrcon (ip, cnt, ban, modified_date) VALUES ('%s','%s',%s, NOW())"
    _CNT_QUERY = "UPDATE badrcon SET cnt=cnt+1 WHERE ip='%s'"
    _BAN_QUERY = "UPDATE badrcon SET ban='%s' WHERE ip='%s'" 
    _LIST_QUERY = "SELECT ip FROM following WHERE ban=true"
    
    def __init__(self, config):
        self._timeStart = self.time()

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
            
        # Do we have access to the SQL table

    def loadConfig(self, config):
        """Set the config file to load"""

        if not config:
            return False

        self.config = config

        return True
    def parseit:
        IPC = ":"
        for line in fileinput.input(log):
            if linetest(line, tp)
                ip, IPC, tail = line[IPP].split(IPC)
                # Insert IP into sql and check it's counter for grace
                stickip(ip, 1)
                self.debug('messing with ip %s', ip
                # Cross reference IP to Clients
                # If either return true then call osipban(IP)
 

    def closefile:
        self.exit
           
    def linetest(line, tp):
        cnt = 0
        while cnt =< len(tp):
            if test(cnt) == tp(cnt)
                b = true
            else
                b = false
            boo = boo + b
            cnt += 1
        return boo

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
            admin.say('%s has been unbanned', ip)
            os.system('%s', self.unbancommand)
            return true
        else:
            self.client('You must supply a valid IP')
            return 
           
    def osipbanlist(self, client=None):
        stdout_handle = os.popen(self.banlistcommand, "r")
        text = stdout_handle.read()
        for lines in text
        self.client('%s', line)
            return true
            
    def stickip(self, ip, cnt)
        """\
        <ip> - add ip to perm ban list
        """
        goat = self.console.storage.query(self._SELECT_QUERY % ip)
        if goat.rowcount == 0:
            cursor2 = self.console.storage.query(self._ADD_QUERY % (sclient.id, client.id, self.console.time()))
            cursor2.close()
            self.debug("ip added to sql")
        else:
            self.debug("ip exists, count added")
            cursor2 = self.console.storage.query(self._CNT_QUERY % (ip))
            cursor2.close()
        cursor.close()

    def unstickip(self, ip, client);
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
        if osipunban(ip)
            client.message("^7%s ip ban removed.", ip)
        else
            client.message("There was a problem, contact tech support")
        
    def listips(self, ip, client);

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
        