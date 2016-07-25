# Copyright (c) 2013 Sylvia van Os
# Copyright (c) 2013 Joshua Phillips
# Based on ircLogBot.py, which is copyright (c) Twisted Matrix Laboratories.
# This file is part of Triggerbot, released under the MIT license
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


"""
Triggerbot
An IRC bot made to help assist keeping a channel safe for those
with triggers.

The bot quitely monitors the channel, until it sees something
wrong. If someone says the bot's name in the channel followed
by a ":", or if someone speaks to the bot in a private query
window, the bot will assume it to be a command and reply to it
as such.

Do not run this script directly. Instead, run main.py with at least 
a server name and port number. For example: 

    $ python main.py --server irc.example.com --port 6667

will connect to irc.example.com on channel 6667. 
For more information, please check the README.
"""

from twisted.words.protocols import irc
from twisted.internet import reactor, protocol, task
from twisted.python import log
import time
import datetime
import sys
import re
import random
import os.path
import cPickle
import xapian
import bcrypt
import reloading

class UserError(Exception):
    pass

class UserNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, I don't know who %r is." % self.message)

class MessageNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, I couldn't find message %s." % self.message)

class TopicNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, there's no such topic %r." % self.message)

class ChannelNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, I don't know channel %s." % self.message)

class OwnerNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, I don't know who owns this channel %s." % self.message)

class CommandNotFound(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, there is no such command %r." % self.message)

class BadValue(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Invalid value: %r." % self.message)

class BadCommand(Exception):
    pass

class MissingParams(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
	        "Sorry, but that command needs more parameters.")

class WrongParamCount(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
            "Sorry, but you entered a wrong amount of parameters.")

class AuthenticationError(UserError):
    def report(self, bot, user, recipient):
        bot.send_and_log(recipient, user,
	        "Sorry, but you need to be logged in to do that.")

def join_and(delim, last_delim, items):
    '''join_and(", ", " and ", ["one", "two", "three"]) == "one, two and three"'''
    items = list(items)
    if len(items) > 1:
        return delim.join(items[:-1]) + last_delim + items[-1]
    elif len(items) == 1:
        return items[0]
    else:
        return ""

def parse_bool(s):
    if s.lower() in ("y", "yes", "on", "enabled", "true"): return True
    elif s.lower() in ("n", "no", "off", "disabled", "false"): return False
    else:
        raise BadValue(s)

class MessageLogger:
    """
    An independent logger class (because separation of application
    and protocol logic is a good thing).
    """
    def __init__(self, file):
        self.file = file

    def log(self, message):
        """Write a message to the file."""
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

def is_channel_name(name):
    return name[0] in irc.CHANNEL_PREFIXES

class Setting(reloading.Reloadable):
    """Class containing bot settings."""
    is_setting = True
    def __init__(self, name):
        self.name = name
        self.channels = []
        self.globalmotd = ""
        self.maindisabled = False
        self.disabledcommands = []

    def __str__(self):
        return self.name

class Channel(reloading.Reloadable):
    """Information about a channel the bot is in."""
    is_channel = True
    def __init__(self, name):
        self.name = name
        self.admins = []
        self.users = set()
        self.rules = {}
        self.topic = None
        self.topicset = None
        self.mode = []
        self.prevmode = []
        self.blockedtopics = {}

    def __str__(self):
        return self.name

class User(reloading.Reloadable):
    """Information about a user."""
    is_user = True
    def __init__(self, nick):
        self.nick = nick
        self.host = ""
        self.admin = 0 # 0: Not an admin; 1: Main admin (claimadmin); 2: Additional admin (admin add)
        self.admincommandsallowed = []
        self.master = None
        self.alts = []
        self.friends = []
        self.trusts = [] # Lists of users having access to settings on this account
        self.topics = {}
        self.trigger_words = set()
        self.helped = False
        self.listenmode = False
        self.channel = False # Defines if the user has its own channel or not
        self.channelallow = [] # Which nicknames which are not alts are allowed in your own channel
        self.away = False
        self.ignore = [] # The user's ignore list
        self.ignoredby = [] # Who is ignoring this user
        self.ignored = False # Defines if the bot ignores all commands of this user
        self.awaycheck = True
        self.autologout = True
        self.autosilence = True # Silence the channel when away
        self.hideown = False # Hide own triggers in triggersafe channel topic and rules
        self.logged_in = False
        self.nickservlogin = True # Log the user in if the "r" flag is set
        self.motdread = False
        self.password = None
        self.seen = datetime.datetime.now()
        self.lastlogout = datetime.datetime.now()
        self.autopurge = True # Automatically purge this user if not online for 30 days
        self.messages = {}
        self.readmessages = []
        self.messagestoretime = 7 # Store messages for a week by default
        self.warnings = {}
        self.logs = {} # Recent logged command executed

    def __str__(self):
        return self.nick
    
    def __repr__(self):
        return self.nick

class Topic(reloading.Reloadable):
    """Information about a trigger topic."""
    def __init__(self, name):
        self.name = name
        self.descriptions = {}
        self.words = {}
        self.supersedes = []

class TimeFormat():
    """Formats dates. Based S Anand's py-pretty code licensed under the WTFPL"""
    def _df(self, seconds, denominator=1, text='', past=True):
        if past:   return         str((seconds + denominator/2)/ denominator) + text + ' ago'
        else:      return 'in ' + str((seconds + denominator/2)/ denominator) + text

    def date(self, time=False, asdays=False):
        '''Returns a pretty formatted date.
        Inputs:
            time is a datetime object or an int timestamp
            asdays is True if you only want to measure days, not seconds
            short is True if you want "1d ago", "2d ago", etc. False if you want
        '''
    
        now = datetime.datetime.now()
        if type(time) is int:   time = datetime.datetime.fromtimestamp(time)
        elif not time:          time = now
        
        if time > now:  past, diff = False, time - now
        else:           past, diff = True,  now - time
        seconds = diff.seconds
        days    = diff.days

        if days == 0 and not asdays:
            if   seconds < 10:          return 'just now'
            elif seconds < 60:          return self._df(seconds, 1, ' seconds', past)
            elif seconds < 120:         return past and 'a minute ago' or 'in a minute'
            elif seconds < 3600:        return self._df(seconds, 60, ' minutes', past)
            elif seconds < 7200:        return past and 'an hour ago' or'in an hour'
            else:                       return self._df(seconds, 3600, ' hours', past)
        else:
            if   days   == 0:           return 'today'
            elif days   == 1:           return past and 'yesterday' or'tomorrow'
            elif days   == 2:           return past and 'the day before yesterday' or 'the day after tomorrow'
            elif days    < 7:           return self._df(days, 1, ' days', past)
            elif days    < 14:          return past and 'last week' or 'next week'
            elif days    < 31:          return self._df(days, 7, ' weeks', past)
            elif days    < 61:          return past and 'last month' or 'next month'
            elif days    < 365:         return self._df(days, 30, ' months', past)
            elif days    < 730:         return past and 'last year' or 'next year'
            else:                       return self._df(days, 365, ' years', past)
    
class TriggerBot(irc.IRCClient, reloading.Reloadable):
    """Main TriggerBot code."""

    bot_commands = {}

    @classmethod
    def add_command(cls, description=None):
        def register(f):
            cls.bot_commands[tuple(f.__name__.strip("_").split("_"))] = (description, f)
            return f
        if callable(description):
            # @add_command case
            f, description = description, None
            return register(f)
        else:
            # @add_command(description) case
            return register

    @classmethod
    def command_description(cls, command):
        return cls.bot_commands[tuple(command)][0]

    @classmethod
    def subcommands(cls, command):
        """
        Iterates over sub-commands of the given command.
        @param command: Command or sub-command, given as a list of parts,
            e.g. ["set", "flags"]
        Returns (subcommand, description) pairs.
        """
        command = tuple(command)
        for k, v in cls.bot_commands.iteritems():
            if len(k) == len(command) + 1 and k[:len(command)] == command:
                yield k[len(command)], v[0]

    def dispatch(self, command, user, reply_to, bypass=False, extend=True):
        sentcommand = command
        params = command.split()
        command = ()
        if extend:
            for current, param in enumerate(params):
                # Reset status
                param = param.lower()
                checklist = []
                found = 0
                perfectmatch = False
                for commandcheck in self.bot_commands:
                    append = True
                    try:
                        # Check if the previous part of this command match the extended values
                        for x in range(0, current):
                            if not commandcheck[x] == params[x]:
                                append = False
                        if append and not commandcheck[current] in checklist:
                            checklist.append(commandcheck[current])
                    except IndexError:
                        continue
                for compareto in checklist:
                    if compareto == param:
                        # Exact match, this must be it
                        params[current] = compareto
                        perfectmatch = True
                        break
                    elif compareto.startswith(param):
                        # Ensure a lack of ambiguity
                        params[current] = compareto
                        found += 1
                if not perfectmatch and found > 1:
                    self.send_and_log(reply_to, user,
                        "Sorry, but word %s (%s) is too ambiguous. Please be more precise."
                        % (current, param))
                    return
        channelknown = False
        if params[0] == "channel" and is_channel_name(params[1].lower()):
            mainchannel = self.get_channel(params[1].split("_")[0].lower())
            params.remove(params[1])
            channelknown = True
        while params and command + (params[0].lower(),) in self.bot_commands:
            command += (params.pop(0).lower(),)
        if command:
            (_, f) = self.bot_commands[command]
            try:
                if not channelknown:
                    try:
                        mainchannel = self.get_channel(str(reply_to).split("_")[0])
                    except KeyError:
                        mainchannel = None
                return f(self, params, user, reply_to, mainchannel, bypass)
            except UserError, e:
                e.report(self, user, reply_to)
            except BadCommand:
                self.send_and_log(reply_to, user,
                    "Please use one of the following sub-commands: %s."
                    % join_and(", ", " or ",
                        (sorted(subc for subc, _ in self.subcommands(command)))))
        else:
            self.send_and_log(reply_to, user,
                "Sorry, I don't know what you mean by %r. Please use the"
                " help command to find out the correct command for what"
                " you want to do." % "".join(params[:1]))

    def get_channel(self, name):
        channel = self.channels.get(name.lower())
        if channel is None:
            channel = Channel(name.lower())
            self.channels[channel.name] = channel
        return channel

    def get_channel_owner(self, name):
        for user in self.users:
            if user.lower() == name:
                return user
        raise OwnerNotFound(name)

    def get_user(self, nick, create_if_nonexistent=True):
        user = self.users.get(nick)
        if create_if_nonexistent:
            if user is None:
                user = User(nick)
                self.users[user.nick] = user
            return user
        else:
            return user if user else None

    def find_user(self, nick):
        user = self.users.get(nick)
        if user is None:
            raise UserNotFound(nick)
        return user

    def find_topic(self, name):
        topic = self.topics.get(name)
        if topic is None:
            raise TopicNotFound(name)
        return topic
    
    def get_settings(self):
        settings = self.settings.get("triggerbot")
        return settings

    def changed(self):
        self.__dirty = True

    def save(self):
        if self.__dirty:
            with open(self.filename, "w") as f:
                cPickle.dump((self.users, self.topics, self.channels, self.settings), f)
            self.__dirty = False
            self.logger.log("Saved state.")

    def load(self):
        with open(self.filename, "r") as f:
            self.users, self.topics, self.channels, self.settings = cPickle.load(f)
        self.__dirty = False
        self.check_database()

    def check_database(self, recipient=None, user_executed=None):
        # Make sure the settings are okay
        database_values = Setting(None).__dict__
        for entry in database_values:
            if not hasattr(self.get_settings(), entry):
                setattr(self.get_settings(), entry, getattr(Setting(None), entry))
                self.changed()
        # Make sure users are okay
        database_values = User(None).__dict__
        for user in self.users.itervalues():
            for entry in database_values:
                if not hasattr(user, entry):
                    setattr(user, entry, getattr(User(None), entry))
                    self.changed()
        deletelist = []
        for entry in self.users:
            if entry != repr(self.users.get(entry)):
                if not recipient and not user_executed:
                    print "WARNING: Database value for %s wrongly links to %s. This user will be deleted." % (entry, repr(self.users.get(entry)))
                else:
                    self.send_and_log(recipient, user_executed,
                        "WARNING: Database value for %s wrongly links to %s. This user will be deleted."
                            % (entry, repr(self.users.get(entry))))
                deletelist.append(entry)
        for entry in deletelist:
            del self.users[entry]
        if deletelist:
            self.changed()
        # Check if there is only one head admin
        headadmincount = 0
        for user in self.users.itervalues():
            if user.admin == 1:
                headadmincount += 1
        if headadmincount > 1:
            if not recipient and not user_executed:
                print "WARNING: There is more than one head admin. All head admins are now normal admins. Please let the head admin execute !claimadmin ASAP."
            else:
                self.send_and_log(recipient, user_executed,
                    "WARNING: There is more than one head admin. All head admins are now normal admins. Please let the head admin execute !claimadmin ASAP.")
            for user in self.users.itervalues():
                if user.admin == 1 or user.admin == True:
                    user.admin = 2
                elif user.admin == False:
                    user.admin = 0
        elif not headadmincount:
            if not recipient and not user_executed:
                print "WARNING: No administrator was found. Please use !claimadmin to claim administrator rights."
            else:
                self.send_and_log(recipient, user_executed,
                    "WARNING: No administrator was found. Please use !claimadmin to claim administrator rights.")
        # Make sure the topics are okay
        database_values = Topic(None).__dict__
        for topic in self.topics.itervalues():
            for entry in database_values:
                if not hasattr(topic, entry):
                    setattr(topic, entry, getattr(Topic(None), entry))
                    self.changed()
        # Make sure the channels are okay
        database_values = Channel(None).__dict__
        for channel in self.channels.itervalues():
            for entry in database_values:
                if not hasattr(channel, entry):
                    setattr(channel, entry, getattr(Channel(None), entry))
                    self.changed()

    def check_for_master(self, name):
        if name.master:
            user = self.find_user(name.master)
            return user
        return name

    def join_channel(self, name):
        chan = self.get_channel(name)
        if not chan.name in self.get_settings().channels:
            self.get_settings().channels.append(chan.name)
            self.changed()
        chan.users = set()
        # Register the channel
        self.msg('Chanserv',
            'REGISTER %s' % name)
        self.join(chan.name)
        # If this is a triggersafe channel...
        if "_" in name:
            channelowner = self.get_channel_owner(name.split("_")[1])
            self.mode(name, True, "s") # Make channel secret
            self.mode(name, True, "i") # Make channel invite-only
            allowstring = "%s!*@*" % channelowner
            exceptionstring = "I"
            # Add an exception for the bot
            # Some servers may need this, even though the bot owns the channel
            allowstring += " %s!*@*" % self.nickname
            exceptionstring += "I"
            # Add alts
            for alt in self.find_user(channelowner).alts:
                allowstring += " %s!*@*" % alt
                exceptionstring += "I"
            # Add channelallows
            for allowed in self.find_user(channelowner).channelallow:
                allowstring += " %s!*@*" % allowed
                exceptionstring += "I"
            # Add invite-only exceptions
            self.mode(name, True, "%s %s" % (exceptionstring, allowstring))

    def leave_channel(self, name, unregister=False):
        chan = self.get_channel(name)
        if chan.name in self.get_settings().channels:
            self.get_settings().channels.remove(chan.name)
            self.changed()
        if chan.name in self.channels.keys():
            del self.channels[chan.name]
            self.leave(chan.name)
        if unregister:
            # Unregister the channel
            self.msg('Chanserv',
                'DROP %s' % name)

    def update_rules(self, channel=None, report=True, changed=False):
        if channel is None:
            for channel in self.channels.itervalues():
                assert channel is not None
                self.update_rules(channel=channel, report=report, changed=changed)
        else:
            basechannel = str(channel).split("_")[0]
            try:
                if str(channel).split("_")[1]:
                    triggersafechannel = True
            except IndexError:
                triggersafechannel = False
            new_rules = {}
            users = []
            for channeltocheck in self.channels:
                if channeltocheck.split("_")[0] == basechannel:
                    for user in self.get_channel(channeltocheck).users:
                        if user not in users:
                            users.append(user)
            try:
                channelowner = self.check_for_master(self.get_user(self.get_channel_owner(str(channel).split("_")[1])))
            except IndexError:
                channelowner = None
            for user in users:
                master = self.check_for_master(user)
                if master == channelowner and channelowner and channelowner.hideown:
                    # Channel owner wants own triggers hidden in rules. Hide it.
                    continue
                if not (user.away and master.awaycheck):
                    for topic, level in master.topics.iteritems():
                        # If a channel does not allow this topic, kick the user out
                        try:
                            if self.get_channel(basechannel).blockedtopics[topic.name] <= level:
                                self.dispatch(command="channel kick %s The topic you have set is not allowed in this channel" % user, user=user, reply_to=channel, bypass=True)
                        except KeyError:
                            pass
                        new_rules[topic] = max(new_rules.get(topic, 0), level)
            if new_rules != channel.rules or (channelowner and channel.prevmode != channel.mode and not ("silent" in channel.prevmode == "silent" in channel.mode)):
                channel.rules = new_rules
                changed = True
            if report:
                self.report_rules(channel=channel, changed=changed)
            channel.prevmode = channel.mode[:]

    def report_rules(self, channel, user=None, recipient=None, report_if_empty=True, changed=False):
        if not is_channel_name(str(channel)):
            return
        try:
            channelowner = self.check_for_master(self.get_user(self.get_channel_owner(str(channel).split("_")[1])))
        except IndexError:
            channelowner = None
        norulesbesidesownstring = "There are currently no additional rules besides yours"
        if channel.rules:
            previousDescription = ""
            descriptions = []
            rules = {}
            topicssuperseded = []
            othershiddencount = 0
            for topic, level in channel.rules.iteritems():
                for entry in topic.supersedes:
                    topicssuperseded.append(entry)
            for topic, level in channel.rules.iteritems():
                if not topic.name in topicssuperseded:
                    if channelowner and channelowner.hideown and topic in channelowner.topics:
                        othershiddencount += 1
                    else:
                        descriptions.append(topic.descriptions[level])
            for topicnumber, description in enumerate(sorted(descriptions)):
                for wordnumber, word in enumerate(description.split(' ')):
                    try:
                        if word != previousDescription.split(' ')[wordnumber]:
                            if wordnumber > 1:
                                rules[topicnumber] = ' '.join(description.split(' ')[wordnumber-1:])
                            else:
                                rules[topicnumber] = description
                            break
                    except IndexError:
                        rules[topicnumber] = description
                        break
                previousDescription = description
            rules = "Current rules: %s.%s" % (("do not %s" % join_and("; ", " or ",
                        (rules[itemnumber]
                        for itemnumber, description in rules.iteritems())))
                        if rules else norulesbesidesownstring,
                        (" | %s trigger%s set by others have been hidden."
                        % (othershiddencount, ("(s)"
                        if othershiddencount >= 2 else "")))
                        if othershiddencount >= 1 else "")
            self.update_topic(channel=channel, replace={"rules": rules})
            if changed:
                self.send_and_log(recipient or user or channel, user, rules)
        elif report_if_empty == True:
            if channelowner and channelowner.topics and channelowner.hideown and not "silent" in channel.mode:
                rules = "%s." % norulesbesidesownstring
            else:
                rules = "There are currently no additional rules."
            self.update_topic(channel=channel, replace={"rules": rules})
            if changed:
                self.send_and_log(recipient or user or channel, user,
                    rules)

    def update_topic(self, channel, text=None, replace={}):
        if not text:
            text = channel.topicset
        if text:
            replace['globalmotd'] = self.get_settings().globalmotd
            self.topic(str(channel))
            for entry in channel.__dict__.keys():
                if not entry in replace.keys():
                    replace[entry] = getattr(channel, entry)
            for entry in replace.keys():
                if replace[entry]:
                    if isinstance(replace[entry], set):
                        continue # What the hell should I do with sets?
                    elif not isinstance(replace[entry], str):
                        replace[entry] = " ".join(replace[entry])
                    if entry == "globalmotd" and not replace[entry].startswith("MOTD:"):
                        replace[entry] = "MOTD: %s" % replace[entry]
                    elif not replace[entry].startswith("Current %s:" % entry):
                        replace[entry] = "Current %s: %s" % (entry, replace[entry])
                    if text.find("[%s]" % entry) != -1:
                        text = text.split("[%s]" % entry)[0] + "%s | " % replace[entry] + text.split("[%s]" % entry)[1]
            # Get rid of things we didn't fill in
            while text.find("[") != -1 and text.find("]") != -1:
                text = text.split("[")[0] + text.split("]")[1]
            # Last cleanups
            text = " | ".join(text.split(" | ")[:-1]).lstrip()
            if getattr(channel, "topic") != text[:self.supported.getFeature("TOPICLEN")]:
                self.topic(str(channel), text)

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        self.logger.log("[connected at %s]" %
                        time.asctime(time.localtime(time.time())))

        self.__dirty = False
        self.channels = {}
        self.users = {}
        self.topics = {}
        self.settings = {"triggerbot": Setting("triggerbot")}
        if os.path.exists(self.filename):
            self.load()
        else:
            print "WARNING: No administrator was found. Please use !claimadmin to claim administrator rights."

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        for user in self.users:
            self.find_user(user).logged_in = False
        self.__dirty = True
        self.save()
        self.logger.log("[disconnected at %s]" %
                        time.asctime(time.localtime(time.time())))

    def signedOn(self):
        """Called when bot has succesfully signed on to server."""
        self.mode(chan=self.nickname, set=True, modes="B")
        self.sourceURLs=["https://github.com/TheLastProject/triggerbot", "https://notabug.org/SylvieLorxu/triggerbot"] # If you fork the bot, change this please
        if self.identify == True:
            self.msg('NickServ',
                'IDENTIFY %s' % self.identifypassword)

        self.check_away_loop = task.LoopingCall(self.minutely_tasks)
        self.check_away_loop.start(60.0)

        self.daily_loop = task.LoopingCall(self.daily_tasks)
        self.daily_loop.start(86400.0)

        if not self.channelsdefined:
            self.channellist = self.get_settings().channels
        for channel in self.channellist:
            self.join_channel(channel)

    def minutely_tasks(self):
        self.claimNick()
        self.checkAway()
        self.save()

    def daily_tasks(self):
        self.purgeOldNicks()
        self.purgeOldLogs()
        self.purgeOldMessages()

    def joined(self, channel):
        """This will get called when the bot joins the channel."""
        self.logger.log("[I have joined %s]" % channel)
        channel = self.get_channel(channel)
        # Also join triggersafe channels
        userchannel = False
        try:
            if str(channel).split("_")[1]:
                userchannel = True
                channelowner = self.get_channel_owner(str(channel).split("_")[1])
                setattr(channel, "topicset", "%s's triggersafe channel. | %s[rules][mode]" % (channelowner, "[globalmotd]" if not self.check_for_master(self.get_user(channelowner)).motdread else ""))
                self.update_rules(channel=channel)
        except IndexError:
            setattr(channel, "topicset", "[globalmotd][rules]")
        if not userchannel:
            for user in self.users.itervalues():
                if user.channel:
                    tojoin = "%s_%s" % (channel, user.nick)
                    tojoin = tojoin.lower()
                    self.join_channel(tojoin)

    def privmsg(self, user, channel, msg):
        """This will get called when the bot receives a message."""
        user = self.get_user(user.split('!', 1)[0])
        self.check_for_master(user).seen = datetime.datetime.now()
        checkmsg = msg.lstrip("!")
        # Do not log passwords
        if not checkmsg.startswith(("identify", "set password")):
            self.logger.log("[%s] <%s> %s" %
                (channel if is_channel_name(channel) else user, user, msg))

        # Private messages, messages beginning with "!" or messages directed to
        # me are commands.
        if is_channel_name(channel):
            channel = self.get_channel(channel)
            for prefix in ["!", self.nickname + ": ", self.nickname + ", "]:
                if msg.startswith(prefix):
                    if user.ignored != True:
                        self.dispatch(command=msg[len(prefix):], user=user, reply_to=channel)
                    else:
                        self.logger.log("Ignored command from %s" % user)
                    return # Do not leak commands
                if "silent" in channel.mode:
                    master = self.check_for_master(user)
                    self.send_and_log(channel, user, "Your channel is currently in silent mode and therefore not relaying. Please unset silent mode by %s." % ("removing your away status" if (user.away and master.awaycheck and master.autosilence) else "executing '!mode remove silent'"))
                    return
                if not "_" in channel.name and self.get_settings().maindisabled:
                    if not user.channel:
                        self.dispatch(command="set channel", user=user, reply_to=channel, bypass=True)
                    self.send_and_log(channel, user, "The main channel has been disabled. Please join %s_%s to chat in this channel." % (channel, str(user).lower()))
                    return
            self.relay_safe(message=msg, channel=channel, action=False, user=user, relateduser=None, chat=True)
        else:
            if not user.listenmode or checkmsg.startswith("unset listenmode"):
                self.dispatch(command=msg.lstrip("!"), user=user, reply_to=user)
            else:
                randomnumber = random.randrange(0,3)
                if randomnumber == 0:
                    templates = [
                        "nods calmly.",
                        "nods.",
                    ]
                    message = random.choice(templates)
                    reactor.callLater(random.randrange(2,5), self.describe, user, message)

    def action(self, user, channel, msg):
        """This will get called when the bot sees someone do an action."""
        user = self.get_user(user.split('!', 1)[0])
        self.check_for_master(user).seen = datetime.datetime.now()
        self.logger.log("[%s] * %s %s" %
            (channel if is_channel_name(channel) else user, user, msg))
        # Very important: Hug back when hugged
        try:
            if msg.split(' ')[0] == "hugs" and msg.split(' ')[1] == self.nickname:
                self.dispatch(command="hug", user=user, reply_to=channel if is_channel_name(channel) else user)
        except IndexError:
            # An ACTION with less than 2 words. Whatever it is, I am not being hugged.
            pass
        if is_channel_name(channel):
            channel = self.get_channel(channel)
            if "silent" in channel.mode:
                master = self.check_for_master(user)
                if user.away and master.awaycheck and master.autosilence:
                    self.send_and_log(channel, user, "Your channel is currently in silent mode and therefore not relaying. Please unset silent mode by removing your away status.")
                else:
                    self.send_and_log(channel, user, "Your channel is currently in silent mode and therefore not relaying. Please unset silent mode by executing '!mode remove silent'.")
            else:
                if not "_" in channel.name and self.get_settings().maindisabled:
                    self.send_and_log(channel, user, "The main channel has been disabled. Please join %s_%s to chat in this channel." % (channel, str(user).lower()))
                    if not user.channel:
                        self.dispatch(command="set channel", user=user, reply_to=recipient, bypass=True)
                    return
                self.relay_safe(message=msg, channel=channel, action=True, user=user, relateduser=None, chat=True)

    def notifyAdmins(self, channel, message):
        """ Notify the channel admins """
        for admin in channel.admins:
            admin = self.get_user(admin)
            self.send(admin, admin, message)

    def relay_safe(self, message, channel=None, action=False, user=None, relateduser=None, chat=True):
        if "silent" in channel.mode:
            return
        badtopics = []
        badwords = []
        triggeredusers = []
        ignoringusers = []
        collateralusers = []
        hiddenchannels = []
        hiddenusers = []
        try:
            basechannel = self.get_channel(str(channel).split("_")[0])
        except IndexError:
            basechannel = channel
        for triggersafechannel in self.channels:
            if str(triggersafechannel).startswith("%s_" % basechannel) and str(triggersafechannel) != str(channel):
                channelowner = str(triggersafechannel).split("_")[1]
                # Check if this channel has a normal user
                # If not, ignore it
                bots = [self.nickname, "ChanServ", "NickServ"]
                currentchannel = self.get_channel(triggersafechannel)
                channelusers = currentchannel.users
                for bot in bots:
                    if bot in channelusers:
                        channelusers.remove(bot)
                if not channelusers:
                    hiddenchannels.append(currentchannel)
                    continue
                # If we reached this point, someone is there. Keep it safe for them
                for checkinguser in channelusers:
                    if currentchannel in hiddenchannels:
                        if not checkinguser in collateralusers:
                            collateralusers.append(checkinguser.nick)
                            continue
                    usertocheck = self.check_for_master(checkinguser)
                    if "silent" in currentchannel.mode or ("rant" in channel.mode and (usertocheck.topics or usertocheck.trigger_words) and not "filterless" in currentchannel.mode) or user.nick in usertocheck.ignore:
                        ignoringusers.append(usertocheck.nick)
                        hiddenchannels.append(currentchannel)
                    if not currentchannel in hiddenchannels and not "filterless" in currentchannel.mode:
                        safe = self.is_safe(message=message, user=usertocheck)
                        if not safe[0]:
                            hiddenchannels.append(currentchannel)
                            if checkinguser.away and usertocheck.awaycheck:
                                if not usertocheck.nick in hiddenusers:
                                    hiddenusers.append(usertocheck.nick)
                            else:
                                for badtopic in safe[1]:
                                    if not badtopic in badtopics:
                                        badtopics.append(badtopic)
                                for badword in safe[2]:
                                    if not badword in badwords:
                                        badwords.append(badword)
                                if not usertocheck.nick in triggeredusers:
                                    triggeredusers.append(usertocheck.nick)
        for entry in ignoringusers:
            if not entry in hiddenusers:
                hiddenusers.append(entry.lower())
            if entry in collateralusers:
                collateralusers.remove(entry)
        for entry in triggeredusers:
            if not entry in hiddenusers:
                hiddenusers.append(entry.lower())
            if entry in collateralusers:
                collateralusers.remove(entry)
        if collateralusers:
            collateraldamage = " Due to user location, it was also hidden from %s." % join_and(", ", " and ", collateralusers)
        else:
            collateraldamage = ""
        # Tell users if stuff is bad and who we hid it from
        if badtopics and badwords:
            self.send_and_log(channel, user,
                "Because your message was possibly about the %s %s and contained the %s %s, it was hidden from %s.%s" %
                ("subjects" if len(badtopics) > 1 else "subject", join_and(", ", " and ", badtopics), \
                "words" if len(badwords) > 1 else "word", join_and(", ", " and ", badwords), \
                join_and(", ", " and ", triggeredusers), collateraldamage))
            user.warnings[datetime.datetime.now()] = (basechannel, None, "Said %r, containing %s %s and %s %s, being unsafe for %s." %
                (message, "subjects" if len(badtopics) > 1 else "subject", join_and(", ", " and ", badtopics), \
                "words" if len(badwords) > 1 else "word", join_and(", ", " and ", badwords), \
                join_and(", ", " and ", triggeredusers)))
            self.notifyAdmins(basechannel, "%s was prevented from triggering %s in %s. Type '!channel %s warnings list %s verbose 1' for more info." % (user, join_and(", ", " and ", triggeredusers), channel, basechannel, user))
        elif badtopics and not badwords:
            self.send_and_log(channel, user,
                "Because your message was possibly about the %s %s, it was hidden from %s.%s" %
                ("subjects" if len(badtopics) > 1 else "subject", join_and(", ", " and ", badtopics), \
                join_and(", ", " and ", triggeredusers), collateraldamage))
            user.warnings[datetime.datetime.now()] = (basechannel, None, "Said %r, containing %s %s, being unsafe for %s." %
                (message, "subjects" if len(badtopics) > 1 else "subject", join_and(", ", " and ", badtopics), \
                join_and(", ", " and ", triggeredusers)))
            self.notifyAdmins(basechannel, "%s was prevented from triggering %s in %s. Type '!channel %s warnings list %s verbose 1' for more info." % (user, join_and(", ", " and ", triggeredusers), channel, basechannel, user))
        elif badwords and not badtopics:
            self.send_and_log(channel, user,
                "Because your message contained the %s %s, it was hidden from %s.%s" %
                ("words" if len(badwords) > 1 else "word", join_and(", ", " and ", badwords), \
                join_and(", ", " and ", triggeredusers), collateraldamage))
            user.warnings[datetime.datetime.now()] = (basechannel, None, "Said %r, containing %s %s, being unsafe for %s." %
                (message, "words" if len(badwords) > 1 else "word", join_and(", ", " and ", badwords), \
                join_and(", ", " and ", triggeredusers)))
            self.notifyAdmins(basechannel, "%s was prevented from triggering %s in %s. Type '!channel %s warnings list %s verbose 1' for more info." % (user, join_and(", ", " and ", triggeredusers), channel, basechannel, user))
        self.relay(message=message, channel=channel, action=action, user=user, relateduser=relateduser, chat=chat, exclude=hiddenchannels)
    
    def is_safe(self, message, user):
        """ Check if a topic is message is safe for an user """
        badwords = []
        badtopics = []
        # First get a list of all words
        wordlist = []
        message = message.split(" ")
        for word in message:
            wordlist.append(word)
        for word in wordlist:
            stemmed = self.stem(word.lower())
            # Then check this user's trigger words:
            if stemmed in user.trigger_words:
                if not word in badwords:
                    badwords.append(word)
            # Last but not least, check if the word is defined in a topic
            for topic in user.topics:
                level = user.topics[topic]
                for x in range(1, level+1):
                    try:
                        if stemmed in topic.words[x]:
                            if not topic.name in badtopics:
                                badtopics.append(topic.name)
                    except KeyError:
                        # No triggerwords defined for this level
                        continue
        if badtopics or badwords:
            return [False, badtopics, badwords]
        else:
            return [True, None, None]

    def send(self, recipient, user, reply):
        if getattr(recipient, "is_user", False):
            self.msg(recipient.nick, reply)
        elif getattr(recipient, "is_channel", False):
            if user is not None:
                reply = "%s: %s" % (user.nick, reply)
            self.msg(recipient.name, reply)
        else:
            assert False

    def send_and_log(self, recipient, user, reply):
        if getattr(recipient, "is_user", False):
            self.msg(recipient.nick, reply)
            self.logger.log("[%s] <%s> %s" % (recipient.nick, self.nickname, reply))
        elif getattr(recipient, "is_channel", False):
            if user is not None:
                reply = "%s: %s" % (user.nick, reply)
            self.msg(recipient.name, reply)
            self.logger.log("[%s] <%s> %s" % (recipient.name, self.nickname, reply))
        else:
            assert False
   
    def relay(self, message, channel=None, action=False, user=None, relateduser=None, chat=True, exclude=[], globalrelay=False, notifyfriends=False):
        """This will relay something to all related channels."""
        if channel == None:
            for channel in self.channels.itervalues():
                try:
                    if str(channel).split("_")[1]:
                        pass
                except IndexError:
                    self.relay(message=message, channel=channel, action=action, user=user, relateduser=relateduser, chat=chat, exclude=exclude, globalrelay=True, notifyfriends=notifyfriends)
        else:
            excluded = []
            for excluding in exclude:
                excluded.append(excluding)
            if user != None:
                for checkignore in self.check_for_master(user).ignoredby:
                    if not checkignore in excluded:
                        excluded.append(checkignore)
            if relateduser != None:
                for checkignore in self.check_for_master(relateduser).ignoredby:
                    if not checkignore in excluded:
                        excluded.append(checkignore)
            if str(channel).split("_")[0]:
                basechannel = Channel(str(channel).split("_")[0])
            for relaychannel in self.channels.itervalues():
                if str(relaychannel).startswith("%s_" % basechannel) and str(relaychannel) != str(channel) and not relaychannel in excluded:
                    messagetosend = message
                    if notifyfriends:
                        friends = []
                        for possiblefriend in relaychannel.users:
                            if relateduser.nick in possiblefriend.friends:
                                friends.append(possiblefriend)
                        if friends:
                            messagetosend = "%s (This is a friend of you, %s)" % (message, join_and(", ", " and ", friends))
                    if action:
                        if chat:
                            self.send(relaychannel, None,
                                "* %s %s" % (user.nick, messagetosend))
                        else:
                            self.send(relaychannel, None,
                                "[INFO] * %s %s" % (user.nick, messagetosend))
                    else:
                        if user:
                            if chat:
                                self.send(relaychannel, None,
                                    "<%s> %s" % (user.nick, messagetosend))
                            else:
                                self.send(relaychannel, None,
                                    "[INFO] <%s> %s" % (user.nick, messagetosend))
                        else:
                            if chat:
                                self.send(relaychannel, None,
                                    messagetosend)
                            else:
                                self.send(relaychannel, None,
                                    "[INFO] %s" % messagetosend)
            if (str(basechannel) != str(channel) or (globalrelay and not channel in excluded)) and is_channel_name(str(channel)):
                if self.get_settings().maindisabled:
                    # If the main channel is disabled, don't relay to there.
                    return
                messagetosend = message
                if notifyfriends:
                    friends = []
                    for possiblefriend in relaychannel.users:
                        if relateduser.nick in possiblefriend.friends:
                            friends.append(possiblefriend)
                    if friends:
                        messagetosend = "%s (This is a friend %s)" % (message, join_and(", ", " and ", friends))
                if action:
                    if chat:
                        self.send(basechannel, None,
                            "* %s %s" % (user.nick, messagetosend))
                    else:
                        self.send(basechannel, None,
                            "[INFO] * %s %s" % (user.nick, messagetosend))
                else:
                    if user:
                        if chat:
                            self.send(basechannel, None,
                                "<%s> %s" % (user.nick, messagetosend))
                        else:
                            self.send(basechannel, None,
                                "[INFO] <%s> %s" % (user.nick, messagetosend))
                    else:
                        if chat:
                            self.send(basechannel, None,
                                messagetosend)
                        else:
                            self.send(basechannel, None,
                                "[INFO] %s" % messagetosend)

    def claimNick(self):
        """ This makes sure the bot will eventually get the nickname it wants. """
        if self.nickname != self.wantednick:
            if self.identify:
                self.msg('NickServ',
                    'GHOST %s %s' % (self.wantednick, self.identifypassword))
            self.setNick(self.wantednick)
            if self.identify:
                self.msg('NickServ',
                    'IDENTIFY %s' % self.identifypassword)

    def checkAway(self, user=None):
        """This checks if someone is away by calling WHO."""
        if user is None:
            # Check all users!
            self.sendLine("WHO 0")
        else:
            # Check a single user.
            self.sendLine("WHO %s" % user)

    def purgeOldNicks(self):
        """ This gets rid of user entries in the database for nicknames 
            which haven't been used in the last 30 days """
        for user in self.users.values()[:]:
            # Don't purge admins or accounts explicitly marked as do-not-purge
            if not user.admin and user.autopurge and (datetime.datetime.now() - user.lastlogout).days > 30:
                useronline = False
                for channel in self.channels:
                    if user in self.get_channel(channel).users:
                        useronline = True
                if not useronline:
                    if user.channel:
                        self.dispatch(command='unset channel', user=user, reply_to=user, bypass=True)
                    del self.users[user.nick]
    
    def purgeOldLogs(self):
        """ This gets rid of admin logs older than 30 days """
        for user in self.users:
            user = self.get_user(user)
            for logdate in user.logs.keys():
                if (datetime.datetime.now() - logdate).days > 30:
                    del user.logs[logdate]
                    self.__dirty = True

    def purgeOldMessages(self):
        """ This gets rid of user messages older than the defined limit """
        for user in self.users:
            user = self.get_user(user)
            for messagedate in user.messages.keys():
                if (datetime.datetime.now() - messagedate).days > user.messagestoretime:
                    del user.messages[messagedate]
                    if messagedate in user.readmessages:
                        user.readmessages.remove(messagedate)
                    self.__dirty = True

    def irc_RPL_WHOREPLY(self, prefix, params):
        (my_nick, channel, username, hostmask, server,
            nickname, flags, hops_and_realname) = params
        hops, realname = hops_and_realname.split(" ", 1)
        user = self.get_user(nickname)
        master = self.check_for_master(user)
        user.host = hostmask
        # Check identified status
        if "r" in flags and master.nickservlogin:
            user.logged_in = True
        # Check away status
        if "H" in flags:
            user.away = False
            if master.channel and master.autosilence:
                for channel in self.channels:
                    if not channel.endswith("_%s" % str(master).lower()):
                        continue
                    channel = self.get_channel(channel)
                    if "silent" in channel.mode:
                        self.dispatch(command="mode remove silent auto", user=user, reply_to=channel, bypass=True)
        elif "G" in flags:
            if not master.awaycheck:
                return
            user.away = True
            if master.channel and master.topics and master.autosilence:
                for channel in self.channels:
                    if not channel.endswith("_%s" % str(master).lower()):
                        continue
                    channel = self.get_channel(channel)
                    # Only silence a channel if all its users are away.
                    allaway = True
                    for usercheck in channel.users:
                        if usercheck.nick in ["ChanServ", "NickServ", self.nickname]:
                            continue
                        if not usercheck.away:
                            allaway = False
                            break
                    if allaway and not "silent" in channel.mode:
                        self.dispatch(command="mode add silent auto", user=user, reply_to=channel, bypass=True)

    def irc_RPL_ENDOFWHO(self, prefix, params):
        self.update_rules()

    def irc_RPL_TOPIC(self, prefix, params):
        self.irc_TOPIC(prefix, params)

    def irc_TOPIC(self, prefix, params):
        if len(params) > 2: # Yay, dealing with irc_TOPIC and irc_RPL_TOPIC inconsistencies
            channel = self.get_channel(params[1])
            topic = params[2]
            changer = params[0]
        else:
            channel = self.get_channel(params[0])
            topic = params[1]
            changer = prefix.split("!")[0]
        if changer == self.nickname:
            setattr(channel, "topic", topic)
        else:
            setattr(channel, "topicset", topic)

    def userRenamed(self, oldnick, newnick):
        self.logger.log("%s is now known as %s." % (oldnick, newnick))
        olduser = self.get_user(oldnick)
        newuser = self.get_user(newnick)
        self.check_for_master(olduser).seen = datetime.datetime.now()
        self.check_for_master(newuser).seen = datetime.datetime.now()
        relayedchannels = []
        for channel in self.channels.itervalues():
            if olduser in channel.users:
                channel.users.remove(olduser)
                channel.users.add(newuser)
                if not str(channel).split("_")[0] in relayedchannels:
                    self.relay("%s is now known as %s." % # TODO: Fake join/quit when old/new nick is on ignore list
                        (oldnick, newnick), channel, chat=False)
                    relayedchannels.append(str(channel).split("_")[0])

    # This code is used to get a list of people there.
    def irc_RPL_NAMREPLY(self, prefix, params):
        "Receive NAMES reply from server"
        my_user, _, channel, nicks = params
        channel = self.get_channel(channel)
        for nick in nicks.split():
            nick = re.sub(r'^[~&@%+]', "", nick)
            if nick != self.nickname:
                user = self.get_user(nick)
                channel.users.add(user)

    def irc_RPL_ENDOFNAMES(self, prefix, params):
        "We know everyone. List admins and rules"
        my_user, channel, _ = params
        channel = self.get_channel(channel)
        self.logger.log("[%s] NAMES: %s" % (channel.name,
            " ".join(user.nick for user in channel.users)))
        reactor.callLater(10, self.update_rules, channel=channel)

    def userJoined(self, nick, channel):
        self.logger.log("[%s] %s has joined." % (channel, nick))
        user = self.get_user(nick, create_if_nonexistent=False)
        joinchannel = self.get_channel(channel)
        users = []
        for onlineuser in self.get_channel(str(channel).split("_")[0]).users:
            users.append(onlineuser.nick)
        for relaychannel in self.channels.itervalues():
            try:
                if str(relaychannel).split("_")[1]:
                    if str(relaychannel).split("_")[0] == str(channel).split("_")[0]:
                        for onlineuser in relaychannel.users:
                            if not onlineuser.nick in users:
                                users.append(onlineuser.nick)
            except IndexError:
                pass
        if user == None:
            user = self.get_user(nick)
            self.send_and_log(joinchannel, user,
                "Hello, %s! I haven't seen you before. If you want, you can take a tutorial on how to best use %s by typing '!tutorial'."
                    % (user, self.nickname))
        elif user.nick in ["NickServ", "ChanServ"]:
            # This ensures that we'll identify to services after they recover from a crash, assuming ChanServ joins our channel
            if self.identify == True:
                self.msg('NickServ',
                    'IDENTIFY %s' % self.identifypassword)
        elif len(user.messages) > len(user.readmessages):
            self.send_and_log(joinchannel, user,
                "You have unread messages. Please check them using '!mail inbox unread'.")
        if (not "_" in channel and not self.get_settings().maindisabled) or ("_" in channel and not "silent" in joinchannel.mode):
            if not nick in users:
                self.relay("%s has joined." % nick, joinchannel, relateduser=self.find_user(nick), chat=False, notifyfriends=True)
            joinchannel.users.add(user)
        elif self.get_settings().maindisabled:
            if not user.channel:
                self.dispatch(command="set channel", user=user, reply_to=joinchannel, bypass=True)
            self.send_and_log(joinchannel, user, "The main channel has been disabled. Please join %s_%s to chat in this channel." % (joinchannel, str(user).lower()))
        if "_" in channel and user.nick not in ["NickServ", "ChanServ"]:
            self.dispatch(command="names", user=None, reply_to=joinchannel)
        self.check_for_master(user).seen = datetime.datetime.now()
        self.checkAway(user=user)

    def userLeft(self, nick, channel):
        self.logger.log("[%s] %s has left." % (channel, nick))
        user = self.get_user(nick)
        master = self.check_for_master(user)
        leavechannel = self.get_channel(channel)
        try:
            leavechannel.users.remove(user)
        except KeyError:
            return
        stillonline = False
        hideleave = False
        for channel in self.channels.itervalues():
            if user in channel.users:
                if not "silent" in channel.mode:
                    stillonline = True
                else:
                    hideleave = True
        if not stillonline:
            if not hideleave:
                self.relay("%s has left." % nick, leavechannel, relateduser=user, chat=False)
            if master.autologout:
                user.logged_in = False
        self.update_rules(channel=channel)
        master.seen = datetime.datetime.now()
        user.lastlogout = datetime.datetime.now()

    def userQuit(self, nick, message):
        self.logger.log("%s has quit (%s)." % (nick, message))
        user = self.get_user(nick)
        exclude = []
        for channel in self.channels.itervalues():
            channel.users.discard(user)
            if user in channel.users or ("_" in channel and "silent" in channel.mode):
                exclude.append(channel)
        if not message.startswith("Quit: "):
            self.relay("%s has quit (%s)." % (nick, message), relateduser=user, chat=False, exclude=exclude)
        else:
            self.relay("%s has quit." % nick, relateduser=user, chat=False, exclude=exclude)
        master = self.check_for_master(user)
        master.seen = datetime.datetime.now()
        user.lastlogout = datetime.datetime.now()
        if master.autologout:
            user.logged_in = False

    def userKicked(self, kicked, channel, kicker, message):
        try:
            oldmessage = message
            message = message.split(": ")[1]
            kicker = oldmessage.split(": ")[0]
        except IndexError:
            pass
        self.logger.log("[%s] %s was kicked by %s (%s)." %
            (channel, kicked, kicker, message))
        channel = self.get_channel(channel)
        try:
            channel.users.remove(self.get_user(kicked))
        except KeyError:
            return
        users = []
        for onlineuser in self.get_channel(str(channel).split("_")[0]).users:
            users.append(onlineuser.nick)
        for relaychannel in self.channels.itervalues():
            try:
                if str(relaychannel).split("_")[1]:
                    if str(relaychannel).split("_")[0] == str(channel).split("_")[0] and relaychannel != channel:
                        for onlineuser in relaychannel.users:
                            if not onlineuser.nick in users:
                                users.append(onlineuser.nick)
            except IndexError:
                pass
        if not kicked in users:
            self.relay("%s has left (kicked by %s)." %
                (kicked, kicker), channel, relateduser=self.find_user(kicked), chat=False)
        else:
            self.relay("%s was kicked by %s." %
                (kicked, kicker), channel, relateduser=self.find_user(kicked), chat=False)
        self.update_rules(channel=channel)
        user = self.get_user(kicked)
        self.check_for_master(user).seen = datetime.datetime.now()
        user.lastlogout = datetime.datetime.now()

    def irc_RPL_AWAY(self, prefix, params):
        nick = params[1]
        self.get_user(nick).away = True
        self.update_rules()

def admin_command(f):
    def wrapper(bot, params, user, recipient, mainchannel, bypass=False):
        master = bot.check_for_master(user)
        # This 'commandcores' silliness is to allow users to execute all subcommands of allowed commands
        commandcores = []
        for x in range(1, len(wrapper.__name__.split("_"))+1):
            commandcores.append("_".join(wrapper.__name__.split("_")[:x]))
        if not master.admin and not any(commandcore in master.admincommandsallowed for commandcore in commandcores):
            bot.send_and_log(recipient, user,
                "You are not authorized to use this command.")
        else:
            return f(bot, params, user, recipient, mainchannel, bypass)
    wrapper.__name__ = f.__name__
    return wrapper

def channelmod_command(f):
    def wrapper(bot, params, user, recipient, mainchannel, bypass=False):
        master = bot.check_for_master(user)
        if not is_channel_name(str(mainchannel)):
            bot.send_and_log(recipient, user,
                "This command needs to be executed in-channel, or given the channel name as first parameter. Please run it in either a main or triggersafe channel, or give the channel name.")
        elif not master.nick in mainchannel.admins and not master.admin:
            bot.send_and_log(recipient, user,
                "You are not authorized to use this command.")
        else:
            return f(bot, params, user, recipient, mainchannel, bypass)
    wrapper.__name__ = f.__name__
    return wrapper

def toggleable_command(f):
    def wrapper(bot, params, user, recipient, mainchannel, bypass=False):
        commandcores = []
        for x in range(1, len(wrapper.__name__.split("_"))+1):
            commandcores.append("_".join(wrapper.__name__.split("_")[:x]))
        if any(commandcore in bot.get_settings().disabledcommands for commandcore in commandcores):
            bot.send_and_log(recipient, user,
                "This command has been disabled by an administrator.")
        else:
            return f(bot, params, user, recipient, mainchannel, bypass)
    wrapper.__name__ = f.__name__
    return wrapper

def protected_command(f):
    def wrapper(bot, params, user, recipient, mainchannel, bypass=False):
        master = bot.check_for_master(user)
        if not bypass and master.password != None and user.logged_in != True:
            raise AuthenticationError
        else:
            return f(bot, params, user, recipient, mainchannel, bypass)
    wrapper.__name__ = f.__name__
    return wrapper

def logged_command(f):
    def wrapper(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.logs[datetime.datetime.now()] = [mainchannel, "%s %s" % (" ".join(wrapper.__name__.split("_")), " ".join(params))]
        return f(bot, params, user_executed, recipient, mainchannel, bypass)
    wrapper.__name__ = f.__name__
    return wrapper

def register_commands():
    """All the commands are defined in here"""
    command = TriggerBot.add_command

    @command("Lists the bot admins that are currently online.\n"
             "admins")
    @toggleable_command
    def admins(bot, params, user_executed, recipient, mainchannel, bypass=False):
        avail_admins = [user.nick for channel in bot.channels.itervalues()
                        for user in channel.users
                        if not user.away and (user.admin or (user.nick in mainchannel.admins and str(mainchannel) == str(channel).split("_")[0]))]
        unavail_admins = [user.nick for user in bot.users.itervalues()
                          if (user.admin or user.nick in mainchannel.admins) and user.nick not in avail_admins]
        if avail_admins:
            bot.send_and_log(recipient, user_executed,
                "The following people are currently available: "
                + ", ".join(["%s (%s)" % (user.nick, "head admin" if user.admin == 1 else ("admin" if user.admin else "channel admin")) for user in bot.users.itervalues() if user.nick in avail_admins]))
        else:
            bot.send_and_log(recipient, user_executed,
                "Nobody is currently available.")
        if unavail_admins:
            bot.send_and_log(recipient, user_executed,
                "The following people are currently unavailable: "
                + ", ".join(["%s (%s)" % (user.nick, "head admin" if user.admin == 1 else ("admin" if user.admin else "channel admin")) for user in bot.users.itervalues() if user.nick in unavail_admins]))

    @command("Anonymously request a topic change.\n"
             "change [<channel>]")
    @toggleable_command
    def change(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            channel = bot.get_channel(params[0])
            if not is_channel_name(channel.name):
                channel.name = "#%s" % channel.name
        else:
            channel = recipient
            if not getattr(channel, "is_channel", False):
                bot.send_and_log(recipient, user,
                    "Please specify a channel to request a topic change for.")
                return
        bot.relay_safe(message="Someone is feeling uncomfortable with this disussion. Could we talk about something else?", channel=channel)
        bot.notifyAdmins(mainchannel, "%s issued !change for %s. Please ensure everyone is sticking to the rules." % (user, channel))

# TODO: Add channel mod commands here

    @command("Manage a channel.\n"
             "channel")
    def channel(bot, params, user_executed, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more users as channel administrator (admin).\n"
             "channel add <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            for nick in params:
                nick = bot.find_user(nick)
                master = bot.check_for_master(nick)
                if master.nick not in mainchannel.admins:
                    mainchannel.admins.append(master.nick)
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) now have channel administrator status.")
            bot.changed()
        else:
            raise MissingParams

    @command("Remove the channel administrator status from one or more users.\n"
             "channel remove <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            for nick in params:
                if nick in mainchannel.admins:
                    mainchannel.admins.remove(nick)
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) no longer have channel administrator status.")
            bot.changed()
        else:
            raise MissingParams

    @command("Sent an announcement to all users in the channel.\n"
             "channel announce <message>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_announce(bot, params, user, recipient, mainchannel, bypass=False):
        if params:
            for channel in bot.channels.itervalues():
                if str(channel) == str(mainchannel) or str(channel).startswith("%s_" % mainchannel):
                    bot.notice(channel,
                        "Announcement from %s: %s" %
                            (user.nick, " ".join(params)))
        else:
            raise MissingParams

    @command("Order the bot to kick someone out.\n"
             "channel kick <user> [<reason>]")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_kick(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        for channel in bot.channels.itervalues():
            if str(channel) == str(mainchannel) or str(channel).startswith("%s_" % mainchannel):
                bot.kick(str(channel), params[0], "%s: %s" % (user, params[1:] if len(params) >= 2 else "no reason specified."))

    @command("Order the bot to ban an user.\n"
             "channel ban <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_ban(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        toban = bot.get_user(params[0])
        for channel in bot.channels.itervalues():
            if str(channel) == str(mainchannel) or str(channel).startswith("%s_" % mainchannel):
                bot.mode(chan=str(channel), set=True, modes="b", mask="*!*@%s" % toban.host)
   
    @command("Remove the ban on an user.\n"
             "channel unban <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_unban(bot, params, user, recipient, mainchannel, bypass=False):
        tounban = bot.get_user(params[0])
        for channel in bot.channels.itervalues():
            if str(channel) == str(mainchannel) or str(channel).startswith("%s_" % mainchannel):
                bot.mode(chan=str(channel), set=False, modes="b", mask="*!*@%s" % tounban.host)

    @command("Order the bot to kickban an user.\n"
             "channel kickban <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_kickban(bot, params, user, recipient, mainchannel, bypass=False):
        bot.dispatch(command="channel kick %s" % ' '.join(params), user=user, reply_to=recipient, bypass=True)
        bot.dispatch(command="channel ban %s" % ' '.join(params), user=user, reply_to=recipient, bypass=True)

    @command("View channel logs.\n"
             "By default, the 10 latest entries are displayed. Type a number or 'all' to see more entries.\n"
             "channel logs [<user>] [<entries>]")
    @channelmod_command
    @protected_command
    def channel_logs(bot, params, user_executed, recipient, mainchannel, bypass=False):
        start = -10
        tosend = []
        timelength = 4
        userlength = 4
        users = []
        if params:
            for param in params:
                try:
                    users.append(bot.find_user(param))
                except UserNotFound:
                    if param == "all":
                        start = 0
                    else:
                        try:
                            start = -int(param)
                        except ValueError:
                            raise UserNotFound(param)
        if not users:
            users = bot.users.itervalues()
        logs = {}
        for user in users:
            for log in user.logs.keys():
                if user.logs[log][0] != mainchannel:
                    # Not related to this channel. Ignore
                    continue
                logs[log] = user.nick, user.logs[log]
        if not logs:
            bot.send_and_log(recipient, user_executed,
                "No logs were found for %s" % join_and(", ", " and ", users))
            return
        if start < 0 and -start < len(logs):
            bot.send_and_log(recipient, user_executed,
                "Limiting output to the most recent %s of %s entries." % (-start, len(logs)))
        else:
            bot.send_and_log(recipient, user_executed,
                "Showing all %s entries." % len(logs))
        sorted_logs = sorted(logs.keys())[start:]
        for log in sorted_logs:
            # Time | User | Command
            time = log.strftime("%Y-%m-%d %H:%M:%S")
            user = logs[log][0]
            command = logs[log][1][1]
            tosend.append("%s | %s | %s" % (time, user, command))
            if len(time) > timelength:
                timelength = len(time)
            if len(user) > userlength:
                userlength = len(user)
        bot.send_and_log(recipient, user_executed,
           "%s | %s | command" % ("time".center(timelength), "user".center(userlength)))
        for abouttosend in tosend:
            abouttosend = "%s | %s | %s" % (abouttosend.split(" | ")[0].center(timelength), abouttosend.split(" | ")[1].center(userlength), abouttosend.split(" | ")[2])
            bot.send_and_log(recipient, user_executed, abouttosend)

    @command("Manage trigger topic blocks in channel.\n"
             "channel topicblock")
    def channel_topicblock(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Block users with a certain trigger topic set.\n"
             "channel topicblock add <topic> <level>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_topicblock_add(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) % 2:
            raise WrongParamCount
        number = 0
        while number < len(params)-1:
            try:
                if not int(params[number+1]) in bot.find_topic(params[number].lower()).descriptions.keys():
                    bot.send_and_log(recipient, user, "Topic %r does not have a level %r" % (params[number], params[number+1]))
                    return
            except ValueError:
                bot.send_and_log(recipient, user, "Please enter a number for topic level")
                return
            mainchannel.blockedtopics[params[number]] = int(params[number+1])
            number += 2
        bot.send_and_log(recipient, user,
            "The requested topics are now blocked")
        bot.changed()

    @command("Unblock one or more trigger topics.\n"
             "channel topicblock remove <topic>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_topicblock_remove(bot, params, user, recipient, mainchannel, bypass=False):
        for param in params:
            del mainchannel.blockedtopics[param]
        bot.send_and_log(recipient, user,
            "The requested topics are no longer blocked")
        bot.changed()

    @command("List blocked trigger topics.\n"
             "channel topicblock list")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_topicblock_list(bot, params, user, recipient, mainchannel, bypass=False):
        # FIXME: Format this nicely
        bot.send_and_log(recipient, user, mainchannel.blockedtopics)

    @command("Warn an user.\n"
             "channel warn <user> [<reason>]")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_warn(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.find_user(params[0])
            user.warnings[datetime.datetime.now()] = mainchannel, user_executed.nick, str(" ".join(params[1:])) if len(params) > 1 else None
            warningsbytriggerbot = 0
            for entry in user.warnings.keys():
                if user.warnings[entry][1] == None:
                    warningsbytriggerbot = warningsbytriggerbot + 1
            if user.warnings[entry][2:] == None:
                bot.send_and_log(user, None,
                    "%s has sent you a warning."
                        % user.warnings[entry][1])
            else:
                bot.send_and_log(user, None,
                    "%s has sent you a warning with the following reason: %s."
                        % (user.warnings[entry][1], user.warnings[entry][2]))
            bot.send_and_log(user, None,
                "Please think about your behaviour and try to improve it.")
            bot.send_and_log(user, None, 
                "For your information, you currently have %s warning(s), of which %s were automatically sent to you by %s." %
                (len(user.warnings), warningsbytriggerbot, bot.nickname))
        else:
            raise MissingParams

    @command("Manage an user's warnings.")
    @channelmod_command
    @protected_command
    def channel_warnings(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand
    
    @command("List the amount of warnings an user has in this channel.\n"
             "Use 'verbose' to receive a more verbose list.\n"
             "By default, only the last 10 entries are shown in verbose mode. Type a number on 'all' to show more entries.\n"
             "channel warnings list <user> [<type>] [<entries>]")
    @channelmod_command
    @protected_command
    def channel_warnings_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.find_user(params[0])
            warnings = {}
            for entry in user.warnings.keys():
                if user.warnings[entry][0] == mainchannel:
                    warnings[entry] = user.warnings[entry]
            if len(warnings) > 0:
                if len(params) <= 1 or params[1] != "verbose":
                    warningsbyuser = {}
                    for entry in warnings.keys():
                        warner = warnings[entry][1] if warnings[entry][1] != None else bot.nickname
                        if warner in warningsbyuser:
                            warningsbyuser[warner] = warningsbyuser[warner] + 1
                        else:
                            warningsbyuser[warner] = 1
                    bot.send_and_log(recipient, user_executed,
                        "Since %s, %s has received %s warning(s) in this channel (%s total). %s." %
                            (warnings.keys()[0].strftime("%Y-%m-%d %H:%M:%S"), user.nick, len(warnings.keys()), len(user.warnings.keys()), ', '.join(["%s by %s" % 
                            (warningdata[1], warningdata[0]) for warningdata in warningsbyuser.items()])))
                else:
                    if user.warnings:
                        start = len(warnings)-10
                        try:
                            if params[2] == "all":
                                start = 0
                            else:
                                try:
                                    start = len(warnings)-int(params[2])
                                except:
                                    pass
                        except:
                            pass
                        if start > 0:
                            bot.send_and_log(recipient, user_executed,
                                "Limiting output to the most recent %s of %s entries." % (len(warnings)-start, len(warnings)))
                        else:
                            bot.send_and_log(recipient, user_executed,
                                "Showing all %s entries." % len(warnings))
                    for number, warning in enumerate(warnings.keys()[start:]):
                        bot.send_and_log(recipient, user_executed,
                            "%s - warned by %s: %s"
                                % (warnings.keys()[number].strftime("%Y-%m-%d %H:%M:%S"), bot.nickname if warnings[warning][1] == None else warnings[warning][1], "No reason specified." if warnings[warning][2] == None else warnings[warning][2]))
            else:
                bot.send_and_log(recipient, user_executed,
                   "%s has not received any warnings%s." % (user, " in this channel" if user.warnings else ""))
        else:
            raise MissingParams

    @command("Reset one or more users' warnings in this channel.\n"
             "channel warnings reset <user>")
    @channelmod_command
    @protected_command
    @logged_command
    def channel_warnings_reset(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            for nick in params:
                user = bot.find_user(nick)
                warnings = {}
                for entry in user.warnings.keys():
                    if user.warnings[entry][0] != mainchannel:
                        warnings[entry] = user.warnings[entry]
                user.warnings = warnings
            bot.send_and_log(recipient, user_executed,
                "Warnings reset.")
        else:
            raise MissingParams

# TODO: End channel mod commands here

    @command("Manage nicks allowed in your channel.\n"
             "Nicks on this list will not be kicked from your channel, even if they are not in your alt list.")
    @toggleable_command
    def channelallow(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more user(s) to your channelallow list."
             "channelallow add <user>")
    @protected_command
    @toggleable_command
    def channelallow_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry not in user.channelallow and entry != user_executed.nick and entry != user.nick and entry not in user.alts:
                    user.channelallow.append(entry)
                    for channel in bot.channels.itervalues():
                        if str(channel).endswith("_%s" % user.nick):
                            self.mode(channel, True, "I %s!*@*" % allowed) # Add an invite-only exception
            bot.send_and_log(recipient, user_executed,
                "The requested users were added to your channelallow list.")
            bot.changed()
        else:
            raise MissingParams

    @command("Remove one or more user(s) from your channelallow list."
             "channelallow remove <user>")
    @protected_command
    @toggleable_command
    def channelallow_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry in user.channelallow:
                    user.channelallow.remove(entry)
                    for channel in bot.channels.itervalues():
                        if str(channel).endswith("_%s" % user.nick):
                            self.mode(channel, False, "I %s!*@*" % allowed) # Remove the invite-only exception
            bot.send_and_log(recipient, user_executed,
                "The requested users are no longer on your channelallow list.")
            bot.changed()
        else:
            raise MissingParams

    @command("List your channelallow list."
             "channelallow list")
    @toggleable_command
    def channelallow_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        userdata = bot.check_for_master(user_executed)
        if userdata.channelallow:
            bot.send_and_log(recipient, user_executed,
                "You allow the following nicks on your channel: %s."
                    % join_and(", ", " and ", userdata.channelallow))
        else:
            bot.send_and_log(recipient, user_executed,
                "You don't allow any additional nicks on your channel.")

    @command("Copy someone else's trigger topics and trigger words.\n"
             "clone <nick> - Copies nick's trigger topics and trigger words to your nick.")
    @protected_command
    @toggleable_command
    def clone(bot, params, user_executed, recipient, mainchannel, bypass=False):
        source_user = bot.check_for_master(bot.find_user(params[0]))
        user = bot.check_for_master(user_executed)
        user.trigger_words.update(source_user.trigger_words)
        for topic, level in source_user.topics.iteritems():
            user.topics[topic] = max(user.topics.get(topic, 0), level)
        bot.changed()
        bot.send_and_log(recipient, user_executed, "It is done.")
        bot.update_rules()

    @command("Manage your friends.\n"
             "When someone on your friend list joins, you will get a notification. They will also be the first to be alerted by the 'panic' feature.")
    @toggleable_command
    def friend(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more user(s) to your friend list."
             "friend add <user>")
    @protected_command
    @toggleable_command
    def friend_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry not in user.friends and entry != user_executed.nick and entry != user.nick and entry not in user.alts:
                    user.friends.append(entry)
            bot.send_and_log(recipient, user_executed,
                "The requested users were added to your friend list.")
            bot.changed()
        else:
            raise MissingParams

    @command("Remove one or more user(s) from your friend list."
             "friend remove <user>")
    @protected_command
    @toggleable_command
    def friend_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry in user.friends:
                    user.friends.remove(entry)
            bot.send_and_log(recipient, user_executed,
                "The requested users are no longer on your friend list.")
            bot.changed()
        else:
            raise MissingParams

    @command("List your own or someone else's friend list."
             "friend list <user>")
    @toggleable_command
    def friend_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user_to_check = bot.find_user(params[0])
        else:
            user_to_check = user_executed
        userdata = bot.check_for_master(user_to_check)
        if userdata.friends:
            bot.send_and_log(recipient, user_executed,
                "%s has the following friends set: %s."
                    % (user_to_check, join_and(", ", " and ", userdata.friends)))
        else:
            bot.send_and_log(recipient, user_executed,
                "%s has no friends set."
                    % user_to_check)

    @command("Group usernames together.")
    @toggleable_command
    def group(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Set the main username this account should belong to. A password needs to be specified if the main username is protected.\n"
             "group add <accountname> <password>")
    @protected_command
    @toggleable_command
    def group_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.find_user(params[0])
            if user_executed != user:
                if not user_executed.alts:
                    if str(user.master) != None:
                        if not user_executed.nick in user.alts:
                            if user.password and not bcrypt.hashpw(' '.join(params[1:]), user.password) == user.password:
                                bot.send_and_log(recipient, user_executed,
                                    "The account you wanted to group with is password protected, and the password entered did not match.")
                                return
                            else:
                                user.alts.append(user_executed.nick)
                        else:
                            bot.send_and_log(recipient, user_executed,
                                "This account is already an alt of %s."
                                    % params[0])
                            return
                        if user_executed.master and user_executed.master != user.nick:
                            master = bot.find_user(user_executed.master)
                            if user_executed.nick in master.alts:
                                master.alts.remove(user_executed.nick)
                        user_executed.master = params[0]
                    else:
                        bot.send_and_log(recipient, user_executed,
                            "%s is already an alt. You can only link an alt to an account which is not an alt itself."
                                % user.nick)
                        return
                    bot.changed()
                    bot.send_and_log(recipient, user_executed,
                        "You are now registered as an alt of %s."
                            % params[0])
                else:
                    bot.send_and_log(recipient, user_executed,
                        "This account already has alts. It cannot become an alt itself.")
            else:
                # There always is that person who likes to see if they can break stuff...
                bot.send_and_log(recipient, user_executed,
                    "You cannot link yourself with yourself.")
        else:
            raise MissingParams

    @command("Remove the alt status from this account.\n"
             "group remove")
    @protected_command
    @toggleable_command
    def group_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if user_executed.master:
            user = bot.find_user(user_executed.master)
            altlist = user.alts
            if user_executed.nick in altlist:
                altlist.remove(user_executed.nick)
                user.alts = altlist
            user_executed.master = None
        else:
            altlist = user_executed.alts
            for user in altlist:
                user = bot.find_user(user)
                user.master = None
            user_executed.alts = []
        bot.changed()
        bot.send_and_log(recipient, user_executed,
            "This account is no longer grouped.")

    @command("List alts and master data."
             "group list <accountname>")
    @toggleable_command
    def group_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.find_user(params[0])
        else:
            user = user_executed
        master = ""
        group = []
        master = bot.check_for_master(user)
        if master != user:
            group += master.alts
            if user in group:
                group.remove(user)
            master = master.nick
        else:
            if master.alts:
                group += master.alts
        if master != user and len(group) > 1:
            bot.send_and_log(recipient, user_executed,
                "%s belongs to a group owned by %s, together with %s."
                    % (user, master,
                       join_and(", ", " and ", group)))
        elif master != user:
            bot.send_and_log(recipient, user_executed,
                "%s is the only alt of %s."
                    % (user, master))
        elif group:
            bot.send_and_log(recipient, user_executed,
                "%s is the leader of a group containing %s."
                    % (user,
                        join_and(", ", " and ", group)))
        else:
            bot.send_and_log(recipient, user_executed,
                "%s is not in any group."
                    % user)

    @command("Lists the available commands.\n"
             "help")
    @toggleable_command
    def help(bot, params, user, recipient, mainchannel, bypass=False):
        disabledcommands = bot.get_settings().disabledcommands
        subcommand_doc = []
        for subcommand, description in bot.subcommands(params):
            if params:
                checkfor = "%s_%s" % ("_".join(params), subcommand)
            else:
                checkfor = subcommand
            if checkfor in disabledcommands:
                continue
            subcommand_doc.append("    %s - %s" %
                (subcommand,
                 description.split("\n", 1)[0]
                    if description else "(no description)"))
        subcommand_doc.sort()
        if params:
            for commandcore in range(1, len(params)+1):
                if "_".join(params[:commandcore]) in disabledcommands:
                    raise CommandNotFound(" ".join(params))
            lines = []
            try:
                description = bot.command_description(params)
            except KeyError:
                raise CommandNotFound(" ".join(params))
            if description is not None:
                lines += (" ".join(params) + " - " + description).split("\n")
            if subcommand_doc:
                lines += ["'%s' has the following sub-commands:" % " ".join(params)] \
                      + subcommand_doc \
                      + ["Use 'help %s <sub-command>' for more information"
                         " about a particular sub-command." % " ".join(params)]
        else:
            lines = ["The following commands are available:"] \
                  + subcommand_doc \
                  + ["Use 'help <command>' to show information about a particular command."]
        for line in lines:
            bot.send_and_log(user, user, line)

    @command("Tell the bot you're being helped.\n"
             "helped")
    def helped(bot, params, user_executed, recipient, resethelp=False, bypass=False):
        user = bot.check_for_master(user_executed)
        if not resethelp:
            user.helped = True
            reactor.callLater(120, helped, bot=bot, params=params, user_executed=user_executed, recipient=recipient, resethelp=True)
            bot.send_and_log(recipient, user_executed, "I'm glad you're being helped. Please, feel better soon!")
        else:
            user.helped = False

    @command("Gives someone a hug!\n"
             "hug")
    def hug(bot, params, user, recipient, mainchannel, bypass=False):
        if params:
            huggee = " ".join(params)
            if huggee.lower() == "me":
                huggee = user
        else:
            huggee = user
        templates = [
            "slowly and softly puts its arms around %s and hugs them.",
            "glomps %s.",
            "wraps %s in bot arms and squeezes gently.",
            "cuddles %s like a plushie."
        ]
        message = random.choice(templates) % huggee
        bot.describe(recipient, message)
        bot.logger.log("[%s] * %s %s" % (recipient, bot.nickname, message))

    @command("Log in to a password-protected account.\n"
             "Required to make changes to the account trigger topics, trigger words or settings if protected.\n"
             "identify <password>")
    @toggleable_command
    def identify(bot, params, user, recipient, mainchannel, bypass=False):
        master = bot.check_for_master(user)
        if master.password != None:
            if bcrypt.hashpw(' '.join(params), master.password) == master.password:
                bot.send_and_log(recipient, user,
                    "You are now logged in.")
                user.logged_in = True
            else:
                bot.send_and_log(recipient, user,
                    "Sorry, but the password you entered is incorrect. Please try again.")
        else:
            bot.send_and_log(recipient, user,
                "This username is not protected.")

    @command("Manage your ignore list.")
    def ignore(bot, params, user_executed, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more users to your ignore list.\n"
             "ignore add <user>")
    def ignore_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for param in params:
                ignored = bot.check_for_master(bot.find_user(param))
                if not ignored.nick in user.ignore:
                    user.ignore.append(ignored.nick)
                if not user.nick in ignored.ignoredby:
                    ignored.ignoredby.append(user.nick)
            bot.send_and_log(recipient, user_executed,
                "The requested %s added to your ignore list" %
                    ("users were" if len(params) > 1 else "user was"))
            bot.changed()
        else:
            raise MissingParams
        
    @command("Remove one or more users from your ignore list.\n"
             "ignore remove <user>")
    def ignore_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for param in params:
                ignored = bot.check_for_master(bot.find_user(param))
                if ignored.nick in user.ignore:
                    user.ignore.remove(ignored.nick)
                if user.nick in ignored.ignoredby:
                    ignored.ignoredby.remove(user.nick)
            bot.send_and_log(recipient, user_executed,
                "The requested %s removed from your ignore list" %
                    ("users were" if len(params) > 1 else "user was"))
            bot.changed()
        else:
            raise MissingParams
    
    @command("List your ignore list.\n"
             "ignore list")
    def ignore_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        if user.ignore:
            bot.send_and_log(recipient, user_executed,
                "The following users are on your ignore list: %s" %
                    (", ".join(user.ignore)))
        else:
            bot.send_and_log(recipient, user_executed,
                "Your ignore list is currently empty.")

    @command("Log out of your account.\n"
             "logout")
    @protected_command
    @toggleable_command
    def logout(bot, params, user, recipient, mainchannel, bypass=False):
        bot.send_and_log(recipient, user,
            "You are now logged out.")
        user.logged_in = False
    
    @command("Manage or send mail.")
    @protected_command
    @toggleable_command
    def mail(bot, params, user_executed, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("List messages in your inbox.\n"
             "Filter will take either 'read', 'unread' or 'all'. Anything other is considered a search.\n"
             "mail inbox [<filter>]")
    @protected_command
    @toggleable_command
    def mail_inbox(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        if user.messages:
            messagelist = sorted(user.messages.keys())
            timelength = 8
            senderlength = 6
            tosend = []
            for number, message in enumerate(messagelist):
                messageid = number+1
                time = TimeFormat().date(time=messagelist[number])
                sender = str(user.messages[message][0])
                messagehidden = False
                if not params:
                    tosend.append("%s%s | %s | %s | %s"
                        % (" " if number < 9 else "", number+1, time, sender, "yes" if message in user.readmessages else "no"))
                elif params and params[0] in ["unread", "all"] and not message in user.readmessages:
                    tosend.append("%s%s | %s | %s | %s"
                        % (" " if number < 9 else "", number+1, time, sender, "no"))
                elif params and params[0] in ["read", "all"] and message in user.readmessages:
                    tosend.append("%s%s | %s | %s | %s"
                        % (" " if number < 9 else "", number+1, time, sender, "yes"))
                else:
                    messagehidden = True
                if messagehidden:
                    continue
                if len(time) > timelength:
                    timelength = len(time)
                if len(sender) > senderlength:
                    senderlength = len(sender)
            if not tosend:
                bot.send_and_log(recipient, user_executed,
                    "There are no messages matching your filter: 'only messages marked as %s'." % (params[0]))
                return
            bot.send_and_log(recipient, user_executed,
                "Tip: To read a message, type 'mail read', followed by the message id.")
            bot.send_and_log(recipient, user_executed,
                "id | %s | %s | read" % ("received".center(timelength), "sender".center(senderlength)))
            for abouttosend in tosend:
                abouttosend = "%s | %s | %s | %s" % (abouttosend.split(" | ")[0], abouttosend.split(" | ")[1].center(timelength), abouttosend.split(" | ")[2].center(senderlength), abouttosend.split(" | ")[3])
                bot.send_and_log(recipient, user_executed, abouttosend)
        else:
            bot.send_and_log(recipient, user_executed,
                "There are no messages for you.")

    @command("Mark one or more mails as read or unread.\n"
             "By default, all mails are marked this way.\n"
             "mail mark <read/unread> [<id>]")
    def mail_mark(bot, params, user_executed, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Mark one or more mails as read.\n"
             "By default, all mails are marked as read.\n"
             "mail mark read [<id>]")
    @protected_command
    @toggleable_command
    def mail_mark_read(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        messagelist = sorted(user.messages.keys())
        if not params:
            for message in messagelist:
                if message not in user.readmessages:
                    user.readmessages.append(message)
        else:
            for  param in params:
                try:
                    number = int(param) - 1
                except ValueError:
                    bot.send_and_log(recipient, user_executed,
                        "When set, this parameter needs to be a number.")
                    return
                if not messagelist[number] in user.readmessages:
                    user.readmessages.append(messagelist[number])
        bot.send_and_log(recipient, user_executed,
            "Marked %s %s as read" % ("all" if not params else len(params), "message" if len(params) == 1 else "messages"))

    @command("Mark one or more mails as unread.\n"
             "By default, all mails are marked as unread.\n"
             "mail mark unread [<id>]")
    @protected_command
    @toggleable_command
    def mail_mark_unread(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        messagelist = sorted(user.messages.keys())
        if not params:
            for message in messagelist:
                if message in user.readmessages:
                    user.readmessages.remove(message)
        else:
            for  param in params:
                try:
                    number = int(param) - 1
                except ValueError:
                    bot.send_and_log(recipient, user_executed,
                        "When set, this parameter needs to be a number.")
                    return
                if messagelist[number] in user.readmessages:
                    user.readmessages.remove(messagelist[number])
        bot.send_and_log(recipient, user_executed,
            "Marked %s %s as unread" % ("all" if not params else len(params), "message" if len(params) == 1 else "messages"))

    @command("Read a message.\n"
             "By default, all unread messages are shown.\n"
             "mail read [<id>]")
    @protected_command
    @toggleable_command
    def mail_read(bot, params, user_executed, recipient, mainchannel, bypass=False):
        try:
            number = int(params[0]) - 1
        except ValueError:
            bot.send_and_log(recipient, user_executed,
                "When set, this parameter needs to be a number.")
        except IndexError:
            pass
        if params and number < 0:
            raise MessageNotFound(number+1)
        user = bot.check_for_master(user_executed)
        messagelist = sorted(user.messages.keys())
        if params:
            try:
                messageid = messagelist[number]
                bot.send_and_log(recipient, user_executed,
                    "[%s] %s: %s" % (number+1, user.messages[messageid][0], user.messages[messageid][1]))
                if not messageid in user.readmessages:
                    user.readmessages.append(messageid)
            except IndexError:
                raise MessageNotFound(number+1)
        elif user.messages:
            messagesfound = False
            for message in messagelist:
                if message in user.readmessages:
                    continue
                user.readmessages.append(message)
                messagesfound = True
                bot.send_and_log(recipient, user_executed,
                    "[%s] %s: %s" % (number+1, user.messages[message][0], user.messages[message][1]))
            if not messagesfound:
                bot.send_and_log(recipient, user_executed,
                    "Sorry, I could not find any unread messages.")
        else:
            bot.send_and_log(recipient, user_executed,
                "Sorry, I could not find any messages.")
    
    @command("Remove a message from your inbox.\n"
             "Then id parameter also takes the value 'all', which purges all messages.\n"
             "mail remove <id>")
    @protected_command
    @toggleable_command
    def mail_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        user = bot.check_for_master(user_executed)
        if params[0] == 'all':
            user.messages = {}
            user.readmessages = []
            bot.send_and_log(recipient, user_executed,
                "All your mail has been removed.")
        else:
            messagelist = sorted(user.messages.keys())
            try:
                number = int(params[0]) - 1
            except ValueError:
                bot.send_and_log(recipient, user_executed,
                    "This parameter needs to be a number or the value 'all'.")
            try:
                del user.messages[messagelist[number]]
            except IndexError:
                raise MessageNotFound(number+1)
            if messagelist[number] in user.readmessages:
                user.readmessages.remove(messagelist[number])
            bot.send_and_log(recipient, user_executed,
                "Message removed.")

    @command("Send a mail to an user for when they log in.\n"
             "mail send <user> <message>")
    @protected_command
    @toggleable_command
    def mail_send(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 1:
            user = bot.check_for_master(bot.find_user(params[0]))
            message = str(" ".join(params[1:]))
            safe = bot.is_safe(message=message, user=user)
            if not safe[0]:
                bot.send_and_log(recipient, user_executed,
                    "Sorry, but your message to %s was not sent due to it possibly being unsafe" % params[0])
                return
            user.messages[datetime.datetime.now()] = user_executed, message
            bot.send_and_log(recipient, user_executed,
                "Your message to %s was sent succesfully." % params[0])
            # Message the user and their alts. Why let them wait until they log in if they're there?
            receiverchannels = []
            receivers = [user]
            for alt in user.alts:
                receivers.append(bot.find_user(alt))
            for channel in bot.channels:
                channeldata = bot.get_channel(channel)
                for receiver in receivers[:]:
                    if receiver in channeldata.users:
                        if channeldata in receiverchannels:
                            continue
                        bot.send_and_log(channeldata, receiver,
                            "You have received a new message. Please check your unread messages using '!mail inbox unread'.")
                        receivers.remove(receiver)
                        receiverchannels.append(channeldata)
            for receiver in receivers:
                bot.send_and_log(receiver, receiver,
                    "You have received a new message. Please check your unread messages using '!mail inbox unread'.")
        else:
            raise MissingParams

    @command("Manage your channel mode(s).")
    @toggleable_command
    def mode(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("List the current channel modes.\n"
             "mode list")
    @toggleable_command
    def mode_list(bot, params, user, recipient, mainchannel, bypass=False):
        modes = recipient.mode
        if "default" in modes:
            modes.remove("default")
        if modes:
            bot.send_and_log(recipient, user,
                "This channel has the following %s set: %s" %
                    ("modes" if len(modes) > 1 else "mode", ", ".join(modes)))
        else:
            bot.send_and_log(recipient, user,
                "This channel is in the default mode.")

    @command("Add a mode to your channel.\n"
             "mode add <mode>")
    @toggleable_command
    def mode_add(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Remove a mode from your channel.\n"
             "mode remove <mode>")
    @toggleable_command
    def mode_remove(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Do not filter any incoming messages, even if they contain triggerwords or subjects.\n"
             "mode add filterless")
    @protected_command
    @toggleable_command
    def mode_add_filterless(bot, params, user, recipient, mainchannel, bypass=False):
        for incompatible in ["silent"]:
            if incompatible in recipient.mode:
                recipient.mode.remove(incompatible)
        if not "filterless" in recipient.mode:
            recipient.mode.append("filterless")
            bot.send_and_log(recipient, user,
                "Mode filterless added.")
            bot.update_rules(recipient)
        else:
            bot.send_and_log(recipient, user,
                "This channel is already in filterless mode.")

    @command("Filter incoming messages if they contain triggerwords or subjects.\n"
             "mode remove filterless")
    @protected_command
    @toggleable_command
    def mode_remove_filterless(bot, params, user, recipient, mainchannel, bypass=False):
        if "filterless" in recipient.mode:
            recipient.mode.remove("filterless")
            bot.send_and_log(recipient, user,
                "Mode filterless removed.")
            bot.update_rules(recipient)
        else:
            bot.send_and_log(recipient, user,
                "This channel was not in filterless mode.")

    @command("Give additional freedom of speech by bypassing triggerbot's rules. Your messages simply will not be sent to anyone sensitive to anything.\n"
             "Incoming messages from users sensitives to anything will be filtered, as they're most likely not related to your rant."
             "mode add rant")
    @protected_command
    @toggleable_command
    def mode_add_rant(bot, params, user, recipient, mainchannel, bypass=False):
        for incompatible in ["silent"]:
            if incompatible in recipient.mode:
                recipient.mode.remove(incompatible)
        if not "rant" in recipient.mode:
            recipient.mode.append("rant")
            bot.send_and_log(recipient, user,
                "Mode rant added.")
            bot.update_rules(recipient)
        else:
            bot.send_and_log(recipient, user,
                "This channel is already in rant mode.")

    @command("Relay your messages to everyone, even those sensitive. This means that you are forced to stick to the triggerbot rules.\n"
             "mode remove rant")
    @protected_command
    @toggleable_command
    def mode_remove_rant(bot, params, user, recipient, mainchannel, bypass=False):
        if "rant" in recipient.mode:
            recipient.mode.remove("rant")
            bot.send_and_log(recipient, user,
                "Mode rant removed.")
            bot.update_rules(recipient)
        else:
            bot.send_and_log(recipient, user,
                "This channel is not in rant mode.")

    @command("Disable any messages from leaving or entering your channel.\n"
             "mode add silent")
    @protected_command
    @toggleable_command
    def mode_add_silent(bot, params, user, recipient, mainchannel, bypass=False):
        for incompatible in ["filterless", "rant"]:
            if incompatible in recipient.mode:
                recipient.mode.remove(incompatible)
        if not "silent" in recipient.mode:
            recipient.mode.append("silent")
            bot.send_and_log(recipient, user,
                "Relaying disabled.")
            bot.relay("%s has left (Relaying disabled)." % user, recipient, relateduser=user, chat=False)
            if not params:
                bot.update_rules(recipient)
        elif not params:
            bot.send_and_log(recipient, user,
                "This channel is already in silent mode.")

    @command("Accept incoming messages and relay outgoing messages.\n"
             "mode remove silent")
    @protected_command
    @toggleable_command
    def mode_remove_silent(bot, params, user, recipient, mainchannel, bypass=False):
        if "silent" in recipient.mode:
            recipient.mode.remove("silent")
            bot.send_and_log(recipient, user,
                "Relaying enabled.")
            bot.relay("%s has joined (Relaying enabled)." % user, recipient, relateduser=user, chat=False, notifyfriends=True)
            if not params:
                bot.update_rules(recipient)
        elif not params:
            bot.send_and_log(recipient, user,
                "This channel is not in silent mode.")

    @command("Reset your channel mode.\n"
             "mode reset")
    @protected_command
    @toggleable_command
    def mode_reset(bot, params, user, recipient, mainchannel, bypass=False):
        recipient.mode = []
        bot.send_and_log(recipient, user,
            "Channel mode reset.")
        bot.update_rules(recipient)

    @command("Get a list of users in channels.\n"
             "names")
    @toggleable_command
    def names(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            channel = bot.get_channel(params[0])
            if not is_channel_name(channel.name):
                channel.name = "#%s" % channel.name
        else:
            channel = recipient
            if not getattr(channel, "is_channel", False):
                bot.send_and_log(recipient, user,
                    "Please specify a channel to see the rules for.")
                return
        users = []
        # In case it's a triggersafe channel, get the base channel
        basechannel = str(channel).split("_")[0]
        for checkchannel in bot.channels.itervalues():
            if "silent" in checkchannel.mode:
                continue
            if str(checkchannel) == basechannel or str(checkchannel).startswith("%s_" % basechannel):
                for user in checkchannel.users:
                    if user.nick in ["ChanServ", "NickServ"]:
                        continue
                    if not user.nick in users:
                        users.append(user.nick)
        users.sort()
        bot.send_and_log(recipient, None,
            "Nicks %s: [%s]" % (recipient, " ".join(users)))

    @command("Ask if someone is available to comfort you.\n"
             "panic")
    def panic(bot, params, user_executed, recipient, alert_channel_if_not_helped=False, bypass=False):
        user = bot.check_for_master(user_executed)
        if user.friends and not alert_channel_if_not_helped:
            userfound = False
            userlist = []
            for channel in bot.channels.itervalues():
                for person in channel.users:
                    userlist.append(person)
            for person.nick in user.friends:
                if person in userlist:
                    bot.send_and_log(person, None, "%s isn't feeling so well and would like you to comfort them." % user_executed)
                    bot.send_and_log(person, None, "If you can hear them out, please type '/query %s' to start a private conversation with them." % user_executed)
                    userfound = True
            if userfound:
                reactor.callLater(120, panic, bot=bot, params=params, user_executed=user_executed, recipient=recipient, alert_channel_if_not_helped=True)
                bot.send_and_log(recipient, user_executed, None, "Please type '!helped' if you're being helped. If nobody is there to help you in 2 minutes, I will search for more help. Everything will be fine, %s."
                    % user_executed)
            else:
                panic(bot=bot, params=params, user_executed=user_executed, recipient=recipient, alert_channel_if_not_helped=True)
        elif user.helped == False:
            bot.send_and_log(recipient, user_executed, "I'm searching for more help for you. Please try to hold on, %s." % user_executed)
            for channel in bot.channels.itervalues():
                if is_channel_name(str(channel.name)):
                    bot.send_and_log(channel, None, "%s isn't feeling so well and would like someone to comfort them." % user_executed)
                    bot.send_and_log(channel, None, "If you can hear them out, please type '/query %s' to start a private conversation with them." % user_executed)

    @command("Lists user permissions.\n"
             "permission - List which admin commands you can execute.\n"
             "permission <nick> - Lists the admin commands nick can execute.")
    @toggleable_command
    def permission(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        queried_user = bot.find_user(params[0]) if len(params) > 0 else user
        if queried_user.admin:
            bot.send_and_log(recipient, user_executed,
                "%s can execute all admin commands." % queried_user.nick)
        else:
            if queried_user.admincommandsallowed:
                bot.send_and_log(recipient, user_executed,
                    "%s can execute the following admin commands: %s."
                        % (queried_user.nick,
                           join_and(", ", " and ",
                                    ("%r" % " ".join(command.split("_")) for command in queried_user.admincommandsallowed))))
            else:
                bot.send_and_log(recipient, user_executed,
                    "%s can not execute any admin commands." % queried_user.nick)

    @command("Lists the current rules.\n"
             "Triggerbot automatically changes the channel rules according to"
             " the trigger topics of the people present. Use this command if you"
             " are ever unsure about the current rules.\n"
             "rules [<channel>]")
    @toggleable_command
    def rules(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            channel = bot.get_channel(params[0])
            if not is_channel_name(channel.name):
                channel.name = "#%s" % channel.name
        else:
            channel = recipient
            if not getattr(channel, "is_channel", False):
                bot.send_and_log(recipient, user,
                    "Please specify a channel to see the rules for.")
                return
        bot.report_rules(channel=channel, user=user, recipient=recipient, changed=True)

    @command("Get info on when triggerbot last saw a specific person.\n"
             "seen <nickname>")
    @toggleable_command
    def seen(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            if params[0] != bot.nickname:
                user = bot.check_for_master(bot.find_user(params[0]))
                lastseen = TimeFormat().date(time=user.seen)
            else:
                lastseen = "now, forever ago and forever in the future"
            bot.send_and_log(recipient, user_executed,
                "I have last seen %s %s." %
                (params[0], lastseen))
        else:
            raise MissingParams

    @command("Sets various settings for you.")
    @toggleable_command
    def set(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Disables a setting for you.")
    @toggleable_command
    def unset(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("When set, triggerbot doesn't apply your trigger topics and"
             " words if you are marked away.\n"
             "set awaycheck")
    @protected_command
    @toggleable_command
    def set_awaycheck(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.awaycheck = True
        bot.send_and_log(recipient, user_executed,
            "Awaycheck set.")
        bot.changed()
        bot.update_rules()

    @command("When unset, triggerbot applies your trigger topics and"
             " words, even if you are marked away.\n"
             "unset awaycheck")
    @protected_command
    @toggleable_command
    def unset_awaycheck(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.awaycheck = False
        bot.send_and_log(recipient, user_executed,
            "Awaycheck unset.")
        bot.changed()
        bot.update_rules()

    @command("when set, triggerbot will silence your channel when you"
             " go away (requires awaycheck to be set).\n"
             "set autosilence")
    @protected_command
    @toggleable_command
    def set_autosilence(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.autosilence = True
        bot.send_and_log(recipient, user_executed,
            "autosilence set.")
        bot.changed()

    @command("when unset, triggerbot will not silence your channel when you"
             " go away (requires awaycheck to be set).\n"
             "unset autosilence")
    @protected_command
    @toggleable_command
    def unset_autosilence(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.autosilence = False
        bot.send_and_log(recipient, user_executed,
            "autosilence set.")
        bot.changed()

    @command("When set, triggerbot will automatically log you out when you quit"
             " or leave all channels the bot is in.\n"
             "set autologout")
    @protected_command
    @toggleable_command
    def set_autologout(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.autologout = True
        bot.send_and_log(recipient, user_executed,
            "Autologout set.")
        bot.changed()

    @command("When unset, triggerbot will keep you logged in, even if you"
             " quit or leave all channels the bot is in.\n"
             "unset autologout")
    @protected_command
    @toggleable_command
    def unset_autologout(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.autologout = False
        bot.send_and_log(recipient, user_executed,
            "Autologout unset.")
        bot.changed()
    
    @command("When set, triggerbot will not report your own triggers in"
             " your own triggersafe channels.\n"
             "set hideown")
    @protected_command
    @toggleable_command
    def set_hideown(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.hideown = True
        bot.send_and_log(recipient, user_executed,
            "Your triggers will no longer be displayed in your own channel(s).")
        bot.changed()

    @command("When unset, triggerbot will also report your own triggers in"
             " your triggersafe channels.\n"
             "unset hideown")
    @protected_command
    @toggleable_command
    def unset_hideown(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.hideown = False
        bot.send_and_log(recipient, user_executed,
            "Your triggers will be displayed in your own channel(s).")
        bot.changed()

    @command("When set, triggerbot will not see any of your sentences in a"
             " private chat as commands and will listen to you like"
             " a therapist would.\n"
             "set listenmode")
    @protected_command
    @toggleable_command
    def set_listenmode(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.listenmode = True
        bot.send_and_log(recipient, user_executed,
            "Listenmode set.")
        bot.changed()

    @command("When unset, triggerbot will see your messages in a"
             " private channel as commands.\n"
             "unset listenmode")
    @protected_command
    @toggleable_command
    def unset_listenmode(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.listenmode = False
        bot.send_and_log(recipient, user_executed,
            "Listenmode unset.")
        bot.changed()

    @command("When set, the MOTD will not be displayed in your channel.\n"
             "set motdread")
    @protected_command
    @toggleable_command
    def set_motdread(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.motdread = True
        bot.send_and_log(recipient, user_executed,
            "MOTD marked as read. The channel topic for your triggersafe channel(s) will be updated soon.")
        for channel in bot.channels:
            if channel.endswith("_%s" % user.nick.lower()):
                setattr(bot.get_channel(channel), "topicset", "%s's triggersafe channel. | [rules][mode]" % user.nick)
        bot.changed()

    @command("When unset, the MOTD will be displayed in your channel.\n"
             "unset motdread")
    @protected_command
    @toggleable_command
    def unset_motdread(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.motdread = False
        if recipient:
            bot.send_and_log(recipient, user_executed,
                "MOTD marked as unread. The channel topic for your triggersafe channel(s) will be updated soon.")
        for channel in bot.channels:
            if channel.endswith("_%s" % user.nick.lower()):
                setattr(bot.get_channel(channel), "topicset", "%s's triggersafe channel. | [globalmotd][rules][mode]" % user.nick)
        bot.changed()

    @command("When set, being logged in with NickServ will log you in with triggerbot.\n"
             "set nickservlogin")
    @protected_command
    @toggleable_command
    def set_nickservlogin(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.nickservlogin = False
        bot.send_and_log(recipient, user_executed,
            "NickServ logins will now cause triggerbot logins.")

    @command("When unset, being logged in with NickServ will not log you in with triggerbot.\n"
             "unset nickservlogin")
    @protected_command
    @toggleable_command
    def unset_nickservlogin(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.nickservlogin = True
        bot.send_and_log(recipient, user_executed,
            "NickServ logins will no long cause triggerbot logins.")

    @command("When set, your account becomes password protected and"
             " trigger topics, triggerwords and setting cannot be changed"
             " without logging in first.\n"
             "set password <password>")
    @protected_command
    @toggleable_command
    def set_password(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.password = bcrypt.hashpw(' '.join(params), bcrypt.gensalt())
        bot.send_and_log(recipient, user_executed,
            "Password set.")
        bot.changed()

    @command("When unset, your account will not be password protected.\n"
             "unset password")
    @protected_command
    @toggleable_command
    def unset_password(bot, params, user_executed, recipient, mainchannel, bypass=False):
        master = bot.check_for_master(user_executed)
        master.password = None
        master.logged_in = False
        for user in master.alts:
            user.logged_in = False
        bot.send_and_log(recipient, user_executed,
            "Password protection removed.")
        bot.changed()

    @command("When set, triggerbot will keep a trigger-safe copy available"
             " for each of the channels for you, in which all messages"
             " without triggerwords will be relayed.\n"
             "This channel name will be like #channelname_yournickname. So,"
             " if your nickname is example, a filtered version of"
             " #examplechannel is available for you at"
             " #examplechannel_example.\n"
             "set channel")
    @protected_command
    @toggleable_command
    def set_channel(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.channel = True
        for channel in bot.channels.keys():
            if is_channel_name(channel):
                userchannel = False
                try:
                    if channel.split("_")[1]:
                        userchannel = True
                except IndexError:
                    pass
                if not userchannel:
                    tocheck = "%s_%s" % (channel, user.nick)
                    tocheck = tocheck.lower()
                    if not tocheck in bot.channels.keys():
                        bot.join_channel(tocheck)
        bot.send_and_log(recipient, user_executed,
            "Trigger-safe channels are now available for you.")
        bot.changed()

    @command("When unset, triggerbot will no longer keep a trigger-safe"
             " copy of each of the channels available for you.\n"
             "unset channel")
    @protected_command
    @toggleable_command
    def unset_channel(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.channel = False
        for channel in bot.channels.keys():
            if is_channel_name(channel):
                userchannel = False
                try:
                    if channel.split("_")[1]:
                        userchannel = True
                except IndexError:
                    pass
                if not userchannel:
                    tocheck = "%s_%s" % (channel, user.nick)
                    tocheck = tocheck.lower()
                    if tocheck in bot.channels.keys():
                        bot.leave_channel(tocheck, unregister=True)
        bot.send_and_log(recipient, user_executed,
            "Trigger-safe channels are no longer available for you.")
        bot.changed()

    @command("Check the status of an account option.\n"
             "status <option>")
    @toggleable_command
    def status(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        try:
            if getattr(user, params[0]) in (None, False):
                bot.send_and_log(recipient, user,
                    "The option %s is currently unset." % params[0])
            else:
                bot.send_and_log(recipient, user_executed,
                    "The option %s is currently set." % params[0])
        except AttributeError:
            bot.send_and_log(recipient, user_executed,
                "Sorry, but I could not find the option %s." % params[0])

    @command("Display a link to triggerbot's source code.\n"
             "source")
    def source(bot, params, user_executed, recipient, mainchannel, bypass=False):
        bot.send_and_log(recipient, user_executed,
            "%s's source code is available on %s and %s" % (bot.nickname, bot.sourceURLs[0], bot.sourceURLs[1]))

    @command("Manage topics which make you feel uncomfortables.")
    @toggleable_command
    def topic(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Adds one or more trigger topic(s) for you.\n"
             "topic add <topic> <level>")
    @protected_command
    @toggleable_command
    def topic_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) < 2:
            raise MissingParams
        user = bot.check_for_master(user_executed)
        x = 0
        while x < len(params)-1:
            topic = bot.find_topic(params[x].lower())
            try:
                level = int(params[x+1])
            except ValueError:
                bot.send_and_log(recipient, user_executed,
                    "Sorry, but that syntax is incorrect. Correct syntax: %r" % "topic add <topic> <level>...")
            if level not in topic.descriptions:
                bot.send_and_log(recipient, user_executed,
                    "Topic %r doesn't have level %d." % (topic.name, level))
            else:
                user.topics[topic] = level
            x = x + 2
        bot.send_and_log(recipient, user_executed, "Topic(s) added.")
        bot.update_rules()
        bot.changed()

    @command("Removes one or more trigger topic(s) for you.\n"
             "topic remove <topic>")
    @protected_command
    @toggleable_command
    def topic_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        for x in range(0, len(params)):
            topic = bot.find_topic(params[x].lower())
            try:
                del user.topics[topic]
            except KeyError:
                bot.send_and_log(recipient, user_executed, "Could not find topic %r" % params[x].lower())
        bot.send_and_log(recipient, user_executed, "Topic(s) removed.")
        bot.update_rules()
        bot.changed()

    @command("Lists trigger topics.\n"
             "topic list - Lists your own triggers.\n"
             "topic list <nick> - Lists nick's triggers.")
    @toggleable_command
    def topic_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        queried_user = bot.find_user(params[0]) if len(params) > 0 else user
        if queried_user.topics:
            bot.send_and_log(recipient, user_executed,
                "%r has the following trigger topics set: %s."
                    % (queried_user.nick,
                       join_and(", ", " and ",
                                ("%s (level %d)" % (topic.name, level)
                                 for topic, level in queried_user.topics.iteritems()))))
        else:
            bot.send_and_log(recipient, user_executed,
                "%r has no trigger topics set." % (queried_user if len(params) > 0 else user_executed))

    @command("Shows information about trigger topics.\n"
             "topic info - Lists all the available trigger topics.\n"
             "topic info <topic> - Shows information about a particular trigger topic.")
    @toggleable_command
    def topic_info(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            # Show info.
            topic = bot.find_topic(params[0])
            for level, description in sorted \
                (topic.descriptions.iteritems(), key=lambda x:x[0]) \
            :
                bot.send_and_log(recipient, user,
                    "%s (level %d) - %s." % (topic.name, level, description))
        else:
            # List all.
            if bot.topics:
                bot.send_and_log(recipient, user,
                    "The following trigger topics are available: %s."
                        % join_and(", ", " and ",
                            (topic.name for topic in bot.topics.itervalues())))
            else:
                bot.send_and_log(recipient, user, "There are no trigger topics available. Please contact a bot admin and ask them to add some.")

    @command("Take a tutorial.\n"
             "tutorial [<step>]")
    @toggleable_command
    def tutorial(bot, params, user, recipient, mainchannel, bypass=False):
        if params:
            try:
                if int(params[0]) == 1:
                    lines = ["%s allows you to define your triggers by defining trigger topics and trigger words. We will start off by explaining how to use trigger topics." % bot.nickname] \
                          + ["The trigger topic system allows you to set one or more trigger topics, that is, one or more topics you are sensitive to and which can trigger you."] \
                          + ["To get a list of trigger topics you can choose from, use the 'topic info' command. To get more information about a certain trigger topic, use the 'topic info' command, followed by a topic."] \
                          + ["For example, if there would be a topic named 'example', you could get more info about the levels of this topic by typing 'topic info example'."] \
                          + ["The list which is shown will list a level and a description. Please note that a higher level means a higher sensitivity to a specific topic."] \
                          + ["Please try to get used to the 'topic info' command. If you feel that you are ready to add actual trigger topics to your profile, please type 'tutorial 2' to continue."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 2:
                    lines = ["Good, time for part 2!"] \
                          + ["Adding a trigger topic to your profile is fairly easy. First, use 'trigger info' to decide which topic and which level you want to add."] \
                          + ["Now, say you want to add level 2 of 'example' to your personal trigger topic list. All you have to do is type 'topic add example 2'."] \
                          + ["The 'topic add' command is also used to change the level of a trigger topic already in your list. If you, for example, want to change your sensitivity level for the topic 'example' to 1, you would type 'topic add example 1'."] \
                          + ["Getting rid of a trigger topic is possible using the 'topic remove' command. If you feel strong enough to take discussions about 'example', just type 'topic remove example'."] \
                          + ["You can have as many trigger topics in your personal list as you want, so do not feel afraid to add as much as you feel is necessary."] \
                          + ["Whenever you join a channel, the rules will be updated to disallow discussions about subjects in your trigger topic list."] \
                          + ["If you think you are ready to learn about trigger words, please type 'tutorial 3'."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 3:
                    lines = ["You're a fast learner, cool!"] \
                          + ["Trigger words are words which you know make you feel uncomfortable and have a tendency to trigger you."] \
                          + ["Adding and removing trigger words goes similar to adding and removing a trigger topic, with the exceptions that trigger words have no level and can be any word you want. There is no list limiting your choices."] \
                          + ["If, for example, the word 'meow' makes you feel uncomfortable, you can add it to your personal trigger word list by typing 'word add meow'."] \
                          + ["Please note that you do not have to add variations of a trigger word, as %s contains support for so-called 'stemming', which means that it will recognise words suchs as 'meowing' to be the same as 'meow'." % bot.nickname] \
                          + ["To remove a trigger word from your list, type 'word remove', followed by the word you want to remove."] \
                          + ["It is possible to add or remove multiple trigger words from your list at once. In case you would want to add 'meow', 'woof' and 'bark', you would type 'word add meow woof bark'."] \
                          + ["Trigger words are useful because they will warn someone if they use a word that may trigger you, teaching them to avoid the usage of certain words."] \
                          + ["If you are ready to learn about account grouping, please type 'tutorial 4'."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 4:
                    lines = ["In our IRC life, we often use more than one nickname. It would be quite inconvenient if we would have to redo everything for every nickname we use. Therefore, %s supports a mechanism we call 'grouping'." % bot.nickname] \
                          + ["Grouping, as you may expect, groups one or more nicknames together. The idea behind grouping is that you choose a 'main' nickname, and group your alternative nicknames with the main one."] \
                          + ["To group, switch to one of your alternative nicknames and type 'group add', followed by your 'main' nickname. For example, if your main nickname is cutefox, you would type 'group add cutefox' using all of your alternative nicknames."] \
                          + ["After nicknames are grouped, you may execute a %s command from any of your nicknames, and they will be updated for all of your nicknames." % bot.nickname] \
                          + ["To remove an alternative nickname from a group, switch to this nickname and run 'group remove'. Please note that, if you run 'group remove' from your main nickname, %s will ungroup all your alternative nicknames as well." % bot.nickname] \
                          + ["Please note that, after ungrouping a nickname returns to the state it was in before it was grouped."] \
                          + ["You're making great progress with the tutorial. If you're ready to learn about the friend list system, please type 'tutorial 5'."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 5:
                    lines = ["Sometimes, we end up feeling quite terrible. Either we end up panicky, or just quite sad. For that case, we have the 'panic' function. The panic function, when executed, will search for someone who can help you."] \
                          + ["However, most of us would have priorities. We trust some people more than others, and we would like to be helped by those we trust, whenever possible. For that, we have the friend list feature."] \
                          + ["Whenever you use the panic feature, %s will first look for people on your friend list and if they are unavailable, look for futher help."] \
                          + ["To add someone to your friend list, type 'friend add', followed by the nickname of this person. Removing a friend is similar, just type 'friend remove', followed by the nickname of this person."] \
                          + ["If you're ready to learn about checking profile information, please type 'tutorial 6'."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 6:
                    lines = ["With all this modifying of our profiles, we sometimes get confused. That's okay, though, because checking profile information is generally very easy."] \
                          + ["First, we most think of what we want to get info about. Trigger topics? Trigger words? Group info? Friend info?"] \
                          + ["Once we've decided what we want to check, we use the command for that group, followed by the word 'list'."] \
                          + ["For example, to check what trigger topics you have, you type 'topic list'. 'word list', 'group list' and 'friend list' are similar examples."] \
                          + ["You can also get the information about someone else. In that case, just type the command followed by their nickname. As an example, to get cutefox's friendlist, you would type 'friend list cutefox'."] \
                          + ["If you're ready to learn about profile settings, please type 'tutorial 7."]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                elif int(params[0]) == 7:
                    lines = ["Each profile has settings. Most settings can be turned on and off, and others take a specific value."] \
                          + ["To get a list of settings you can set, use the 'set' command."] \
                          + ["To enable a setting, type 'set', followed by the setting name. For some settings, you can set a specific value. For example, to set your password to cookies, type 'set password cookies'."] \
                          + ["To disable a setting, type 'unset', followed by the setting name."] \
                          + ["To check if an option is set or unset, type 'status', followed by the setting names."] \
                          + ["Congratulations, this concludes the tutorial."] \
                          + ["To learn more about specific commands, use the 'help' command. Feel free to ask people for help if you get stuck!"] \
                          + ["Thank you for taking the time to go through this tutorial. I wish you a trigger-free time!"]
                    for line in lines:
                        bot.send_and_log(user, user, line)
                else:
                    bot.send_and_log(recipient, user,
                        "I'm sorry, but I could not find a tutorial for that number. Currently, the tutorial has 7 steps.")
            except ValueError:
                bot.send_and_log(recipient, user,
                    "I'm sorry, but you need to enter a number.")
        else:
            lines = ["Welcome to the tutorial. This tutorial will teach you everything you need to know to use %s properly." % bot.nickname] \
                  + ["To start learning more about %s, type 'tutorial 1'." % bot.nickname]
            for line in lines:
                bot.send_and_log(user, user, line)

    @command("Manage your trust list.\n"
             "People on your trust list have complete control over your account.")
    @toggleable_command
    def trust(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more user(s) to your trust list."
             "trust add <user>")
    @protected_command
    @toggleable_command
    def trust_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry not in user.trusts and entry != user_executed.nick and entry != user.nick and entry not in user.alts:
                    user.trusts.append(entry)
            bot.send_and_log(recipient, user_executed,
                "The requested users were added to your trust list.")
            bot.changed()
        else:
            raise MissingParams

    @command("Remove one or more user(s) from your trust list."
             "trust remove <user>")
    @protected_command
    @toggleable_command
    def trust_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            user = bot.check_for_master(user_executed)
            for entry in params:
                if entry in user.trusts:
                    user.trusts.remove(entry)
            bot.send_and_log(recipient, user_executed,
                "The requested users are no longer on your trust list.")
            bot.changed()
        else:
            raise MissingParams

    @command("List your trust list."
             "trust list")
    @protected_command
    @toggleable_command
    def trust_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        userdata = bot.check_for_master(user_executed)
        if userdata.trusts:
            bot.send_and_log(recipient, user_executed,
                "You trust the following users: %s."
                    % join_and(", ", " and ", userdata.trusts))
        else:
            bot.send_and_log(recipient, user_executed,
                "You don't have anyone on your trust list.")

    @command("Execute commands as another user who has you on their trust list.\n"
             "user <nickname> <command>")
    @protected_command
    @logged_command
    @toggleable_command
    def user(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.find_user(params[0])
        if bot.check_for_master(user_executed) in user.trusts:
            # FIXME: Reply in-channel when executed in-channel
            bot.dispatch(command=' '.join(params[1:]), user=user, reply_to=user_executed, bypass=True)
        else:
            bot.send_and_log(recipient, user_executed, "%s does not have you on their trust list." % user.nick)

    @command("Retrieve information about an user.\n"
             "whois <nick>")
    @toggleable_command
    def whois(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        user = bot.find_user(params[0])
        master = bot.check_for_master(user)
        bot.send_and_log(recipient, user_executed, "%s is a %s user" % (user.nick, bot.nickname))
        if user != master:
            bot.send_and_log(recipient, user_executed, "%s is an alt of %s" % (user.nick, master.nick))
        elif user.alts:
            bot.send_and_log(recipient, user_executed, "%s is also known as %s" % (user.nick, join_and(", ", " and ", user.alts)))
        if master.admin:
            bot.send_and_log(recipient, user_executed, "%s is %s administrator" % (user.nick, "the head" if master.admin == 1 else "an"))
        channeladmin = []
        for channel in bot.channels.itervalues():
            if master.nick in channel.admins:
                channeladmin.append(channel)
        if channeladmin:
            bot.send_and_log(recipient, user_executed, "%s is a channel administrator on %s" % (user.nick, join_and(", ", " and ", channeladmin)))

    @command("Deletes all your trigger topics and trigger words.\n"
             "wipe")
    @protected_command
    @toggleable_command
    def wipe(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        user.trigger_words.clear()
        user.topics.clear()
        bot.changed()
        bot.send_and_log(recipient, user_executed,
            "All your data are gone. I hope it's what you wanted.")
        bot.update_rules()

    @command("Manage words which can trigger you.")
    @toggleable_command
    def word(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Adds one or more trigger word(s) for you. Users will be warned when they use"
             " this word while you are present.\n"
             "word add <word>")
    @protected_command
    @toggleable_command
    def word_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.check_for_master(user_executed)
            for entry in params:
                user.trigger_words.add(bot.stem(entry.lower()))
            bot.changed()
            bot.send_and_log(recipient, user_executed,
                "Trigger word(s) added.")
        else:
            raise MissingParams

    @command("Removes one or more of your trigger words.\n"
             "word remove <word>")
    @protected_command
    @toggleable_command
    def word_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.check_for_master(user_executed)
            for entry in params:
                user.trigger_words.discard(bot.stem(entry.lower()))
            bot.changed()
            bot.send_and_log(recipient, user_executed,
                "Trigger word(s) removed.")
        else:
            raise MissingParams

    @command("Lists trigger words.\n"
             "word list - Lists your own trigger words.\n"
             "word list <nick> - Lists nick's trigger words.")
    @toggleable_command
    def word_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.check_for_master(user_executed)
        queried_user = bot.find_user(params[0]) if params else user
        if queried_user.trigger_words:
            bot.send_and_log(recipient, user_executed,
                "%s has the following trigger words set: %s."
                    % (params[0] if params else user_executed.nick,
                       join_and(", ", " and ", queried_user.trigger_words)))
        else:
            bot.send_and_log(recipient, user_executed,
                "%s has no trigger words set." % (params[0] if params else user))

    @command("Shows who has the given trigger word set.\n"
             "word who <word>")
    @toggleable_command
    def word_who(bot, params, user, recipient, mainchannel, bypass=False):
        word = bot.stem(params[0])
        users = set()
        for channel in bot.channels.itervalues():
            for u in channel.users:
                if word in u.trigger_words:
                    users.add(u)
        if users:
            bot.send_and_log(recipient, user,
                "The following users have that trigger word: %s."
                    % join_and(", ", " and ", (u.nick for u in users if not u.master)))
        else:
            bot.send_and_log(recipient, user,
                "Nobody present seems to have that trigger word.")

    # Start of administrative commands
    @command("Various administrative commands.")
    def admin(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more users as administrator (admin).\n"
             "admin add <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            for nick in params:
                user = bot.find_user(nick)
                user.admin = 2
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) now has administrator status.")
        else:
            raise MissingParams

    @command("Remove the administrator status from one or more users.\n"
             "admin remove <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            for nick in params:
                user = bot.find_user(nick)
                if not user.admin == 1 or user == user_executed: # Only main admin can get rid of the main admin
                    user.admin = 0
                else:
                    bot.send_and_log(recipient, user_executed,
                        "Could not remove admin status from %s: The main admin can only resign, not have their power taken away" % nick)
                    return
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) no longer have administrator status.")
        else:
            raise MissingParams

    @command("Sent an announcement to all users.\n"
             "admin announce <message>")
    @admin_command
    @protected_command
    @logged_command
    def admin_announce(bot, params, user, recipient, mainchannel, bypass=False):
        if params:
            for channel in bot.channels.itervalues():
                if is_channel_name(str(channel)):
                    bot.notice(channel,
                        "Announcement from %s: %s" %
                            (user.nick, " ".join(params)))
        else:
            raise MissingParams

    @command("Join, leave or list managed channels.\n"
             "admin channel")
    def admin_channel(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Manage channel admins.\n"
             "admin channel admin")
    def admin_channel_admin(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add a channel admin.\n"
             "admin channel admin add <channel(s)> <user(s)>")
    def admin_channel_admin_add(bot, params, user, recipient, mainchannel, bypass=False):
        channels = []
        for number, entry in enumerate(params):
            if not is_channel_name(entry):
                break
            channels.append(entry)
        for entry in params[number:]:
            # Ensure the user is known
            bot.find_user(entry)
            for channel in channels:
                channeldata = bot.get_channel(channel)
                if not entry in channeldata.admins:
                    channeldata.admins.append(entry)
        bot.send_and_log(recipient, user,
            "Added the requested user(s) as channel admin for the requested channel(s).")
        bot.changed()

    @command("Remove a channel admin.\n"
             "admin channel admin remove <channel(s)> <user(s)>")
    def admin_channel_admin_remove(bot, params, user, recipient, mainchannel, bypass=False):
        channels = []
        for number, entry in enumerate(params):
            if not is_channel_name(entry):
                break
            channels.append(entry)
        for entry in params[number:]:
            for channel in channels:
                channeldata = bot.get_channel(channel)
                if entry in channeldata.admins:
                    channeldata.admins.remove(entry)
        bot.send_and_log(recipient, user,
            "Removed the requested user(s) as channel admin for the requested channel(s).")
        bot.changed()

    @command("Order the bot to join one or more channel(s).\n"
             "admin channel join <channel(s)>")
    @admin_command
    @protected_command
    @logged_command
    def admin_channel_join(bot, params, user, recipient, mainchannel, bypass=False):
        for entry in params:
            bot.join_channel(entry)
        bot.send_and_log(recipient, user,
            "Joined the requested channel(s).")

    @command("Order the bot to leave one or more channel(s).\n"
             "admin channel leave <channel(s)>")
    @admin_command
    @protected_command
    @logged_command
    def admin_channel_leave(bot, params, user, recipient, mainchannel, bypass=False):
        for entry in params:
            bot.leave_channel(entry, unregister=True)
        bot.send_and_log(recipient, user,
            "Left the requested channel(s).")
   
    @command("Get a list of main channels the bot is managing.\n"
             "admin channel list")
    @admin_command
    @protected_command
    @logged_command
    def admin_channel_list(bot, params, user, recipient, mainchannel, bypass=False):
        channellist = []
        for channel in bot.channels:
            if is_channel_name(channel) and not "_" in channel:
                channellist.append(channel)
        bot.send_and_log(recipient, user,
            "I'm managing %s" % join_and(", ", " and ", channellist))

    @command("Create a database entry for one or more user(s).\n"
             "admin create <nick>")
    @admin_command
    @protected_command
    @logged_command
    def admin_create(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        for param in params:
            bot.get_user(param)
        bot.send_and_log(recipient, user,
            "%s created" % ("Entries" if len(params) > 1 else "Entry"))

    @command("Check for issues and force consistency.")
    def admin_check(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Check and force database consistency.\n"
             "admin check database")
    @admin_command
    @protected_command
    @logged_command
    def admin_check_database(bot, params, user_executed, recipient, mainchannel, bypass=False):
        bot.check_database(recipient, user_executed)
        bot.send_and_log(recipient, user_executed,
            "Check complete.")

    @command("Export the database as triggerbot commands.\n"
             "admin export <all|topics|users> [<filename>]")
    def admin_export(bot, params, user_executed, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Export everything in the database as triggerbot commands.\n"
             "admin export all [<filename>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_export_all(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            filename = ' '.join(params)
        else:
            filename = "triggerbot_export"
        bot.dispatch(command="admin export topics %s_topics" % filename, user=user_executed, reply_to=recipient, bypass=True)
        bot.dispatch(command="admin export users %s_users" % filename, user=user_executed, reply_to=recipient, bypass=True)
        bot.send_and_log(recipient, user_executed, "Export complete.")

    @command("Export all topics as triggerbot commands.\n"
             "admin export topics [<filename>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_export_topics(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            filename = ' '.join(params)
        else:
            filename = "triggerbot_export_topics"
        export = []
        for topic in bot.topics.itervalues():
            for level in topic.descriptions.keys():
                export.append("!admin topic add %s %s %s" % (topic.name, level, topic.descriptions[level]))
            for level in topic.words.keys():
                export.append("!admin topic word add %s %s %s" % (topic.name, level, ' '.join(topic.words[level])))
            for supersede in topic.supersedes:
                export.append("!admin topic supersede add %s %s" % (topic.name, supersede))
        with open(filename, "w") as f:
            f.write('\n'.join(export))
        bot.send_and_log(recipient, user_executed, "All topics have been exported.")

    @command("Export all users as triggerbot commands.\n"
             "For security reasons, passwords cannot be exported, as they're saved in a hashed form."
             "admin export users [<filename>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_export_users(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            filename = ' '.join(params)
        else:
            filename = "triggerbot_export_users"
        export = []
        createdusers = []
        for user in bot.users.itervalues():
            if user.nick not in createdusers:
                export.append("!admin create user %s" % user.nick)
                createdusers.append(user.nick)
            for topic in user.topics.keys():
                export.append("!admin user %s topic add %s %s" % (user.nick, topic.name, user.topics[topic]))
            if user.trigger_words:
                export.append("!admin user %s word add %s" % (user.nick, ' '.join(user.trigger_words)))
            if user.admin:
                export.append("!admin add %s" % user.nick)
            if user.master:
                if user.master not in createdusers:
                    export.append("!admin create user %s" % user.master)
                    createdusers.append(user.master)
                export.append("!admin user %s group add %s" % (user.nick, user.master))
            for ignore in user.ignore:
                if ignore not in createdusers:
                    export.append("!admin create user %s" % ignore)
                    createdusers.append(ignore)
                export.append("!admin user %s ignore add %s" % (user.nick, ignore))
            if user.friends:
                export.append("!admin user %s friend add %s" % (user.nick, ' '.join(user.friends)))
            if user.channelallow:
                export.append("!admin user %s channelallow add %s" % (user.nick, ' '.join(user.channelallow)))
            for setting in ['listenmode', 'channel', 'awaycheck', 'autologout', 'autosilence', 'hideown', 'motdread']:
                if getattr(user, setting) == getattr(User(None), setting):
                    continue
                export.append("!admin user %s %s %s" % (user.nick, "set" if getattr(user, setting) else "unset", setting))
        with open(filename, "w") as f:
            f.write('\n'.join(export))
        bot.send_and_log(recipient, user_executed, "All users have been exported.")

    @command("Manage the bot's ignore list.")
    @admin_command
    def admin_ignore(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more users to the bot's ignore list, causing it to ignore all the user's commands.\n"
             "admin ignore add <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_ignore_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            for nick in params:
                user = bot.find_user(nick)
                user.ignored = True
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) added to the bot's ignore list.")
        else:
            raise MissingParams

    @command("Remove one or more users from the bot's ignore list, causing it to act on their commands again.\n"
             "admin ignore remove <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_ignore_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            for nick in params:
                user = bot.find_user(nick)
                user.ignored = False
            bot.send_and_log(recipient, user_executed,
                "Requested user(s) removed from the bot's ignore list.")
        else:
            raise MissingParams

    @command("List users on the bot's ignore list.")
    @admin_command
    @protected_command
    def admin_ignore_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        ignoredusers = []
        for user in bot.users.itervalues():
            if user.ignored:
                ignoredusers.append(user.nick)
        if len(ignoredusers) > 0:
            bot.send_and_log(recipient, user_executed,
                "The following users are on the bot's ignore list: %s." %
                    ', '.join(ignoredusers))
        else:
            bot.send_and_log(recipient, user_executed,
                "The bot's ignore list is empty.")

    @command("Order the bot to kick someone out.\n"
             "When listing channels, make sure they all start with a channel character. The first value that does not is seen as the user value.\n"
             "admin kick [<channels>] <user> [<reason>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_kick(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        channels = []
        for param in params:
            if is_channel_name(param):
                channels.append(param.split("_")[0])
        if not len(params) > len(channels):
            raise MissingParams
        for channel in bot.channels.itervalues():
            if channels:
                for kickfromchannel in channels:
                    if str(channel) == kickfromchannel or str(channel).startswith("%s_" % kickfromchannel):
                        bot.kick(str(channel), params[len(channels)], "%s: %s" % (user, params[len(channels)+1:] if len(params) >= len(channels)+2 else "no reason specified."))
            else:
                bot.kick(str(channel), params[len(channels)], "%s: %s" % (user, params[len(channels)+1:] if len(params) >= len(channels)+2 else "no reason specified."))

    @command("Order the bot to ban an user.\n"
             "When listing channels, make sure they all start with a channel character. The first value that does not is seen as the user value.\n"
             "admin ban [<channels>] <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_ban(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        channels = []
        for param in params:
            if is_channel_name(param):
                channels.append(param.split("_")[0])
        if not len(params) > len(channels):
            raise MissingParams
        toban = bot.get_user(params[len(channels)])
        for channel in bot.channels.itervalues():
            if channels:
                for banfromchannel in channels:
                    if str(channel) == banfromchannel or str(channel).startswith("%s_" % banfromchannel):
                        bot.mode(chan=str(channel), set=True, modes="b", mask="*!*@%s" % toban.host)
            else:
                bot.mode(chan=str(channel), set=True, modes="b", mask="*!*@%s" % toban.host)
   
    @command("Remove the ban on an user.\n"
             "When listing channels, make sure they all start with a channel character. The first value that does not is seen as the user value.\n"
             "admin unban [<channels>] <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_unban(bot, params, user, recipient, mainchannel, bypass=False):
        if not params:
            raise MissingParams
        channels = []
        for param in params:
            if is_channel_name(param):
                channels.append(param.split("_")[0])
        if not len(params) > len(channels):
            raise MissingParams
        tounban = bot.get_user(params[len(channels)])
        for channel in bot.channels.itervalues():
            if channels:
                for banfromchannel in channels:
                    if str(channel) == banfromchannel or str(channel).startswith("%s_" % banfromchannel):
                        bot.mode(chan=str(channel), set=False, modes="b", mask="*!*@%s" % tounban.host)
            else:
                bot.mode(chan=str(channel), set=False, modes="b", mask="*!*@%s" % tounban.host)

    @command("Order the bot to kickban an user.\n"
             "When listing channels, make sure they all start with a channel character. The first value that does not is seen as the user value.\n"
             "admin kickban [<channels>] <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_kickban(bot, params, user, recipient, mainchannel, bypass=False):
        bot.dispatch(command="admin kick %s" % ' '.join(params), user=user, reply_to=recipient, bypass=True)
        bot.dispatch(command="admin ban %s" % ' '.join(params), user=user, reply_to=recipient, bypass=True)

    @command("View admin logs.\n"
             "By default, the 10 latest entries are displayed. Type a number or 'all' to see more entries.\n"
             "admin logs [<user>] [<entries>]")
    @admin_command
    @protected_command
    def admin_logs(bot, params, user_executed, recipient, mainchannel, bypass=False):
        start = -10
        tosend = []
        channellength = 7
        timelength = 4
        userlength = 4
        users = []
        if params:
            for param in params:
                try:
                    users.append(bot.find_user(param))
                except UserNotFound:
                    if param == "all":
                        start = 0
                    else:
                        try:
                            start = -int(param)
                        except ValueError:
                            raise UserNotFound(param)
        if not users:
            users = bot.users.itervalues()
        logs = {}
        for user in users:
            for log in user.logs.keys():
                logs[log] = user.nick, user.logs[log]
        if not logs:
            bot.send_and_log(recipient, user_executed,
                "No logs were found for %s" % join_and(", ", " and ", users))
            return
        if start < 0 and -start < len(logs):
            bot.send_and_log(recipient, user_executed,
                "Limiting output to the most recent %s of %s entries." % (-start, len(logs)))
        else:
            bot.send_and_log(recipient, user_executed,
                "Showing all %s entries." % len(logs))
        sorted_logs = sorted(logs.keys())[start:]
        for log in sorted_logs:
            # Channel | Time | User | Command
            channel = str(logs[log][1][0])
            time = log.strftime("%Y-%m-%d %H:%M:%S")
            user = logs[log][0]
            command = logs[log][1][1]
            tosend.append("%s | %s | %s | %s" % (channel, time, user, command))
            if len(channel) > channellength:
                channellength = len(channel)
            if len(time) > timelength:
                timelength = len(time)
            if len(user) > userlength:
                userlength = len(user)
        bot.send_and_log(recipient, user_executed,
           "%s | %s | %s | command" % ("channel".center(channellength), "time".center(timelength), "user".center(userlength)))
        for abouttosend in tosend:
            abouttosend = "%s | %s | %s | %s" % (abouttosend.split(" | ")[0].center(channellength), abouttosend.split(" | ")[1].center(timelength), abouttosend.split(" | ")[2].center(userlength), abouttosend.split(" | ")[3])
            bot.send_and_log(recipient, user_executed, abouttosend)

    @command("Manage which admin commands a specific non-admin can execute.")
    def admin_permission(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Give an user the ability to execute a certain admin command.\n"
             "admin permission add <user> <command>")
    @admin_command
    @protected_command
    @logged_command
    def admin_permission_add(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 1:
            user = bot.get_user(params[0])
            if params[1] != "admin":
                params.insert(1, "admin")
            try:
                bot.command_description(params[1:])
                if not "_".join(params[1:]) in user.admincommandsallowed:
                    user.admincommandsallowed.append("_".join(params[1:]))
                    bot.send_and_log(recipient, user_executed,
                        "%s is now allowed to run the command %r" %
                        (params[0], " ".join(params[1:])))
                else:
                    bot.send_and_log(recipient, user_executed,
                        "%s was already allowed to run the command %r" %
                        (params[0], " ".join(params[1:])))
            except KeyError:
                raise CommandNotFound(" ".join(params[1:]))

    @command("Remove an user's ability to execute a certain admin command.\n"
             "admin permission remove <user> <command>")
    @admin_command
    @protected_command
    @logged_command
    def admin_permission_remove(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 1:
            user = bot.get_user(params[0])
            if params[1] != "admin":
                params.insert(1, "admin")
            if "_".join(params[1:]) in user.admincommandsallowed:
                user.admincommandsallowed.remove("_".join(params[1:]))
                bot.send_and_log(recipient, user_executed,
                    "%s is no longer allowed to run the command %r" %
                    (params[0], " ".join(params[1:])))
            else:
                bot.send_and_log(recipient, user_executed,
                    "%s was already not allowed to run the command %r" %
                    (params[0], " ".join(params[1:])))

    @command("Disconnects and shuts the bot down.\n"
             "admin quit")
    @admin_command
    @protected_command
    @logged_command
    def admin_quit(bot, params, user, recipient, mainchannel, bypass=False):
        global reconnectondc
        reconnectondc = False
        bot.quit()

    @command("Orders the bot to reconnect to the server.\n"
             "admin reconnect")
    @admin_command
    @protected_command
    @logged_command
    def admin_reconnect(bot, params, user, recipient, mainchannel, bypass=False):
        global reconnectondc
        reconnectondc = True
        bot.quit()

    @command("Set a global settings")
    def admin_set(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Unset a global setting")
    def admin_unset(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Set the global MOTD, displayed in all channel topics.\n"
             "admin set globalmotd <value>")
    @admin_command
    @protected_command
    @logged_command
    def admin_set_globalmotd(bot, params, user, recipient, mainchannel, bypass=False):
        bot.get_settings().globalmotd = " ".join(params)
        if params:
            bot.send_and_log(recipient, user, "Global MOTD set.")
        else:
            bot.send_and_log(recipient, user, "Global MOTD disabled.")
        for userloop in bot.users:
            bot.dispatch(command="unset motdread", user=bot.get_user(userloop), reply_to=None, bypass=True)
        bot.changed()

    @command("Disable the main channels.\n"
             "admin set maindisabled")
    @admin_command
    @protected_command
    @logged_command
    def admin_set_maindisabled(bot, params, user, recipient, mainchannel, bypass=False):
        if not bot.get_settings().maindisabled:
            bot.get_settings().maindisabled = True
            bot.send_and_log(recipient, user, "Main channels disabled.")
        else:
            bot.send_and_log(recipient, user, "Main channels are already disabled.")

    @command("Enable the main channels.\n"
             "admin unset maindisabled")
    @admin_command
    @protected_command
    @logged_command
    def admin_unset_maindisabled(bot, params, user, recipient, mainchannel, bypass=False):
        if bot.get_settings().maindisabled:
            bot.get_settings().maindisabled = False
            bot.send_and_log(recipient, user, "Main channels enabled.")
        else:
            bot.send_and_log(recipient, user, "Main channels are already enabled.")

    @command("Manage which commands are enabled or disabled.")
    def admin_togglecommand(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    # TODO: Don't require exact matching with disabled command
    @command("Enable a command.\n"
             "admin togglecommand enable <command>")
    @admin_command
    @protected_command
    @logged_command
    def admin_togglecommand_enable(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            try:
                bot.command_description(params)
                if "_".join(params) in bot.get_settings().disabledcommands:
                    bot.get_settings().disabledcommands.remove("_".join(params))
                    bot.send_and_log(recipient, user_executed,
                        "Command %r is no longer disabled." %
                        " ".join(params))
                    bot.changed()
                else:
                    bot.send_and_log(recipient, user_executed,
                        "Command %r has not been disabled." %
                        " ".join(params))
            except KeyError:
                raise CommandNotFound(" ".join(params[1:]))
        else:
            raise MissingParams

    # TODO: Give a message when the command is not toggleable
    @command("Disable a command and all its subcommands.\n"
             "admin togglecommand disable <command>")
    @admin_command
    @protected_command
    @logged_command
    def admin_togglecommand_disable(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if params:
            if not "_".join(params) in bot.get_settings().disabledcommands:
                bot.get_settings().disabledcommands.append("_".join(params))
                bot.send_and_log(recipient, user_executed,
                    "Command %r and all its subcommands are now disabled." %
                    " ".join(params))
                bot.changed()
            else:
                bot.send_and_log(recipient, user_executed,
                    "Command %r and all its subcommands were already disabled." %
                    " ".join(params))
        else:
            raise MissingParams

    # TODO: Format list a bit more nicely (e.g.: 'toggle list' instead of toggle_list)
    @command("Get a list of disabled commands.\n"
             "admin togglecommand list")
    @admin_command
    @protected_command
    def admin_togglecommand_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if bot.get_settings().disabledcommands:
            bot.send_and_log(recipient, user_executed,
                "The following commands have been disabled: %s." %
                join_and(", ", " and ", bot.get_settings().disabledcommands))
        else:
            bot.send_and_log(recipient, user_executed,
                "No commands have been disabled.")

    @command("Adds and removes trigger topics.")
    def admin_topic(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Adds a trigger topic.\n"
             "admin topic add <name> <level> <description>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_add(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 2:
            name = params[0].lower()
            level = int(params[1])
            description = " ".join(params[2:])
            if name in bot.topics:
                topic = bot.topics[name]
            else:
                topic = Topic(name)
                bot.topics[topic.name] = topic
            topic.descriptions[level] = description
            bot.changed()
            bot.send_and_log(recipient, user, "It is done.")
        else:
            raise MissingParams

    @command("Manage topic detection words.\n")
    def admin_topic_word(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add words to a topic.\n"
             "These words will be used to detect the topic a certain message is about.\n"
             "admin topic word add <name> <level> <list>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_word_add(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 2:
            topic = bot.find_topic(params[0].lower())
            level = int(params[1])
            if not level in topic.words.keys():
               topic.words[level] = []
            for word in params[2:]:
                if not bot.stem(word.lower()) in topic.words[level]:
                    topic.words[level].append(bot.stem(word.lower()))
            bot.changed()
            bot.send_and_log(recipient, user, "Words added")
        else:
            raise MissingParams

    @command("Remove words from a topic.\n"
             "These words will be used to detect the topic a certain message is about.\n"
             "admin topic word remove <name> <level> <list>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_word_remove(bot, params, user, recipient, mainchannel, bypass=False):
        if len(params) > 2:
            topic = bot.find_topic(params[0].lower())
            level = int(params[1])
            for word in params[2:]:
                if bot.stem(word.lower()) in topic.words[level]:
                    topic.words[level].remove(word.lower())
            bot.changed()
            bot.send_and_log(recipient, user, "Words removed")
        else:
            raise MissingParams

    @command("List words from a topic.\n"
             "admin topic word list <name>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_word_list(bot, params, user, recipient, mainchannel, bypass=False):
        if params:
            topic = bot.find_topic(params[0].lower())
            bot.send_and_log(recipient, user, topic.words)
        else:
            raise MissingParams

    @command("Removes a trigger topic.\n"
             "If level is not specified, removes all levels.\n"
             "admin topic remove <name> [<level>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_remove(bot, params, user, recipient, mainchannel, bypass=False):
        topic = bot.find_topic(params[0])
        if len(params) >= 2:
            level = int(params[1])
            del topic.descriptions[level]
        else:
            del bot.topics[topic.name]
            # Note that some users might still refer to this topic.
        bot.changed()
        bot.send_and_log(recipient, user, "Topic removed.")

    @command("Manage topic superseding")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_supersede(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand

    @command("Add one or more topic(s) to the list of topics the specified topic supersedes.\n"
             "admin topic supersede add <topic> <superseded topic>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_supersede_add(bot, params, user, recipient, mainchannel, bypass=False):
        topic = bot.find_topic(params[0])
        for entry in params[1:]:
            topic.supersedes.append(entry)
        bot.changed()
        bot.send_and_log(recipient, user, "Requested topic(s) will now be superseded by %s." % topic.name)

    @command("Remove one or more topic(s) to the list of topics the specified topic supersedes.\n"
             "admin topic supersede remove <topic> <superseded topic>")
    @admin_command
    @protected_command
    @logged_command
    def admin_topic_supersede_remove(bot, params, user, recipient, mainchannel, bypass=False):
        topic = bot.find_topic(params[0])
        for entry in params[1:]:
            if entry in topic.supersedes:
                topic.supersedes.remove(entry)
        bot.changed()
        bot.send_and_log(recipient, user, "Requested topic(s) will no longer be superseded by %s." % topic.name)

    @command("List which topics are superseded by a specific topic.\n"
             "admin topic supersede list <topic>")
    @admin_command
    @protected_command
    def admin_topic_supersede_list(bot, params, user, recipient, mainchannel, bypass=False):
        topic = bot.find_topic(params[0])
        if len(topic.supersedes) > 0:
            bot.send_and_log(recipient, user, "%s supersedes the following topics: %s"
                % (topic.name, join_and(", ", " and ", (entry for entry in topic.supersedes))))
        else:
            bot.send_and_log(recipient, user, "%s does not supersede any topics." % topic.name)

    @command("Execute commands as another user.\n"
             "admin user <nickname> <command>")
    @admin_command
    @protected_command
    @logged_command
    def admin_user(bot, params, user_executed, recipient, mainchannel, bypass=False):
        user = bot.find_user(params[0])
        # FIXME: Reply in-channel when executed in-channel
        bot.dispatch(command=' '.join(params[1:]), user=user, reply_to=user_executed, bypass=True)

    @command("Warn an user.\n"
             "admin warn <user> [<reason>]")
    @admin_command
    @protected_command
    @logged_command
    def admin_warn(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.find_user(params[0])
            user.warnings[datetime.datetime.now()] = None, user_executed.nick, str(" ".join(params[1:])) if len(params) > 1 else None
            warningsbytriggerbot = 0
            for entry in user.warnings.keys():
                if user.warnings[entry][1] == None:
                    warningsbytriggerbot = warningsbytriggerbot + 1
            if user.warnings[entry][2:] == None:
                bot.send_and_log(user, None,
                    "%s has sent you a warning."
                        % user.warnings[entry][1])
            else:
                bot.send_and_log(user, None,
                    "%s has sent you a warning with the following reason: %s."
                        % (user.warnings[entry][1], user.warnings[entry][2]))
            bot.send_and_log(user, None,
                "Please think about your behaviour and try to improve it.")
            bot.send_and_log(user, None, 
                "For your information, you currently have %s warning(s), of which %s were automatically sent to you by %s." %
                (len(user.warnings), warningsbytriggerbot, bot.nickname))
        else:
            raise MissingParams

    @command("Manage an user's warnings.")
    @admin_command
    @protected_command
    def admin_warnings(bot, params, user, recipient, mainchannel, bypass=False):
        raise BadCommand
    
    @command("List the amount of warnings an user has.\n"
             "Use 'verbose' to receive a more verbose list.\n"
             "By default, only the last 10 entries are shown in verbose mode. Type a number on 'all' to show more entries.\n"
             "admin warnings list <user> [<type>] [<entries>]")
    @admin_command
    @protected_command
    def admin_warnings_list(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            user = bot.find_user(params[0])
            if len(user.warnings) > 0:
                if len(params) <= 1 or params[1] != "verbose":
                    warningsbyuser = {}
                    for entry in user.warnings.keys():
                        warner = user.warnings[entry][1] if user.warnings[entry][1] != None else bot.nickname
                        if warner in warningsbyuser:
                            warningsbyuser[warner] = warningsbyuser[warner] + 1
                        else:
                            warningsbyuser[warner] = 1
                    bot.send_and_log(recipient, user_executed,
                        "Since %s, %s has received %s warning(s). %s." %
                            (user.warnings.keys()[0].strftime("%Y-%m-%d %H:%M:%S"), user.nick, len(user.warnings.keys()), ', '.join(["%s by %s" % 
                            (warningdata[1], warningdata[0]) for warningdata in warningsbyuser.items()])))
                else:
                    if user.warnings:
                        start = len(user.warnings)-10
                        try:
                            if params[2] == "all":
                                start = 0
                            else:
                                try:
                                    start = len(user.warnings)-int(params[2])
                                except:
                                    pass
                        except:
                            pass
                        if start > 0:
                            bot.send_and_log(recipient, user_executed,
                                "Limiting output to the most recent %s of %s entries." % (len(user.warnings)-start, len(user.warnings)))
                        else:
                            bot.send_and_log(recipient, user_executed,
                                "Showing all %s entries." % len(user.warnings))
                    for number, warning in enumerate(user.warnings.keys()[start:]):
                        bot.send_and_log(recipient, user_executed,
                            "%s - warned by %s: %s"
                                % (user.warnings.keys()[number].strftime("%Y-%m-%d %H:%M:%S"), bot.nickname if user.warnings[warning][1] == None else user.warnings[warning][1], "No reason specified." if user.warnings[warning][2] == None else user.warnings[warning][2]))
            else:
                bot.send_and_log(recipient, user_executed,
                   "%s has not received any warnings." % user)
        else:
            raise MissingParams

    @command("Reset one or more users' warnings.\n"
             "admin warnings reset <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_warnings_reset(bot, params, user_executed, recipient, mainchannel, bypass=False):
        if len(params) > 0:
            for nick in params:
                user = bot.find_user(nick)
                user.warnings = {}
            bot.send_and_log(recipient, user_executed,
                "Warnings reset.")
        else:
            raise MissingParams

    @command("Delete all someone's trigger topics and words.\n"
             "admin wipe <user>")
    @admin_command
    @protected_command
    @logged_command
    def admin_wipe(bot, params, user, recipient, mainchannel, bypass=False):
        target = bot.find_user(params[0])
        target.trigger_words.clear()
        target.topics.clear()
        bot.changed()
        bot.send_and_log(recipient, user,
            "All data for %s are gone. I hope it's what you wanted."
                % target)
    
    @command("Claim administrative powers if no admin has been registered yet.\n"
             "claimadmin")
    def claimadmin(bot, params, user_executed, recipient, mainchannel, bypass=False):
        for user in bot.users.itervalues():
            if user.admin == 1:
                bot.send_and_log(recipient, user_executed, "A head admin already exists. Therefore, you cannot claim administrative power.")
                return
        user_executed.admin = 1
        bot.send_and_log(recipient, user_executed, "You have claimed administrative powers.")

register_commands()

class TriggerBotFactory(protocol.ReconnectingClientFactory):
    """A factory for TriggerBots.

    A new protocol instance will be created each time we connect to the server.
    """

    # This factor is an approximation of Phi, instead of Twisted's default 
    # approximation of e. Because triggerbot should limit its downtime, a 
    # lower exponential backoff value is useful
    factor = 1.6180339887498948

    def __init__(self, channellist, channelsdefined, logger, filename, nickname, identify, identifypassword):
        self.channellist = channellist
        self.channelsdefined = channelsdefined
        self.logger = logger
        self.filename = filename
        self.nickname = nickname
        self.identify = identify
        self.identifypassword = identifypassword

    def buildProtocol(self, addr):
        p = TriggerBot()
        p.channellist = self.channellist
        p.channelsdefined = self.channelsdefined
        p.logger = self.logger
        p.filename = self.filename
        p.nickname = self.nickname
        p.wantednick = self.nickname
        p.identify = self.identify
        if self.identify == True:
            p.identifypassword = self.identifypassword
        p.stem = xapian.Stem("en")
        self.resetDelay()
        return p

    def clientConnectionLost(self, connector, reason):
        global reconnectondc
        if reconnectondc:
            connector.connect()
        else:
            reactor.stop()

def main():
    """Main function. Called from main.py."""
    # Default values:
    database = "triggerbot.db"
    nickname = "triggerbot"
    channellist = []
    logfile = None
    identify = False
    identifypassword = None

    serverdefined = False
    portdefined = False
    channelsdefined = False
    for index, arg in enumerate(sys.argv):
        if arg == "--server" or arg == "-s":
            server = sys.argv[index+1]
            serverdefined = True
        elif arg == "--port" or arg == "-p":
            port = sys.argv[index+1]
            portdefined = True
        elif arg == "--channel" or arg == "-c":
            channelsdefined = True
            for x in range(index, len(sys.argv)):
                try:
                    if sys.argv[x+1][:1] != "-":
                        channellist.append(sys.argv[x+1])
                    else:
                        break
                except IndexError:
                    # End of list, don't worry
                    break
        elif arg == "--nick" or arg == "-n":
            nickname = sys.argv[index+1]
        elif arg == "--identify" or arg == "-i":
            identify = True
            identifypassword = sys.argv[index+1]
        elif arg == "--logfile" or arg == "-l":
            logfile = sys.argv[index+1]
        elif arg == "--database" or arg == "-d":
            database = sys.argv[index+1]

    if serverdefined != True or portdefined != True:
        print "Please specify at least the server and port info using --server (-s) and --port (-p) followed by the related information."
        exit(1)
    log.startLogging(sys.stdout)

    logger = MessageLogger \
        (open(logfile, "a") if logfile != None
         else sys.stdout)

    global reconnectondc
    reconnectondc = True
    f = TriggerBotFactory \
        (channellist=channellist, channelsdefined=channelsdefined, logger=logger, filename=database, nickname=nickname, identify=identify, identifypassword=identifypassword)
    reactor.connectTCP(server, int(port), f)
    reactor.run()
