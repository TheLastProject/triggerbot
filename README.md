<!--
Copyright (c) 2013 Sylvia van Os
This file is part of Triggerbot, released under the MIT license

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
-->

Triggerbot
==========

Triggerbot is an IRC bot to assist in creating a safe environment for people with triggers.

It allows people to specify triggers (from a pre-set list of triggers) and their sensitivity for this. Triggerbot will then check the triggers of all users in the current channel to create a set of rules exactly as strict and loose as it should be, updating it as users join, leave or update their triggers.

The main idea was that people with triggers, or those who just dislike certain things, should be protected against these things, but that it makes no sense protecting them when they are not there (which is often the case with static rules)

Dependencies
------------

Triggerbot depends on the Twisted framework, Xapian, Python's BCrypt module and Python 2.7.x (other versions may work, but have not been tested)

How to run Triggerbot
---------------------

To run triggerbot, execute the main.py file using Python 2.7, while defining at least server and port. For example:
``python main.py --server irc.example.com --port 6667``

Triggerbot supports the following flags, which can be set in any order:

Required:
* --server (-s) -> Set the name or IP address of the server to connect to
* --port (-p) -> Set the port to connect to

Optional:
* --channel (-c) -> Set the channel(s) to join when connected. When not defined, join the channels connected to during the last settings
* --nick (-n) -> Set the bot's nickname (default: triggerbot)
* --logfile (-l) -> Set a file to log to (default: don't log to a file, but to stdout)
* --identify (-i) -> Identifies to NickServ
* --database (-d) -> Set the database file to use (defult: triggerbot.db)

*Note: On first run, be sure to use the "claimadmin" command to claim administrator rights. This command is only available if there is no administrator in the database. If another user claims it before you, they will control the bot and the database. It is important to be the first to claim administrator rights!*

Commands
--------

When possible, triggerbot will attempt to finish your command. In many cases, you can abbreviate your command!

Triggerbot supports the following commands:

### For users:
##### Managing your profile
* clone -> clone someone's profile over to your profile (this overwrites your own profile, if you have one)
* friend -> manage your friend list (friends will contacted first if you're panicking, and you will get an alert when they join)
    * add -> add one or more user(s) to your friend list
    * remove -> remove one or more user(s) from your friend list
    * list -> list your or someone else's friends
* group -> group the current account with another one (make this account an alt)
    * add -> specify the "master account" this account should become an alt of
    * remove -> ungroup this account
    * list -> list the group an account is part of an its position in the group
* mail -> use the mail system
    * inbox -> list your messages
    * mark -> mark mail(s) as read or unread
        * read -> mark as read
        * unread -> mark as unread
    * read -> read a message
    * remove -> remove a message
    * send -> send a message
* topics -> manage topics which make you feel uncomfortable
    * add -> add one or more trigger topic(s) to your triggerlist
    * remove -> remove one or more trigger topic(s) from your triggerlist
    * list -> list trigger topics belonging to you or other people
    * info -> get info about the trigger topics or a specific trigger topic
* word -> manage words which may trigger you
    * add -> add one or more word(s) to your triggerword list
    * remove -> remove one or more word(s) from your triggerword list
    * list -> list triggerwords belonging to you or someone else
    * who -> check who is sensitive to a certain word
* trust -> manage users who are allowed to manage your profile
    * add -> give an user complete permission over your profile
    * remove -> remove an user's ability to manage your profile
    * list -> list users you trust to manage your profile
* set -> activate an account-based option or set the exact value of it
    * awaycheck -> do not apply your trigger topics and words if you are away
    * autosilence -> block in and outcoming messages automatically when you are away
    * hideown -> hide your own trigger topics from the rules in your personal triggersafe channels
    * listenmode -> ignore all commands in a private chat and sometimes answer with a friendly nod
    * motdread -> marks the MOTD as read and prevents it from being displayed in your channel topic
    * nickservlogin -> causes NickServ logins to identify you with triggerbot
    * password -> password protect your account
    * channel -> create a #channel_nickname channel for each channel in which triggerwords do not get relayed
* unset -> deactivate an account-based option
    * awaycheck -> apply your trigger topics and words even if you are away
    * autosilence -> do not automatically block in and outcoming messages when you are away
    * hideown -> do not hide your own trigger topics from the rules in your personal triggersafe channels
    * listenmode -> check all sentences for commands, even in private chat
    * motdread -> marks the MOTD as unread, showing it in your channel topic
    * nickservlogin -> causes NickServ logins to no longer identify you with triggerbot
    * password -> disable password protection for your account
    * channel -> remove all #channel_nickname channels
* status -> check the status of an account-based option
* identify -> Login to your account in case it is protected
* logout -> Log yourself out
* user -> execute commands as another user
* wipe -> wipe all your data (triggers and triggerwords)

##### Knowing what is up
* names -> get a list of online users, including those in triggersafe channels
* rules -> receive a list of rules
* seen -> get info on when someone was last see
* whois -> get info on someone

##### Asking for help / Keeping the channel safe
* admins -> gives a list of online bot admins
* channelallow -> manage who is allowed on your channel
    * add -> allow one or more users to be in your channel
    * remove -> disallow one or more users to be in your channel
    * list -> show your channelallow list
* change -> anonymously request a topic change
* ignore -> manage your ignore list
    * add -> add one or more users to your ignore list
    * remove -> remove one or more users from your ignore list
    * list -> show your ignore list
* mode -> manage channel mode
    * add -> add a channel mode
        * filterless -> do not filter incoming messages, regardless of their content
        * rant -> do not relay your messages to anyone having any triggerword or topic set
        * silent -> do not relay messages and block all incoming messages
    * remove -> remove a channel mode
        * filterless -> filter incoming messages if they contain content unsafe for you
        * rant -> relay your messages to all users, even those having triggerwords or topics set
        * silent -> relay messages and do not block incoming messages
    * list -> get current mode
    * reset -> reset the channel mode to the default
* panic -> check channels to see if anyone is available to comfort you
* permission -> see what admin commands a moderator is allowed to execute

##### Various
* hug -> let the bot hug you or someone else
* source -> receive a link to triggerbot's source code
* tutorial -> learn more about how to use triggerbot

### For channel admins:
*Note: all channel admin commands start with "channel" and should be executed in-channel, or with the channel name as first parameter*

#### Managing channel admins
* add -> add another user as channel administrator
* logs -> get a list of all mod/admin actions executed in your channel in the last month
* remove -> remove another user as channel administrator

#### Managing users
* announce -> sent an announcement to all the users in the channel
* ban -> ban an user
* kick -> kick an user
* kickban -> kick and ban an user
* unban -> unban an user
* topicblock -> manage blocked topics
    * add -> block a topic
    * list -> list blocked topics
    * remove -> unblock a topic
* warn -> warn an user for bad behaviour
* warnings -> manage an user's warnings
    * list -> get a list of warnings (use verbose for a verbose list)
    * reset -> remove all user warnings

### For admins:
*Note: all admin commands start with "admin"*

##### Managing admins
* add -> add another user as administrator
* logs -> get a list of all actions an admin executed in the last month
* remove -> remove all powers from a user
* permission -> manage which admin command a non-admin user can execute
    * add -> add an admin command to the list
    * remove -> remove an admin command from the list

##### Managing users
* announce -> sent an announcement to all channels
* ban -> ban an user
* create -> create a database entry for an user
* kick -> kick an user
* kickban -> kick and ban an user
* unban -> unban an user
* warn -> warn an user for bad behaviour
* warnings -> manage an user's warnings
    * list -> get a list of warnings (use verbose for a verbose list)
    * reset -> remove all user warnings
* topic -> managing trigger topics
    * add -> add a trigger topic or update it
    * remove -> remove a trigger topic
    * supersede -> manage which topics are not applied when a certain topic is in place
        * add -> add a topic to the supersede list of another topic
        * remove -> remove a topic from the supersede list of another topic
        * list -> list topics superseded by a certain topic
    * word -> manage words used to detect a topic
        * add -> add one or more words to the topic word list
        * remove -> remove one or more words from the topic word list
        * list -> list words used to detect a topic
* user -> execute a command as another user
* wipe -> wipe data
    * user -> wipe the data of a specific user
    * users -> wipe the data of all users
    * triggers -> wipe all trigger topics

##### Managing the bot
* channel -> manage channels
    * join -> order the bot to join one or more channels
    * leave -> order the bot to leave one or more channels
    * list -> retrieve a list of managed channels
* ignore -> manage the bot's ignore list
    * add -> add one or more users to the bot's ignore list
    * remove -> remove one or more users from the bot's ignore list
    * list -> get a list of who the bot is ignoring
* quit -> order the bot to disconnect
* reconnect -> order the bot to reconnect
* set -> change bot settings
    * globalmotd -> set a motd which will be displayed on all channels
    * maindisabled -> disables the main channel, forcing every user to use a triggerfree channel
* togglecommand -> enable or disable certain commands
    * enable -> enable a previously disabled command
    * disable -> disable a command
    * list -> list disabled commands

##### Various
* check -> check and force consistency
    * database -> check and force database consistency (either run this or restart the bot after updating!)
* export -> export topics and users as triggerbot formats

For a more detailed explanation, use the built-in help system

License
-------

This project is MIT-licensed. For more info, read LICENSE
