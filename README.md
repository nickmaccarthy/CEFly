Title: CEFly
Author: Nick MacCarthy
Email: nickmaccarthy@gmail.com

# CEFly #

What is CEFly?
------------------------------------

CEFly ( pronouced sef lee ) is an app that allows Splunk to output its events in something called "CEF format" via syslog to a receiver such as HP's ArcSight ESM or ArcSight Logger.

CEF aka "Common Event Format" is a standard derived by ArcSight for the interoperability of logging events between different systems and central logging solutions.  Many vendors output their logs in CEF format and use the standard syslog protocol to send its events to a destination server that supports CEF such as HP's ArcSight. 

Why did you make this?
------------------------------------


Splunk is great tool for centeralized log aggregation and reporting; however my company, like many others also utilize SIEM ( Security, Information and Event Monitoring ) tools for daily Security Operations Center (SOC) work.  While Splunk was by far the best logging and reporting tool we had at our disposal, the data in it was too siloed when it came to intergrating it with the SIEM; i.e. there was no good way to export data from Splunk into the SIEM natively without alot of work on the SIEM side of things.  

In steps CEFly.  

Since the SIEM accepts CEF natively, I figured we could utilze Splunk to tranlate the events inside of it into CEF messages that could be sent via syslog to our SIEM by utilizing the powerful features such Saved Reporting, Alerting, and Scripted Outputs. 

By utilizing these features, all messages for an entire log source or even down to just specific events can be sent to the SIEM as needed having Splunk act as both a 'filter' and translator for the CEF format.  All you need is a Saved Search with an Alert and a definition in cefly.conf to define and map the Splunk filds to the CEF Fields accordingly and that is it.


How do I use it?
------------------------------------

1. Download and extract this app and its contents to $SPLUNK_HOME/etc/apps
2. Copy the savedsearches.conf from default into local/savedsearches.conf
3. Copy cefly.conf from default/cefly.conf to local/cefly.conf
4. Create or modify a new entry in local/savedsearches.conf for the search you wish to run to get the events you want CEFly out
5. Create a new entry or modify an example in local/cefly.conf with a label name the same as your saved search from above
6. Define your cefly outputs, use the example provided from default/cefly.conf for clarification

Do you have a list of CEF Field names to make mapping easier?
-----------------------------------

Yes I do, please checkout share/cef_maps.csv for a list off supported CEF field names for ArcSight Logger.

Things you should know:
------------------------------------

1. The label in cefly.conf and savedsearches.conf  must be exact for the log type you want to output.  Check out the example default/cefly.conf and default/savesearches.conf for clarification and how they match up.
2. You can do real time searches instead of scheduled searches, however, I find that scheduled searches take up much less resources on the system.  I have tested this with fairly big sources with searches that run every minute with no issues.  Realtime for the same source were causing a pretty noticable performace impact for the same ammount of data.  My suggestion is not use real time unless you absolutely have to for this reason, since at most you your outputted event will be one minute behind which was acceptable for our needs and kept load on the server down considerably.
3. CEFly keeps metrics about itself in the _internal index, or under the $SPLUNK_HOME/var/log/splunk/cefly.log file.

How much testing have you done?
------------------------------------

I have been using CEFly for a few months now, outputting 30+GB of data per day with no issues.  We havent seen any major issues, and as long as the Saved Searches arent real time, we havent seen any load or resource issues with the 15 or so outputs we have configured today.  If you run it, and for some reason encouter an issue, please get in contact with me.

Whats next:
------------------------------------

1. I plan to make a web UI for the configuation/setup of CEFly in the future so we dont have edit/create config files manually
2. More enhancements to the dashboard such as drilldowns, more/prettier graphs etc



Issues / Comments / Concerns?
------------------------------------

If you have any questions, comments or concerns, please get in contact with me.  Please also feel free to fork this project if you have anything you would like to add.

email me: nickmaccarthy@gmail.com


