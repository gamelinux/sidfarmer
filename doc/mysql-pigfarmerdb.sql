CREATE TABLE `sensor` (
  `sensorid`    int(10) unsigned NOT NULL auto_increment,
  `hostname`    varchar(255) NOT NULL,
  `agent_type`  varchar(40) default NULL,
  `net_name`    varchar(40) default NULL,
  `interface`   varchar(255) default NULL,
  `description` text,
  `bpf_filter`  text,
  `updated`     timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  `active`      enum('Y','N') default 'Y',
  `ip`          varchar(15) default NULL,
  `public_key`  varchar(255) default NULL,
  PRIMARY KEY   (`sensorid`),
  KEY `hostname_idx` (`hostname`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;

INSERT INTO sensor (sensorid, hostname, agent_type, net_name, interface, description, bpf_filter, active, ip, public_key) VALUES ('1','MASTER', 'MASTER_TEMPLATE', 'DUMMY_NET', 'eth0', 'Master template dummy', 'ip', 'Y', '127.0.0.1', '');

CREATE TABLE `sensor_group` (
  `sensorgid`   int(10) NOT NULL auto_increment,
  `name`        varchar(40) default NULL,
  `description` varchar(255) default NULL,
  `updated`     timestamp NOT NULL,
  PRIMARY KEY  (`sensorgid`)
) ENGINE=MyISAM;

INSERT INTO sensor_group (sensorgid, name, description) VALUES ('1','ALL SENSORS','This group contains all sensors');

CREATE TABLE `sensor_gid` (
  `sensorid`   int(10) default NULL,
  `sensorgid`  int(10) default NULL,
  KEY `idx_rid` (`sensorid`)
) ENGINE=MyISAM;

INSERT INTO sensor_gid (sensorid, sensorgid) VALUES ('1','1');

CREATE TABLE `sensor_status` (
  `sensorid`     int(10) NOT NULL default '0',
  `statusflag`   int(11) default NULL,
  `lastlog`      text,
  `lastcheck`    timestamp NOT NULL,
  `lastupdate`   timestamp NOT NULL,
  PRIMARY KEY  (`sensorid`)
) ENGINE=MyISAM;

CREATE TABLE `rule_group` (
  `rulegid`      int(10) NOT NULL auto_increment,
  `name`         varchar(40) default NULL,
  `description`  varchar(255) default NULL,
  `updated`      timestamp NOT NULL,
  PRIMARY KEY  (`rulegid`)
) ENGINE=MyISAM;

INSERT INTO rules_group (rulegid, name, description) VALUES ('1','All rules','This group contains all rules');

CREATE TABLE `rules` (
  `ruleid`       int(12) NOT NULL auto_increment,
  `sid`          int(12) NOT NULL,
  `sensorid`     int(10) NOT NULL default '0',
  `name`         varchar(255) default NULL,
  `active`       enum('Y','N') default NULL,
  `rev`          int(10) default NULL,
  `updated`      timestamp NOT NULL,
  `created`      timestamp NOT NULL,
  `action`       varchar(30) default NULL,
  `proto`        varchar(30) default NULL,
  `s_ip`         varchar(255) default NULL,
  `s_port`       varchar(30) default NULL,
  `dir`          enum('->','<-','<>') default NULL,
  `d_ip`         varchar(255) default NULL,
  `d_port`       varchar(30) default NULL,
  `options`      blob,
  PRIMARY KEY  (`ruleid`)
) ENGINE=MyISAM AUTO_INCREMENT=1; 

# ALTER TABLE rules AUTO_INCREMENT=1;

CREATE TABLE `rrgid` (
  `ruleid`       int(12) default NULL,
  `rulegid`      int(10) default NULL,
  KEY `idx_rid` (`ruleid`)
) ENGINE=MyISAM;

CREATE TABLE `sensor_rulegroup` (
  `sensorid`     int(10) default NULL,
  `rulegid`      int(10) default NULL
) ENGINE=MyISAM;

CREATE TABLE `variables` (
  `varid`        int(10) NOT NULL auto_increment,
  `varname`      varchar(30) default NULL,
  `vartype`      enum('var','portvar') default NULL,
  PRIMARY KEY  (`varid`)
) ENGINE=MyISAM;

INSERT INTO variables (varid, vartype, varname) VALUES ( 1, 'var',     'HOME_NET');
INSERT INTO variables (varid, vartype, varname) VALUES ( 2, 'var',     'EXTERNAL_NET');
INSERT INTO variables (varid, vartype, varname) VALUES ( 3, 'var',     'HTTP_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 4, 'var',     'SQL_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 5, 'var',     'SMTP_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 6, 'var',     'DNS_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 7, 'portvar', 'SHELLCODE_PORTS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 8, 'portvar', 'HTTP_PORTS');
INSERT INTO variables (varid, vartype, varname) VALUES ( 9, 'portvar', 'ORACLE_PORTS');
INSERT INTO variables (varid, vartype, varname) VALUES (10, 'var',     'TELNET_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES (11, 'var',     'AIM_SERVERS');
INSERT INTO variables (varid, vartype, varname) VALUES (12, 'var',     'RULE_PATH');
INSERT INTO variables (varid, vartype, varname) VALUES (13, 'var',     'PREPROC_RULE_PATH');

ALTER TABLE variables AUTO_INCREMENT=1000;

CREATE TABLE `varvalue` (
  `varid`        int(11) NOT NULL,
  `sensorid`     int(11) NOT NULL,
  `value`        varchar(255) NOT NULL,
  `comment`      varchar(255) default NULL,
  `updated`      timestamp NOT NULL
) ENGINE=MyISAM;

# Insert defaults for sensor '0' i.e. default sensor
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 1,0,'any','Default definition for HOME_NET');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 2,0,'any','Default definition for EXTERNAL_NET');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 3,0,'$HOME_NET','Default definition for HTTP_SERVERS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 4,0,'$HOME_NET','Default definition for SQL_SERVERS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 5,0,'$HOME_NET','Default definition for SMTP');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 6,0,'$HOME_NET','Default definition for DNS_SERVERS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 7,0,'!80','Default definition for SHELLCODE_PORTS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 8,0,'80','Default definition for HTTP_PORTS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES ( 9,0,'1521','Default definition for ORACLE_PORTS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES (10,0,'$HOME_NET','Default definition for TELNET_SERVERS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES (11,0,'[64.12.24.0/24,64.12.25.0/24,64.12.26.14/24,64.12.28.0/24,64.12.29.0/24,64.12.161.0/24,64.12.163.0/24,205.188.5.0/24,205.188.9.0/24]','Default definition for AIM_SERVERS');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES (12,0,'/etc/snort/rules','Default definition for RULE_PATH');
INSERT INTO varvalue (varid, sensorid, value, comment) VALUES (13,0,'/etc/snort/preproc_rules','Default definition for PREPROC_RULE_PATH');

CREATE TABLE `preprocessor` (
  `ppid`       int(11) NOT NULL auto_increment,
  `ppname`     varchar(30) default NULL,
  PRIMARY KEY  (`ppid`)
) ENGINE=MyISAM;

INSERT INTO preprocessor (ppid, ppname) VALUES ( '1', 'frag3_global');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '2', 'frag3_engine');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '3', 'stream5_global');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '4', 'stream5_tcp');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '5', 'perfmonitor');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '6', 'http_inspect');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '7', 'http_inspect_server');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '8', 'rpc_decode');
INSERT INTO preprocessor (ppid, ppname) VALUES ( '9', 'bo');
INSERT INTO preprocessor (ppid, ppname) VALUES ('10', 'ftp_telnet');
INSERT INTO preprocessor (ppid, ppname) VALUES ('11', 'ftp_telnet_protocol');
INSERT INTO preprocessor (ppid, ppname) VALUES ('12', 'ftp_telnet_protocol');
INSERT INTO preprocessor (ppid, ppname) VALUES ('13', 'ftp_telnet_protocol');
INSERT INTO preprocessor (ppid, ppname) VALUES ('14', 'smtp');
INSERT INTO preprocessor (ppid, ppname) VALUES ('15', 'sfportscan');
INSERT INTO preprocessor (ppid, ppname) VALUES ('16', 'ssh');
INSERT INTO preprocessor (ppid, ppname) VALUES ('17', 'dcerpc');
INSERT INTO preprocessor (ppid, ppname) VALUES ('18', 'dns');
INSERT INTO preprocessor (ppid, ppname) VALUES ('19', 'ssl');

CREATE TABLE `preprocessorvalue` (
  `ppid`         int(11) NOT NULL,
  `sensorid`     int(11) NOT NULL,
  `options`      text NOT NULL,
  `comment`      varchar(255) default NULL,
  `active`       enum('Y','N') default 'Y',
  `updated`      timestamp NOT NULL
) ENGINE=MyISAM;

INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '1','0','max_frags 65536','Default options for frag3_global');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '2','0','policy linux detect_anomalies','Default options for frag3_engine');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '3','0','max_tcp 8192, track_tcp yes, track_udp no','Default options for stream5_global');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '4','0','policy first, use_static_footprint_sizes','Default options for stream5_tcp');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '5','0','time 60 file /var/log/snort/snort.stats pktcnt 1000','Default options for perfmonitor');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '6','0','global iis_unicode_map unicode.map 1252','Default options for http_inspect');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '7','0','server default profile all ports { 80 8080 8180 } oversize_dir_length 500','Default options for http_inspect_server');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '8','0','111 32771','Default options for rpc_decode');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ( '9','0',"",'Default options for bo');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('10','0','global encrypted_traffic yes inspection_type stateful','Default options for ftp_telnet');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('11','0','telnet normalize ayt_attack_thresh 200','Default options for ftp_telnet_protocol');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('12','0','ftp server default def_max_param_len 100 alt_max_param_len 200 { CWD } cmd_validity MODE < char ASBCZ > cmd_validity MDTM < [ date nnnnnnnnnnnnnn[.n[n[n]]] ] string > chk_str_fmt { USER PASS RNFR RNTO SITE MKD } telnet_cmds yes data_chan','Default options for ftp_telnet_protocol');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('13','0','ftp client default max_resp_len 256 bounce yes telnet_cmds yes','Default options for ftp_telnet_protocol');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('14','0','ports { 25 587 691 } inspection_type stateful normalize cmds normalize_cmds { EXPN VRFY RCPT } alt_max_command_line_len 260 { MAIL } alt_max_command_line_len 300 { RCPT } alt_max_command_line_len 500 { HELP HELO ETRN } alt_max_command_line_len 255 { EXPN VRFY }','Default options for smtp');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('15','0','proto  { all } memcap { 10000000 } logfile { /etc/snort/portscans }  sense_level { low }','Default options for sfportscan');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('16','0','server_ports { 22 } max_client_bytes 19600 max_encrypted_packets 20','Default options for ssh');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('17','0','autodetect max_frag_size 3000 memcap 100000','Default options for dcerpc');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('18','0','ports { 53 } enable_rdata_overflow','Default options for dns');
INSERT INTO preprocessorvalue (ppid, sensorid, options, comment) VALUES ('19','0','noinspect_encrypted','Default options for ssl');


CREATE TABLE `version` (
  `version`       VARCHAR(32),
  `installed`     DATETIME
);

INSERT INTO version (version, installed) VALUES ("0.01", now());

