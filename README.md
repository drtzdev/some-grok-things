# some-grok-things
some grok patterns tested and working fine in logstash

### Using /var/log/audit/audit.log

SSH Log format.

    type=USER_AUTH msg=audit(1650551854.832:836): pid=5233 uid=0 auid=4294967295 ses=4294967295 
    msg='op=PAM:authentication grantors=pam_unix acct="weow"exe="/usr/sbin/sshd" hostname=192.168.0.109 
    addr=192.168.0.109 terminal=ssh res=success'UID="root" AUID="unset"
    
Grok pattern SSH login succeed.

    type=USER_AUTH msg=audit\(%{NUMBER:audit_epoch}:%{NUMBER:audit_counter}\): pid=%{NUMBER:audit_pid} 
    uid=%{NUMBER:audit_uid} auid=%{NUMBER:audit_auid} ses=%{NUMBER:audit_session} msg=\'op=%{WORD:pam}:%{WORD:auth} 
    grantors=%{DATA:grantors} acct=\"%{WORD:username}\" exe=\"/usr/sbin/sshd\" hostname=%{HOSTNAME:hostname} 
    addr=%{DATA:ipaddr} terminal=%{DATA:terminal} res=success

Grok pattern SSH login failed.

    type=USER_AUTH msg=audit\(%{NUMBER:audit_epoch}:%{NUMBER:audit_counter}\): pid=%{NUMBER:audit_pid} 
    uid=%{NUMBER:audit_uid} auid=%{NUMBER:audit_auid} ses=%{NUMBER:audit_session} msg=\'op=%{WORD:pam}:%{WORD:auth} 
    grantors=%{DATA:grantors} acct=\"%{WORD:username}\" exe=\"/usr/sbin/sshd\" hostname=%{HOSTNAME:hostname} 
    addr=%{DATA:ipaddr} terminal=%{DATA:terminal} res=failed

/etc/logstash/conf.d/03_linux.conf

    filter {
        if[log][file][path] == "/var/log/audit/audit.log" {
        
                grok {
                        match => { "message" => "type=USER_AUTH msg=audit\(%{NUMBER:audit_epoch}:%{NUMBER:audit_counter}\): pid=%{NUMBER:audit_pid} uid=%{NUMBER:audit_uid} auid=%{NUMBER:audit_auid} ses=%{NUMBER:audit_session} msg=\'op=%{WORD:pam}:%{WORD:auth} grantors=%{DATA:grantors} acct=\"%{WORD:username}\" exe=\"/usr/sbin/sshd\" hostname=%{HOSTNAME:hostname} addr=%{DATA:ipaddr} terminal=%{DATA:terminal} res=success"}
                        add_tag => ["ssh_login_successful"]
                }

                grok {
                        match => { "message" => "type=USER_AUTH msg=audit\(%{NUMBER:audit_epoch}:%{NUMBER:audit_counter}\): pid=%{NUMBER:audit_pid} uid=%{NUMBER:audit_uid} auid=%{NUMBER:audit_auid} ses=%{NUMBER:audit_session} msg=\'op=%{WORD:pam}:%{WORD:auth} grantors=%{DATA:grantors} acct=\"%{WORD:username}\" exe=\"/usr/sbin/sshd\" hostname=%{HOSTNAME:hostname} addr=%{DATA:ipaddr} terminal=%{DATA:terminal} res=failed"}
                        add_tag => ["ssh_login_failed"]
                }
         }
    }
    
### Using /var/log/secure

SSH log format.

    Sep 12 06:15:56 localhost sshd[16029]: Accepted password for root from 192.168.0.109 port 56312 ssh2 

Grok pattern SSH login succeed.

    %{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sshd\[%{BASE10NUM:num}\]: Accepted password for
    %{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port} ssh2

/etc/logstash/conf.d/03_linux.conf

    filter {
        if[log][file][path] == "/var/log/secure" {
    
            grok {
                    match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sshd\[%{BASE10NUM:num}\]: Accepted password for %{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port} ssh2"}
                    add_tag => ["ssh_login_successful"]
            }
        }
    }
