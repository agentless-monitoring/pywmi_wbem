# Introduction
Python library for Web-Based Enterprise Management (WBEM). WMI Queries and Remote Shell scripts can be sent securely to windows hosts via encrypted communication. Based on this, nagios plugins can gather arbitrary information about the remote system for monitoring purposes.

#Testing
First of all the python path needs to be set

cd pywmi_wbem/src/
export PYTHONPATH=$(pwd) 

cd ..
./nagios_checks/check_disk_wbem -H 'host.to.check' -a 'user:pw' --ssl

One can also authenticate via Kerberos. After adding a local user to the Administrator group on the remote host, Kerberos client needs to be set up on the local server. A kerberos ticketcan be created via **kinit domain_user_account**.

Supported checks are:

Disk
File
Load
Memory
Process
Remote Ping
Smart
Swap
Windows Task (via Remote Shell)
Windows Updates (via Remote Shell)

# Icinga config commands 

```
object CheckCommand "load-wbem" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_load_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
  }

  timeout = 120

  vars.wmi_host = "$address$"
}

object CheckCommand "win-task-wbem" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_win_task_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
    "-P" = {
    value = "$task_path_regex$"
   }
  }

  timeout = 120

  vars.wmi_host = "$address$"
}

object CheckCommand "memory-wbem" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_memory_wbem"]

  arguments = {
    "-H" = "$wmi_host$"
    "-W" = "$memory_warn_used$"
    "-C" = "$memory_crit_used$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
  }

  timeout = 120

  vars.wmi_host = "$address$"
  vars.memory_warn_used = "90"
  vars.memory_crit_used = "95"
}

object CheckCommand "disk-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_disk_wbem"]

  arguments = {
    "-H" = "$wmi_host$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
    "-W" = {
      value = "$warning_disk_free$"
      description = "Warning Threshold"
    }
    "-C" = {
      value = "$critical_disk_free$"
      description = "Critical Threshold"
    }
    "-d" = {
      value = "$drives$"
      description = "Drives to show"
    }
    "-i" = {
      value = "$ignore_drives$"
      description = "Drives to ignore"
    }
  }

  timeout = 120

  vars.warning_disk_free = "2GB"
  vars.critical_disk_free = "1GB"
  vars.wmi_host = "$address$"
}

object CheckCommand "swap-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_swap_wbem"]

  arguments = {
    "-H" = "$wmi_host$"
    "-W" = "$swap_warn_used$"
    "-C" = "$swap_crit_used$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
 }

  timeout = 240

  vars.wmi_host = "$address$"
  vars.swap_warn_used = 90
  vars.swap_crit_used = 95
}

object CheckCommand "smart-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_smart_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
  }

  timeout = 120

  vars.wmi_host = "$address$"
}

object CheckCommand "process-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_process_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-p" = "$process_name$"
    "-r" = "$regex$"
    "-S" = {
      set_if = "$wmi_ssl$"
    }
    "-C" = "$process_count$"
    "-a" = {
      value = "$wmi_auth_pair$"
      description = "Username:password on sites with basic authentication"
    }
    "-m" = "$mode$"
  }

  vars.wmi_host = "$address$"
}

object CheckCommand "remote-ping-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_remote_ping_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-r" = "$remote_ip$"
  }

  vars.wmi_host = "$address$"
}

object CheckCommand "file-wmi" {
  import "plugin-check-command"

  command = [ PluginDir + "/check_file_wbem" ]

  arguments = {
    "-H" = "$wmi_host$"
    "-f" = "$filename$"
    "-m" = "$minutes$"
    "-w" = {
      set_if = "$file_error_is_warning$"
    }
  }

  vars.wmi_host = "$address$"
}
```
