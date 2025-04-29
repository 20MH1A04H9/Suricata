# Suricata
Suricata Intrusion Detection System Lab
# **Suricata IDS Home-Lab**

The goal of setting up a Suricata home-lab is to gain practical experience in deploying and configuring an Intrusion Detection System (IDS) for network security monitoring. Suricata is an open-source IDS capable of detecting and preventing various network-based threats. This home-lab provides individuals with hands-on experience in setting up, configuring, and utilizing Suricata to enhance network security.

- **Host-Based IDS/IPS:** If you've configured Suricata to only monitor the network interface(s) of your Ubuntu machine itself, it will primarily act as a **host-based intrusion detection/prevention system (HIDS/HIPS)**. It will protect the Ubuntu machine by analyzing traffic going to and from it.

**Diagram:**

![303840792-f7891499-7a73-4f03-99dc-df2a2720904c.png](attachment:5cabc342-e740-40b4-b03d-453d2eeee02a:303840792-f7891499-7a73-4f03-99dc-df2a2720904c.png)

---

- **Layer 2: Data Link Layer:** Suricata can operate at this layer using technologies like **AF_PACKET** or **PF_RING**. This allows it to capture raw Ethernet frames directly from the network interface, seeing all traffic regardless of the destination IP address. This is crucial for tasks like detecting ARP spoofing or MAC flooding.
- **Layer 3: Network Layer:** Suricata analyzes IP packets, looking at source and destination IP addresses, protocols (like TCP, UDP, ICMP), and flags. It can detect suspicious IP traffic, malformed packets, and certain types of network scans.

![image.png](attachment:23ae48c6-dc70-42cc-be79-72126d5fe080:image.png)

## Auto-Configuration, and Rule Setting Guide

This document provides a step-by-step guide to installing, performing basic auto-configuration, and setting up rules for the Suricata Intrusion Detection and Prevention System (IDPS) on Ubuntu.

### 1. Installation

This section details how to install the latest version of Suricata using the official repository.

**Steps:**

1. **Add the Suricata repository:** Open your terminal and execute the following command to add the official Suricata repository to your system's package sources:Bash
    
    ```bash
    sudo add-apt-repository ppa:oisf/suricata-stable
    ```
    
    Press Enter when prompted to confirm the addition of the repository.
    
2. **Update package lists:** After adding the repository, update your system's package lists to include the newly added packages:Bash
    
    ```bash
    sudo apt update
    ```
    
3. **Install Suricata:** Install the Suricata package using the following command:Bash
    
    ```bash
    sudo apt install suricata -y
    ```
    
    To upgrade:
    
    ```bash
    sudo apt-get update
    sudo apt-get upgrade suricata
    ```
    
4. **Verify Installation:** Once the installation is complete, you can verify it by checking the Suricata version:Bash
    
    ```bash
    suricata --version
    ```
    
    This command should display the installed Suricata version.
    

### 2. Basic Auto-Configuration

This section covers the essential initial configuration settings in the `suricata.yaml` file.

**Steps:**

1. **Open the Suricata configuration file:** Use a text editor with root privileges to open the `suricata.yaml` file:Bash
    
    ```bash
    sudo nano /etc/suricata/suricata.yaml
    ```
    
    You can also use other editors like `vim` or `gedit`.
    
2. **Configure `HOME_NET` variable:** Locate the `HOME_NET` variable. This defines the internal network(s) you want Suricata to monitor. Replace the default value with your network's IP address range in CIDR notation. You can find your network information using the `ip a` or `ifconfig` command.YAML
    
    ```bash
    vars:
      HOME_NET: "[192.168.2.0/24]" # Replace with your actual network range
      EXTERNAL_NET: "!$HOME_NET"
    ```
    
    **Note:** Ensure the `HOME_NET` value is specific to your network for better alert accuracy and performance.
    
3. **Configure Network Interface(s):**
    - **AF-PACKET (Linux High-Speed Capture):** Find the `af-packet` section and specify the network interface you want Suricata to listen on.
    YAML
    You can add multiple interfaces if needed, ensuring each has a unique `cluster-id`.
        
        ```bash
        af-packet:
          - interface: eth0 # Replace with your actual interface name (e.g., enp0s3)
            threads: 2     # Adjust based on your system's CPU cores
        ```
        
    - **Libpcap (Cross-Platform Capture):** Locate the `pcap` section and specify the network interface.
    YAML
        
        ```bash
        pcap:
          - interface: eth0 # Replace with your actual interface name
            snaplen: 65535
            buffer-size: 2048
        ```
        
4. **Enable Community ID:** Locate the `community-id` section and set `enable` to `yes`. This adds a predictable flow ID to event logs, useful for correlation with other tools like Zeek.YAML
    
    ```bash
    community-id:
      enable: yes
      seed: 0xdeadbeef # You can change the seed value
    ```
    
5. **Save and Close the Configuration File:** After making the necessary changes, save the `suricata.yaml` file and close the text editor.

### 3. Setting Up Rules

Suricata uses rules to identify malicious activity. This section explains how to manage and add rule sets.

**Understanding Rule Paths:**

The `rule-files` section in `suricata.yaml` specifies the location(s) where Suricata looks for rule files. By default, it might include a path like `/etc/suricata/rules`.

**Adding Rule Sets:**

1. **Existing Rule Sets:** Suricata typically comes with a set of default rules located in `/var/lib/suricata/rules` (this directory might be created after the first Suricata run). These rules are organized by protocol (e.g., `http.rules`, `ip.rules`).
2. **Custom Rule Files:** To add your own custom rules or third-party rule sets, you can create a new rule file (e.g., `local.rules`) within the Suricata rules directory or in a location you prefer.
3. **Specify Custom Rule Files in `suricata.yaml`:** To tell Suricata to load your custom rule file, add its path to the `rule-files` section in `suricata.yaml`.
    - **If the file is in the default rules directory (`/var/lib/suricata/rules`):**YAML
        
        ```bash
        rule-files:
          - http.rules
          - ip.rules
          - ...
          - local.rules
        ```
        
    - **If the file is in a different directory (e.g., `/etc/suricata/rules/`):**YAML
        
        ```bash
        rule-files:
          - http.rules
          - ip.rules
          - ...
          - /etc/suricata/rules/local.rules
        ```
        

**Example Custom Rule:**

Create a file named `local.rules` (or any name you specified in `suricata.yaml`) and add a simple rule, for example, to detect HTTP requests to a specific URL:

Code snippet

```bash
alert http any any -> any any (msg:"ET INFO Test HTTP Request to example.com"; http.request_uri; content:"example.com"; http.method; content:"GET"; sid:1000001; rev:1;)
```

**Explanation of the Rule:**

- alert: The action to take when the rule matches (generate an alert).
- http: The protocol the rule applies to.
- any any -> any any: Source and destination IP addresses and ports (any in this case).
- ( ): Rule options.
- msg :"ET INFO Test HTTP Request to example.com";: A descriptive message for the alert.
- http.request_uri; content:"example.com";: Check if "example.com" is present in the HTTP request URI.
- http.method; content:"GET";: Check if the HTTP method is GET.
- sid:1000001;: A unique rule identifier (Suricata ID).
- rev:1;: Rule revision number.

### 4. Running Suricata

This section explains how to start, stop, and check the status of the Suricata service.

**Using systemd:**

On systems using systemd (like your Ubuntu VM), you can manage the Suricata service using the `systemctl` command.

- Update Suricata:
    
    ```bash
    sudo suricata-update 
    ```
    
- **Start Suricata:**
    
    ```bash
    sudo systemctl start suricata
    ```
    
- **Stop Suricata:**
    
    ```bash
    sudo systemctl stop suricata
    ```
    
- **Check Suricata Status:**
    
    ```bash
    sudo systemctl status suricata
    ```
    
    This command will show you if Suricata is active, any recent logs, and potential errors.
    
- **Enable Suricata on Boot:** To automatically start Suricata when your system boots, enable the service:Bash
    
    ```bash
    sudo systemctl enable suricata
    ```
    
- **Disable Suricata on Boot:** To prevent Suricata from starting automatically at boot:Bash
    
    ```bash
    sudo systemctl disable suricata
    ```
    

### 5. Practical Demonstration (as shown in your transcript)

Your provided transcript effectively demonstrates the installation and initial configuration steps on an Ubuntu VM. You covered:

- Adding the Suricata repository.
- Updating the package lists.
- Installing Suricata.
- Starting, stopping, and enabling the Suricata service using systemctl.
- Locating the suricata.yaml configuration file and the default rules directory.
- Modifying the HOME_NET variable.
- Configuring the af-packet and pcap interfaces.
- Enabling the community-id feature.
- Discussing the rule-files path and how to add custom rules.

**To enhance your demonstration, you could further show:**

- Creating a simple custom rule in a local.rules file.
- Restarting the Suricata service after adding the custom rule.
- Generating some network traffic that should trigger the custom rule.
- Examining the Suricata logs (usually in /var/log/suricata/eve.json for JSON format) to see the generated alert.

![**SPAN ports, also known as mirror ports, are a feature of network switches that allow traffic from one or more switch ports to be copied and sent to a monitoring port. This functionality enables network administrators to capture and analyze traffic without physically interrupting the network connection.** ](attachment:fd299f04-3608-413e-8244-03a950dd8cf2:image.png)

**SPAN ports, also known as mirror ports, are a feature of network switches that allow traffic from one or more switch ports to be copied and sent to a monitoring port. This functionality enables network administrators to capture and analyze traffic without physically interrupting the network connection.** 

Run in Demon Mode:

```bash
sudo suricata -D -c /etc/suricata/suricata.yaml -i ens33
```

Valedating Configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Start

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i ens33
```

Running

```bash
sudo tail -f /var/log/suricata/suricata.log
```

```bash
alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; sid:1000010; rev:1;)
```

```bash
sudo surictata-update list-sources
```

```bash
sudo suricata-update enable-source <name>
```

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

```bash
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
```

![image.png](attachment:e7af9ec4-3c2c-4a92-940d-e98c887047bd:image.png)

---

**Excercises- Network-based attacks**

- **Nmap Stealth Scan Detection**: Create a Suricata rule to detect TCP SYN packets sent to multiple ports within a short time frame, indicative of Nmap stealth scans.

```bash
alert tcp any any -> any any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:100001;)
```

- **Nmap OS Fingerprinting Detection**: Develop a Suricata rule to detect ICMP echo requests and responses with specific TTL values, characteristic of Nmap OS fingerprinting activities.

```bash
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 64; content:"ECHO REQUEST"; sid:100002;)
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 128; content:"ECHO REPLY"; sid:100003;)
```

- **Nmap Service Version Detection Detection**: Formulate a Suricata rule to detect Nmap service version detection probes based on unique HTTP GET requests or TCP SYN/ACK packets.

```bash
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; content:"GET"; http_method; sid:100004;)
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; flags:SA; sid:100005;)
```

- **Metasploit Exploit Payload Detection**: Craft a Suricata rule to detect Metasploit exploit payload traffic based on unique signatures or payloads commonly used in exploits.

```bash
alert tcp any any -> any any (msg:"Metasploit Exploit Payload Detected"; content:"<metasploit_payload>"; sid:100006;)
```

- **Metasploit Reverse Shell Detection**: Develop a Suricata rule to detect Metasploit reverse shell connections by monitoring for outbound TCP connections to known attacker IP addresses.

```bash
alert tcp any any -> <attacker_ip> any (msg:"Metasploit Reverse Shell Connection Detected"; sid:100007;)
```

- **Metasploit Meterpreter Communication Detection**: Create a Suricata rule to detect Meterpreter communication activities by analyzing HTTP or TCP traffic with characteristic Meterpreter payloads.

```bash
alert tcp any any -> any any (msg:"Meterpreter Communication Detected"; content:"<meterpreter_payload>"; sid:100008;)
```

- **Metasploit Credential Harvesting Detection**: Formulate a Suricata rule to detect Metasploit credential harvesting activities by monitoring for specific LDAP or SMB traffic patterns indicative of credential theft.
    
    ```bash
    alert tcp any any -> any any (msg:"Metasploit Credential Harvesting Activity Detected"; content:"LDAP" content:"SMB"; sid:100009;)
    ```
