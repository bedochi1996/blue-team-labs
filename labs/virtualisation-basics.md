# Virtualisation Basics

## Overview
Completed the Virtualisation Basics path on TryHackMe ✔️

This path provided a clear understanding of how modern IT infrastructure is built, especially in terms of how virtualisation forms the foundation of cloud computing, data centers, and security operations.

## Key Concepts Learned

### 1. Understanding Virtualisation
- **Definition**: Running multiple operating systems (VMs) on a single physical machine
- **Purpose**: Maximizing hardware utilization and resource efficiency
- **Benefits**: Isolation, flexibility, cost savings
- **Evolution**: From physical servers to virtual infrastructure

### 2. The Hypervisor
- **Type 1 Hypervisor (Bare-Metal)**:
  - Runs directly on hardware
  - Used in enterprise environments (VMware ESXi, Hyper-V, KVM)
  - Better performance and security
  
- **Type 2 Hypervisor (Hosted)**:
  - Runs on top of an OS
  - Used for testing and development (VirtualBox, VMware Workstation)
  - Easier to set up, slightly lower performance

### 3. Virtual Machine Components
- **vCPU**: Virtual processor cores allocated to VM
- **vRAM**: Virtual memory assigned to VM
- **vDisk**: Virtual storage (VMDK, VHD, QCOW2 formats)
- **vNIC**: Virtual network interface card

### 4. Virtual Networking
- **NAT (Network Address Translation)**:
  - VM shares host's IP
  - VM can access external network
  - External network cannot directly access VM
  
- **Bridged Mode**:
  - VM gets its own IP on the physical network
  - Acts as a separate machine on the network
  
- **Host-Only**:
  - VM can only communicate with host
  - Isolated from external network
  - Ideal for malware analysis

### 5. Isolation in Cybersecurity
- **Security Boundary**: VMs are isolated from each other and host
- **Sandboxing**: Safe environment for testing suspicious files
- **Malware Analysis**: Analyze malicious code without risking host system
- **Forensics**: Snapshot and analyze system states

### 6. Use in SOC & Security Labs
- **Blue Team Labs**: Build isolated environments for defensive training
- **Malware Analysis**: Safely detonate and analyze samples
- **Incident Response**: Replicate compromised systems for investigation
- **Threat Hunting**: Set up honeypots and detection labs
- **Testing**: Validate security controls without impacting production

## Key Takeaways

Virtualisation is not just about running virtual machines — it is fundamental for:

✅ **Building secure analysis environments** (Malware Analysis / Testing)
✅ **Running labs without affecting the base system**
✅ **Supporting Blue Team operations and Threat Hunting**
✅ **Creating isolated networks for security testing**
✅ **Snapshots for quick recovery and forensic analysis**

## SOC Analyst Perspective

As a SOC analyst, virtualisation is critical because:
- Most enterprise infrastructure runs on virtual machines
- Security monitoring tools (SIEM, EDR) must understand virtual environments
- Incident response often involves isolating and analyzing VMs
- Threat hunting requires building detection labs
- Understanding VM escape vulnerabilities and hypervisor security

## Next Steps
- Learn about container technology (Docker, Kubernetes)
- Study hypervisor security and VM escape techniques
- Practice building SOC labs in virtual environments
- Explore cloud computing fundamentals (AWS, Azure, GCP)
- Learn about virtual network security and microsegmentation

## Resources
- [TryHackMe: Virtualisation Basics](https://tryhackme.com)
- VMware Documentation
- VirtualBox User Manual
- KVM/QEMU Documentation

---
**Tags:** #Virtualisation #VirtualMachines #Hypervisor #ThreatHunting #MalwareAnalysis #SOC #BlueTeam #CyberSecurity #TryHackMe
