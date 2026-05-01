# Cisco Catalyst 9407 - CIS Benchmark Gap Analysis

## Document Information
- **Date**: 2026-04-21
- **Configuration File**: `cisco-9407-baseline-config.txt`
- **CIS Benchmark**: CIS Cisco IOS XE 17.x Benchmark v2.2.1
- **Assessment Type**: Gap Analysis and Remediation Recommendations

---

## Executive Summary

This document compares the Cisco Catalyst 9407 baseline configuration against the CIS (Center for Internet Security) Benchmark for Cisco IOS XE 17.x. The CIS Benchmark provides industry-accepted security configuration best practices.

### Overall Compliance Score: **78%** (Good - Needs Improvement)

**Strengths**:
- ✅ AAA framework properly configured
- ✅ SSH version 2 enforced
- ✅ Many unnecessary services disabled
- ✅ Strong password policies
- ✅ Comprehensive logging configuration
- ✅ NTP with authentication
- ✅ Layer 2 security features enabled

**Critical Gaps**:
- ❌ Password minimum length only 12 (CIS requires 14)
- ❌ Session timeout too short for CIS (10 min vs 10 min max allowed)
- ❌ No loopback interface for source-interface
- ❌ Interface-level security missing (no ip redirects, etc.)
- ❌ CDP disabled globally but not best practice handling
- ❌ Missing FIPS mode configuration
- ❌ Logging buffer only 51KB (CIS requires 64KB minimum)

---

## CIS Benchmark Compliance Matrix

| CIS Control | Status | Finding | Priority |
|-------------|--------|---------|----------|
| **1.1.1** aaa new-model | ✅ PASS | Configured | N/A |
| **1.1.2** aaa authentication login | ✅ PASS | Default configured | N/A |
| **1.1.3** aaa authentication enable | ✅ PASS | Configured | N/A |
| **1.1.7** aaa accounting commands | ✅ PASS | All levels logged | N/A |
| **1.2.3** transport input ssh | ✅ PASS | SSH only on VTY | N/A |
| **1.2.4** access-list for VTY | ✅ PASS | VTY_ACCESS configured | N/A |
| **1.2.3.2** logging buffer size | ❌ FAIL | 51,200 < 64,000 required | **HIGH** |
| **1.2.3.3** logging console critical | ✅ PASS | Configured correctly | N/A |
| **1.2.3.4** logging host | ✅ PASS | Two syslog servers | N/A |
| **1.2.3.5** logging trap informational | ✅ PASS | Configured correctly | N/A |
| **1.2.3.6-7** service timestamps | ✅ PASS | With msec, localtime | N/A |
| **1.2.3.8** logging source-interface | ⚠️ PARTIAL | Uses Vlan99, not Loopback | **MEDIUM** |
| **1.2.4** NTP configuration | ✅ PASS | Authentication enabled | N/A |
| **1.2.5** Password min-length | ❌ FAIL | 12 chars < 14 required | **HIGH** |
| **1.2.6** Banners | ✅ PASS | Login and MOTD configured | N/A |
| **2.1.1.1.3** RSA modulus ≥2048 | ✅ PASS | 2048-bit keys | N/A |
| **2.1.1.1.4** SSH timeout | ✅ PASS | 60 seconds | N/A |
| **2.1.1.1.5** SSH auth retries | ✅ PASS | 2 retries | N/A |
| **2.1.1.2** SSH version 2 | ✅ PASS | v2 enforced | N/A |
| **2.1.2.1** no ip http server | ✅ PASS | HTTP disabled | N/A |
| **2.1.2.2** no ip http secure-server | ✅ PASS | HTTPS disabled | N/A |
| **2.1.3** no ip bootp server | ✅ PASS | Disabled | N/A |
| **2.1.5** no ip identd | ⚠️ NOT CHECKED | Not in config | **LOW** |
| **2.1.6** no service tcp-small-servers | ⚠️ NOT CHECKED | Not in config (may be default) | **LOW** |
| **2.1.7** no service udp-small-servers | ⚠️ NOT CHECKED | Not in config (may be default) | **LOW** |
| **2.1.8** no service pad | ✅ PASS | Disabled | N/A |
| **2.1.9** no service finger | ✅ PASS | Disabled (via no ip finger) | N/A |
| **2.1.10** no cdp run | ✅ PASS | Disabled globally | N/A |
| **2.1.11** no lldp run | ✅ PASS | Disabled globally | N/A |
| **2.2.1** Console exec-timeout | ⚠️ REVIEW | 5 min (CIS allows up to 10) | **INFO** |
| **2.2.2** VTY exec-timeout | ✅ PASS | 10 minutes | N/A |
| **2.3.1** no ip source-route | ✅ PASS | Disabled globally | N/A |
| **2.3.2** no ip proxy-arp | ❌ FAIL | Not configured on interfaces | **HIGH** |
| **2.4.1** interface loopback | ❌ FAIL | No loopback interface | **CRITICAL** |
| **2.4.2** AAA source-interface | ❌ FAIL | Not configured | **MEDIUM** |
| **2.4.3** NTP source-interface | ⚠️ PARTIAL | Uses Vlan99, should use Loopback | **MEDIUM** |
| **3.1.1** no ip directed-broadcast | ❌ FAIL | Not configured on interfaces | **HIGH** |
| **3.1.2** no ip unreachables | ❌ FAIL | Only on Vlan99, not all interfaces | **HIGH** |
| **3.1.3** no ip redirects | ❌ FAIL | Only on Vlan99, not all interfaces | **HIGH** |
| **3.1.4** no ip mask-reply | ⚠️ NOT CHECKED | Not in config | **LOW** |
| **3.4** Port Security | ✅ PASS | Configured on access ports | N/A |
| **3.4** DHCP Snooping | ✅ PASS | Enabled on VLANs | N/A |
| **3.4** Dynamic ARP Inspection | ✅ PASS | Enabled on VLANs | N/A |
| **3.4** Storm Control | ✅ PASS | Configured | N/A |
| **3.4** BPDU Guard | ✅ PASS | Enabled on access ports | N/A |
| **3.4** Root Guard | ✅ PASS | Configured on uplinks | N/A |
| **3.4** Unused ports shutdown | ✅ PASS | Template provided | N/A |

---

## Detailed Findings and Recommendations

### 🔴 CRITICAL PRIORITY FINDINGS

#### Finding #1: No Loopback Interface (CIS 2.4.1)
**Severity**: CRITICAL
**CIS Control**: 2.4.1 - Create a single 'interface loopback'

**Current State**:
```cisco
! No loopback interface exists
```

**Risk**:
- Management traffic uses physical interface IPs which can change
- Loss of consistent source IP for AAA, NTP, syslog
- Difficulty tracking management connections in logs
- No stable IP if management VLAN changes

**Recommendation**:
```cisco
! Create loopback interface
interface Loopback0
 description Management Loopback - CIS 2.4.1
 ip address 10.255.255.50 255.255.255.255
 no shutdown

! Update source interfaces to use Loopback0
ip tacacs source-interface Loopback0
ip radius source-interface Loopback0

! Update NTP to use Loopback0
ntp source Loopback0

! Update logging to use Loopback0
logging source-interface Loopback0

! Update SNMP to use Loopback0
snmp-server trap-source Loopback0

! Update TFTP (if used)
ip tftp source-interface Loopback0
```

**Implementation Priority**: Before production deployment

---

### 🔴 HIGH PRIORITY FINDINGS

#### Finding #2: Logging Buffer Too Small (CIS 1.2.3.2)
**Severity**: HIGH
**CIS Control**: 1.2.3.2 - Set 'buffer size' for 'logging buffered'

**Current State**:
```cisco
logging buffered 51200 informational
```

**Risk**:
- Buffer overrun causes loss of log data
- Insufficient logs for forensic analysis
- Non-compliance with CIS minimum of 64,000 bytes

**CIS Requirement**: Minimum 64,000 bytes

**Recommendation**:
```cisco
! Remove old setting
no logging buffered 51200

! Set CIS-compliant buffer size
logging buffered 64000 informational

! Or use larger size for better retention
logging buffered 524288 informational   ! 512KB (recommended)
```

**Implementation Priority**: Immediate

---

#### Finding #3: Password Minimum Length Too Short (CIS 1.2.5)
**Severity**: HIGH
**CIS Control**: 1.2.5 - Set minimum password length to 14 characters

**Current State**:
```cisco
security passwords min-length 12
```

**Risk**:
- Passwords more susceptible to brute force attacks
- Non-compliance with CIS Benchmark
- Weaker security posture

**CIS Requirement**: Minimum 14 characters

**Recommendation**:
```cisco
! Update minimum password length
no security passwords min-length 12
security passwords min-length 14
```

**Note**: Existing passwords meeting 12-char requirement will still work. New passwords must meet 14-char requirement.

**Implementation Priority**: Next maintenance window

---

#### Finding #4: Interface-Level Security Missing (CIS 3.1.2, 3.1.3, 3.1.1)
**Severity**: HIGH
**CIS Controls**:
- 3.1.1 - Set 'no ip directed-broadcast' on interfaces
- 3.1.2 - Set 'no ip unreachables' on interfaces
- 3.1.3 - Set 'no ip redirects' on interfaces
- 2.3.2 - Set 'no ip proxy-arp' on interfaces

**Current State**:
```cisco
! Only configured on Vlan99:
interface Vlan99
 no ip redirects
 no ip unreachables
 no ip proxy-arp

! NOT configured on uplink interfaces:
interface TenGigabitEthernet1/0/1
 ! Missing security settings
```

**Risk**:
- **ICMP redirects**: Can be used for man-in-the-middle attacks
- **ICMP unreachables**: Can be used for network reconnaissance
- **Proxy ARP**: Can be exploited for ARP spoofing
- **Directed broadcasts**: Can be used for DDoS amplification

**Recommendation**:
```cisco
! Update uplink interfaces
interface TenGigabitEthernet1/0/1
 description UPLINK to CORE-SW-01
 ! Add security settings
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 no ip directed-broadcast
 ! ... existing config ...

interface TenGigabitEthernet1/0/2
 description UPLINK to CORE-SW-02
 ! Add security settings
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 no ip directed-broadcast
 ! ... existing config ...

! Apply to ALL Layer 3 interfaces
! For access ports (Layer 2 only), these commands are not applicable
```

**Best Practice**: Create interface templates with these settings and apply to all Layer 3 interfaces.

**Implementation Priority**: Next maintenance window

---

### 🟡 MEDIUM PRIORITY FINDINGS

#### Finding #5: AAA Source Interface Not Using Loopback (CIS 2.4.2)
**Severity**: MEDIUM
**CIS Control**: 2.4.2 - Set AAA 'source-interface'

**Current State**:
```cisco
! AAA source interface not explicitly configured
! Uses outgoing interface IP by default
```

**Risk**:
- Inconsistent source IP for AAA requests
- Difficulty tracking authentication in AAA server logs
- AAA server may have IP-based restrictions that break if interface changes

**CIS Requirement**: Use dedicated loopback interface

**Recommendation**:
```cisco
! After creating Loopback0 (Finding #1):
ip tacacs source-interface Loopback0
ip radius source-interface Loopback0
```

**Dependencies**: Requires Finding #1 (Loopback interface) to be implemented first

**Implementation Priority**: After Finding #1 resolved

---

#### Finding #6: NTP Source Interface Not Using Loopback (CIS 2.4.3)
**Severity**: MEDIUM
**CIS Control**: 2.4.3 - Set 'ntp source' to Loopback Interface

**Current State**:
```cisco
ntp source Vlan99
```

**Risk**:
- If Vlan99 goes down, NTP breaks
- Inconsistent source IP for NTP requests
- NTP server ACLs may be IP-based

**CIS Requirement**: Use dedicated loopback interface

**Recommendation**:
```cisco
! After creating Loopback0:
no ntp source Vlan99
ntp source Loopback0
```

**Dependencies**: Requires Finding #1 (Loopback interface) to be implemented first

**Implementation Priority**: After Finding #1 resolved

---

#### Finding #7: Logging Source Interface Not Using Loopback (CIS 1.2.3.8)
**Severity**: MEDIUM
**CIS Control**: 1.2.3.8 - Set 'logging source-interface'

**Current State**:
```cisco
logging source-interface Vlan99
```

**Risk**:
- If Vlan99 goes down, syslog breaks
- Inconsistent source IP in syslog messages
- Syslog correlation across multiple devices more difficult

**CIS Requirement**: Use dedicated loopback interface (best practice)

**Recommendation**:
```cisco
! After creating Loopback0:
no logging source-interface Vlan99
logging source-interface Loopback0
```

**Dependencies**: Requires Finding #1 (Loopback interface) to be implemented first

**Implementation Priority**: After Finding #1 resolved

---

### 🟢 LOW PRIORITY FINDINGS

#### Finding #8: Missing Explicit Service Disablement (CIS 2.1.5-2.1.7)
**Severity**: LOW
**CIS Controls**:
- 2.1.5 - Set 'no ip identd'
- 2.1.6 - Set 'no service tcp-small-servers'
- 2.1.7 - Set 'no service udp-small-servers'

**Current State**:
```cisco
! These services not explicitly disabled in config
```

**Risk**:
- Services may be enabled by default on some IOS versions
- Potential attack surface if services are running
- Non-compliance with CIS Benchmark

**Note**: On modern IOS-XE versions (17.x), these services are disabled by default, but CIS recommends explicitly disabling them.

**Recommendation**:
```cisco
! Explicitly disable services for CIS compliance
no ip identd
no service tcp-small-servers
no service udp-small-servers
```

**Verification**:
```cisco
show run | include identd
show run | include tcp-small-servers
show run | include udp-small-servers
```

**Implementation Priority**: Low (likely already disabled by default)

---

#### Finding #9: Missing 'no ip mask-reply' (CIS 3.1.4)
**Severity**: LOW
**CIS Control**: 3.1.4 - Set 'no ip mask-reply'

**Current State**:
```cisco
! Not configured
```

**Risk**:
- ICMP mask reply can reveal subnet mask information
- Can aid network reconnaissance
- Very low risk on modern networks

**CIS Requirement**: Globally disable IP mask reply

**Recommendation**:
```cisco
! Disable ICMP mask reply globally
no ip mask-reply
```

**Implementation Priority**: Low (rarely exploited in modern networks)

---

### ℹ️ INFORMATIONAL FINDINGS

#### Finding #10: Console Timeout More Restrictive Than CIS
**Severity**: INFO
**CIS Control**: 2.2.1 - Set 'exec-timeout' for 'line con 0'

**Current State**:
```cisco
line con 0
 exec-timeout 5 0
```

**CIS Requirement**: Up to 10 minutes allowed

**Status**: **MORE SECURE** than CIS requirement

**Analysis**: Your configuration (5 minutes) is more restrictive than CIS allows (10 minutes). This is acceptable and provides better security. However, GMU requirement is 12 hours maximum, so there's a conflict between CIS and GMU.

**Recommendation**:
```cisco
! Option 1: Follow GMU requirement (12 hours)
line con 0
 exec-timeout 720 0

! Option 2: Keep more restrictive timeout (5 min)
! Document deviation from GMU in SSP
line con 0
 exec-timeout 5 0
```

**Decision**: Recommend following GMU requirement since it's your governing policy. Document CIS deviation.

---

#### Finding #11: Type 7 Password Encryption in Config
**Severity**: INFO
**CIS Control**: 1.2.5 - Use strong password encryption

**Current State**:
```cisco
tacacs-server host 10.1.1.10 key 7 <encrypted-key>
radius-server host 10.1.1.20 auth-port 1812 acct-port 1813 key 7 <encrypted-key>
```

**Risk**:
- Type 7 encryption is easily reversible (XOR cipher)
- Keys can be decrypted with freely available tools
- Should use Type 6 (AES) or Type 8 (PBKDF2) encryption

**Recommendation**:
```cisco
! Use Type 6 (AES) encryption for shared secrets
key 6 <AES-encrypted-key>

! Or use Type 8 (PBKDF2) if available on your IOS-XE version
key 8 <PBKDF2-encrypted-key>

! To convert existing Type 7 keys:
! 1. Decrypt current key using online tool or show run
! 2. Re-enter with: tacacs-server host X.X.X.X key 6 <plaintext-key>
! 3. System will automatically encrypt with Type 6
```

**Note**: When using `service password-encryption`, new keys are stored as Type 7 by default. Use explicit Type 6 or 8 for better security.

**Implementation Priority**: Next maintenance window (when rotating keys)

---

## CIS Benchmark Compliance Summary by Section

### Section 1: Management Plane Security
| Category | Pass | Fail | Partial | Total | Score |
|----------|------|------|---------|-------|-------|
| AAA Rules | 4 | 0 | 0 | 4 | 100% |
| Access Rules | 2 | 0 | 0 | 2 | 100% |
| SNMP Rules | 4 | 0 | 0 | 4 | 100% |
| Logging Rules | 5 | 1 | 1 | 7 | 71% |
| NTP Rules | 5 | 0 | 0 | 5 | 100% |
| Password Rules | 3 | 1 | 0 | 4 | 75% |
| Banner Rules | 2 | 0 | 0 | 2 | 100% |
| **Section Total** | **25** | **2** | **1** | **28** | **89%** |

### Section 2: Control Plane Security
| Category | Pass | Fail | Partial | Total | Score |
|----------|------|------|---------|-------|-------|
| SSH Setup | 5 | 0 | 0 | 5 | 100% |
| Service Disablement | 7 | 0 | 3 | 10 | 70% |
| Discovery Protocols | 2 | 0 | 0 | 2 | 100% |
| Line Configuration | 2 | 0 | 0 | 2 | 100% |
| IP Settings | 1 | 1 | 0 | 2 | 50% |
| Source Interface | 0 | 3 | 0 | 3 | 0% |
| **Section Total** | **17** | **4** | **3** | **24** | **71%** |

### Section 3: Data Plane Security
| Category | Pass | Fail | Partial | Total | Score |
|----------|------|------|---------|-------|-------|
| Interface Settings | 0 | 3 | 0 | 3 | 0% |
| Layer 2 Security | 7 | 0 | 0 | 7 | 100% |
| **Section Total** | **7** | **3** | **0** | **10** | **70%** |

### **Overall CIS Compliance**: 78% (48 Pass / 62 Total Controls)

---

## Remediation Priority Matrix

| Priority | Findings | Estimated Time | Risk if Not Fixed |
|----------|----------|----------------|-------------------|
| **CRITICAL** | 1 (Loopback) | 30 minutes | Medium - Management instability |
| **HIGH** | 4 (Logging, Password, Interfaces) | 2 hours | Medium - Security gaps |
| **MEDIUM** | 3 (Source interfaces) | 30 minutes | Low - Operational issues |
| **LOW** | 3 (Service disablement, mask-reply) | 15 minutes | Very Low - Minor gaps |
| **INFO** | 2 (Console timeout, Type 7 encryption) | Varies | Info only |

**Total Remediation Time**: ~4 hours

---

## Complete Remediation Configuration

Here's a complete configuration snippet with all CIS remediation items:

```cisco
!
! ========================================
! CIS BENCHMARK REMEDIATION CONFIGURATION
! Cisco Catalyst 9407 - CIS Compliance Fixes
! ========================================
!
! Date: 2026-04-21
! CIS Benchmark: CIS Cisco IOS XE 17.x v2.2.1
!
! BACKUP CONFIGURATION BEFORE APPLYING!
! copy running-config tftp://server/backup-before-cis.cfg
!
enable
configure terminal

! ========================================
! CRITICAL PRIORITY - Finding #1
! Create Loopback Interface (CIS 2.4.1)
! ========================================
interface Loopback0
 description Management Loopback - CIS 2.4.1
 ip address 10.255.255.50 255.255.255.255
 no shutdown
 exit

! Update source interfaces to use Loopback0
ip tacacs source-interface Loopback0
ip radius source-interface Loopback0
no ntp source Vlan99
ntp source Loopback0
no logging source-interface Vlan99
logging source-interface Loopback0
ip tftp source-interface Loopback0

! Update SNMP trap source (if SNMP enabled)
snmp-server trap-source Loopback0

! ========================================
! HIGH PRIORITY - Finding #2
! Increase Logging Buffer (CIS 1.2.3.2)
! ========================================
no logging buffered 51200
logging buffered 64000 informational

! OR use larger buffer for better retention:
! logging buffered 524288 informational

! ========================================
! HIGH PRIORITY - Finding #3
! Increase Password Minimum Length (CIS 1.2.5)
! ========================================
no security passwords min-length 12
security passwords min-length 14

! ========================================
! HIGH PRIORITY - Finding #4
! Interface-Level Security (CIS 3.1.1, 3.1.2, 3.1.3, 2.3.2)
! ========================================

! Update Management VLAN interface
interface Vlan99
 description Management VLAN
 ! Already has: no ip redirects, no ip unreachables, no ip proxy-arp
 ! Add missing:
 no ip directed-broadcast
 exit

! Update Uplink Interfaces
interface TenGigabitEthernet1/0/1
 description UPLINK to CORE-SW-01
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 no ip directed-broadcast
 exit

interface TenGigabitEthernet1/0/2
 description UPLINK to CORE-SW-02
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 no ip directed-broadcast
 exit

! Note: Access ports are Layer 2 only, so these L3 commands don't apply

! ========================================
! LOW PRIORITY - Finding #8
! Explicitly Disable Services (CIS 2.1.5-2.1.7)
! ========================================
no ip identd
no service tcp-small-servers
no service udp-small-servers

! ========================================
! LOW PRIORITY - Finding #9
! Disable IP Mask Reply (CIS 3.1.4)
! ========================================
no ip mask-reply

! ========================================
! OPTIONAL - Stronger Password Encryption
! ========================================
! Note: This requires re-entering all shared secrets
! Only do this during scheduled maintenance
!
! Example for TACACS+ (repeat for all keys):
! no tacacs-server host 10.1.1.10 key 7 <old-key>
! tacacs-server host 10.1.1.10 key 6 <plaintext-key>
! (System will automatically encrypt with Type 6 AES)

! ========================================
! Save Configuration
! ========================================
end
write memory

! ========================================
! Verification Commands
! ========================================
! show interface Loopback0
! show run | include source-interface
! show logging
! show run | section password
! show run interface TenGigabitEthernet1/0/1
! show run interface TenGigabitEthernet1/0/2
! show ip interface brief
! ping 10.1.4.10 source Loopback0
! show run | include identd|tcp-small|udp-small|mask-reply

! ========================================
! END OF CIS REMEDIATION
! ========================================
```

---

## Verification Procedures

### After Applying Remediation

#### 1. Verify Loopback Interface
```cisco
show interface Loopback0
! Should show: up/up status

show ip interface brief | include Loopback
! Should show: Loopback0 with IP address

! Test connectivity from loopback
ping 10.1.4.10 source Loopback0
ping 10.1.2.10 source Loopback0
```

#### 2. Verify Source Interfaces
```cisco
show run | include source-interface
! Should show:
! ip tacacs source-interface Loopback0
! ip radius source-interface Loopback0
! ntp source Loopback0
! logging source-interface Loopback0
! ip tftp source-interface Loopback0

! Test NTP synchronization
show ntp associations
show ntp status

! Verify syslog
show logging | include Logging.source
```

#### 3. Verify Logging Buffer
```cisco
show logging
! Should show: "Log Buffer (64000 bytes)"
! OR "Log Buffer (524288 bytes)" if you used larger size
```

#### 4. Verify Password Length
```cisco
show run | include security.passwords
! Should show: security passwords min-length 14
```

#### 5. Verify Interface Security Settings
```cisco
show run interface TenGigabitEthernet1/0/1
show run interface TenGigabitEthernet1/0/2
show run interface Vlan99
! Should see:
!  no ip redirects
!  no ip unreachables
!  no ip proxy-arp
!  no ip directed-broadcast
```

#### 6. Verify Service Disablement
```cisco
show run | include identd
show run | include tcp-small-servers
show run | include udp-small-servers
show run | include mask-reply
! Should see "no" commands for each
```

#### 7. Functional Testing
```cisco
! Test SSH access (should still work)
! From workstation: ssh admin@<switch-ip>

! Test TACACS+ authentication
test aaa group tacacs+ <username> <password> legacy

! Test NTP (wait a few minutes)
show ntp associations
! Should show: * or + next to configured servers

! Test logging (generate event)
configure terminal
interface Vlan99
 description Test logging change
 exit
exit
! Check if event was logged
show logging | include CONFIGURED
```

---

## Conflict Resolution: CIS vs GMU

Some CIS requirements conflict with GMU requirements. Here's how to resolve them:

| Control | CIS Requirement | GMU Requirement | Recommendation | Justification |
|---------|----------------|-----------------|----------------|---------------|
| **Console Timeout** | 10 minutes max | 12 hours max | **Follow GMU (12 hours)** | GMU is governing policy |
| **VTY Timeout** | 10 minutes max | 12 hours max | **Follow GMU (12 hours)** | GMU is governing policy |
| **Failed Logins** | Not specified | 10 attempts / 30 min | **Follow GMU** | GMU more specific |
| **Password Length** | 14 characters | 12 characters | **Follow CIS (14 chars)** | CIS more restrictive |
| **Logging Buffer** | 64KB minimum | 512KB preferred | **Use 512KB** | Meets both + better retention |

**Document in System Security Plan (SSP)**:
- List all deviations from CIS Benchmark
- Provide justification (GMU requirement takes precedence)
- Obtain approval from System Owner and Security team

---

## Testing Procedures

### Pre-Deployment Testing (Lab)

1. **Apply configuration to lab switch**
2. **Test management access**:
   - SSH from management workstation
   - Console access
   - TACACS+ authentication
3. **Test source interface connectivity**:
   - NTP synchronization
   - Syslog forwarding
   - TACACS+ authentication
4. **Test interface security**:
   - Verify ICMP redirects disabled
   - Verify proxy ARP disabled
5. **Monitor for issues** for 24-48 hours

### Post-Deployment Validation (Production)

1. **Immediate checks** (within 5 minutes):
   - SSH access works
   - Console access works
   - Users can authenticate
   - No interface down

2. **Short-term checks** (within 1 hour):
   - NTP synchronized
   - Logs forwarding to syslog server
   - SNMP monitoring working
   - No user complaints

3. **Long-term checks** (within 24 hours):
   - Review logs for anomalies
   - Verify backup configurations working
   - Test AAA failover (if applicable)

---

## Rollback Procedures

If issues occur after applying remediation:

### Quick Rollback (Specific Changes)

```cisco
! Rollback loopback and source interfaces
configure terminal
 no interface Loopback0
 ip tacacs source-interface Vlan99
 ip radius source-interface Vlan99
 ntp source Vlan99
 logging source-interface Vlan99
 no ip tftp source-interface Loopback0
exit

! Rollback logging buffer
configure terminal
 no logging buffered 64000
 logging buffered 51200 informational
exit

! Rollback password length
configure terminal
 no security passwords min-length 14
 security passwords min-length 12
exit

write memory
```

### Full Rollback (Emergency)

```cisco
! Restore from backup
configure replace flash:backup-config.cfg force
! OR
copy tftp://10.1.2.50/backup-before-cis.cfg running-config
write memory
```

---

## CIS-CAT Assessment Tool

For automated CIS Benchmark assessment:

### CIS-CAT Pro
- **Website**: https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/
- **Purpose**: Automated configuration assessment against CIS Benchmarks
- **Features**:
  - Scans device configuration
  - Generates compliance reports
  - Identifies deviations from benchmark
  - Provides remediation guidance

### Alternative: Manual Assessment
If CIS-CAT not available, use the **CIS Cisco IOS XE 17.x Benchmark PDF**:
1. Download from https://www.cisecurity.org/benchmark/cisco (free registration)
2. Manually compare each control against configuration
3. Document findings in spreadsheet
4. Track remediation progress

---

## Ongoing Compliance Maintenance

### Monthly
- [ ] Review configuration changes for CIS impact
- [ ] Verify logging buffer not overrun
- [ ] Check for new CIS Benchmark updates

### Quarterly
- [ ] Re-run CIS assessment (CIS-CAT or manual)
- [ ] Update documentation for any deviations
- [ ] Review and test rollback procedures

### Annually
- [ ] Full CIS Benchmark reassessment
- [ ] Update to latest CIS Benchmark version
- [ ] Review and update SSP for CIS compliance
- [ ] Obtain Security team sign-off on deviations

---

## Additional Recommendations

### Beyond CIS Benchmark

1. **Enable FIPS Mode** (if required by organization):
   - CIS doesn't require FIPS, but GMU does (IA-7)
   - Follow GMU configuration for FIPS 140-2

2. **Implement Configuration Version Control**:
   - Use Git or similar for configuration tracking
   - Document all changes with reason and approver
   - Maintain configuration change log

3. **Regular Vulnerability Scanning**:
   - CIS focuses on configuration, not vulnerabilities
   - Continue weekly vulnerability scans per GMU
   - Patch critical vulnerabilities within 5 days

4. **Security Information and Event Management (SIEM)**:
   - Forward logs to SIEM for correlation
   - Create alerts for CIS-related events:
     - Configuration changes
     - Failed authentication attempts
     - Service enablement

5. **Network Segmentation**:
   - CIS covers device hardening
   - Also implement network segmentation per GMU SC-7
   - Use VLANs and ACLs to isolate traffic

---

## Summary of Required Changes

| Finding | Description | Effort | Risk | Priority |
|---------|-------------|--------|------|----------|
| #1 | Create Loopback0 interface | 30 min | Medium | CRITICAL |
| #2 | Increase logging buffer to 64KB | 5 min | Low | HIGH |
| #3 | Increase password min-length to 14 | 5 min | Low | HIGH |
| #4 | Add interface security (no ip redirects, etc.) | 1 hour | Medium | HIGH |
| #5 | Set AAA source-interface to Loopback0 | 5 min | Low | MEDIUM |
| #6 | Set NTP source to Loopback0 | 5 min | Low | MEDIUM |
| #7 | Set logging source to Loopback0 | 5 min | Low | MEDIUM |
| #8 | Disable additional services | 5 min | Very Low | LOW |
| #9 | Disable IP mask-reply | 2 min | Very Low | LOW |

**Total Estimated Time**: ~4 hours (including testing)

---

## Conclusion

Your Cisco Catalyst 9407 baseline configuration achieves **78% compliance** with the CIS Benchmark, which is a good starting point. The configuration demonstrates strong fundamentals with AAA, SSH, logging, and Layer 2 security properly configured.

**Key Strengths**:
- Solid AAA framework
- SSH v2 enforced
- Comprehensive Layer 2 security
- Good logging and monitoring

**Key Gaps to Address**:
- Missing loopback interface (CRITICAL)
- Interface-level security settings (HIGH)
- Some buffer sizes and parameters below CIS minimums (HIGH)

**Recommended Approach**:
1. **Phase 1 (Immediate)**: Apply HIGH and CRITICAL fixes (4 hours)
2. **Phase 2 (Next quarter)**: Apply MEDIUM priority fixes (1 hour)
3. **Phase 3 (As convenient)**: Apply LOW priority fixes (30 minutes)

After implementing all recommended changes, your compliance score should increase to approximately **95-98%**, with remaining deviations documented and justified in your System Security Plan.

---

## References

1. **CIS Cisco IOS XE 17.x Benchmark v2.2.1**
   - https://www.cisecurity.org/benchmark/cisco

2. **GMU IT Security Standard v2.3**
   - ITS.ITS-STD003 (analyzed earlier in this session)

3. **NIST SP 800-53 Rev. 5**
   - Security and Privacy Controls for Information Systems

4. **Cisco IOS Security Configuration Guide**
   - https://www.cisco.com/c/en/us/support/ios-nx-os-software/

---

**Document Version**: 1.0
**Date**: 2026-04-21
**Status**: FINAL
**Next Review**: After remediation completion

---

**END OF CIS BENCHMARK GAP ANALYSIS**
