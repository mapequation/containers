<h2>:mag: Vulnerabilities of <code>mapequation/jupyter:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>mapequation/jupyter:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:f08bb0105788a83a1c3d6d76219874f1bbfd5d9b54cce92afa3222335821f671</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 2" src="https://img.shields.io/badge/critical-2-8b1924"/> <img alt="high: 10" src="https://img.shields.io/badge/high-10-e25d68"/> <img alt="medium: 129" src="https://img.shields.io/badge/medium-129-fbb552"/> <img alt="low: 97" src="https://img.shields.io/badge/low-97-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/arm64</td></tr>
<tr><td>size</td><td>1.4 GB</td></tr>
<tr><td>packages</td><td>1145</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pyarrow</strong> <code>13.0.0</code> (pypi)</summary>

<small><code>pkg:pypi/pyarrow@13.0.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-47248?s=github&n=pyarrow&t=pypi&vr=%3E%3D0.14.0%2C%3C14.0.1"><img alt="critical 9.8: CVE--2023--47248" src="https://img.shields.io/badge/CVE--2023--47248-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=0.14.0<br/><14.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>14.0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Deserialization of untrusted data in IPC and Parquet readers in PyArrow versions 0.14.0 to 14.0.0 allows arbitrary code execution. An application is vulnerable if it reads Arrow IPC, Feather or Parquet data from untrusted sources (for example user-supplied input files).

This vulnerability only affects PyArrow, not other Apache Arrow implementations or bindings.

It is recommended that users of PyArrow upgrade to 14.0.1. Similarly, it is recommended that downstream libraries upgrade their dependency requirements to PyArrow 14.0.1 or later. PyPI packages are already available, and we hope that conda-forge packages will be available soon.

If it is not possible to upgrade, maintainers provide a separate package `pyarrow-hotfix` that disables the vulnerability on older PyArrow versions. See https://pypi.org/project/pyarrow-hotfix/  for instructions.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>numexpr</strong> <code>2.8.7</code> (pypi)</summary>

<small><code>pkg:pypi/numexpr@2.8.7</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-39631?s=pypa&n=numexpr&t=pypi&vr=%3D2.8.7"><img alt="critical 9.8: CVE--2023--39631" src="https://img.shields.io/badge/CVE--2023--39631-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> 

<table>
<tr><td>Affected range</td><td><code>=2.8.7</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue in LanChain-ai Langchain v.0.0.245 allows a remote attacker to execute arbitrary code via the evaluate function in the numexpr library.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 5" src="https://img.shields.io/badge/H-5-e25d68"/> <img alt="medium: 58" src="https://img.shields.io/badge/M-58-fbb552"/> <img alt="low: 28" src="https://img.shields.io/badge/L-28-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>5.15.0-87.97</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@5.15.0-87.97?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-0646?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="high 7.8: CVE--2024--0646" src="https://img.shields.io/badge/CVE--2024--0646-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds memory write flaw was found in the Linux kernel’s Transport Layer Security functionality in how a user calls a function splice with a ktls socket as the destination. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.8: CVE--2023--6931" src="https://img.shields.io/badge/CVE--2023--6931-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be exploited to achieve local privilege escalation. A perf_event's read_size can overflow, leading to an heap out-of-bounds increment or write in perf_read_group(). We recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6817?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.8: CVE--2023--6817" src="https://img.shields.io/badge/CVE--2023--6817-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The function nft_pipapo_walk did not skip inactive elements during set walk which could lead double deactivations of PIPAPO (Pile Packet Policies) elements, leading to use-after-free. We recommend upgrading past commit 317eb9685095678f2c9f5a8189de698c5354316a.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.0: CVE--2023--6932" src="https://img.shields.io/badge/CVE--2023--6932-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve local privilege escalation. A race condition can be exploited to cause a timer be mistakenly registered on a RCU read locked object which is freed by another thread. We recommend upgrading past commit e2b706c691905fe78468c361aaabc719d0a496f1.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 6.7: CVE--2024--0193" src="https://img.shields.io/badge/CVE--2024--0193-lightgrey?label=high%206.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the netfilter subsystem of the Linux kernel. If the catchall element is garbage-collected when the pipapo set is removed, the element can be deactivated twice. This can cause a use-after-free issue on an NFT_CHAIN object or NFT_OBJECT object, allowing a local unprivileged user with CAP_NET_ADMIN capability to escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5178?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 9.8: CVE--2023--5178" src="https://img.shields.io/badge/CVE--2023--5178-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability was found in drivers/nvme/target/tcp.c` in `nvmet_tcp_free_crypto` due to a logical bug in the NVMe-oF/TCP subsystem in the Linux kernel. This issue may allow a malicious user to cause a use-after-free and double-free problem, which may permit remote code execution or lead to local privilege escalation problem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38427?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 9.8: CVE--2023--38427" src="https://img.shields.io/badge/CVE--2023--38427-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.3.8. fs/smb/server/smb2pdu.c in ksmbd has an integer underflow and out-of-bounds read in deassemble_neg_contexts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-25775?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-89.99"><img alt="medium 9.8: CVE--2023--25775" src="https://img.shields.io/badge/CVE--2023--25775-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-89.99</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-89.99</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38431?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 9.1: CVE--2023--38431" src="https://img.shields.io/badge/CVE--2023--38431-lightgrey?label=medium%209.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>9.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.3.8. fs/smb/server/connection.c in ksmbd does not validate the relationship between the NetBIOS header's length field and the SMB header sizes, via pdu_size in ksmbd_conn_handler_loop, leading to an out-of-bounds read.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38430?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 9.1: CVE--2023--38430" src="https://img.shields.io/badge/CVE--2023--38430-lightgrey?label=medium%209.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>9.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.3.9. ksmbd does not validate the SMB request protocol ID, leading to an out-of-bounds read.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-51780?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--51780" src="https://img.shields.io/badge/CVE--2023--51780-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.6.8. do_vcc_ioctl in net/atm/ioctl.c has a use-after-free because of a vcc_recvmsg race condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32258?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--32258" src="https://img.shields.io/badge/CVE--2023--32258-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the processing of SMB2_LOGOFF and SMB2_CLOSE commands. The issue results from the lack of proper locking when performing operations on an object. An attacker can leverage this vulnerability to execute code in the context of the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32257?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--32257" src="https://img.shields.io/badge/CVE--2023--32257-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the processing of SMB2_SESSION_SETUP and SMB2_LOGOFF commands. The issue results from the lack of proper locking when performing operations on an object. An attacker can leverage this vulnerability to execute code in the context of the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32254?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--32254" src="https://img.shields.io/badge/CVE--2023--32254-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the processing of SMB2_TREE_DISCONNECT commands. The issue results from the lack of proper locking when performing operations on an object. An attacker can leverage this vulnerability to execute code in the context of the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32250?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--32250" src="https://img.shields.io/badge/CVE--2023--32250-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the processing of SMB2_SESSION_SETUP commands. The issue results from the lack of proper locking when performing operations on an object. An attacker can leverage this vulnerability to execute code in the context of the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1194?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2023--1194" src="https://img.shields.io/badge/CVE--2023--1194-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds (OOB) memory read flaw was found in parse_lease_state in the KSMBD implementation of the in-kernel samba server and CIFS in the Linux kernel. When an attacker sends the CREATE command with a malformed payload to KSMBD, due to a missing check of `NameOffset` in the `parse_lease_state()` function, the `create_context` object can access invalid memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-22705?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--22705" src="https://img.shields.io/badge/CVE--2024--22705-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in ksmbd in the Linux kernel before 6.6.10. smb2_get_data_area_len in fs/smb/server/smb2misc.c can cause an smb_strndup_from_utf16 out-of-bounds access because the relationship between Name data and CreateContexts data is mishandled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5717?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 7.8: CVE--2023--5717" src="https://img.shields.io/badge/CVE--2023--5717-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap out-of-bounds write vulnerability in the Linux kernel's Linux Kernel Performance Events (perf) component can be exploited to achieve local privilege escalation. If perf_read_group() is called while an event's sibling_list is smaller than its child's sibling_list, it can increment or write to memory locations outside of the allocated buffer. We recommend upgrading past commit 32671e3799ca2e4590773fd0e63aaa4229e50c06.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-26242?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2023--26242" src="https://img.shields.io/badge/CVE--2023--26242-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

afu_mmio_region_get_by_offset in drivers/fpga/dfl-afu-region.c in the Linux kernel through 6.1.12 has an integer overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-2007?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2023--2007" src="https://img.shields.io/badge/CVE--2023--2007-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The specific flaw exists within the DPT I2O Controller driver. The issue results from the lack of proper locking when performing operations on an object. An attacker can leverage this in conjunction with other vulnerabilities to escalate privileges and execute arbitrary code in the context of the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-0030?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2023--0030" src="https://img.shields.io/badge/CVE--2023--0030-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the Linux kernel’s nouveau driver in how a user triggers a memory overflow that causes the nvkm_vma_tail function to fail. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3238?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2022--3238" src="https://img.shields.io/badge/CVE--2022--3238-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A double-free flaw was found in the Linux kernel’s NTFS3 subsystem in how a user triggers remount and umount simultaneously. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0995?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2022--0995" src="https://img.shields.io/badge/CVE--2022--0995-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-45871?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-89.99"><img alt="medium 7.5: CVE--2023--45871" src="https://img.shields.io/badge/CVE--2023--45871-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-89.99</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-89.99</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel before 6.5.3. A buffer size may not be adequate for frames larger than the MTU.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32252?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2023--32252" src="https://img.shields.io/badge/CVE--2023--32252-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the handling of SMB2_LOGOFF commands. The issue results from the lack of proper validation of a pointer prior to accessing it. An attacker can leverage this vulnerability to create a denial-of-service condition on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32247?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2023--32247" src="https://img.shields.io/badge/CVE--2023--32247-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's ksmbd, a high-performance in-kernel SMB server. The specific flaw exists within the handling of SMB2_SESSION_SETUP commands. The issue results from the lack of control of resource consumption. An attacker can leverage this vulnerability to create a denial-of-service condition on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-25836?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2022--25836" src="https://img.shields.io/badge/CVE--2022--25836-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Bluetooth® Low Energy Pairing in Bluetooth Core Specification v4.0 through v5.3 may permit an unauthenticated MITM to acquire credentials with two pairing devices via adjacent access when the MITM negotiates Legacy Passkey Pairing with the pairing Initiator and Secure Connections Passkey Pairing with the pairing Responder and brute forces the Passkey entered by the user into the Initiator. The MITM attacker can use the identified Passkey value to complete authentication with the Responder via Bluetooth pairing method confusion.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0400?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2022--0400" src="https://img.shields.io/badge/CVE--2022--0400-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds read vulnerability was discovered in linux kernel in the smc protocol stack, causing remote dos.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6610?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2023--6610" src="https://img.shields.io/badge/CVE--2023--6610-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds read vulnerability was found in smb2_dump_detail in fs/smb/client/smb2ops.c in the Linux Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6606?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="medium 7.1: CVE--2023--6606" src="https://img.shields.io/badge/CVE--2023--6606-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6546?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 7.0: CVE--2023--6546" src="https://img.shields.io/badge/CVE--2023--6546-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This could allow a local unprivileged user to escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-46813?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2023--46813" src="https://img.shields.io/badge/CVE--2023--46813-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.5.9, exploitable by local users with userspace access to MMIO registers. Incorrect access checking in the #VC handler and instruction emulation of the SEV-ES emulation of MMIO accesses could lead to arbitrary write access to kernel memory (and thus privilege escalation). This depends on a race condition through which userspace can replace an instruction before the #VC handler reads it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-2961?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2022--2961" src="https://img.shields.io/badge/CVE--2022--2961-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the Linux kernel’s PLP Rose functionality in the way a user triggers a race condition by calling bind while simultaneously triggering the rose_bind() function. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1247?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2022--1247" src="https://img.shields.io/badge/CVE--2022--1247-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue found in linux-kernel that leads to a race condition in rose_connect(). The rose driver uses rose_neigh->use to represent how many objects are using the rose_neigh. When a user wants to delete a rose_route via rose_ioctl(), the rose driver calls rose_del_node() and removes neighbours only if their “count” and “use” are zero.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-3864?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2021--3864" src="https://img.shields.io/badge/CVE--2021--3864-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the way the dumpable flag setting was handled when certain SUID binaries executed its descendants. The prerequisite is a SUID binary that sets real UID equal to effective UID, and real GID equal to effective GID. The descendant will then have a dumpable value set to 1. As a result, if the descendant process crashes and core_pattern is set to a relative value, its core dump is stored in the current directory with uid:gid permissions. An unprivileged local user with eligible root SUID binary could use this flaw to place core dumps into root-owned directories, potentially resulting in escalation of privileges.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 6.5: CVE--2023--1193" src="https://img.shields.io/badge/CVE--2023--1193-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in setup_async_work in the KSMBD implementation of the in-kernel samba server and CIFS in the Linux kernel. This issue could allow an attacker to crash the system by accessing freed work.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2015-8553?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 6.5: CVE--2015--8553" src="https://img.shields.io/badge/CVE--2015--8553-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Xen allows guest OS users to obtain sensitive information from uninitialized locations in host OS kernel memory by not enabling memory and I/O decoding control bits.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-0777.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-39198?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 6.4: CVE--2023--39198" src="https://img.shields.io/badge/CVE--2023--39198-lightgrey?label=medium%206.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A race condition was found in the QXL driver in the Linux kernel. The qxl_mode_dumb_create() function dereferences the qobj returned by the qxl_gem_object_create_with_handle(), but the handle is the only one holding a reference to it. This flaw allows an attacker to guess the returned handle value and trigger a use-after-free issue, potentially leading to a denial of service or privilege escalation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-39193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 6.0: CVE--2023--39193" src="https://img.shields.io/badge/CVE--2023--39193-lightgrey?label=medium%206.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Netfilter subsystem in the Linux kernel. The sctp_mt_check did not validate the flag_count field. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-39192?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 6.0: CVE--2023--39192" src="https://img.shields.io/badge/CVE--2023--39192-lightgrey?label=medium%206.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Netfilter subsystem in the Linux kernel. The xt_u32 module did not validate the fields in the xt_u32 structure. This flaw allows a local privileged attacker to trigger an out-of-bounds read by setting the size fields with a value beyond the array boundaries, leading to a crash or information disclosure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-39189?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 6.0: CVE--2023--39189" src="https://img.shields.io/badge/CVE--2023--39189-lightgrey?label=medium%206.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Netfilter subsystem in the Linux kernel. The nfnl_osf_add_callback function did not validate the user mode controlled opt_num field. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-7042?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--7042" src="https://img.shields.io/badge/CVE--2023--7042-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A null pointer dereference vulnerability was found in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() in drivers/net/wireless/ath/ath10k/wmi-tlv.c in the Linux kernel. This issue could be exploited to trigger a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5158?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 5.5: CVE--2023--5158" src="https://img.shields.io/badge/CVE--2023--5158-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in vringh_kiov_advance in drivers/vhost/vringh.c in the host side of a virtio ring in the Linux Kernel. This issue may result in a denial of service from guest to host via zero length descriptor.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-42754?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 5.5: CVE--2023--42754" src="https://img.shields.io/badge/CVE--2023--42754-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference flaw was found in the Linux kernel ipv4 stack. The socket buffer (skb) was assumed to be associated with a device before calling __ip_options_compile, which is not always the case if the skb is re-routed by ipvs. This issue may allow a local user with CAP_NET_ADMIN privileges to crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-31082?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--31082" src="https://img.shields.io/badge/CVE--2023--31082-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in drivers/tty/n_gsm.c in the Linux kernel 6.2. There is a sleeping function called from an invalid context in gsmld_write, which will block the kernel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-28327?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--28327" src="https://img.shields.io/badge/CVE--2023--28327-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference flaw was found in the UNIX protocol in net/unix/diag.c In unix_diag_get_exact in the Linux Kernel. The newly allocated skb does not have sk, leading to a NULL pointer. This flaw allows a local user to crash or potentially cause a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-23000?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--23000" src="https://img.shields.io/badge/CVE--2023--23000-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel before 5.17, drivers/phy/tegra/xusb.c mishandles the tegra_xusb_find_port_node return value. Callers expect NULL in the error case, but an error pointer is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-4543?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--4543" src="https://img.shields.io/badge/CVE--2022--4543-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw named "EntryBleed" was found in the Linux Kernel Page Table Isolation (KPTI). This issue could allow a local attacker to leak KASLR base via prefetch side-channels based on TLB timing for Intel systems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-40133?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--40133" src="https://img.shields.io/badge/CVE--2022--40133-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free(UAF) vulnerability was found in function 'vmw_execbuf_tie_context' in drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38457?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--38457" src="https://img.shields.io/badge/CVE--2022--38457-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free(UAF) vulnerability was found in function 'vmw_cmd_res_check' in drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38096?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--38096" src="https://img.shields.io/badge/CVE--2022--38096-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference vulnerability was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_execbuf.c in GPU component of Linux kernel with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0480?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--0480" src="https://img.shields.io/badge/CVE--2022--0480-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the filelock_init in fs/locks.c function in the Linux kernel. This issue can lead to host memory exhaustion due to memcg not limiting the number of Portable Operating System Interface (POSIX) file locks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-4095?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2021--4095" src="https://img.shields.io/badge/CVE--2021--4095-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference was found in the Linux kernel's KVM when dirty ring logging is enabled without an active vCPU context. An unprivileged local attacker on the host may use this flaw to cause a kernel oops condition and thus a denial of service by issuing a KVM_XEN_HVM_SET_ATTR ioctl. This flaw affects Linux kernel versions prior to 5.17-rc1.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-8660?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2016--8660" src="https://img.shields.io/badge/CVE--2016--8660-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The XFS subsystem in the Linux kernel through 4.8.2 allows local users to cause a denial of service (fdatasync failure and system hang) by using the vfs syscall group in the trinity program, related to a "page lock order bug in the XFS seek hole/data implementation."

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3523?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.3: CVE--2022--3523" src="https://img.shields.io/badge/CVE--2022--3523-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211020.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-46862?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2023--46862" src="https://img.shields.io/badge/CVE--2023--46862-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.5.9. During a race with SQ thread exit, an io_uring/fdinfo.c io_uring_show_fdinfo NULL pointer dereference can occur.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-37453?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 4.6: CVE--2023--37453" src="https://img.shields.io/badge/CVE--2023--37453-lightgrey?label=medium%204.6&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the USB subsystem in the Linux kernel through 6.4.2. There is an out-of-bounds and crash in read_descriptors in drivers/usb/core/sysfs.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-39194?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 4.4: CVE--2023--39194" src="https://img.shields.io/badge/CVE--2023--39194-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the XFRM subsystem in the Linux kernel. The specific flaw exists within the processing of state filters, which can result in a read past the end of an allocated buffer. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, potentially leading to an information disclosure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3773?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="medium 4.4: CVE--2023--3773" src="https://img.shields.io/badge/CVE--2023--3773-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel’s IP framework for transforming packets (XFRM subsystem). This issue may allow a malicious user with CAP_NET_ADMIN privileges to cause a 4 byte out-of-bounds read of XFRMA_MTIMER_THRESH when parsing netlink attributes, leading to potential leakage of sensitive heap data to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3772?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-88.98"><img alt="medium 4.4: CVE--2023--3772" src="https://img.shields.io/badge/CVE--2023--3772-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-88.98</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-88.98</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel’s IP framework for transforming packets (XFRM subsystem). This issue may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in xfrm_update_ae_params(), leading to a possible kernel crash and denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-17977?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 4.4: CVE--2018--17977" src="https://img.shields.io/badge/CVE--2018--17977-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Linux kernel 4.14.67 mishandles certain interaction among XFRM Netlink messages, IPPROTO_AH packets, and IPPROTO_IP packets, which allows local users to cause a denial of service (memory consumption and system hang) by leveraging root access to execute crafted applications, as demonstrated on CentOS 7.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3867?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium : CVE--2023--3867" src="https://img.shields.io/badge/CVE--2023--3867-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr></table>

<details><summary>Description</summary>
<blockquote>

[ksmbd: add missing compound request handing in some commands]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2013-7445?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium : CVE--2013--7445" src="https://img.shields.io/badge/CVE--2013--7445-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr></table>

<details><summary>Description</summary>
<blockquote>

The Direct Rendering Manager (DRM) subsystem in the Linux kernel through 4.x mishandles requests for Graphics Execution Manager (GEM) objects, which allows context-dependent attackers to cause a denial of service (memory consumption) via an application that processes graphics data, as demonstrated by JavaScript code that creates many CANVAS elements for rendering by Chrome or Firefox.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-33053?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2023--33053" src="https://img.shields.io/badge/CVE--2023--33053-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Memory corruption in Kernel while parsing metadata.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-22995?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2023--22995" src="https://img.shields.io/badge/CVE--2023--22995-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel before 5.17, an error path in dwc3_qcom_acpi_register_core in drivers/usb/dwc3/dwc3-qcom.c lacks certain platform_device_put and kfree calls.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-26934?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2021--26934" src="https://img.shields.io/badge/CVE--2021--26934-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel 4.18 through 5.10.16, as used by Xen. The backend allocation (aka be-alloc) mode of the drm_xen_front drivers was not meant to be a supported configuration, but this wasn't stated accordingly in its support status entry.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-19814?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--19814" src="https://img.shields.io/badge/CVE--2019--19814-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 5.0.21, mounting a crafted f2fs filesystem image can cause __remove_dirty_segment slab-out-of-bounds write access because an array is bounded by the number of dirty types (8) but the array index can exceed this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-19378?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--19378" src="https://img.shields.io/badge/CVE--2019--19378-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image can lead to slab-out-of-bounds write access in index_rbio_pages in fs/btrfs/raid56.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2018--12931" src="https://img.shields.io/badge/CVE--2018--12931-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_attr_find in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a stack-based out-of-bounds write and cause a denial of service (kernel oops or panic) or possibly have unspecified other impact via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12930?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2018--12930" src="https://img.shields.io/badge/CVE--2018--12930-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_end_buffer_async_read in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a stack-based out-of-bounds write and cause a denial of service (kernel oops or panic) or possibly have unspecified other impact via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13165?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2017--13165" src="https://img.shields.io/badge/CVE--2017--13165-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An elevation of privilege vulnerability in the kernel file system. Product: Android. Versions: Android kernel. Android ID A-31269937.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14899?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.4: CVE--2019--14899" src="https://img.shields.io/badge/CVE--2019--14899-lightgrey?label=low%207.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was discovered in Linux, FreeBSD, OpenBSD, MacOS, iOS, and Android that allows a malicious access point, or an adjacent user, to determine if a connected user is using a VPN, make positive inferences about the websites they are visiting, and determine the correct sequence and acknowledgement numbers in use, allowing the bad actor to inject data into the TCP stream. This provides everything that is needed for an attacker to hijack active connections inside the VPN tunnel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1989?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.0: CVE--2023--1989" src="https://img.shields.io/badge/CVE--2023--1989-lightgrey?label=low%207.0&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on hdev devices.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.0: CVE--2022--45885" src="https://img.shields.io/badge/CVE--2022--45885-lightgrey?label=low%207.0&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a race condition that can cause a use-after-free when a device is disconnected.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45884?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.0: CVE--2022--45884" src="https://img.shields.io/badge/CVE--2022--45884-lightgrey?label=low%207.0&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-after-free, related to dvb_register_device dynamically allocating fops.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45888?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.4: CVE--2022--45888" src="https://img.shields.io/badge/CVE--2022--45888-lightgrey?label=low%206.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.9. drivers/char/xillybus/xillyusb.c has a race condition and use-after-free during physical removal of a USB device.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-44034?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.4: CVE--2022--44034" src="https://img.shields.io/badge/CVE--2022--44034-lightgrey?label=low%206.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/scr24x_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between scr24x_open() and scr24x_remove().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-44033?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.4: CVE--2022--44033" src="https://img.shields.io/badge/CVE--2022--44033-lightgrey?label=low%206.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/cm4040_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between cm4040_open() and reader_detach().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-1121?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.9: CVE--2018--1121" src="https://img.shields.io/badge/CVE--2018--1121-lightgrey?label=low%205.9&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

procps-ng, procps is vulnerable to a process hiding through race condition. Since the kernel's proc_pid_readdir() returns PID entries in ascending numeric order, a process occupying a high PID can use inotify events to determine when the process list is being scanned, and fork/exec to obtain a lower PID, thus avoiding enumeration. An unprivileged attacker can hide a process from procps-ng's utilities by exploiting a race condition in reading /proc/PID entries. This vulnerability affects procps and procps-ng up to version 3.3.15, newer versions might be affected also.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4133?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2023--4133" src="https://img.shields.io/badge/CVE--2023--4133-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability was found in the cxgb4 driver in the Linux kernel. The bug occurs when the cxgb4 device is detaching due to a possible rearming of the flower_stats_timer from the work queue. This flaw allows a local user to crash the system, causing a denial of service condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-31085?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-89.99"><img alt="low 5.5: CVE--2023--31085" src="https://img.shields.io/badge/CVE--2023--31085-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-89.99</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-89.99</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in drivers/mtd/ubi/cdev.c in the Linux kernel 6.2. There is a divide-by-zero error in do_div(sz,mtd->erasesize), used indirectly by ctrl_cdev_ioctl, when mtd->erasesize is 0.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3114?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--3114" src="https://img.shields.io/badge/CVE--2022--3114-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 5.16-rc6. imx_register_uart_clocks in drivers/clk/imx/clk.c lacks check of the return value of kcalloc() and will cause the null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12929?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2018--12929" src="https://img.shields.io/badge/CVE--2018--12929-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_read_locked_inode in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a use-after-free read and possibly cause a denial of service (kernel oops or panic) via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12928?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2018--12928" src="https://img.shields.io/badge/CVE--2018--12928-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 4.15.0, a NULL pointer dereference was discovered in hfs_ext_read_extent in hfs.ko. This can occur during a mount of a crafted hfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13693?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2017--13693" src="https://img.shields.io/badge/CVE--2017--13693-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The acpi_ds_create_operands() function in drivers/acpi/acpica/dsutils.c in the Linux kernel through 4.12.9 does not flush the operand cache and causes a kernel stack dump, which allows local users to obtain sensitive information from kernel memory and bypass the KASLR protection mechanism (in the kernel through 4.9) via a crafted ACPI table.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-31083?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-88.98"><img alt="low 4.7: CVE--2023--31083" src="https://img.shields.io/badge/CVE--2023--31083-lightgrey?label=low%204.7&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-88.98</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-88.98</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in drivers/bluetooth/hci_ldisc.c in the Linux kernel 6.2. In hci_uart_tty_ioctl, there is a race condition between HCIUARTSETPROTO and HCIUARTGETPROTO. HCI_UART_PROTO_SET is set before hu->proto is set. A NULL pointer dereference may occur.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-0537?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 4.7: CVE--2017--0537" src="https://img.shields.io/badge/CVE--2017--0537-lightgrey?label=low%204.7&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An information disclosure vulnerability in the kernel USB gadget driver could enable a local malicious application to access data outside of its permission levels. This issue is rated as Moderate because it first requires compromising a privileged process. Product: Android. Versions: Kernel-3.18. Android ID: A-31614969.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-15213?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 4.6: CVE--2019--15213" src="https://img.shields.io/badge/CVE--2019--15213-lightgrey?label=low%204.6&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 5.2.3. There is a use-after-free caused by a malicious USB device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14304?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 4.4: CVE--2020--14304" src="https://img.shields.io/badge/CVE--2020--14304-lightgrey?label=low%204.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A memory disclosure flaw was found in the Linux kernel's ethernet drivers, in the way it read data from the EEPROM of the device. This flaw allows a local user to read uninitialized values from the kernel memory. The highest threat from this vulnerability is to confidentiality.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-41848?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 4.2: CVE--2022--41848" src="https://img.shields.io/badge/CVE--2022--41848-lightgrey?label=low%204.2&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

drivers/char/pcmcia/synclink_cs.c in the Linux kernel through 5.19.12 has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling ioctl, aka a race condition between mgslpc_ioctl and mgslpc_detach.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-35501?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 3.4: CVE--2020--35501" src="https://img.shields.io/badge/CVE--2020--35501-lightgrey?label=low%203.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>3.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernels implementation of audit rules, where a syscall can unexpectedly not be correctly not be logged by the audit subsystem

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>jupyterlab</strong> <code>4.0.7</code> (pypi)</summary>

<small><code>pkg:pypi/jupyterlab@4.0.7</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22421?s=github&n=jupyterlab&t=pypi&vr=%3E%3D4.0.0%2C%3C%3D4.0.10"><img alt="high 7.6: CVE--2024--22421" src="https://img.shields.io/badge/CVE--2024--22421-lightgrey?label=high%207.6&labelColor=e25d68"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=4.0.0<br/><=4.0.10</code></td></tr>
<tr><td>Fixed version</td><td><code>4.0.11</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
Users of JupyterLab who click on a malicious link may get their `Authorization` and `XSRFToken` tokens exposed to a third party when running an older `jupyter-server` version.

### Patches
JupyterLab 4.1.0b2, 4.0.11, and 3.6.7 were patched.

### Workarounds
No workaround has been identified, however users should ensure to upgrade `jupyter-server` to version 2.7.2 or newer which includes a redirect vulnerability fix.

### References

Vulnerability reported by user @davwwwx via the [bug bounty program](https://app.intigriti.com/programs/jupyter/jupyter/detail) [sponsored by the European Commission](https://commission.europa.eu/news/european-commissions-open-source-programme-office-starts-bug-bounties-2022-01-19_en) and hosted on the [Intigriti platform](https://www.intigriti.com/).


</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-22420?s=github&n=jupyterlab&t=pypi&vr=%3E%3D4.0.0%2C%3C%3D4.0.10"><img alt="medium 6.5: CVE--2024--22420" src="https://img.shields.io/badge/CVE--2024--22420-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</i>

<table>
<tr><td>Affected range</td><td><code>>=4.0.0<br/><=4.0.10</code></td></tr>
<tr><td>Fixed version</td><td><code>4.0.11</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

The vulnerability depends on user interaction by opening a malicious notebook with Markdown cells, or Markdown file using JupyterLab preview feature.

A malicious user can access any data that the attacked user has access to as well as perform arbitrary requests acting as the attacked user.

### Patches

JupyterLab v4.0.11 was patched.

### Workarounds

Users can either disable the table of contents extension by running:

```bash
jupyter labextension disable @jupyterlab/toc-extension:registry
```

### References

Vulnerability reported via the [bug bounty program](https://app.intigriti.com/programs/jupyter/jupyter/detail) [sponsored by the European Commission](https://commission.europa.eu/news/european-commissions-open-source-programme-office-starts-bug-bounties-2022-01-19_en) and hosted on the [Intigriti platform](https://www.intigriti.com/).


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>notebook</strong> <code>7.0.6</code> (pypi)</summary>

<small><code>pkg:pypi/notebook@7.0.6</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22421?s=github&n=notebook&t=pypi&vr=%3E%3D7.0.0%2C%3C%3D7.0.6"><img alt="high 7.6: CVE--2024--22421" src="https://img.shields.io/badge/CVE--2024--22421-lightgrey?label=high%207.6&labelColor=e25d68"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=7.0.0<br/><=7.0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>7.0.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
Users of JupyterLab who click on a malicious link may get their `Authorization` and `XSRFToken` tokens exposed to a third party when running an older `jupyter-server` version.

### Patches
JupyterLab 4.1.0b2, 4.0.11, and 3.6.7 were patched.

### Workarounds
No workaround has been identified, however users should ensure to upgrade `jupyter-server` to version 2.7.2 or newer which includes a redirect vulnerability fix.

### References

Vulnerability reported by user @davwwwx via the [bug bounty program](https://app.intigriti.com/programs/jupyter/jupyter/detail) [sponsored by the European Commission](https://commission.europa.eu/news/european-commissions-open-source-programme-office-starts-bug-bounties-2022-01-19_en) and hosted on the [Intigriti platform](https://www.intigriti.com/).


</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-22420?s=github&n=notebook&t=pypi&vr=%3E%3D7.0.0%2C%3C%3D7.0.6"><img alt="medium 6.5: CVE--2024--22420" src="https://img.shields.io/badge/CVE--2024--22420-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</i>

<table>
<tr><td>Affected range</td><td><code>>=7.0.0<br/><=7.0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>7.0.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

The vulnerability depends on user interaction by opening a malicious notebook with Markdown cells, or Markdown file using JupyterLab preview feature.

A malicious user can access any data that the attacked user has access to as well as perform arbitrary requests acting as the attacked user.

### Patches

JupyterLab v4.0.11 was patched.

### Workarounds

Users can either disable the table of contents extension by running:

```bash
jupyter labextension disable @jupyterlab/toc-extension:registry
```

### References

Vulnerability reported via the [bug bounty program](https://app.intigriti.com/programs/jupyter/jupyter/detail) [sponsored by the European Commission](https://commission.europa.eu/news/european-commissions-open-source-programme-office-starts-bug-bounties-2022-01-19_en) and hosted on the [Intigriti platform](https://www.intigriti.com/).


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gitpython</strong> <code>3.1.40</code> (pypi)</summary>

<small><code>pkg:pypi/gitpython@3.1.40</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22190?s=github&n=gitpython&t=pypi&vr=%3C3.1.41"><img alt="high 7.8: CVE--2024--22190" src="https://img.shields.io/badge/CVE--2024--22190-lightgrey?label=high%207.8&labelColor=e25d68"/></a> <i>Untrusted Search Path</i>

<table>
<tr><td>Affected range</td><td><code><3.1.41</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.41</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

This issue exists because of an incomplete fix for CVE-2023-40590. On Windows, GitPython uses an untrusted search path if it uses a shell to run `git`, as well as when it runs `bash.exe` to interpret hooks. If either of those features are used on Windows, a malicious `git.exe` or `bash.exe` may be run from an untrusted repository.

### Details

Although GitPython often avoids executing programs found in an untrusted search path since 3.1.33, two situations remain where this still occurs. Either can allow arbitrary code execution under some circumstances.

#### When a shell is used

GitPython can be told to run `git` commands through a shell rather than as direct subprocesses, by passing `shell=True` to any method that accepts it, or by both setting `Git.USE_SHELL = True` and not passing `shell=False`. Then the Windows `cmd.exe` shell process performs the path search, and GitPython does not prevent that shell from finding and running `git` in the current directory.

When GitPython runs `git` directly rather than through a shell, the GitPython process performs the path search, and currently omits the current directory by setting `NoDefaultCurrentDirectoryInExePath` in its own environment during the `Popen` call. Although the `cmd.exe` shell will honor this environment variable when present, GitPython does not currently pass it into the shell subprocess's environment.

Furthermore, because GitPython sets the subprocess CWD to the root of a repository's working tree, using a shell will run a malicious `git.exe` in an untrusted repository even if GitPython itself is run from a trusted location.

This also applies if `Git.execute` is called directly with `shell=True` (or after `Git.USE_SHELL = True`) to run any command.

#### When hook scripts are run

On Windows, GitPython uses `bash.exe` to run hooks that appear to be scripts. However, unlike when running `git`, no steps are taken to avoid finding and running `bash.exe` in the current directory.

This allows the author of an untrusted fork or branch to cause a malicious `bash.exe` to be run in some otherwise safe workflows. An example of such a scenario is if the user installs a trusted hook while on a trusted branch, then switches to an untrusted feature branch (possibly from a fork) to review proposed changes. If the untrusted feature branch contains a malicious `bash.exe` and the user's current working directory is the working tree, and the user performs an action that runs the hook, then although the hook itself is uncorrupted, it runs with the malicious `bash.exe`.

Note that, while `bash.exe` is a shell, this is a separate scenario from when `git` is run using the unrelated Windows `cmd.exe` shell.

### PoC

On Windows, create a `git.exe` file in a repository. Then create a `Repo` object, and call any method through it (directly or indirectly) that supports the `shell` keyword argument with `shell=True`:

```powershell
mkdir testrepo
git init testrepo
cp ... testrepo git.exe # Replace "..." with any executable of choice.
python -c "import git; print(git.Repo('testrepo').git.version(shell=True))"
```

The `git.exe` executable in the repository directory will be run.

Or use no `Repo` object, but do it from the location with the `git.exe`:

```powershell
cd testrepo
python -c "import git; print(git.Git().version(shell=True))"
```

The `git.exe` executable in the current directory will be run.

For the scenario with hooks, install a hook in a repository, create a `bash.exe` file in the current directory, and perform an operation that causes GitPython to attempt to run the hook:

```powershell
mkdir testrepo
cd testrepo
git init
mv .git/hooks/pre-commit.sample .git/hooks/pre-commit
cp ... bash.exe # Replace "..." with any executable of choice.
echo "Some text" >file.txt
git add file.txt
python -c "import git; git.Repo().index.commit('Some message')"
```

The `bash.exe` executable in the current directory will be run.

### Impact

The greatest impact is probably in applications that set `Git.USE_SHELL = True` for historical reasons. (Undesired console windows had, in the past, been created in some kinds of applications, when it was not used.) Such an application may be vulnerable to arbitrary code execution from a malicious repository, even with no other exacerbating conditions. This is to say that, if a shell is used to run `git`, the full effect of CVE-2023-40590 is still present. Furthermore, as noted above, running the application itself from a trusted directory is not a sufficient mitigation.

An application that does not direct GitPython to use a shell to run `git` subprocesses thus avoids most of the risk. However, there is no such straightforward way to prevent GitPython from running `bash.exe` to interpret hooks. So while the conditions needed for that to be exploited are more involved, it may be harder to mitigate decisively prior to patching.

### Possible solutions

A straightforward approach would be to address each bug directly:

- When a shell is used, pass `NoDefaultCurrentDirectoryInExePath` into the subprocess environment, because in that scenario the subprocess is the `cmd.exe` shell that itself performs the path search.
- Set `NoDefaultCurrentDirectoryInExePath` in the GitPython process environment during the `Popen` call made to run hooks with a `bash.exe` subprocess.

These need only be done on Windows.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>jupyter-lsp</strong> <code>2.2.0</code> (pypi)</summary>

<small><code>pkg:pypi/jupyter-lsp@2.2.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22415?s=github&n=jupyter-lsp&t=pypi&vr=%3C%3D2.2.1"><img alt="high 7.3: CVE--2024--22415" src="https://img.shields.io/badge/CVE--2024--22415-lightgrey?label=high%207.3&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><=2.2.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
Installations of jupyter-lsp running in environments without configured file system access control (on the operating system level), and with jupyter-server instances exposed to non-trusted network are vulnerable to unauthorised access and modification of file system beyond the jupyter root directory.

### Patches
Version 2.2.2 has been patched.

### Workarounds
Users of jupyterlab who do not use jupyterlab-lsp can uninstall jupyter-lsp.

### Credits
We would like to credit Bary Levy, researcher of pillar.security research team, for the discovery and responsible disclosure of this vulnerability.

Edit: based on advice from pillar.security the Confidentiality/Integrity/Availability were increased to High to reflect potential for critical impact on publicly hosted jupyter-server instances lacking isolation of user privileges on operating system level (for best practices please consult https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html#protect-users-from-each-other) and CWE-94 was added due to a potential vulnerability chaining in specific environments.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pillow</strong> <code>10.1.0</code> (pypi)</summary>

<small><code>pkg:pypi/pillow@10.1.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-50447?s=github&n=pillow&t=pypi&vr=%3C10.2.0"><img alt="high 8.1: CVE--2023--50447" src="https://img.shields.io/badge/CVE--2023--50447-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><10.2.0</code></td></tr>
<tr><td>Fixed version</td><td><code>10.2.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution via the environment parameter, a different vulnerability than CVE-2022-22817 (which was about the expression parameter).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 15" src="https://img.shields.io/badge/M-15-fbb552"/> <img alt="low: 9" src="https://img.shields.io/badge/L-9-fce1a9"/> <!-- unspecified: 0 --><strong>vim</strong> <code>2:8.2.3995-1ubuntu2.12</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/vim@2:8.2.3995-1ubuntu2.12?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-5535?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--5535" src="https://img.shields.io/badge/CVE--2023--5535-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use After Free in GitHub repository vim/vim prior to v9.0.2010.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4781?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4781" src="https://img.shields.io/badge/CVE--2023--4781-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1873.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4752?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4752" src="https://img.shields.io/badge/CVE--2023--4752-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use After Free in GitHub repository vim/vim prior to 9.0.1858.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4751?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4751" src="https://img.shields.io/badge/CVE--2023--4751-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1331.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4750?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4750" src="https://img.shields.io/badge/CVE--2023--4750-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use After Free in GitHub repository vim/vim prior to 9.0.1857.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4735?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4735" src="https://img.shields.io/badge/CVE--2023--4735-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1847.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4734?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4734" src="https://img.shields.io/badge/CVE--2023--4734-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1846.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4733?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.8: CVE--2023--4733" src="https://img.shields.io/badge/CVE--2023--4733-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use After Free in GitHub repository vim/vim prior to 9.0.1840.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-2042?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="medium 7.8: CVE--2022--2042" src="https://img.shields.io/badge/CVE--2022--2042-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use After Free in GitHub repository vim/vim prior to 8.2.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-2000?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="medium 7.8: CVE--2022--2000" src="https://img.shields.io/badge/CVE--2022--2000-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5344?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 7.5: CVE--2023--5344" src="https://img.shields.io/badge/CVE--2023--5344-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5441?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.13"><img alt="medium 5.5: CVE--2023--5441" src="https://img.shields.io/badge/CVE--2023--5441-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

NULL Pointer Dereference in GitHub repository vim/vim prior to 20d161ace307e28690229b68584f2d84556f8960.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-46246?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="medium 5.5: CVE--2023--46246" src="https://img.shields.io/badge/CVE--2023--46246-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an improved version of the good old UNIX editor Vi. Heap-use-after-free in memory allocated in the function `ga_grow_inner` in in the file `src/alloc.c` at line 748, which is freed in the file `src/ex_docmd.c` in the function `do_cmdline` at line 1010 and then used again in `src/cmdhist.c` at line 759. When using the `:history` command, it's possible that the provided argument overflows the accepted value. Causing an Integer Overflow and potentially later an use-after-free. This vulnerability has been patched in version 9.0.2068. 

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48706?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="medium 4.7: CVE--2023--48706" src="https://img.shields.io/badge/CVE--2023--48706-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is a UNIX editor that, prior to version 9.0.2121, has a heap-use-after-free vulnerability. When executing a `:s` command for the very first time and using a sub-replace-special atom inside the substitution part, it is possible that the recursive `:s` call causes free-ing of memory which may later then be accessed by the initial `:s` command. The user must intentionally execute the payload and the whole process is a bit tricky to do since it seems to work only reliably for the very first :s command. It may also cause a crash of Vim. Version 9.0.2121 contains a fix for this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48231?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="medium 4.3: CVE--2023--48231" src="https://img.shields.io/badge/CVE--2023--48231-lightgrey?label=medium%204.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. When closing a window, vim may try to access already freed window structure. Exploitation beyond crashing the application has not been shown to be viable. This issue has been addressed in commit `25aabc2b` which has been included in release version 9.0.2106. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1897?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 7.8: CVE--2022--1897" src="https://img.shields.io/badge/CVE--2022--1897-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1886?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 7.8: CVE--2022--1886" src="https://img.shields.io/badge/CVE--2022--1886-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1771?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 5.5: CVE--2022--1771" src="https://img.shields.io/badge/CVE--2022--1771-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1725?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 5.5: CVE--2022--1725" src="https://img.shields.io/badge/CVE--2022--1725-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4959.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48237?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 4.3: CVE--2023--48237" src="https://img.shields.io/badge/CVE--2023--48237-lightgrey?label=low%204.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. In affected versions when shifting lines in operator pending mode and using a very large value, it may be possible to overflow the size of integer. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `6bf131888` which has been included in version 9.0.2112. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48236?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 4.3: CVE--2023--48236" src="https://img.shields.io/badge/CVE--2023--48236-lightgrey?label=low%204.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. When using the z= command, the user may overflow the count with values larger than MAX_INT. Impact is low, user interaction is required and a crash may not even happen in all situations. This vulnerability has been addressed in commit `73b2d379` which has been included in release version 9.0.2111. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48235?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 4.3: CVE--2023--48235" src="https://img.shields.io/badge/CVE--2023--48235-lightgrey?label=low%204.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. When parsing relative ex addresses one may unintentionally cause an overflow. Ironically this happens in the existing overflow check, because the line number becomes negative and LONG_MAX - lnum will cause the overflow. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `060623e` which has been included in release version 9.0.2110. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48234?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 4.3: CVE--2023--48234" src="https://img.shields.io/badge/CVE--2023--48234-lightgrey?label=low%204.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. When getting the count for a normal mode z command, it may overflow for large counts given. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `58f9befca1` which has been included in release version 9.0.2109. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48233?s=ubuntu&n=vim&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A8.2.3995-1ubuntu2.15"><img alt="low 4.3: CVE--2023--48233" src="https://img.shields.io/badge/CVE--2023--48233-lightgrey?label=low%204.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2:8.2.3995-1ubuntu2.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vim is an open source command line text editor. If the count after the :s command is larger than what fits into a (signed) long variable, abort with e_value_too_large. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `ac6378773` which has been included in release version 9.0.2108. Users are advised to upgrade. There are no known workarounds for this vulnerability.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 10" src="https://img.shields.io/badge/M-10-fbb552"/> <img alt="low: 6" src="https://img.shields.io/badge/L-6-fce1a9"/> <!-- unspecified: 0 --><strong>binutils</strong> <code>2.38-4ubuntu2.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/binutils@2.38-4ubuntu2.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-47695?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2022--47695" src="https://img.shields.io/badge/CVE--2022--47695-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered Binutils objdump before 2.39.3 allows attackers to cause a denial of service or other unspecified impacts via function bfd_mach_o_get_synthetic_symtab in match-o.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45703?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 7.8: CVE--2022--45703" src="https://img.shields.io/badge/CVE--2022--45703-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap buffer overflow vulnerability in binutils readelf before 2.40 via function display_debug_section in file readelf.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-44840?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 7.8: CVE--2022--44840" src="https://img.shields.io/badge/CVE--2022--44840-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap buffer overflow vulnerability in binutils readelf before 2.40 via function find_section_in_set in file readelf.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48065?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--48065" src="https://img.shields.io/badge/CVE--2022--48065-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU Binutils before 2.40 was discovered to contain a memory leak vulnerability var the function find_abstract_instance in dwarf2.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48063?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--48063" src="https://img.shields.io/badge/CVE--2022--48063-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function load_separate_debug_files at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-47011?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 5.5: CVE--2022--47011" src="https://img.shields.io/badge/CVE--2022--47011-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered function parse_stab_struct_fields in stabs.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-47010?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 5.5: CVE--2022--47010" src="https://img.shields.io/badge/CVE--2022--47010-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered function pr_function_type in prdbg.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-47008?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 5.5: CVE--2022--47008" src="https://img.shields.io/badge/CVE--2022--47008-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered function make_tempdir, and make_tempname in bucomm.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-47007?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.5"><img alt="medium 5.5: CVE--2022--47007" src="https://img.shields.io/badge/CVE--2022--47007-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered function stab_demangle_v3_arg in stabs.c in Binutils 2.34 thru 2.38, allows attackers to cause a denial of service due to memory leaks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-35205?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.4"><img alt="medium 5.5: CVE--2022--35205" src="https://img.shields.io/badge/CVE--2022--35205-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in Binutils readelf 2.38.50, reachable assertion failure in function display_debug_names allows attackers to cause a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-20657?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2018--20657" src="https://img.shields.io/badge/CVE--2018--20657-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The demangle_template function in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31.1, has a memory leak via a crafted string, leading to a denial of service (memory consumption), as demonstrated by cxxfilt, a related issue to CVE-2018-12698.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48064?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--48064" src="https://img.shields.io/badge/CVE--2022--48064-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function bfd_dwarf2_find_nearest_line_with_alt at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-4285?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.38-4ubuntu2.4"><img alt="low 5.5: CVE--2022--4285" src="https://img.shields.io/badge/CVE--2022--4285-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.38-4ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.38-4ubuntu2.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An illegal memory access flaw was found in the binutils package. Parsing an ELF file containing corrupt symbol version information may result in a denial of service. This issue is the result of an incomplete fix for CVE-2020-16599.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-27943?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--27943" src="https://img.shields.io/badge/CVE--2022--27943-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-1010204?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2019--1010204" src="https://img.shields.io/badge/CVE--2019--1010204-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU binutils gold gold v1.11-v1.16 (GNU binutils v2.21-v2.31.1) is affected by: Improper Input Validation, Signed/Unsigned Comparison, Out-of-bounds Read. The impact is: Denial of service. The component is: gold/fileread.cc:497, elfcpp/elfcpp_file.h:644. The attack vector is: An ELF file with an invalid e_shoff header field must be opened.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13716?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2017--13716" src="https://img.shields.io/badge/CVE--2017--13716-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The C++ symbol demangler routine in cplus-dem.c in libiberty, as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (excessive memory allocation and application crash) via a crafted file, as demonstrated by a call from the Binary File Descriptor (BFD) library (aka libbfd).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 5" src="https://img.shields.io/badge/M-5-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>avahi</strong> <code>0.8-5ubuntu5.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/avahi@0.8-5ubuntu5.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-38473?s=ubuntu&n=avahi&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.8-5ubuntu5.2"><img alt="medium 5.5: CVE--2023--38473" src="https://img.shields.io/badge/CVE--2023--38473-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.8-5ubuntu5.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.8-5ubuntu5.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Avahi. A reachable assertion exists in the avahi_alternative_host_name() function.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38472?s=ubuntu&n=avahi&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.8-5ubuntu5.2"><img alt="medium 5.5: CVE--2023--38472" src="https://img.shields.io/badge/CVE--2023--38472-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.8-5ubuntu5.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.8-5ubuntu5.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Avahi. A reachable assertion exists in the avahi_rdata_parse() function.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38471?s=ubuntu&n=avahi&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.8-5ubuntu5.2"><img alt="medium 5.5: CVE--2023--38471" src="https://img.shields.io/badge/CVE--2023--38471-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.8-5ubuntu5.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.8-5ubuntu5.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Avahi. A reachable assertion exists in the dbus_set_host_name function.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38470?s=ubuntu&n=avahi&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.8-5ubuntu5.2"><img alt="medium 5.5: CVE--2023--38470" src="https://img.shields.io/badge/CVE--2023--38470-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.8-5ubuntu5.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.8-5ubuntu5.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Avahi. A reachable assertion exists in the avahi_escape_label() function.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38469?s=ubuntu&n=avahi&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.8-5ubuntu5.2"><img alt="medium 5.5: CVE--2023--38469" src="https://img.shields.io/badge/CVE--2023--38469-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.8-5ubuntu5.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.8-5ubuntu5.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Avahi, where a reachable assertion exists in avahi_dns_packet_append_record.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>openssh</strong> <code>1:8.9p1-3ubuntu0.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openssh@1:8.9p1-3ubuntu0.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-51767?s=ubuntu&n=openssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2023--51767" src="https://img.shields.io/badge/CVE--2023--51767-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSH through 9.6, when common types of DRAM are used, might allow row hammer attacks (for authentication bypass) because the integer value of authenticated in mm_answer_authpassword does not resist flips of a single bit. NOTE: this is applicable to a certain threat model of attacker-victim co-location in which the attacker has user privileges.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-51385?s=ubuntu&n=openssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1%3A8.9p1-3ubuntu0.6"><img alt="medium 6.5: CVE--2023--51385" src="https://img.shields.io/badge/CVE--2023--51385-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:8.9p1-3ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1:8.9p1-3ubuntu0.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-48795?s=ubuntu&n=openssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1%3A8.9p1-3ubuntu0.5"><img alt="medium 5.9: CVE--2023--48795" src="https://img.shields.io/badge/CVE--2023--48795-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:8.9p1-3ubuntu0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>1:8.9p1-3ubuntu0.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-51384?s=ubuntu&n=openssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1%3A8.9p1-3ubuntu0.6"><img alt="medium 5.5: CVE--2023--51384" src="https://img.shields.io/badge/CVE--2023--51384-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:8.9p1-3ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1:8.9p1-3ubuntu0.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In ssh-agent in OpenSSH before 9.6, certain destination constraints can be incompletely applied. When destination constraints are specified during addition of PKCS#11-hosted private keys, these constraints are only applied to the first key, even if a PKCS#11 token returns multiple keys.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-28531?s=ubuntu&n=openssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1%3A8.9p1-3ubuntu0.5"><img alt="low 9.8: CVE--2023--28531" src="https://img.shields.io/badge/CVE--2023--28531-lightgrey?label=low%209.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:8.9p1-3ubuntu0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>1:8.9p1-3ubuntu0.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ssh-add in OpenSSH before 9.3 adds smartcard keys to ssh-agent without the intended per-hop destination constraints. The earliest affected version is 8.9.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>ffmpeg</strong> <code>7:4.4.2-0ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/ffmpeg@7:4.4.2-0ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-48434?s=ubuntu&n=ffmpeg&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2022--48434" src="https://img.shields.io/badge/CVE--2022--48434-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libavcodec/pthread_frame.c in FFmpeg before 5.1.2, as used in VLC and other products, leaves stale hwaccel state in worker threads, which allows attackers to trigger a use-after-free and execute arbitrary code in some circumstances (e.g., hardware re-initialization upon a mid-video SPS change when Direct3D11 is used).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3964?s=ubuntu&n=ffmpeg&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 8.1: CVE--2022--3964" src="https://img.shields.io/badge/CVE--2022--3964-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic has been found in ffmpeg. This affects an unknown part of the file libavcodec/rpzaenc.c of the component QuickTime RPZA Video Encoder. The manipulation of the argument y_size leads to out-of-bounds read. It is possible to initiate the attack remotely. The name of the patch is 92f9b28ed84a77138105475beba16c146bdaf984. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-213543.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3109?s=ubuntu&n=ffmpeg&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2022--3109" src="https://img.shields.io/badge/CVE--2022--3109-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the FFmpeg package, where vp3_decode_frame in libavcodec/vp3.c lacks check of the return value of av_malloc() and will cause a null pointer dereference, impacting availability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3341?s=ubuntu&n=ffmpeg&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.3: CVE--2022--3341" src="https://img.shields.io/badge/CVE--2022--3341-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A null pointer dereference issue was discovered in 'FFmpeg' in decode_main_header() function of libavformat/nutdec.c file. The flaw occurs because the function lacks check of the return value of avformat_new_stream() and triggers the null pointer dereference error, causing an application to crash.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libssh</strong> <code>0.9.6-2ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libssh@0.9.6-2ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-48795?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.2"><img alt="medium 5.9: CVE--2023--48795" src="https://img.shields.io/badge/CVE--2023--48795-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6918?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.3"><img alt="medium 5.3: CVE--2023--6918" src="https://img.shields.io/badge/CVE--2023--6918-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.3</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the libssh implements abstract layer for message digest (MD) operations implemented by different supported crypto backends. The return values from these were not properly checked, which could cause low-memory situations failures, NULL dereferences, crashes, or usage of the uninitialized memory as an input for the KDF. In this case, non-matching keys will result in decryption/integrity failures, terminating the connection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6004?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.3"><img alt="medium 4.8: CVE--2023--6004" src="https://img.shields.io/badge/CVE--2023--6004-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.3</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libssh. By utilizing the ProxyCommand or ProxyJump feature, users can exploit unchecked hostname syntax on the client. This issue may allow an attacker to inject malicious code into the command of the features mentioned through the hostname parameter.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.7.3-4ubuntu1.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.7.3-4ubuntu1.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-0567?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.4"><img alt="medium 7.5: CVE--2024--0567" src="https://img.shields.io/badge/CVE--2024--0567-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GnuTLS, where a cockpit (which uses gnuTLS) rejects a certificate chain with distributed trust. This issue occurs when validating a certificate chain with cockpit-certificate-ensure. This flaw allows an unauthenticated, remote client or attacker to initiate a denial of service attack.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0553?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.4"><img alt="medium 7.5: CVE--2024--0553" src="https://img.shields.io/badge/CVE--2024--0553-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GnuTLS. The response times to malformed ciphertexts in RSA-PSK ClientKeyExchange differ from the response times of ciphertexts with correct PKCS#1 v1.5 padding. This issue may allow a remote attacker to perform a timing side-channel attack in the RSA-PSK key exchange, potentially leading to the leakage of sensitive data. CVE-2024-0553 is designated as an incomplete resolution for CVE-2023-5981.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5981?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.3"><img alt="medium 5.9: CVE--2023--5981" src="https://img.shields.io/badge/CVE--2023--5981-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found that the response times to malformed ciphertexts in RSA-PSK ClientKeyExchange differ from response times of ciphertexts with correct PKCS#1 v1.5 padding.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libsndfile</strong> <code>1.0.31-2build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libsndfile@1.0.31-2build1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-33065?s=ubuntu&n=libsndfile&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.0.31-2ubuntu0.1"><img alt="medium 7.8: CVE--2022--33065" src="https://img.shields.io/badge/CVE--2022--33065-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.0.31-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.0.31-2ubuntu0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Multiple signed integers overflow in function au_read_header in src/au.c and in functions mat4_open and mat4_read_header in src/mat4.c in Libsndfile, allows an attacker to cause Denial of Service or other unspecified impacts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-33064?s=ubuntu&n=libsndfile&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2022--33064" src="https://img.shields.io/badge/CVE--2022--33064-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An off-by-one error in function wav_read_header in src/wav.c in Libsndfile 1.1.0, results in a write out of bound, which allows an attacker to execute arbitrary code, Denial of Service or other unspecified impacts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-4156?s=ubuntu&n=libsndfile&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.1: CVE--2021--4156" src="https://img.shields.io/badge/CVE--2021--4156-lightgrey?label=low%207.1&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds read flaw was found in libsndfile's FLAC codec functionality. An attacker who is able to submit a specially crafted file (via tricking a user to open or otherwise) to an application linked with libsndfile and using the FLAC codec, could trigger an out-of-bounds read that would most likely cause a crash but could potentially leak memory information that could be used in further exploitation of other flaws.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>python3.10</strong> <code>3.10.12-1~22.04.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/python3.10@3.10.12-1~22.04.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-40217?s=ubuntu&n=python3.10&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.10.12-1%7E22.04.3"><img alt="medium 5.3: CVE--2023--40217" src="https://img.shields.io/badge/CVE--2023--40217-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.10.12-1~22.04.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.10.12-1~22.04.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in Python before 3.8.18, 3.9.x before 3.9.18, 3.10.x before 3.10.13, and 3.11.x before 3.11.5. It primarily affects servers (such as HTTP servers) that use TLS client authentication. If a TLS server-side socket is created, receives data into the socket buffer, and then is closed quickly, there is a brief window where the SSLSocket instance will detect the socket as "not connected" and won't initiate a handshake, but buffered data will still be readable from the socket buffer. This data will not be authenticated if the server-side TLS peer is expecting client certificate authentication, and is indistinguishable from valid TLS stream data. Data is limited in size to the amount that will fit in the buffer. (The TLS connection cannot directly be used for data exfiltration because the vulnerable code path requires that the connection be closed on initialization of the SSLSocket.)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-27043?s=ubuntu&n=python3.10&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.3: CVE--2023--27043" src="https://img.shields.io/badge/CVE--2023--27043-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some applications, an attacker can bypass a protection mechanism in which application access is granted only after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be used for signup). This occurs in email/_parseaddr.py in recent versions of Python.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 7" src="https://img.shields.io/badge/L-7-fce1a9"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.2-0ubuntu1.10</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-5363?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.12"><img alt="medium 7.5: CVE--2023--5363" src="https://img.shields.io/badge/CVE--2023--5363-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths. This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers. Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of confidentiality for some cipher modes. When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been established. Any alterations to the key length, via the "keylen" parameter or the IV length, via the "ivlen" parameter, within the OSSL_PARAM array will not take effect as intended, potentially causing truncation or overreading of these values. The following ciphers and cipher modes are impacted: RC2, RC4, RC5, CCM, GCM and OCB. For the CCM, GCM and OCB cipher modes, truncation of the IV can result in loss of confidentiality. For example, when following NIST's SP 800-38D section 8.2.1 guidance for constructing a deterministic IV for AES in GCM mode, truncation of the counter portion could lead to IV reuse. Both truncations and overruns of the key and overruns of the IV will produce incorrect results and could, in some cases, trigger a memory exception. However, these issues are not currently assessed as security critical. Changing the key and/or IV lengths is not considered to be a common operation and the vulnerable API was recently introduced. Furthermore it is likely that application developers will have spotted this problem during testing since decryption would fail unless both peers in the communication were similarly vulnerable. For these reasons we expect the probability of an application being vulnerable to this to be quite low. However if an application is vulnerable then this issue is considered very serious. For these reasons we have assessed this issue as Moderate severity overall. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because the issue lies outside of the FIPS provider boundary. OpenSSL 3.1 and 3.0 are vulnerable to this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6129?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2023--6129" src="https://img.shields.io/badge/CVE--2023--6129-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might corrupt the internal state of applications running on PowerPC CPU based platforms if the CPU provides vector instructions. Impact summary: If an attacker can influence whether the POLY1305 MAC algorithm is used, the application state might be corrupted with various application dependent consequences. The POLY1305 MAC (message authentication code) implementation in OpenSSL for PowerPC CPUs restores the contents of vector registers in a different order than they are saved. Thus the contents of some of these vector registers are corrupted when returning to the caller. The vulnerable code is used only on newer PowerPC processors supporting the PowerISA 2.07 instructions. The consequences of this kind of internal application state corruption can be various - from no consequences, if the calling application does not depend on the contents of non-volatile XMM registers at all, to the worst consequences, where the attacker could get complete control of the application process. However unless the compiler uses the vector registers for storing pointers, the most likely consequence, if any, would be an incorrect result of some application dependent calculations or a crash leading to a denial of service. The POLY1305 MAC algorithm is most frequently used as part of the CHACHA20-POLY1305 AEAD (authenticated encryption with associated data) algorithm. The most common usage of this AEAD cipher is with TLS protocol versions 1.2 and 1.3. If this cipher is enabled on the server a malicious client can influence whether this AEAD cipher is used. This implies that TLS server applications using OpenSSL can be potentially impacted. However we are currently not aware of any concrete application that would be affected by this issue therefore we consider this a Low severity security issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5678?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.3: CVE--2023--5678" src="https://img.shields.io/badge/CVE--2023--5678-lightgrey?label=low%205.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow. Impact summary: Applications that use the functions DH_generate_key() to generate an X9.42 DH key may experience long delays. Likewise, applications that use DH_check_pub_key(), DH_check_pub_key_ex() or EVP_PKEY_public_check() to check an X9.42 DH key or X9.42 DH parameters may experience long delays. Where the key or parameters that are being checked have been obtained from an untrusted source this may lead to a Denial of Service. While DH_check() performs all the necessary checks (as of CVE-2023-3817), DH_check_pub_key() doesn't make any of these checks, and is therefore vulnerable for excessively large P and Q parameters. Likewise, while DH_generate_key() performs a check for an excessively large P, it doesn't check for an excessively large Q. An application that calls DH_generate_key() or DH_check_pub_key() and supplies a key or parameters obtained from an untrusted source could be vulnerable to a Denial of Service attack. DH_generate_key() and DH_check_pub_key() are also called by a number of other OpenSSL functions. An application calling any of those other functions may similarly be affected. The other functions affected by this are DH_check_pub_key_ex(), EVP_PKEY_public_check(), and EVP_PKEY_generate(). Also vulnerable are the OpenSSL pkey command line application when using the "-pubcheck" option, as well as the OpenSSL genpkey command line application. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3817?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.12"><img alt="low 5.3: CVE--2023--3817" src="https://img.shields.io/badge/CVE--2023--3817-lightgrey?label=low%205.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary: Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays. Where the key or parameters that are being checked have been obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs various checks on DH parameters. After fixing CVE-2023-3446 it was discovered that a large q parameter value can also trigger an overly long computation during some of these checks. A correct q value, if present, cannot be larger than the modulus p parameter, thus it is unnecessary to perform these checks if q is larger than p. An application that calls DH_check() and supplies a key or parameters obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function DH_check() is itself called by a number of other OpenSSL functions. An application calling any of those other functions may similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check(). Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the "-check" option. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3446?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.12"><img alt="low 5.3: CVE--2023--3446" src="https://img.shields.io/badge/CVE--2023--3446-lightgrey?label=low%205.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary: Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays. Where the key or parameters that are being checked have been obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs various checks on DH parameters. One of those checks confirms that the modulus ('p' parameter) is not too large. Trying to use a very large modulus is slow and OpenSSL will not normally use a modulus which is over 10,000 bits in length. However the DH_check() function checks numerous aspects of the key or parameters that have been supplied. Some of those checks use the supplied modulus value even if it has already been found to be too large. An application that calls DH_check() and supplies a key or parameters obtained from an untrusted source could be vulernable to a Denial of Service attack. The function DH_check() is itself called by a number of other OpenSSL functions. An application calling any of those other functions may similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check(). Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the '-check' option. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-2975?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.12"><img alt="low 5.3: CVE--2023--2975" src="https://img.shields.io/badge/CVE--2023--2975-lightgrey?label=low%205.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: The AES-SIV cipher implementation contains a bug that causes it to ignore empty associated data entries which are unauthenticated as a consequence. Impact summary: Applications that use the AES-SIV algorithm and want to authenticate empty data entries as associated data can be mislead by removing adding or reordering such empty entries as these are ignored by the OpenSSL implementation. We are currently unaware of any such applications. The AES-SIV algorithm allows for authentication of multiple associated data entries along with the encryption. To authenticate empty data the application has to call EVP_EncryptUpdate() (or EVP_CipherUpdate()) with NULL pointer as the output buffer and 0 as the input buffer length. The AES-SIV implementation in OpenSSL just returns success for such a call instead of performing the associated data authentication operation. The empty data thus will not be authenticated. As this issue does not affect non-empty associated data authentication and we expect it to be rare for an application to use empty associated data entries this is qualified as Low severity issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0727?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low : CVE--2024--0727" src="https://img.shields.io/badge/CVE--2024--0727-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr></table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL does not correctly check for this case. This can lead to a NULL pointer dereference that results in OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are: PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6237?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low : CVE--2023--6237" src="https://img.shields.io/badge/CVE--2023--6237-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr></table>

<details><summary>Description</summary>
<blockquote>

Excessive time spent checking invalid RSA public keys

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 5" src="https://img.shields.io/badge/L-5-fce1a9"/> <!-- unspecified: 0 --><strong>tiff</strong> <code>4.3.0-6ubuntu0.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/tiff@4.3.0-6ubuntu0.6?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40090?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C4.3.0-6ubuntu0.7"><img alt="medium 6.5: CVE--2022--40090" src="https://img.shields.io/badge/CVE--2022--40090-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.3.0-6ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>4.3.0-6ubuntu0.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in function TIFFReadDirectory libtiff before 4.4.0 allows attackers to cause a denial of service via crafted TIFF file.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6277?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2023--6277" src="https://img.shields.io/badge/CVE--2023--6277-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-memory flaw was found in libtiff. Passing a crafted tiff file to TIFFOpen() API may allow a remote attacker to cause a denial of service via a craft input with size smaller than 379 KB.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-10126?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2018--10126" src="https://img.shields.io/badge/CVE--2018--10126-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

LibTIFF 4.0.9 has a NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6228?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2023--6228" src="https://img.shields.io/badge/CVE--2023--6228-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was found in the tiffcp utility distributed by the libtiff package where a crafted TIFF file on processing may cause a heap-based buffer overflow leads to an application crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3576?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C4.3.0-6ubuntu0.7"><img alt="low 5.5: CVE--2023--3576" src="https://img.shields.io/badge/CVE--2023--3576-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.3.0-6ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>4.3.0-6ubuntu0.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A memory leak flaw was found in Libtiff's tiffcrop utility. This issue occurs when tiffcrop operates on a TIFF image file, allowing an attacker to pass a crafted TIFF image file to tiffcrop utility, which causes this memory leak issue, resulting an application crash, eventually leading to a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3164?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2023--3164" src="https://img.shields.io/badge/CVE--2023--3164-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overflow vulnerability was found in LibTIFF, in extractImageSection() at tools/tiffcrop.c:7916 and tools/tiffcrop.c:7801. This flaw allows attackers to cause a denial of service via a crafted tiff file.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 4" src="https://img.shields.io/badge/L-4-fce1a9"/> <!-- unspecified: 0 --><strong>texlive-bin</strong> <code>2021.20210626.59705-1ubuntu0.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/texlive-bin@2021.20210626.59705-1ubuntu0.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-32668?s=ubuntu&n=texlive-bin&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--32668" src="https://img.shields.io/badge/CVE--2023--32668-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

LuaTeX before 1.17.0 allows a document (compiled with the default settings) to make arbitrary network requests. This occurs because full access to the socket library is permitted by default, as stated in the documentation. This also affects TeX Live before 2023 r66984 and MiKTeX before 23.5.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-9588?s=ubuntu&n=texlive-bin&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--9588" src="https://img.shields.io/badge/CVE--2019--9588-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There is an Invalid memory access in gAtomicIncrement() located at GMutex.h in Xpdf 4.01. It can be triggered by sending a crafted pdf file to (for example) the pdftops binary. It allows an attacker to cause Denial of Service (Segmentation fault) or possibly have unspecified other impact.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-9587?s=ubuntu&n=texlive-bin&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--9587" src="https://img.shields.io/badge/CVE--2019--9587-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There is a stack consumption issue in md5Round1() located in Decrypt.cc in Xpdf 4.01. It can be triggered by sending a crafted pdf file to (for example) the pdfimages binary. It allows an attacker to cause Denial of Service (Segmentation fault) or possibly have unspecified other impact. This is related to Catalog::countPageTree.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12493?s=ubuntu&n=texlive-bin&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.1: CVE--2019--12493" src="https://img.shields.io/badge/CVE--2019--12493-lightgrey?label=low%207.1&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A stack-based buffer over-read exists in PostScriptFunction::transform in Function.cc in Xpdf 4.01.01 because GfxSeparationColorSpace and GfxDeviceNColorSpace mishandle tint transform functions. It can, for example, be triggered by sending a crafted PDF document to the pdftops tool. It might allow an attacker to cause Denial of Service or leak memory data.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12360?s=ubuntu&n=texlive-bin&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.1: CVE--2019--12360" src="https://img.shields.io/badge/CVE--2019--12360-lightgrey?label=low%207.1&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A stack-based buffer over-read exists in FoFiTrueType::dumpString in fofi/FoFiTrueType.cc in Xpdf 4.01.01. It can, for example, be triggered by sending crafted TrueType data in a PDF document to the pdftops tool. It might allow an attacker to cause Denial of Service or leak memory data into dump content.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.35-0ubuntu3.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.35-0ubuntu3.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-5156?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.35-0ubuntu3.5"><img alt="medium 7.5: CVE--2023--5156" src="https://img.shields.io/badge/CVE--2023--5156-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.35-0ubuntu3.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.35-0ubuntu3.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the GNU C Library. A recent fix for CVE-2023-4806 introduced the potential for a memory leak, which may result in an application crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-20013?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2016--20013" src="https://img.shields.io/badge/CVE--2016--20013-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4813?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.35-0ubuntu3.5"><img alt="low 5.9: CVE--2023--4813" src="https://img.shields.io/badge/CVE--2023--4813-lightgrey?label=low%205.9&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.35-0ubuntu3.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.35-0ubuntu3.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in glibc. In an uncommon situation, the gaih_inet function may use memory that has been freed, resulting in an application crash. This issue is only exploitable when the getaddrinfo function is called and the hosts database in /etc/nsswitch.conf is configured with SUCCESS=continue or SUCCESS=merge.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4806?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.35-0ubuntu3.5"><img alt="low 5.9: CVE--2023--4806" src="https://img.shields.io/badge/CVE--2023--4806-lightgrey?label=low%205.9&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.35-0ubuntu3.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.35-0ubuntu3.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in glibc. In an extremely rare situation, the getaddrinfo function may access memory that has been freed, resulting in an application crash. This issue is only exploitable when a NSS module implements only the _nss_*_gethostbyname2_r and _nss_*_getcanonname_r hooks without implementing the _nss_*_gethostbyname3_r hook. The resolved name should return a large number of IPv6 and IPv4, and the call to the getaddrinfo function should have the AF_INET6 address family with AI_CANONNAME, AI_ALL and AI_V4MAPPED as flags.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.37.2-2ubuntu0.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.37.2-2ubuntu0.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-7104?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.37.2-2ubuntu0.3"><img alt="medium 7.3: CVE--2023--7104" src="https://img.shields.io/badge/CVE--2023--7104-lightgrey?label=medium%207.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.37.2-2ubuntu0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.37.2-2ubuntu0.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified as critical. This issue affects the function sessionReadRecord of the file ext/session/sqlite3session.c of the component make alltest Handler. The manipulation leads to heap-based buffer overflow. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-248999.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-46908?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.37.2-2ubuntu0.3"><img alt="low 7.3: CVE--2022--46908" src="https://img.shields.io/badge/CVE--2022--46908-lightgrey?label=low%207.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.37.2-2ubuntu0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.37.2-2ubuntu0.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

SQLite through 3.40.0, when relying on --safe for execution of an untrusted CLI script, does not properly implement the azProhibitedFunctions protection mechanism, and instead allows UDF functions such as WRITEFILE.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.34.0-3ubuntu1.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.34.0-3ubuntu1.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-47038?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.34.0-3ubuntu1.3"><img alt="medium 7.8: CVE--2023--47038" src="https://img.shields.io/badge/CVE--2023--47038-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.34.0-3ubuntu1.3</code></td></tr>
<tr><td>Fixed version</td><td><code>5.34.0-3ubuntu1.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in perl. This issue occurs when a crafted regular expression is compiled by perl, which can allow an attacker controlled byte buffer overflow in a heap allocated buffer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48522?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.34.0-3ubuntu1.3"><img alt="low 9.8: CVE--2022--48522" src="https://img.shields.io/badge/CVE--2022--48522-lightgrey?label=low%209.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.34.0-3ubuntu1.3</code></td></tr>
<tr><td>Fixed version</td><td><code>5.34.0-3ubuntu1.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Perl 5.34.0, function S_find_uninit_var in sv.c has a stack-based crash that can lead to remote code execution or local privilege escalation.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gcc-defaults</strong> <code>1.193ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gcc-defaults@1.193ubuntu1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2020-13844?s=ubuntu&n=gcc-defaults&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2020--13844" src="https://img.shields.io/badge/CVE--2020--13844-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Arm Armv8-A core implementations utilizing speculative execution past unconditional changes in control flow may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis, aka "straight-line speculation."

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>follow-redirects</strong> <code>1.15.2</code> (npm)</summary>

<small><code>pkg:npm/follow-redirects@1.15.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-26159?s=github&n=follow-redirects&t=npm&vr=%3C1.15.4"><img alt="medium 6.1: CVE--2023--26159" src="https://img.shields.io/badge/CVE--2023--26159-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><1.15.4</code></td></tr>
<tr><td>Fixed version</td><td><code>1.15.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Versions of the package follow-redirects before 1.15.4 are vulnerable to Improper Input Validation due to the improper handling of URLs by the url.parse() function. When new URL() throws an error, it can be manipulated to misinterpret the hostname. An attacker could exploit this weakness to redirect traffic to a malicious site, potentially leading to information disclosure, phishing attacks, or other security breaches.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>jinja2</strong> <code>3.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/jinja2@3.1.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22195?s=github&n=jinja2&t=pypi&vr=%3C3.1.3"><img alt="medium 5.4: CVE--2024--22195" src="https://img.shields.io/badge/CVE--2024--22195-lightgrey?label=medium%205.4&labelColor=fbb552"/></a> <i>Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</i>

<table>
<tr><td>Affected range</td><td><code><3.1.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted as a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. Note that accepting keys as user input is not common or a particularly intended use case of the `xmlattr` filter, and an application doing so should already be verifying what keys are provided regardless of this fix.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wget</strong> <code>1.21.2-2ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/wget@1.21.2-2ubuntu1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-31879?s=ubuntu&n=wget&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 6.1: CVE--2021--31879" src="https://img.shields.io/badge/CVE--2021--31879-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU Wget through 1.21.1 does not omit the Authorization header upon a redirect to a different origin, a related issue to CVE-2018-1000007.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.4.0-11ubuntu2.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.4.0-11ubuntu2.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-22365?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.4.0-11ubuntu2.4"><img alt="medium : CVE--2024--22365" src="https://img.shields.io/badge/CVE--2024--22365-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.4.0-11ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>1.4.0-11ubuntu2.4</code></td></tr></table>

<details><summary>Description</summary>
<blockquote>

pam_namespace local denial of service

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.19.2-2ubuntu0.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/krb5@1.19.2-2ubuntu0.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-36054?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.3"><img alt="medium 6.5: CVE--2023--36054" src="https://img.shields.io/badge/CVE--2023--36054-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

lib/kadm5/kadm_rpc_xdr.c in MIT Kerberos 5 (aka krb5) before 1.20.2 and 1.21.x before 1.21.1 frees an uninitialized pointer. A remote authenticated user can trigger a kadmind crash. This occurs because _xdr_kadm5_principal_ent_rec does not validate the relationship between n_key_data and the key_data array count.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>tar</strong> <code>1.34+dfsg-1ubuntu0.1.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/tar@1.34+dfsg-1ubuntu0.1.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-39804?s=ubuntu&n=tar&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.34%2Bdfsg-1ubuntu0.1.22.04.2"><img alt="medium : CVE--2023--39804" src="https://img.shields.io/badge/CVE--2023--39804-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.34+dfsg-1ubuntu0.1.22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>1.34+dfsg-1ubuntu0.1.22.04.2</code></td></tr></table>

<details><summary>Description</summary>
<blockquote>

[A stack overflow vulnerability exists in GNU Tar up to including v1.34. The bug exists in the function xattr_decoder() in xheader.c, where alloca() is used and it may overflow the stack if a sufficiently long xattr key is used. The vulnerability can be triggered when extracting a tar/pax archive that contains such a long xattr key.]

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>curl</strong> <code>7.81.0-1ubuntu1.14</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.14?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-46218?s=ubuntu&n=curl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C7.81.0-1ubuntu1.15"><img alt="medium 6.5: CVE--2023--46218" src="https://img.shields.io/badge/CVE--2023--46218-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.81.0-1ubuntu1.15</code></td></tr>
<tr><td>Fixed version</td><td><code>7.81.0-1ubuntu1.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

This flaw allows a malicious HTTP server to set "super cookies" in curl that are then passed back to more origins than what is otherwise allowed or possible. This allows a site to set cookies that then would get sent to different and unrelated sites and domains. It could do this by exploiting a mixed case flaw in curl's function that verifies a given cookie domain against the Public Suffix List (PSL). For example a cookie could be set with `domain=co.UK` when the URL used a lower case hostname `curl.co.uk`, even though `co.uk` is listed as a PSL domain.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pixman</strong> <code>0.40.0-1ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pixman@0.40.0-1ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-37769?s=ubuntu&n=pixman&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 6.5: CVE--2023--37769" src="https://img.shields.io/badge/CVE--2023--37769-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

stress-test master commit e4c878 was discovered to contain a FPE vulnerability via the component combine_inner at /pixman-combine-float.c.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gdk-pixbuf</strong> <code>2.42.8+dfsg-1ubuntu0.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gdk-pixbuf@2.42.8+dfsg-1ubuntu0.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-48622?s=ubuntu&n=gdk-pixbuf&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium : CVE--2022--48622" src="https://img.shields.io/badge/CVE--2022--48622-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr></table>

<details><summary>Description</summary>
<blockquote>

In GNOME GdkPixbuf (aka gdk-pixbuf) through 2.42.10, the ANI (Windows animated cursor) decoder encounters heap memory corruption (in ani_load_chunk in io-ani.c) when parsing chunks in a crafted .ani file. A crafted file could allow an attacker to overwrite heap metadata, leading to a denial of service or code execution attack. This occurs in gdk_pixbuf_set_option() in gdk-pixbuf.c.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>apparmor</strong> <code>3.0.4-2ubuntu2.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/apparmor@3.0.4-2ubuntu2.2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-1585?s=ubuntu&n=apparmor&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="medium 9.8: CVE--2016--1585" src="https://img.shields.io/badge/CVE--2016--1585-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In all versions of AppArmor mount rules are accidentally widened when compiled.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>cryptography</strong> <code>41.0.4</code> (pypi)</summary>

<small><code>pkg:pypi/cryptography@41.0.4</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-49083?s=github&n=cryptography&t=pypi&vr=%3E%3D3.1%2C%3C41.0.6"><img alt="medium 5.9: CVE--2023--49083" src="https://img.shields.io/badge/CVE--2023--49083-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>NULL Pointer Dereference</i>

<table>
<tr><td>Affected range</td><td><code>>=3.1<br/><41.0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>41.0.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

Calling `load_pem_pkcs7_certificates` or `load_der_pkcs7_certificates` could lead to a NULL-pointer dereference and segfault.

### PoC
Here is a Python code that triggers the issue:
```python
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates, load_pem_pkcs7_certificates

pem_p7 = b"""
-----BEGIN PKCS7-----
MAsGCSqGSIb3DQEHAg==
-----END PKCS7-----
"""

der_p7 = b"\x30\x0B\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"

load_pem_pkcs7_certificates(pem_p7)
load_der_pkcs7_certificates(der_p7)
```

### Impact
Exploitation of this vulnerability poses a serious risk of Denial of Service (DoS) for any application attempting to deserialize a PKCS7 blob/certificate. The consequences extend to potential disruptions in system availability and stability.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>jupyter-server</strong> <code>2.8.0</code> (pypi)</summary>

<small><code>pkg:pypi/jupyter-server@2.8.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-49080?s=github&n=jupyter-server&t=pypi&vr=%3C2.11.2"><img alt="medium 4.3: CVE--2023--49080" src="https://img.shields.io/badge/CVE--2023--49080-lightgrey?label=medium%204.3&labelColor=fbb552"/></a> <i>Generation of Error Message Containing Sensitive Information</i>

<table>
<tr><td>Affected range</td><td><code><2.11.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.11.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

Unhandled errors in API requests include traceback information, which can include path information. There is no known mechanism by which to trigger these errors without authentication, so the paths revealed are not considered particularly sensitive, given that the requesting user has arbitrary execution permissions already in the same environment.

### Patches

jupyter-server PATCHED_VERSION no longer includes traceback information in JSON error responses. For compatibility, the traceback field is present, but always empty.

### Workarounds

None

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>nghttp2</strong> <code>1.43.0-1build3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/nghttp2@1.43.0-1build3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-44487?s=ubuntu&n=nghttp2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.43.0-1ubuntu0.1"><img alt="medium 7.5: CVE--2023--44487" src="https://img.shields.io/badge/CVE--2023--44487-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.43.0-1ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.43.0-1ubuntu0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>ghostscript</strong> <code>9.55.0~dfsg1-0ubuntu5.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/ghostscript@9.55.0~dfsg1-0ubuntu5.5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-46751?s=ubuntu&n=ghostscript&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C9.55.0%7Edfsg1-0ubuntu5.6"><img alt="medium 7.5: CVE--2023--46751" src="https://img.shields.io/badge/CVE--2023--46751-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><9.55.0~dfsg1-0ubuntu5.6</code></td></tr>
<tr><td>Fixed version</td><td><code>9.55.0~dfsg1-0ubuntu5.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the function gdev_prn_open_printer_seekable() in Artifex Ghostscript through 10.02.0 allows remote attackers to crash the application via a dangling pointer.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>openjpeg2</strong> <code>2.4.0-6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openjpeg2@2.4.0-6?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-3575?s=ubuntu&n=openjpeg2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2021--3575" src="https://img.shields.io/badge/CVE--2021--3575-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-based buffer overflow was found in openjpeg in color.c:379:42 in sycc420_to_rgb when decompressing a crafted .j2k file. An attacker could use this to execute arbitrary code with the permissions of the application compiled against openjpeg.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-6988?s=ubuntu&n=openjpeg2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2019--6988" src="https://img.shields.io/badge/CVE--2019--6988-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in OpenJPEG 2.3.0. It allows remote attackers to cause a denial of service (attempted excessive memory allocation) in opj_calloc in openjp2/opj_malloc.c, when called from opj_tcd_init_tile in openjp2/tcd.c, as demonstrated by the 64-bit opj_decompress.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-29338?s=ubuntu&n=openjpeg2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2021--29338" src="https://img.shields.io/badge/CVE--2021--29338-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Integer Overflow in OpenJPEG v2.4.0 allows remote attackers to crash the application, causing a Denial of Service (DoS). This occurs when the attacker uses the command line option "-ImgDir" on a directory that contains 1048576 files.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>cairo</strong> <code>1.16.0-5ubuntu2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/cairo@1.16.0-5ubuntu2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2019-6461?s=ubuntu&n=cairo&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2019--6461" src="https://img.shields.io/badge/CVE--2019--6461-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in cairo 1.16.0. There is an assertion problem in the function _cairo_arc_in_direction in the file cairo-arc.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-18064?s=ubuntu&n=cairo&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2018--18064" src="https://img.shields.io/badge/CVE--2018--18064-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

cairo through 1.15.14 has an out-of-bounds stack-memory write during processing of a crafted document by WebKitGTK+ because of the interaction between cairo-rectangular-scan-converter.c (the generate and render_rows functions) and cairo-image-compositor.c (the _cairo_image_spans_and_zero function).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-7475?s=ubuntu&n=cairo&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2017--7475" src="https://img.shields.io/badge/CVE--2017--7475-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Cairo version 1.15.4 is vulnerable to a NULL pointer dereference related to the FT_Load_Glyph and FT_Render_Glyph resulting in an application crash.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>gcc-11</strong> <code>11.4.0-1ubuntu1~22.04</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gcc-11@11.4.0-1ubuntu1~22.04?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-3826?s=ubuntu&n=gcc-11&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2021--3826" src="https://img.shields.io/badge/CVE--2021--3826-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap/stack buffer overflow in the dlang_lname function in d-demangle.c in libiberty allows attackers to potentially cause a denial of service (segmentation fault and crash) via a crafted mangled symbol.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-27943?s=ubuntu&n=gcc-11&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--27943" src="https://img.shields.io/badge/CVE--2022--27943-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-46195?s=ubuntu&n=gcc-11&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2021--46195" src="https://img.shields.io/badge/CVE--2021--46195-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GCC v12.0 was discovered to contain an uncontrolled recursion via the component libiberty/rust-demangle.c. This vulnerability allows attackers to cause a Denial of Service (DoS) by consuming excessive CPU and memory resources.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>patch</strong> <code>2.7.6-7build2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/patch@2.7.6-7build2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-6952?s=ubuntu&n=patch&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2018--6952" src="https://img.shields.io/badge/CVE--2018--6952-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A double free exists in the another_hunk function in pch.c in GNU patch through 2.7.6.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-45261?s=ubuntu&n=patch&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2021--45261" src="https://img.shields.io/badge/CVE--2021--45261-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An Invalid Pointer vulnerability exists in GNU patch 2.7 via the another_hunk function, which causes a Denial of Service.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>zziplib</strong> <code>0.13.72+dfsg.1-1.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/zziplib@0.13.72+dfsg.1-1.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-17828?s=ubuntu&n=zziplib&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2018--17828" src="https://img.shields.io/badge/CVE--2018--17828-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Directory traversal vulnerability in ZZIPlib 0.13.69 allows attackers to overwrite arbitrary files via a .. (dot dot) in a zip file, because of the function unzzip_cat in the bins/unzzipcat-mem.c file.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>git</strong> <code>1:2.34.1-1ubuntu1.10</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/git@1:2.34.1-1ubuntu1.10?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-1000021?s=ubuntu&n=git&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 8.8: CVE--2018--1000021" src="https://img.shields.io/badge/CVE--2018--1000021-lightgrey?label=low%208.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GIT version 2.15.1 and earlier contains a Input Validation Error vulnerability in Client that can result in problems including messing up terminal configuration to RCE. This attack appear to be exploitable via The user must interact with a malicious git server, (or have their traffic modified in a MITM attack).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>pcre3</strong> <code>2:8.39-13ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pcre3@2:8.39-13ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-11164?s=ubuntu&n=pcre3&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2017--11164" src="https://img.shields.io/badge/CVE--2017--11164-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.2.27-3ubuntu2.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnupg2@2.2.27-3ubuntu2.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-3219?s=ubuntu&n=gnupg2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 3.3: CVE--2022--3219" src="https://img.shields.io/badge/CVE--2022--3219-lightgrey?label=low%203.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libpng1.6</strong> <code>1.6.37-3build5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libpng1.6@1.6.37-3build5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-3857?s=ubuntu&n=libpng1.6&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--3857" src="https://img.shields.io/badge/CVE--2022--3857-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libpng 1.6.38. A crafted PNG image can lead to a segmentation fault and denial of service in png_setup_paeth_row() function.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>shadow</strong> <code>1:4.8.1-2ubuntu2.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/shadow@1:4.8.1-2ubuntu2.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-29383?s=ubuntu&n=shadow&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 3.3: CVE--2023--29383" src="https://img.shields.io/badge/CVE--2023--29383-lightgrey?label=low%203.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that "cat /etc/passwd" shows a rogue user account.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>jbig2dec</strong> <code>0.19-3build2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/jbig2dec@0.19-3build2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-46361?s=ubuntu&n=jbig2dec&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2023--46361" src="https://img.shields.io/badge/CVE--2023--46361-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Artifex Software jbig2dec v0.20 was discovered to contain a SEGV vulnerability via jbig2_error at /jbig2dec/jbig2.c.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>bash</strong> <code>5.1-6ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/bash@5.1-6ubuntu1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-3715?s=ubuntu&n=bash&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2022--3715" src="https://img.shields.io/badge/CVE--2022--3715-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libgd2</strong> <code>2.3.0-2ubuntu2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libgd2@2.3.0-2ubuntu2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-40812?s=ubuntu&n=libgd2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2021--40812" src="https://img.shields.io/badge/CVE--2021--40812-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The GD Graphics Library (aka LibGD) through 2.3.2 has an out-of-bounds read because of the lack of certain gdGetBuf and gdPutBuf return value checks.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>xdg-utils</strong> <code>1.1.3-4.1ubuntu3~22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/xdg-utils@1.1.3-4.1ubuntu3~22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-4055?s=ubuntu&n=xdg-utils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.4: CVE--2022--4055" src="https://img.shields.io/badge/CVE--2022--4055-lightgrey?label=low%207.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When xdg-mail is configured to use thunderbird for mailto URLs, improper parsing of the URL can lead to additional headers being passed to thunderbird that should not be included per RFC 2368. An attacker can use this method to create a mailto URL that looks safe to users, but will actually attach files when clicked.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>dbus</strong> <code>1.12.20-2ubuntu4.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/dbus@1.12.20-2ubuntu4.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-34969?s=ubuntu&n=dbus&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2023--34969" src="https://img.shields.io/badge/CVE--2023--34969-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

D-Bus before 1.15.6 sometimes allows unprivileged users to crash dbus-daemon. If a privileged user with control over the dbus-daemon is using the org.freedesktop.DBus.Monitoring interface to monitor message bus traffic, then an unprivileged user with the ability to connect to the same dbus-daemon can cause a dbus-daemon crash under some circumstances via an unreplyable message. When done on the well-known system bus, this is a denial-of-service vulnerability. The fixed versions are 1.12.28, 1.14.8, and 1.15.6.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>procps</strong> <code>2:3.3.17-6ubuntu2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/procps@2:3.3.17-6ubuntu2?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-4016?s=ubuntu&n=procps&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2%3A3.3.17-6ubuntu2.1"><img alt="low 3.3: CVE--2023--4016" src="https://img.shields.io/badge/CVE--2023--4016-lightgrey?label=low%203.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2:3.3.17-6ubuntu2.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2:3.3.17-6ubuntu2.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Under some circumstances, this weakness allows a user who has access to run the “ps” utility on a machine, the ability to write almost unlimited amounts of unfiltered data into the process heap.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>openldap</strong> <code>2.5.16+dfsg-0ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openldap@2.5.16+dfsg-0ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-2953?s=ubuntu&n=openldap&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.5.16%2Bdfsg-0ubuntu0.22.04.2"><img alt="low 7.5: CVE--2023--2953" src="https://img.shields.io/badge/CVE--2023--2953-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.5.16+dfsg-0ubuntu0.22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.16+dfsg-0ubuntu0.22.04.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in openldap. This security flaw causes a null pointer dereference in ber_memalloc_x() function.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>harfbuzz</strong> <code>2.7.4-1ubuntu3.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/harfbuzz@2.7.4-1ubuntu3.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-25193?s=ubuntu&n=harfbuzz&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2023--25193" src="https://img.shields.io/badge/CVE--2023--25193-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

hb-ot-layout-gsubgpos.hh in HarfBuzz through 6.0.0 allows attackers to trigger O(n^2) growth via consecutive marks during the process of looking back for base glyphs when attaching marks.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libzstd</strong> <code>1.4.8+dfsg-3build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libzstd@1.4.8+dfsg-3build1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-4899?s=ubuntu&n=libzstd&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2022--4899" src="https://img.shields.io/badge/CVE--2022--4899-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in zstd v1.4.10, where an attacker can supply empty string as an argument to the command line tool to cause buffer overrun.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>texlive-base</strong> <code>2021.20220204-1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/texlive-base@2021.20220204-1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-17513?s=ubuntu&n=texlive-base&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 8.8: CVE--2017--17513" src="https://img.shields.io/badge/CVE--2017--17513-lightgrey?label=low%208.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

TeX Live through 20170524 does not validate strings before launching the program specified by the BROWSER environment variable, which might allow remote attackers to conduct argument-injection attacks via a crafted URL, related to linked_scripts/context/stubs/unix/mtxrun, texmf-dist/scripts/context/stubs/mswin/mtxrun.lua, and texmf-dist/tex/luatex/lualibs/lualibs-os.lua.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gcc-12</strong> <code>12.3.0-1ubuntu1~22.04</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gcc-12@12.3.0-1ubuntu1~22.04?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-27943?s=ubuntu&n=gcc-12&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2022--27943" src="https://img.shields.io/badge/CVE--2022--27943-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>249.11-0ubuntu3.10</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/systemd@249.11-0ubuntu3.10?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-7008?s=ubuntu&n=systemd&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 5.9: CVE--2023--7008" src="https://img.shields.io/badge/CVE--2023--7008-lightgrey?label=low%205.9&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature, allowing man-in-the-middles (or the upstream DNS resolver) to manipulate records.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>coreutils</strong> <code>8.32-4.1ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/coreutils@8.32-4.1ubuntu1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-2781?s=ubuntu&n=coreutils&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2016--2781" src="https://img.shields.io/badge/CVE--2016--2781-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libsdl2</strong> <code>2.0.20+dfsg-2ubuntu1.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libsdl2@2.0.20+dfsg-2ubuntu1.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-4743?s=ubuntu&n=libsdl2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2022--4743" src="https://img.shields.io/badge/CVE--2022--4743-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A potential memory leak issue was discovered in SDL2 in GLES_CreateTexture() function in SDL_render_gles.c. The vulnerability allows an attacker to cause a denial of service attack. The vulnerability affects SDL2 v2.0.4 and above. SDL-1.x are not affected.

</blockquote>
</details>
</details></td></tr>
</table>


What's Next?
  View base image update recommendations → docker scout recommendations mapequation/jupyter:latest

