---
layout: post
title: Do you really know Access Control Model?
date: 2025-07-1
categories: [Windows]
tags: [Windows]
---

**重新以一个研究人员的思维看待访问控制模型**。

研究动机是  当我在研究AppContainer时，发现了james 一篇漏洞关于 [Windows Sandbox Anonymous Kernel Object Unrestricted DACL](https://issues.chromium.org/issues/40078787)  问题。 这个漏洞也成为了 james 入职 Google Project Zero的标志性漏洞（fixed it by myself **:)**) 

这里不过多涉及该漏洞，漏洞的本质是**chrome使用多进程架构sandbox隔离以降低安全风险。准确说主进程与render process通过Section共享内存通信，但是Anonymous Section  安全权限是未知的，意味着在DuplicateHandle中 render process可以将只读的section handle设置为 rw，有机会逃逸出 render process.**  感兴趣的可以看看 off-by-one 2025 james受邀的演讲  [here](https://www.youtube.com/watch?v=Xr_IYWd71JM&list=PLiIDIO1Gp6V8_CMvMVabhyeABTW1yZrRZ&index=1&pp=iAQB)



仅就笔者目前的理解 

1. Windows访问安全模型以用户和组为核心，Mandatory Integrity Control (MIC) 对其进行补充 这种宏观的角色分组以SID为底层实现依据
2. 从细节上看以DACL/ACE 细粒度控制待访问的资源，以Privilege对其再一次进行补充，最后MS意识到这种分组方式的访问控制模型从设计上就鼓励了提权漏洞（这意味着跨越分组即可拥有无上的权限，仅从资源访问的角度而言，不需要这样做）win8开始MS 使用Capability能力进行权限控制。
3. Capability 的实现也是基于SID，只是Capability 是对传统访问控制模型的再一次补充。只是这种新的权限控制机制从设计上有何缺陷还有待进一步研究

# DACL

[SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control)  安全描述符控制符是 bitmap

每一个 security descriptor都有一个Control 成员，作为 `SECURITY_DESCRIPTOR_CONTROL`bits 

```
automatic inheritance algorithm
```

Windows 使用下列算法为  securable object 生成DACL

1. 对象的DACL 从对象的创建者的 security descriptor而来， 当Control bit没有设置 `SE_DACL_PROTECTED`时系统会 merge 任何继承的ACEs 
2. creator没有指定 SD，系统从继承的ACE 生成对象的DACL
3. 如果没有指定SD，也没有继承的ACE，对象的DACL 使用 creator的私有或模拟token default DACL
4. 上面都没有时，系统创建对象 `with no DACL` 允许everyone 完全访问。

值得提的是 对于AD域对象的SD MS有特别的算法  [SD On Active Directory Object](https://learn.microsoft.com/en-us/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects)

那么对于内核对象来讲，DACL访问控制的本质其实就是一堆 ACE。我们清楚了DACL的算法之后，我们可以看下ACE是如何允许或拒绝操作发生的。MS 定义了 [ACE](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace) 的类型

ACL 是ACE的逻辑容器，ACE 结构包含 ACE_HEADER，这里以`ACCESS_ALLOWED_ACE`允许访问的ACE为例

```c
typedef struct _ACE_HEADER {
  BYTE AceType;
  BYTE AceFlags;
  WORD AceSize;
} ACE_HEADER;

typedef struct _ACCESS_ALLOWED_ACE {
  ACE_HEADER  Header;
  ACCESS_MASK Mask;
  DWORD       SidStart;
} ACCESS_ALLOWED_ACE;
```

每种ACE 成员是一致的， SidStart 成员是  SID的第一个Dword值（有关SID的格式 参考[security identifier](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)）

SID其余的数据在 SidStart 成员连续的内存中。通过这种安全标识（内核对象的安全描述）当访问资源时，进行DACL检查，首先得到了SID信息。其次，Mask 掩码包含了读写，可执行，增加，删除，修改等掩码信息来具体决定可以执行哪些操作。比如对文件只读，执行和不可写操作等。



## Mandatory Integrity Control

强制性完整性控制的本质

```
Mandatory Integrity Control (MIC) provides a mechanism for controlling access to securable objects. This mechanism is in addition to discretionary access control and evaluates access before access checks aginst an object's DACL are evaluated.
```

那么这里笔者有一个问题： 强制性完整性控制既然先于 DACL的检查，那么MIC和用户有何关系或区别呢？Windows 分为Guest, 普通用户，管理员和System用户，简单的说普通用户MIC 能否是High或者System呢？这个我们稍后测试下。

MIC 使用 `integrity levels`和 `mandatory policy`评估访问。安全主体和对象评估 `integrity level`决定保护资源还是允许访问。

Windows 关于MIC机制有几个原则：

1. **默认情况下low integrity的主体无法写入 medium integrity的对象，即使对象的DACL允许写入操作**。
2. standard user 使用medium integrity, 提权用户 high integrity
3. 创建的进程或对象继承完整性级别或者更低完整性
4. 对3.1补充  理论上lower integrity进程无法创建 medium/high/system integrity的进程。但是当有漏洞发生时 integrity level可以通过写入内核内存达到这种“异常”行为。并且elastic 有对这种LPE漏洞利用的检测  [elastic  LPE 0Day detection](https://www.elastic.co/fr/security-labs/itw-windows-lpe-0days-insights-and-detection-strategies)
5. 缺失 integrity label的对象默认由操作系统赋予 medium level, 阻止 low-integrity code更改 unlabeled objects
6. Windows确保运行在 low integrity level的进程无法访问 app container进程



所谓的原则我们可以这样说：恒常运行中事物遵循的既定规则，然"反者道之动" 我们不能忽视事物向着相反方向运动的倾向。

基于此我们谈下 `Integrity labels`

关于第一个原则  默认情况下低完整性无法访问高完整性

integrity labels 由SID进行表示， 对于securable object Integrity SID 存储在 SCAL中。SACL 包含 `SYSTEM_MANDATORY_LABEL_ACE`

```c
typedef struct _SYSTEM_MANDATORY_LABEL_ACE {
    ACE_HEADER  Header;
    ACCESS_MASK Mask;
    DWORD       SidStart;
} SYSTEM_MANDATORY_LABEL_ACE, *PSYSTEM_MANDATORY_LABEL_ACE;
```

这条ACE  Mask表示了在DACL 访问之前 MIC校验的实际策略。 Mask可以是以下几个标识 `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` 低完整性级别的主体无法写入对象  `SYSTEM_MANDATORY_LABEL_NO_READ_UP` 低完整性级别的主体无法读对象  `SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP` 低完整性级别的主体无法对对象进行执行操作。现在，我们转换下思维。上面的策略可以这样说：对象自身由操作系统提供了这样一种能力和天赋--允许进行自我保护。但是这种安全保护是有一定限制的，只能保护不被"弱小欺负"，至于从更高维度下对其进行攻击，这种能力也就失去了应有的效果。同时，当策略没有应用 `SYSTEM_MANDATORY_LABEL_NO_XXX`时默认就打破了第一条原则--低完整性级别的主体也能搞访问高完整性对象。

默认情况下Sid没有指定时，系统使用`SepDefaultMandatorySid` 在系统引导阶段 `SepInitializationPhase0`使用 `SeMediumMandatorySid`作为默认完整性SID

```c
bool SepInitializationPhase0()
{
    _KPROCESS *Process; // rbx
    __int64 SystemToken; // rax
    ...
    SystemToken = SeMakeSystemToken();
    SepDefaultMandatorySid = *(PSID *)&SeMediumMandatorySid;
}
```



### Windbg go out

现在我们对用户和 Integrity level进行实验，两者是否有必然联系

实验环境:  win11 24h2  26100  4351

这里参考 @Yarden shafir  [_TOKEN->IntegrityLevelIndex](https://windows-internals.com/exploiting-a-simple-vulnerability-part-2-what-if-we-made-exploitation-harder/)  

简单来说 内核结构_TOKEN 中 IntegrityLevelIndex 存储了完整性结构索引

这个索引在 _TOKEN->UserAndGroups 数组中，数组成员类型是 `_SID_AND_ATTRIBUTES`

`SepLocateTokenIntegrity`根据TOKEN对象获取SID

```c
_SID_AND_ATTRIBUTES *__fastcall SepLocateTokenIntegrity(_TOKEN *_TOKEN)
{
  __int64 IntegrityLevelIndex; // rax

  IntegrityLevelIndex = _TOKEN->IntegrityLevelIndex;
  if ( (_DWORD)IntegrityLevelIndex == -1 )
    return 0;
  else
    return &_TOKEN->UserAndGroups[IntegrityLevelIndex];
}
```



```c
// 1. 创建cmd.exe进程  medium integrity level
dx -s @$cursession.Processes.Where(x => x.Name == "cmd.exe")[6800].SwitchTo()
// 2. 获取_TOKEN 内核对象地址  需要减去 RefCount
dx @$curprocess.KernelObject.Token.Object
// 3. 查看token 字段信息
dt nt!_TOKEN [address]
// 在笔者的实验环境下是 IntegrityLevelIndex是 0xf

// 4. 使用 @yarden的表达式快速获取结果
dx @$sidAndAttr = *((nt!_SID_AND_ATTRIBUTES(*)[0x10])((nt!_TOKEN*)(@$curprocess.KernelObject.Token.Object & ~0xf))->UserAndGroups)
dx -g @$sidAndAttr.Select(s => new {Attributes = s->Attributes, Sid = Debugger.Utility.Control.ExecuteCommand("!sid " + ((__int64)(s->Sid)).ToDisplayString("x"))[0].Remove(0, 8)})

// 0xf 索引 SID是  S-1-16-8192
// 结果
=         = Attributes    = Sid                                              =
==============================================================================
= [0]     - 0x0           - S-1-5-21-2666309814-3047373840-419697302-1001    =
= [1]     - 0x7           - S-1-5-21-2666309814-3047373840-419697302-513     =
= [2]     - 0x7           - S-1-1-0                                          =
= [3]     - 0x10          - S-1-5-114                                        =
= [4]     - 0x10          - S-1-5-32-544                                     =
= [5]     - 0x7           - S-1-5-32-559                                     =
= [6]     - 0x7           - S-1-5-32-545                                     =
= [7]     - 0x7           - S-1-5-4                                          =
= [8]     - 0x7           - S-1-2-1                                          =
= [9]     - 0x7           - S-1-5-11                                         =
= [10]    - 0x7           - S-1-5-15                                         =
= [11]    - 0x7           - S-1-5-113                                        =
= [12]    - 0xc0000007    - S-1-5-5-0-1149321                                =
= [13]    - 0x7           - S-1-2-0                                          =
= [14]    - 0x7           - S-1-5-64-10                                      =
= [15]    - 0x60          - S-1-16-8192                                      

// 5. 解析SID   SubAuthority 是0x2000
 dt nt!_SID ffffe685`b0b29c6c
   +0x000 Revision         : 0x1 ''
   +0x001 SubAuthorityCount : 0x1 ''
   +0x002 IdentifierAuthority : _SID_IDENTIFIER_AUTHORITY
   +0x008 SubAuthority     : [1] 0x2000

// 6. 修改为 0x4000   将普通用户的integrity level 修改为 system label
ed 0xffffe685b0b29c74 4000

// 7. 实验结果

whoami /all

USER INFORMATION
----------------

User Name             SID
===================== =============================================
desktop-2b6lie7\bopin S-1-5-21-2666309814-3047373840-419697302-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
...                          
Mandatory Label\System Mandatory Level                        Label            S-1-16-16384


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

观察到的现象： system label 完整性可以访问低完整性的资源，和当前用户是否是管理员无关。

### Integrity 

强制完整性检查算法 [MandatoryIntegrityCheck Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/ae69a089-473d-4c23-bf3d-7a12a9d11123)

根据我们Windbg调试结果，我们可以确定Integrity level 和用户本质上是没有关系的，只是操作系统为了方便权限管理默认Integrity 是medium, 管理员是high。Integrity 本质上来说就是SACL中新增的一条ACE。

现在我们可以对Integrity进行下结论了：依托于SID机制，Integrity 借宿于SACL中对资源的访问控制进行先于DACL的检查，不仅仅是对DACL的补充，更是一种访问控制模型的优化。



## Privilege

关于特权的本质 MS上阐述的非常清楚了

```
A privilege is used to control access to an object or service more strictly than is typical with discretionary access control
```

特权作为DACL 精细度的补充，并且MS并没有对privilege 与用户组进行渊源往来，即任何用户理论上都可以拥有任何特权，这部分没有任何代码校验和约束。参考  [we should know what are privileges essentially on ired](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation#adding-more-privileges)

@yarden 通过increment 1 完成提权  [Get SeDebugPrivilege with TOKEN.RestrictedToken ](https://windows-internals.com/exploiting-a-simple-vulnerability-part-2-what-if-we-made-exploitation-harder/)



笔者相信，仅就上面的概述不足以支持我们对Privielge的理解。虽然我们清楚特权是不同于DACL的，是对Windows操作系统访问控制模型的补充，这里我们需要弄清楚一个概念。

所谓ACM 访问控制模型不单单是安全主体与访问资源之间的访问控制，还有一些操作或行为需要对其进行约束，但是安全主体访问的不仅仅是内核对象。常规的访问资源，Windows 抽象出内核对象这个概念。对于内核对象文件，进程，线程，注册表Key, Section等可以采用DACL方式进行访问控制，对于非内核对象-另一种抽象的资源进行操作时应该如何处理呢？比如系统关机时，加载驱动时，查询或更改某些信息时。当然使用逻辑我们也可以抽象出   主体-行为-行为对象，但是我们发现操作系统和自然界一样是非常复杂的，一种访问控制模型不可能完美应用于所有规则。基于这种原因，特权对于非内核对象或者`Securable Object`进行访问控制约束。

为了具象化这个观点，我们通过逆向内核有关Privilege的操作来进行论证。

内核调用`SeSinglePrivilegeCheck`进行特权检查的例程有很多，以下并不全面

```c
NtSetInformationFile
IopLoadDriverImage
PsQueryCpuQuotaInformation
NtShutdownSystem
ExPoolQueryLimits
ExPoolSetLimit
NtSetInformationSymbolicLink
NtSetInformationJobObject
NtSetSystemTime
NtEnumerateDriverEntries
NtEnumerateSystemEnvironmentValues
PsOpenThread
NtSetInformationProcess
NtSetSystemInformation
NtManageHotPatch
// 
NtCompressKey
NtCreateEvent
NtCreateSemaphore
NtCreateWnfStateName
NtCreateUserProcess
NtCreateTokenEx
NtCreateMutant
NtCreateWaitCompletionPacket
```

其中我们能够看到创建内核对象时，也会基于Privilege特权概念进行某些检查

`NtCreateUserProcess` `SeLockMemoryPrivilege`检查锁定内存页特权

`NtCreateTokenEx` `SeCreateTokenPrivilege` 创建Primary token特权

重新来看，我们可以得到这样一个猜想。从设计上，Privilege的确是作为DACL的补充在关键行为(API调用)发生前进行检查。从资源角度来看，Privilege 更多的是对非内核对象--这一行为的访问控制。它可能更像对某一操作而非某一具体对象资源进行约束，从开发和发展的角度我更倾向于后者这个观点。

## Capability

前面我们已经探讨过，Windows权限校验的底层实现是SID。 Capability 本身也是基于SID设计的一种权限类型。Capability 实现是Windows 对于appcontain  sandbox的权限约束，旨在提升sandbox环境下权限的访问。

这里不涉及Appcontainer的东西。

内核中有一些 Capability相关线索，笔者这里获取了Lpac相关 capability sid  [SeLpacCapabilitySid](https://github.com/bopin2020/WindowsCamp/blob/main/Windows认证模型/AppContainer/SeLpacCapabilitySid.md)

```c
BOOLEAN __fastcall SepIsLpacCapabilitySid(PSID Sid1)
{
  PSID **SeLpacCapabilitySids; // rdi
  unsigned int n0x11; // ebx
  BOOLEAN result; // al

  SeLpacCapabilitySids = (PSID **)SeLpacCapabilitySids;
  n0x11 = 0;
  while ( 1 )
  {
    result = RtlEqualSid(Sid1, **SeLpacCapabilitySids);
    if ( result )
      break;
    ++n0x11;
    ++SeLpacCapabilitySids;
    if ( n0x11 >= 0x11 )
      return result;
  }
  return 1;
}
```

内核定义变量 `SeLpacCapabilitySids` 作为链表头 长度为0x11,   `SepIsLpacCapabilitySid`传入 SID参数然后从链表中迭代 `RtlEqualSid`判断是否相同

```c
windbg>
r $t0 = nt!SeLpacCapabilitySids
.while (poi(@$t0) !=0) { !sid poi(poi(@$t0)); r $t0 = @$t0 + 8 }
```

这里可以使用 [james forshaw](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) NtCoreLib 工具查看 Lpac Capability SID

```c
pwsh> Get-NtSidName -Sid "S-1-15-3-1024-1742180919-3973133362-3881819074-3076390979-3006877977-1258694795-2087530448-2333862241"

Domain             Name                           Source     NameUse
------             ----                           ------     -------
NAMED CAPABILITIES Lpac Package Manager Operation Capability Group
```



传统的普通用户，管理员进行权限划分来管理对资源的访问方式，从根本上激励了提权漏洞的攻击，并且这种控制力度过于粗糙。很明显MS已经意识到这个问题了，container  基于 capability 方式对资源控制粒度更为强烈。没有普通用户，管理员之分，基于capability 与访问的资源对应起来，这样从根本上解决了权限问题。

仅就资源而言，可以无视admin,system这种身份的甄别。有一个比较明显的案例是 `TrustedInstaller`特权，它是基于SID `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` 对  `File/Register`进行访问控制。[Windows Resource Protection](https://learn.microsoft.com/en-us/windows/win32/wfp/windows-resource-protection-portal)

# Reference

- https://googleprojectzero.blogspot.com/2014/10/did-man-with-no-name-feel-insecure.html
- https://learn.microsoft.com/en-gb/windows/win32/secauthz/dacl-for-a-new-object?redirectedfrom=MSDN
- https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set
- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation#adding-more-privileges
- https://www.elastic.co/fr/security-labs/itw-windows-lpe-0days-insights-and-detection-strategies
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/ae69a089-473d-4c23-bf3d-7a12a9d11123
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070    Security Descriptor Description Language
- https://windows-internals.com/exploiting-a-simple-vulnerability-part-2-what-if-we-made-exploitation-harder/