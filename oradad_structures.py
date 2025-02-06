from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from enum import IntEnum

class SectionType(IntEnum):
    HEADER = 0x0001
    DOMAIN_INFO = 0x0002
    USER_INFO = 0x0003
    GROUP_INFO = 0x0004
    COMPUTER_INFO = 0x0005
    GPO_INFO = 0x0006
    TRUST_INFO = 0x0007

class UserFlags(IntEnum):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000

class TrustDirection(IntEnum):
    DISABLED = 0
    INBOUND = 1
    OUTBOUND = 2
    BIDIRECTIONAL = 3

class TrustType(IntEnum):
    WINDOWS_NT4 = 1
    WINDOWS_AD = 2
    MIT = 3

@dataclass
class OradadHeader:
    magic: bytes  # Should be b'ORADAD\x00\x00'
    version: int
    scan_date: datetime
    domain_count: int

@dataclass
class DomainInfo:
    name: str
    sid: str
    functional_level: int
    forest_name: str
    dc_count: int

@dataclass
class UserInfo:
    sam_account_name: str
    display_name: str
    user_principal_name: str
    enabled: bool
    password_never_expires: bool
    password_not_required: bool
    last_logon: datetime
    creation_date: datetime
    user_flags: int
    sid: str
    primary_group_id: int
    home_directory: Optional[str]
    profile_path: Optional[str]
    admin_comment: Optional[str]
    groups: List[str]

@dataclass
class GroupInfo:
    name: str
    sid: str
    member_count: int
    group_type: int
    members: List[str]
    description: Optional[str]
    admin_comment: Optional[str]
    group_category: str  # Security or Distribution
    group_scope: str    # Domain Local, Global, or Universal

@dataclass
class ComputerInfo:
    name: str
    os_version: str
    last_logon: datetime
    enabled: bool
    dns_hostname: str
    service_principal_names: List[str]
    operating_system: str
    operating_system_version: str
    operating_system_service_pack: str
    when_created: datetime
    when_changed: datetime
    last_logon_timestamp: datetime
    ms_ds_supported_encryption_types: Optional[int]

@dataclass
class TrustInfo:
    trusted_domain: str
    trust_type: TrustType
    trust_direction: TrustDirection
    trust_attributes: int
    creation_date: datetime
    sid: Optional[str]

@dataclass
class GPOInfo:
    name: str
    display_name: str
    gpo_status: int  # Enabled/Disabled/All settings disabled
    creation_time: datetime
    modification_time: datetime
    version: int
    computer_extensions: List[str]
    user_extensions: List[str]
    applied_to: List[str]  # List of OUs/groups where this GPO is linked

@dataclass
class OUInfo:
    name: str
    distinguished_name: str
    description: Optional[str]
    when_created: datetime
    when_changed: datetime
    gpo_links: List[str]
    child_ous: List[str]
    managed_objects: Dict[str, List[str]]  # Type -> [object_names]
    protected_from_deletion: bool

@dataclass
class ServiceAccountInfo:
    account_name: str
    display_name: str
    service_principal_names: List[str]
    account_type: str  # User/Computer
    delegation_type: str  # None/Unconstrained/Constrained
    constrained_to: List[str]
    last_password_change: datetime
    password_never_expires: bool
    enabled: bool

@dataclass
class PasswordPolicy:
    min_password_length: int
    password_history_length: int
    password_complexity_enabled: bool
    reversible_encryption_enabled: bool
    lockout_threshold: int
    lockout_duration: timedelta
    lockout_observation_window: timedelta
    max_password_age: timedelta
    min_password_age: timedelta

@dataclass
class SecurityDescriptor:
    owner_sid: str
    group_sid: str
    dacl: List[AceInfo]
    sacl: Optional[List[AceInfo]]
    
@dataclass
class AceInfo:
    ace_type: str  # ACCESS_ALLOWED, ACCESS_DENIED, SYSTEM_AUDIT
    ace_flags: int
    rights: int
    object_type: Optional[str]
    inherited_object_type: Optional[str]
    trustee: str  # SID of the trustee 