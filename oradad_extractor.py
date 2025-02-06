import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, BinaryIO, Union
from datetime import datetime
from .oradad_structures import *
import logging
import gzip

class OradadParsingError(Exception):
    pass

class DomainInfo:
    def __init__(self, name: str):
        self.name = name
        self.users = []
        self.computers = []
        self.groups = []
        self.ous = []
        self.gpos = []
        self.trusts = []
        self.schema = []
        self.password_policies = []
        self.laps_passwords = []

class OradadExtractor:
    def __init__(self, file_path: str, logger: logging.Logger = None):
        self.file_path = file_path
        self.logger = logger or logging.getLogger(__name__)
        self.domains = {}  # Dictionary of domain_name: DomainInfo

    def _open_file(self) -> Union[BinaryIO, gzip.GzipFile]:
        """Open MLA file, handling both compressed and uncompressed formats."""
        if self.file_path.endswith('.gz'):
            self.logger.debug("Opening compressed MLA file")
            return gzip.open(self.file_path, 'rb')
        else:
            self.logger.debug("Opening uncompressed MLA file")
            return open(self.file_path, 'rb')

    def parse_file(self):
        """Parse MLA file content with multi-domain support."""
        self.logger.info(f"Starting to parse file: {self.file_path}")
        
        try:
            with self._open_file() as f:
                tree = ET.parse(f)
                root = tree.getroot()

                # Parse each domain
                for domain_elem in root.findall(".//domain"):
                    domain_name = domain_elem.get('name')
                    if not domain_name:
                        continue
                        
                    self.logger.info(f"Parsing domain: {domain_name}")
                    domain_info = DomainInfo(domain_name)
                    self.domains[domain_name] = domain_info
                    
                    # Parse entries for this domain
                    for entry in domain_elem.findall(".//entry"):
                        try:
                            self._parse_entry(entry, domain_info)
                        except Exception as e:
                            self.logger.error(f"Error parsing entry in domain {domain_name}: {e}")
                            continue

                    self.logger.info(
                        f"Domain {domain_name} stats: "
                        f"{len(domain_info.users)} users, "
                        f"{len(domain_info.computers)} computers, "
                        f"{len(domain_info.groups)} groups, "
                        f"{len(domain_info.ous)} OUs"
                    )

        except Exception as e:
            self.logger.error(f"Error parsing file: {e}")
            raise OradadParsingError(f"Failed to parse MLA file: {str(e)}")

    def _parse_entry(self, entry: ET.Element, domain_info: DomainInfo):
        """Parse an entry and add it to the appropriate domain collection."""
        object_class = entry.find("./objectClass")
        if object_class is None:
            return

        if "user" in object_class.text.lower():
            user = self._parse_user(entry)
            if user:
                domain_info.users.append(user)
        elif "computer" in object_class.text.lower():
            computer = self._parse_computer(entry)
            if computer:
                domain_info.computers.append(computer)
        elif "group" in object_class.text.lower():
            group = self._parse_group(entry)
            if group:
                domain_info.groups.append(group)
        elif "organizationalUnit" in object_class.text.lower():
            self._parse_ou(entry)
        elif "trustedDomain" in object_class.text.lower():
            self._parse_trust(entry)
        elif "groupPolicyContainer" in object_class.text.lower():
            self._parse_gpo(entry)
        elif "schemaIDGUID" in entry.attrib:
            self._parse_schema(entry)
        elif "msDS-PasswordSettings" in entry.attrib:
            self._parse_password_policies(entry)
        elif "ms-Mcs-AdmPwd" in entry.attrib:
            self._parse_laps(entry)

    def _get_attribute(self, entry: ET.Element, attr_name: str) -> Optional[str]:
        """Helper to get attribute value from XML entry"""
        attr = entry.find(f".//{attr_name}")
        return attr.text if attr is not None else None

    def _parse_user(self, entry: ET.Element):
        """Parse user entry from MLA XML"""
        sam_account_name = self._get_attribute(entry, "sAMAccountName")
        if not sam_account_name:
            return

        user_flags = int(self._get_attribute(entry, "userAccountControl") or "0")
        
        user = UserInfo(
            sam_account_name=sam_account_name,
            display_name=self._get_attribute(entry, "displayName"),
            user_principal_name=self._get_attribute(entry, "userPrincipalName"),
            enabled=not bool(user_flags & UserFlags.ACCOUNTDISABLE),
            password_never_expires=bool(user_flags & UserFlags.DONT_EXPIRE_PASSWORD),
            password_not_required=bool(user_flags & UserFlags.PASSWD_NOTREQD),
            last_logon=self._parse_date(self._get_attribute(entry, "lastLogon")),
            creation_date=self._parse_date(self._get_attribute(entry, "whenCreated")),
            user_flags=user_flags,
            sid=self._get_attribute(entry, "objectSid"),
            primary_group_id=int(self._get_attribute(entry, "primaryGroupID") or "0"),
            home_directory=self._get_attribute(entry, "homeDirectory"),
            profile_path=self._get_attribute(entry, "profilePath"),
            admin_comment=self._get_attribute(entry, "adminComment"),
            groups=self._parse_member_of(entry)
        )
        return user

    def _parse_computer(self, entry: ET.Element):
        """Parse computer entry from MLA XML"""
        name = self._get_attribute(entry, "sAMAccountName")
        if not name:
            return

        user_flags = int(self._get_attribute(entry, "userAccountControl") or "0")
        
        spns = []
        service_principal_names = entry.findall(".//servicePrincipalName")
        if service_principal_names:
            spns = [spn.text for spn in service_principal_names if spn.text]

        computer = ComputerInfo(
            name=name.rstrip('$'),  # Remove trailing $ from computer accounts
            os_version=self._get_attribute(entry, "operatingSystemVersion"),
            last_logon=self._parse_date(self._get_attribute(entry, "lastLogon")),
            enabled=not bool(user_flags & UserFlags.ACCOUNTDISABLE),
            dns_hostname=self._get_attribute(entry, "dNSHostName") or "",
            service_principal_names=spns,
            operating_system=self._get_attribute(entry, "operatingSystem") or "",
            operating_system_version=self._get_attribute(entry, "operatingSystemVersion") or "",
            operating_system_service_pack=self._get_attribute(entry, "operatingSystemServicePack") or "",
            when_created=self._parse_date(self._get_attribute(entry, "whenCreated")),
            when_changed=self._parse_date(self._get_attribute(entry, "whenChanged")),
            last_logon_timestamp=self._parse_date(self._get_attribute(entry, "lastLogonTimestamp")),
            ms_ds_supported_encryption_types=int(self._get_attribute(entry, "msDS-SupportedEncryptionTypes") or "0")
        )
        return computer

    def _parse_group(self, entry: ET.Element):
        """Parse group entry from MLA XML"""
        name = self._get_attribute(entry, "sAMAccountName")
        if not name:
            return

        group_type = int(self._get_attribute(entry, "groupType") or "0")
        
        # Parse members
        members = []
        member_elements = entry.findall(".//member")
        if member_elements:
            members = [m.text for m in member_elements if m.text]

        group = GroupInfo(
            name=name,
            sid=self._get_attribute(entry, "objectSid"),
            member_count=len(members),
            group_type=group_type,
            members=members,
            description=self._get_attribute(entry, "description"),
            admin_comment=self._get_attribute(entry, "adminComment"),
            group_category="Security" if group_type & 0x80000000 else "Distribution",
            group_scope=self._get_group_scope(group_type)
        )
        return group

    def _get_group_scope(self, group_type: int) -> str:
        """Determine group scope from groupType attribute"""
        if group_type & 0x00000004:
            return "Universal"
        elif group_type & 0x00000002:
            return "Global"
        else:
            return "Domain Local"

    def _parse_ou(self, entry: ET.Element):
        """Parse organizational unit entry from MLA XML"""
        name = self._get_attribute(entry, "name")
        if not name:
            return

        # Get GPO links
        gpo_links = []
        gpo_link_elements = entry.findall(".//gPLink")
        if gpo_link_elements:
            for link in gpo_link_elements:
                if link.text:
                    # Extract GUID from GPO link
                    gpo_links.extend([guid.strip('[]') for guid in link.text.split(',')])

        # Get child OUs
        child_ous = []
        children = entry.findall(".//childOU")
        if children:
            child_ous = [child.text for child in children if child.text]

        # Parse managed objects
        managed_objects = {
            "users": [],
            "computers": [],
            "groups": []
        }
        
        for child in entry.findall(".//managedBy"):
            if child.text:
                managed_objects["users"].append(child.text)

        ou = OUInfo(
            name=name,
            distinguished_name=self._get_attribute(entry, "distinguishedName"),
            description=self._get_attribute(entry, "description"),
            when_created=self._parse_date(self._get_attribute(entry, "whenCreated")),
            when_changed=self._parse_date(self._get_attribute(entry, "whenChanged")),
            gpo_links=gpo_links,
            child_ous=child_ous,
            managed_objects=managed_objects,
            protected_from_deletion=bool(self._get_attribute(entry, "protectedFromAccidentalDeletion"))
        )
        return ou

    def _parse_trust(self, entry: ET.Element):
        """Parse trust relationship entry from MLA XML"""
        domain = self._get_attribute(entry, "trustPartner")
        if not domain:
            return

        trust_direction = int(self._get_attribute(entry, "trustDirection") or "0")
        trust_type = int(self._get_attribute(entry, "trustType") or "0")
        trust_attributes = int(self._get_attribute(entry, "trustAttributes") or "0")

        trust = TrustInfo(
            trusted_domain=domain,
            trust_type=TrustType(trust_type) if trust_type in [t.value for t in TrustType] else TrustType.WINDOWS_AD,
            trust_direction=TrustDirection(trust_direction) if trust_direction in [d.value for d in TrustDirection] else TrustDirection.DISABLED,
            trust_attributes=trust_attributes,
            creation_date=self._parse_date(self._get_attribute(entry, "whenCreated")),
            sid=self._get_attribute(entry, "securityIdentifier")
        )
        return trust

    def _parse_gpo(self, entry: ET.Element):
        """Parse Group Policy Object entry from MLA XML"""
        name = self._get_attribute(entry, "displayName")
        if not name:
            return

        # Parse GPO status
        flags = int(self._get_attribute(entry, "flags") or "0")
        
        # Parse extensions
        computer_extensions = []
        user_extensions = []
        
        gpc_extensions = entry.findall(".//gPCMachineExtensionNames")
        if gpc_extensions:
            computer_extensions = [ext.text for ext in gpc_extensions if ext.text]
            
        gpu_extensions = entry.findall(".//gPCUserExtensionNames")
        if gpu_extensions:
            user_extensions = [ext.text for ext in gpu_extensions if ext.text]

        # Get linked OUs
        applied_to = []
        links = entry.findall(".//gPLinkOUs")
        if links:
            applied_to = [link.text for link in links if link.text]

        gpo = GPOInfo(
            name=self._get_attribute(entry, "cn"),
            display_name=name,
            gpo_status=flags,
            creation_time=self._parse_date(self._get_attribute(entry, "whenCreated")),
            modification_time=self._parse_date(self._get_attribute(entry, "whenChanged")),
            version=int(self._get_attribute(entry, "versionNumber") or "0"),
            computer_extensions=computer_extensions,
            user_extensions=user_extensions,
            applied_to=applied_to
        )
        return gpo

    def _parse_date(self, date_str: Optional[str]) -> datetime:
        """Parse AD date format to datetime"""
        if not date_str:
            return datetime.min
        try:
            # Handle AD's date format
            return datetime.strptime(date_str, "%Y%m%d%H%M%S.0Z")
        except ValueError:
            return datetime.min

    def _parse_member_of(self, entry: ET.Element) -> List[str]:
        """Parse memberOf attribute"""
        member_of = entry.findall(".//memberOf")
        return [m.text for m in member_of if m.text]

    def identify_service_accounts(self) -> List[ServiceAccountInfo]:
        """Identify and analyze service accounts from users and computers."""
        service_accounts = []
        
        # Analyze user accounts
        for user in self.all_users:
            if user.service_principal_names:
                delegation_type = "None"
                if user.user_flags & UserFlags.TRUSTED_FOR_DELEGATION:
                    delegation_type = "Unconstrained"
                elif user.user_flags & UserFlags.TRUSTED_TO_AUTH_FOR_DELEGATION:
                    delegation_type = "Constrained"
                
                service_accounts.append(ServiceAccountInfo(
                    account_name=user.sam_account_name,
                    display_name=user.display_name,
                    service_principal_names=user.service_principal_names,
                    account_type="User",
                    delegation_type=delegation_type,
                    constrained_to=[],  # Would need to parse msDS-AllowedToDelegateTo
                    last_password_change=user.password_last_set,
                    password_never_expires=user.password_never_expires,
                    enabled=user.enabled
                ))
        
        # Analyze computer accounts
        for computer in self.all_computers:
            if computer.service_principal_names:
                service_accounts.append(ServiceAccountInfo(
                    account_name=computer.name,
                    display_name=computer.dns_hostname,
                    service_principal_names=computer.service_principal_names,
                    account_type="Computer",
                    delegation_type="None",  # Would need additional flags
                    constrained_to=[],
                    last_password_change=computer.password_last_set,
                    password_never_expires=False,
                    enabled=computer.enabled
                ))
        
        return service_accounts 

    def _parse_domain_info(self, root: ET.Element):
        """Parse domain information from MLA file."""
        domain_info = root.find(".//domain")
        if domain_info is not None:
            self.logger.info(f"Found domain: {domain_info.get('name')}")
            # Add domain info parsing logic here

    def _parse_schema(self, entry: ET.Element):
        """Parse schema modifications."""
        if "schemaIDGUID" in entry.attrib:
            self.schema.append({
                'id': entry.attrib['schemaIDGUID'],
                'name': self._get_attribute(entry, "name"),
                'modified': self._parse_date(self._get_attribute(entry, "whenChanged")),
                'attributes': self._parse_schema_attributes(entry)
            })

    def _parse_password_policies(self, entry: ET.Element):
        """Parse domain password policies."""
        if "msDS-PasswordSettings" in entry.attrib:
            policy = {
                'name': self._get_attribute(entry, "name"),
                'precedence': int(self._get_attribute(entry, "msDS-PasswordSettingsPrecedence") or "0"),
                'min_length': int(self._get_attribute(entry, "msDS-MinimumPasswordLength") or "0"),
                'history_length': int(self._get_attribute(entry, "msDS-PasswordHistoryLength") or "0"),
                'complexity_enabled': bool(self._get_attribute(entry, "msDS-PasswordComplexityEnabled")),
                'reversible_encryption': bool(self._get_attribute(entry, "msDS-PasswordReversibleEncryptionEnabled")),
                'max_age': self._get_attribute(entry, "msDS-MaximumPasswordAge"),
                'min_age': self._get_attribute(entry, "msDS-MinimumPasswordAge"),
                'lockout_threshold': int(self._get_attribute(entry, "msDS-LockoutThreshold") or "0"),
                'lockout_duration': self._get_attribute(entry, "msDS-LockoutDuration"),
                'lockout_window': self._get_attribute(entry, "msDS-LockoutObservationWindow")
            }
            self.password_policies.append(policy)

    def _parse_laps(self, entry: ET.Element):
        """Parse LAPS password information."""
        laps_password = self._get_attribute(entry, "ms-Mcs-AdmPwd")
        if laps_password:
            self.laps_passwords.append({
                'computer': self._get_attribute(entry, "name"),
                'expiration': self._parse_date(self._get_attribute(entry, "ms-Mcs-AdmPwdExpirationTime")),
                'last_change': self._parse_date(self._get_attribute(entry, "ms-Mcs-AdmPwdLastChange"))
            }) 

    @property
    def all_users(self):
        """Get all users across all domains."""
        return [user for domain in self.domains.values() for user in domain.users]

    @property
    def all_computers(self):
        """Get all computers across all domains."""
        return [computer for domain in self.domains.values() for computer in domain.computers]

    @property
    def all_groups(self):
        """Get all groups across all domains."""
        return [group for domain in self.domains.values() for group in domain.groups] 