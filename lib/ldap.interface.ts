/** @format */
// Copyright 2020 Stanislav V Vyaliy.  All rights reserved.

//#region Imports NPM
import type { Logger } from '@nestjs/common';
import type { ModuleMetadata, Type } from '@nestjs/common/interfaces';
import type { ClientOptions, SearchEntryObject } from 'ldapjs';
import type { Redis } from 'ioredis';
//#endregion

export const LDAP_SYNC = 'LDAP_SYNC';
export const LDAP_OPTIONS = 'LDAP_OPTIONS';

export type Scope = 'base' | 'one' | 'sub';

export interface LoggerContext {
  [key: string]: string | unknown | null;
}

export interface LDAPAddEntry {
  /**
   * Common name
   */
  cn?: string;
  displayName?: string;
  name?: string;

  comment?: Record<string, string> | string;

  thumbnailPhoto?: Buffer;

  [p: string]: undefined | string | string[] | Record<string, string> | Buffer;
}

export interface LdapResponseGroup {
  /**
   * Common name
   */
  cn: string;

  /**
   * Description
   */
  description: string;

  /**
   * DN
   */
  dn: string;

  /**
   * Distinguished name
   */
  distinguishedName: string;

  // Name
  name: string;

  /**
   * SAM account name
   */
  sAMAccountName: string;

  sAMAccountType: string;

  // Object category
  objectCategory: string;
  objectClass: string[];

  // Object GUID - ID in ldap
  objectGUID: string;

  whenChanged: Date;
  whenCreated: Date;
}

export interface LdapResponseUser {
  /**
   * DN
   */
  'dn': string;

  /**
   * Ldap response groups
   */
  'groups'?: LdapResponseGroup[];

  /**
   * Country
   */
  'c': string;

  /**
   * Common name
   */
  'cn': string;

  /**
   * Country expanded
   */
  'co': string;

  /**
   * Comment
   */
  'comment': string;

  /**
   * Company
   */
  'company': string;

  /**
   * Country code
   */
  'countryCode': string;

  /**
   * Department name
   */
  'department': string;

  /**
   * Description
   */
  'description': string;

  /**
   * Display name
   */
  'displayName': string;

  /**
   * Distinguished name
   */
  'distinguishedName': string;

  /**
   * Employee ID
   */
  'employeeID'?: string;
  'employeeNumber'?: string;
  'employeeType'?: string;

  /**
   * Given name
   */
  'givenName': string;

  /**
   * Additional flags
   */
  'flags': string;

  /**
   * Locality
   */
  'l': string;

  // Lockout time
  'lockoutTime': string;

  // E-mail
  'mail': string;
  'otherMailbox': string[];

  // Member of groups
  'memberOf': string[];

  // middle name
  'middleName': string;

  // Mobile phone
  'mobile': string;

  // Manager Profile ?
  'manager': string;

  // Name
  'name': string;

  // Object category
  'objectCategory': string;

  'objectClass': string[];

  // Object GUID - ID in ldap
  'objectGUID': string;

  // Other telephone
  'otherTelephone': string;

  // Postal code
  'postalCode': string;

  /**
   * Office name
   */
  'physicalDeliveryOfficeName': string;

  /**
   * SAM account name
   */
  'sAMAccountName': string;

  'sAMAccountType': string;

  /**
   * Family name
   */
  'sn': string;

  /**
   * Region
   */
  'st': string;

  /**
   * Street address
   */
  'streetAddress': string;

  /**
   * Telephone number
   */
  'telephoneNumber': string;

  /**
   * Fax number
   */
  'facsimileTelephoneNumber': string;

  /**
   * Thumbnail photo
   */
  'thumbnailPhoto': string;

  /**
   * Jpeg photo
   */
  'jpegPhoto': string[];

  'carLicense'?: string;

  /**
   * Work title
   */
  'title': string;

  'userAccountControl': string;

  'wWWHomePage': string;

  'userPrincipalName': string;

  'whenChanged'?: Date;
  'whenCreated'?: Date;
  'badPasswordTime'?: Date;
  'badPwdCount'?: number;

  // Logon, logoff
  'logonCount'?: number;
  'lastLogoff'?: Date;
  'lastLogon'?: Date;
  'lastLogonTimestamp'?: Date;

  'pwdLastSet'?: Date;

  /* Active Directory */
  'msDS-cloudExtensionAttribute1'?: string;
  'msDS-cloudExtensionAttribute2'?: string;

  /* In our AD: Date of birth */
  'msDS-cloudExtensionAttribute3'?: string;

  'msDS-cloudExtensionAttribute4'?: string;
  'msDS-cloudExtensionAttribute5'?: string;
  'msDS-cloudExtensionAttribute6'?: string;
  'msDS-cloudExtensionAttribute7'?: string;
  'msDS-cloudExtensionAttribute8'?: string;
  'msDS-cloudExtensionAttribute9'?: string;
  'msDS-cloudExtensionAttribute10'?: string;
  'msDS-cloudExtensionAttribute11'?: string;
  'msDS-cloudExtensionAttribute12'?: string;

  /* In our AD: access card (pass) */
  'msDS-cloudExtensionAttribute13'?: string;

  'msDS-cloudExtensionAttribute14'?: string;
  'msDS-cloudExtensionAttribute15'?: string;
  'msDS-cloudExtensionAttribute16'?: string;
  'msDS-cloudExtensionAttribute17'?: string;
  'msDS-cloudExtensionAttribute18'?: string;
  'msDS-cloudExtensionAttribute19'?: string;
  'msDS-cloudExtensionAttribute20'?: string;
}

interface GroupSearchFilterFunction {
  /**
   * Construct a group search filter from user object
   *
   * @param user The user retrieved and authenticated from LDAP
   */
  (user: SearchEntryObject): string;
}

export interface LdapDomainsConfig extends ClientOptions {
  /**
   * Name string: EXAMPLE.COM
   */
  name: string;

  /**
   * Admin connection DN, e.g. uid=myapp,ou=users,dc=example,dc=org.
   * If not given at all, admin client is not bound. Giving empty
   * string may result in anonymous bind when allowed.
   *
   * Note: Not passed to ldapjs, it would bind automatically
   */
  bindDN: string;
  /**
   * Password for bindDN
   */
  bindCredentials: string;
  /**
   * Property of the LDAP user object to use when binding to verify
   * the password. E.g. name, email. Default: dn
   */
  bindProperty?: 'dn';

  /**
   * The base DN from which to search for users by username.
   * E.g. ou=users,dc=example,dc=org
   */
  searchBase: string;
  /**
   * LDAP search filter with which to find a user by username, e.g.
   * (uid={{username}}). Use the literal {{username}} to have the
   * given username interpolated in for the LDAP search.
   */
  searchFilter: string;
  /**
   * Scope of the search. Default: 'sub'
   */
  searchScope?: Scope;
  /**
   * Array of attributes to fetch from LDAP server. Default: all
   */
  searchAttributes?: string[];

  /**
   * LDAP search filter with synchronization.
   */
  searchFilterAllUsers: string;
  /**
   * Scope of the search. Default: 'sub'
   */
  searchScopeAllUsers?: Scope;
  /**
   * Array of attributes to fetch from LDAP server. Default: all
   */
  searchAttributesAllUsers?: string[];

  /**
   * The base DN from which to search for groups. If defined,
   * also groupSearchFilter must be defined for the search to work.
   */
  groupSearchBase?: string;
  /**
   * LDAP search filter for groups. Place literal {{dn}} in the filter
   * to have it replaced by the property defined with `groupDnProperty`
   * of the found user object. Optionally you can also assign a
   * function instead. The found user is passed to the function and it
   * should return a valid search filter for the group search.
   */
  groupSearchFilter?: string | GroupSearchFilterFunction;
  searchFilterAllGroups?: string;
  /**
   * Scope of the search. Default: sub
   */
  groupSearchScope?: Scope;
  /**
   * Array of attributes to fetch from LDAP server. Default: all
   */
  groupSearchAttributes?: string[];

  /**
   * The property of user object to use in '{{dn}}' interpolation of
   * groupSearchFilter. Default: 'dn'
   */
  groupDnProperty?: string;

  /**
   * Set to true to add property '_raw' containing the original buffers
   * to the returned user object. Useful when you need to handle binary
   * attributes
   */
  includeRaw?: boolean;

  timeLimit?: number;
  sizeLimit?: number;

  /**
   * Where to have new objects (contacts, users) to place
   */
  newObject?: string;
}

export interface LdapModuleOptions {
  /**
   * Logger function
   */
  logger?: Logger;

  /**
   * Domains config
   */
  domains: LdapDomainsConfig[];

  /**
   * If true, then up to 100 credentials at a time will be cached for
   * 5 minutes.
   */
  cache?: Redis;
  cacheUrl?: string;
  cacheTtl?: number;
}

export interface LdapOptionsFactory {
  createLdapOptions(): Promise<LdapModuleOptions> | LdapModuleOptions;
}

export interface LdapModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useExisting?: Type<LdapOptionsFactory>;
  useClass?: Type<LdapOptionsFactory>;
  useFactory?: (...args: any[]) => Promise<LdapModuleOptions> | LdapModuleOptions;
  inject?: any[];
}

export const ldapADattributes = [
  'thumbnailPhoto;binary',
  // 'jpegPhoto;binary',
  'objectGUID;binary',
  // 'objectSid;binary',
  'c',
  'cn',
  'co',
  'codePage',
  'comment',
  'company',
  'countryCode',
  'department',
  'description',
  'displayName',
  'distinguishedName',
  'dn',
  'employeeID',
  'flags',
  'givenName',
  'l',
  'mail',
  'memberOf',
  'middleName',
  'manager',
  'mobile',
  'name',
  'objectCategory',
  'objectClass',
  'otherMailbox',
  'otherTelephone',
  'postalCode',
  'primaryGroupID',
  'sAMAccountName',
  'sAMAccountType',
  'sn',
  'st',
  'streetAddress',
  'telephoneNumber',
  'title',
  'wWWHomePage',
  'userAccountControl',
  'whenChanged',
  'whenCreated',
  'msDS-cloudExtensionAttribute1',
  'msDS-cloudExtensionAttribute2',
  'msDS-cloudExtensionAttribute3',
  'msDS-cloudExtensionAttribute4',
  'msDS-cloudExtensionAttribute5',
  'msDS-cloudExtensionAttribute6',
  'msDS-cloudExtensionAttribute7',
  'msDS-cloudExtensionAttribute8',
  'msDS-cloudExtensionAttribute9',
  'msDS-cloudExtensionAttribute10',
  'msDS-cloudExtensionAttribute11',
  'msDS-cloudExtensionAttribute12',
  'msDS-cloudExtensionAttribute13',
  'msDS-cloudExtensionAttribute14',
  'msDS-cloudExtensionAttribute15',
  'msDS-cloudExtensionAttribute16',
  'msDS-cloudExtensionAttribute17',
  'msDS-cloudExtensionAttribute18',
  'msDS-cloudExtensionAttribute19',
  'msDS-cloudExtensionAttribute20',
];

export interface LDAPCache {
  user: LdapResponseUser;
  password: string;
}
