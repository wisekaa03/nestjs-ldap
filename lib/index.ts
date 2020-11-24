/** @format */
// Copyright 2020 Stanislav V Vyaliy.  All rights reserved.

export {
  InsufficientAccessRightsError,
  InvalidCredentialsError,
  EntryAlreadyExistsError,
  NoSuchObjectError,
  NoSuchAttributeError,
  ProtocolError,
  OperationsError,
  Error as LdapError,
} from 'ldapjs';

export { Change } from './ldap/change';
export { Attribute } from './ldap/attribute';
export { Protocol } from './ldap/protocol';
export { LdapModule } from './ldap.module';
export { LdapService } from './ldap.service';
export * from './ldap.interface';
