/** @format */
// Copyright 2020 Stanislav V Vyaliy.  All rights reserved.

//#region Imports NPM
import { Inject, Injectable } from '@nestjs/common';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';
import CacheManager from 'cache-manager';
import RedisStore from 'cache-manager-ioredis';
import { parse as urlLibParse } from 'url';
import bcrypt from 'bcrypt';
//#endregion
//#region Imports Local
import type { LdapModuleOptions, LDAPCache, LdapResponseUser, LdapResponseGroup, LDAPAddEntry, LoggerContext } from './ldap.interface';
import { LDAP_OPTIONS } from './ldap.interface';
import { Change } from './ldap/change';
import { LdapDomain } from './ldap.class';

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
//#endregion

const LDAP_PASSWORD_NULL = '2058e76c5f3d68e12d7eec7e334fece75b0552edc5348f85c7889404d9211a36';

@Injectable()
export class LdapService {
  public ldapDomains: LdapDomain[];

  private cache?: CacheManager.Cache;
  private cacheSalt: string;
  private cacheTtl: number;

  /**
   * Create an LDAP class.
   *
   * @param {LdapModuleOptions} opts Config options
   * @param {LogService} logger Logger service
   * @param {ConfigService} configService Config service
   * @constructor
   */
  constructor(
    @Inject(LDAP_OPTIONS) private readonly options: LdapModuleOptions,
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger,
  ) {
    if (options.cacheUrl || options.cache) {
      this.cacheTtl = options.cacheTtl || 600;
      this.cacheSalt = bcrypt.genSaltSync(6);

      if (options.cache) {
        this.cache = CacheManager.caching({
          store: RedisStore,
          redisInstance: options.cache,
          keyPrefix: 'LDAP:',
          ttl: this.cacheTtl,
        });
      } else if (options.cacheUrl) {
        const redisArray = urlLibParse(options.cacheUrl);
        if (redisArray && (redisArray.protocol === 'redis:' || redisArray.protocol === 'rediss:')) {
          let username: string | undefined;
          let password: string | undefined;
          const db = parseInt(redisArray.pathname?.slice(1) || '0', 10);
          if (redisArray.auth) {
            [username, password] = redisArray.auth.split(':');
          }

          this.cache = CacheManager.caching({
            store: RedisStore,
            host: redisArray.hostname,
            port: parseInt(redisArray.port || '6379', 10),
            username,
            password,
            db,
            keyPrefix: 'LDAP:',
            ttl: this.cacheTtl,
          });
        }
      }
      if (this.cache?.store) {
        this.logger.debug('Redis connection: success.', {
          context: LdapService.name,
          function: this.constructor.name,
        });
      } else {
        this.logger.error('Redis connection: some error.', {
          context: LdapService.name,
          function: this.constructor.name,
        });
      }
    } else {
      this.cacheSalt = '';
      this.cacheTtl = 0;
    }

    this.ldapDomains = this.options.domains.map((opts) => new LdapDomain(opts, logger));
  }

  /**
   * Search user by Username
   *
   * @async
   * @param {string} userByUsername user name
   * @returns {Promise<LdapResponseUser>} User in LDAP
   */
  public async searchByUsername({
    userByUsername,
    domain,
    cache = true,
    loggerContext,
  }: {
    userByUsername: string;
    domain: string;
    cache?: boolean;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    const cachedID = `user:${domain}:${userByUsername}`;

    if (cache && this.cache) {
      // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
      const cached: LDAPCache = await this.cache.get<LDAPCache>(cachedID);
      if (cached && cached.user && cached.user.sAMAccountName) {
        this.logger.debug(`From cache: ${cached.user.sAMAccountName}`, {
          context: LdapService.name,
          function: this.searchByUsername.name,
          ...loggerContext,
        });

        return cached.user as LdapResponseUser;
      }
    }

    const domainLdap = this.ldapDomains.find((value) => value.domainName === domain);
    if (!domainLdap) {
      this.logger.debug(`Domain does not exist: ${domain}`, {
        context: LdapService.name,
        function: this.searchByUsername.name,
        ...loggerContext,
      });
      throw new Error(`Domain does not exist: ${domain}`);
    }

    return domainLdap.searchByUsername({ userByUsername, loggerContext }).then((user) => {
      if (user && this.cache) {
        this.logger.debug(`To cache from domain ${domain}: ${user.dn}`, {
          context: LdapService.name,
          function: this.searchByUsername.name,
          ...loggerContext,
        });
        this.cache.set<LDAPCache>(`dn:${domain}:${user.dn}`, { user, password: LDAP_PASSWORD_NULL }, { ttl: this.cacheTtl });

        if (user.sAMAccountName) {
          this.logger.debug(`To cache from domain ${domain}: ${user.sAMAccountName}`, {
            context: LdapService.name,
            function: this.searchByUsername.name,
            ...loggerContext,
          });
          this.cache.set<LDAPCache>(
            `user:${domain}:${user.sAMAccountName}`,
            { user, password: LDAP_PASSWORD_NULL },
            { ttl: this.cacheTtl },
          );
        }
      }

      return user;
    });
  }

  /**
   * Search user by DN
   *
   * @async
   * @param {string} userByDN user distinguished name
   * @returns {Promise<LdapResponseUser>} User in LDAP
   */
  public async searchByDN({
    userByDN,
    domain,
    cache = true,
    loggerContext,
  }: {
    userByDN: string;
    domain: string;
    cache?: boolean;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    const cachedID = `dn:${domain}:${userByDN}`;
    if (cache && this.cache) {
      // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
      const cached: LDAPCache = await this.cache.get<LDAPCache>(cachedID);
      if (cached && cached.user && cached.user.sAMAccountName) {
        this.logger.debug(`From cache: ${cached.user.sAMAccountName}`, {
          context: LdapService.name,
          function: this.searchByDN.name,
          ...loggerContext,
        });

        return cached.user as LdapResponseUser;
      }
    }

    const domainLdap = this.ldapDomains.find((value) => value.domainName === domain);
    if (!domainLdap) {
      this.logger.debug(`Domain does not exist: ${domain}`, {
        context: LdapService.name,
        function: this.searchByDN.name,
        ...loggerContext,
      });
      throw new Error(`Domain does not exist: ${domain}`);
    }

    return domainLdap.searchByDN({ userByDN, loggerContext }).then((user) => {
      if (user && this.cache) {
        this.logger.debug(`To cache from domain ${domain}: ${userByDN}`, {
          context: LdapService.name,
          function: this.searchByDN.name,
          ...loggerContext,
        });
        this.cache.set<LDAPCache>(cachedID, { user, password: LDAP_PASSWORD_NULL }, { ttl: this.cacheTtl });

        if (user.sAMAccountName) {
          this.logger.debug(`To cache from domain ${domain}: ${user.sAMAccountName}`, {
            context: LdapService.name,
            function: this.searchByDN.name,
            ...loggerContext,
          });
          this.cache.set<LDAPCache>(
            `user:${domain}:${user.sAMAccountName}`,
            { user, password: LDAP_PASSWORD_NULL },
            { ttl: this.cacheTtl },
          );
        }
      }

      return user;
    });
  }

  /**
   * Synchronize users
   *
   * @async
   * @returns {Record<string, LdapResponseUser[]>} User in LDAP
   * @throws {Error}
   */
  public async synchronization({ loggerContext }: { loggerContext?: LoggerContext }): Promise<Record<string, LdapResponseUser[]>> {
    const promiseDomain = this.ldapDomains.map(async (domain) => domain.synchronization({ loggerContext }));
    return Promise.allSettled(promiseDomain).then((promises) =>
      promises.reduce((accumulator, domain) => (domain.status === 'fulfilled' ? { ...accumulator, ...domain.value } : accumulator), {}),
    );
  }

  /**
   * Synchronize users
   *
   * @async
   * @returns {Record<string, LdapResponseGroup[]>} Group in LDAP
   * @throws {Error}
   */
  public async synchronizationGroups({ loggerContext }: { loggerContext?: LoggerContext }): Promise<Record<string, LdapResponseGroup[]>> {
    const promiseDomain = this.ldapDomains.map(async (domain) => domain.synchronizationGroups({ loggerContext }));
    return Promise.allSettled(promiseDomain).then((promises) =>
      promises.reduce((accumulator, domain) => (domain.status === 'fulfilled' ? { ...accumulator, ...domain.value } : accumulator), {}),
    );
  }

  /**
   * Modify using the admin client.
   *
   * @public
   * @async
   * @param {string} dn LDAP Distiguished Name
   * @param {Change[]} data LDAP modify data
   * @param {string} username The optional parameter
   * @param {string} password The optional parameter
   * @returns {boolean} The result
   * @throws {Ldap.Error}
   */
  public async modify({
    dn,
    data,
    domain,
    username,
    password,
    loggerContext,
  }: {
    dn: string;
    data: Change[];
    domain: string;
    username?: string;
    password?: string;
    loggerContext?: LoggerContext;
  }): Promise<boolean> {
    const domainLdap = this.ldapDomains.find((value) => value.domainName === domain);
    if (!domainLdap) {
      this.logger.debug(`Domain does not exist: ${domain}`, {
        context: LdapService.name,
        function: this.modify.name,
        ...loggerContext,
      });
      throw new Error(`Domain does not exist: ${domain}`);
    }

    return domainLdap.modify({ dn, data, username, password, loggerContext });
  }

  /**
   * Authenticate given credentials against LDAP server
   *
   * @async
   * @param {string} username The username to authenticate
   * @param {string} password The password to verify
   * @param {string} domain The domain to check
   * @returns {LdapResponseUser} User in LDAP
   * @throws {Error}
   */
  public async authenticate({
    username,
    password,
    domain,
    cache = true,
    loggerContext,
  }: {
    username: string;
    password: string;
    domain: string;
    cache?: boolean;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    if (!password) {
      this.logger.error(`${domain}: No password given`, {
        error: `${domain}: No password given`,
        context: LdapService.name,
        function: this.authenticate.name,
        ...loggerContext,
      });
      throw new Error('No password given');
    }

    const domainLdap = this.ldapDomains.find((value) => value.domainName === domain);
    if (!domainLdap) {
      this.logger.debug(`Domain does not exist: ${domain}`, {
        context: LdapService.name,
        function: this.authenticate.name,
        ...loggerContext,
      });
      throw new Error(`Domain does not exist: ${domain}`);
    }

    const cachedID = `user:${domain}:${username}`;
    if (cache && this.cache) {
      // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
      const cached: LDAPCache = await this.cache.get<LDAPCache>(cachedID);
      if (cached?.user?.sAMAccountName && (cached?.password === LDAP_PASSWORD_NULL || bcrypt.compareSync(password, cached.password))) {
        this.logger.debug(`From cache ${domain}: ${cached.user.sAMAccountName}`, {
          context: LdapService.name,
          function: this.authenticate.name,
          ...loggerContext,
        });

        (async (): Promise<void> => {
          try {
            const user = await domainLdap.authenticate({
              username,
              password,
              loggerContext,
            });
            if (JSON.stringify(user) !== JSON.stringify(cached.user) && this.cache) {
              this.logger.debug(`To cache from domain ${domain}: ${user.sAMAccountName}`, {
                context: LdapService.name,
                function: this.authenticate.name,
                ...loggerContext,
              });

              this.cache.set<LDAPCache>(
                `user:${domain}:${user.sAMAccountName}`,
                {
                  user,
                  password: bcrypt.hashSync(password, this.cacheSalt),
                },
                { ttl: this.cacheTtl },
              );
            }
          } catch (error) {
            this.logger.error(`LDAP auth error [${domain}]: ${error.toString()}`, {
              error,
              context: LdapService.name,
              function: this.authenticate.name,
              ...loggerContext,
            });
          }
        })();

        return cached.user;
      }
    }

    return domainLdap
      .authenticate({
        username,
        password,
        loggerContext,
      })
      .then((user) => {
        if (this.cache) {
          this.logger.debug(`To cache from domain ${domain}: ${user.sAMAccountName}`, {
            context: LdapService.name,
            function: this.authenticate.name,
            ...loggerContext,
          });

          this.cache.set<LDAPCache>(
            `user:${domain}:${user.sAMAccountName}`,
            {
              user,
              password: bcrypt.hashSync(password, this.cacheSalt),
            },
            { ttl: this.cacheTtl },
          );
        }

        return user;
      });
  }

  /**
   * Trusted domain
   *
   * @async
   * @returns {LdapTrustedDomain} ?
   * @throws {Error}
   */
  public async trustedDomain({
    searchBase,
    domain,
    loggerContext,
  }: {
    searchBase: string;
    domain: string;
    loggerContext?: LoggerContext;
  }): Promise<any> {
    const trustedDomain = '';

    return trustedDomain;
  }

  /**
   * This is add a LDAP object
   *
   * @async
   * @param {Record<string, string>} value
   * @returns {LdapResponseUser} User | Profile in LDAP
   * @throws {Error}
   */
  public async add({
    entry,
    domain,
    loggerContext,
  }: {
    entry: LDAPAddEntry;
    domain: string;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    const domainLdap = this.ldapDomains.find((value) => value.domainName === domain);
    if (!domainLdap) {
      this.logger.debug(`Domain does not exist: ${domain}`, {
        context: LdapService.name,
        function: this.searchByUsername.name,
        ...loggerContext,
      });
      throw new Error(`Domain does not exist: ${domain}`);
    }

    return domainLdap.add({ entry, loggerContext });
  }

  /**
   * Unbind connections
   *
   * @async
   * @returns {Promise<boolean[]>}
   */
  public async close(): Promise<boolean[]> {
    const promiseDomain = this.ldapDomains.map(async (domain) => domain.close());
    return Promise.allSettled(promiseDomain)
      .then((values) => values.map((promise) => (promise.status === 'fulfilled' ? promise.value : false)))
      .then((values) => values.reduce((accumulator, value) => accumulator.concat(value), [] as boolean[]));
  }
}
