/** @format */
import { LoggerService } from '@nestjs/common';
import { EventEmitter } from 'events';
import Ldap from 'ldapjs';
import type { LdapDomainsConfig, LoggerContext } from './ldap.interface';
import { ldapADattributes, LdapResponseObject, LdapResponseGroup, LdapResponseUser, LdapAddEntry } from './ldap.interface';
import { Change } from './ldap/change';

export class LdapDomain extends EventEmitter {
  public domainName: string;
  public hideSynchronization: boolean;

  private clientOpts: Ldap.ClientOptions;

  private bindDN: string;

  private bindCredentials: string;

  private adminClient: Ldap.Client;

  private adminBound: boolean;

  private userClient: Ldap.Client;

  private getGroups: ({ user, loggerContext }: { user: LdapResponseUser; loggerContext?: LoggerContext }) => Promise<LdapResponseGroup[]>;

  /**
   * Create an LDAP class.
   *
   * @param {LdapModuleOptions} opts Config options
   * @param {LogService} logger Logger service
   * @param {ConfigService} configService Config service
   * @constructor
   */
  constructor(private readonly options: LdapDomainsConfig, private readonly logger: LoggerService) {
    super();

    this.domainName = options.name;
    this.hideSynchronization = options.hideSynchronization ?? false;

    this.clientOpts = {
      url: options.url,
      tlsOptions: options.tlsOptions,
      socketPath: options.socketPath,
      log: options.log,
      timeout: options.timeout || 5000,
      connectTimeout: options.connectTimeout || 5000,
      idleTimeout: options.idleTimeout || 5000,
      reconnect: options.reconnect || true,
      strictDN: options.strictDN,
      queueSize: options.queueSize || 200,
      queueTimeout: options.queueTimeout || 5000,
      queueDisable: options.queueDisable || false,
    };

    this.bindDN = options.bindDN;
    this.bindCredentials = options.bindCredentials;

    this.adminClient = Ldap.createClient(this.clientOpts);
    this.adminBound = false;
    this.userClient = Ldap.createClient(this.clientOpts);

    this.adminClient.on('connectError', this.handleConnectError.bind(this));
    this.userClient.on('connectError', this.handleConnectError.bind(this));

    this.adminClient.on('error', this.handleErrorAdmin.bind(this));
    this.userClient.on('error', this.handleErrorUser.bind(this));

    if (options.reconnect) {
      this.once('installReconnectListener', () => {
        this.logger.debug!({
          message: `${options.name}: install reconnect listener`,
          context: LdapDomain.name,
          function: 'constructor',
        });
        this.adminClient.on('connect', () => this.onConnectAdmin({}));
      });
    }

    this.adminClient.on('connectTimeout', this.handleErrorAdmin.bind(this));
    this.userClient.on('connectTimeout', this.handleErrorUser.bind(this));

    if (options.groupSearchBase && options.groupSearchFilter) {
      if (typeof options.groupSearchFilter === 'string') {
        const { groupSearchFilter } = options;
        // eslint-disable-next-line no-param-reassign
        options.groupSearchFilter = (user: LdapResponseUser): string =>
          groupSearchFilter
            .replace(
              /{{dn}}/g,
              (options.groupDnProperty && (user[options.groupDnProperty] as string))?.replace(/\(/, '\\(')?.replace(/\)/, '\\)') ||
                'undefined',
            )
            .replace(/{{username}}/g, user.sAMAccountName);
      }

      this.getGroups = this.findGroups;
    } else {
      // Assign an async identity function so there is no need to branch
      // the authenticate function to have cache set up.
      this.getGroups = async () => [];
    }
  }

  /**
   * Format a GUID
   *
   * @public
   * @param {string} objectGUID GUID in Active Directory notation
   * @returns {string} string GUID
   */
  GUIDtoString = (objectGUID: string): string =>
    (objectGUID &&
      Buffer.from(objectGUID, 'base64')
        .toString('hex')
        .replace(/^(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)(..)$/, '$4$3$2$1-$6$5-$8$7-$10$9-$16$15$14$13$12$11')
        .toUpperCase()) ||
    '';

  /**
   * Ldap Date

   * @param {string} string
   */
  dateFromString = (string: string): Date | null => {
    const b = string.match(/\d\d/g);

    return (
      b &&
      new Date(
        Date.UTC(
          Number.parseInt(b[0] + b[1], 10),
          Number.parseInt(b[2], 10) - 1,
          Number.parseInt(b[3], 10),
          Number.parseInt(b[4], 10),
          Number.parseInt(b[5], 10),
          Number.parseInt(b[6], 10),
        ),
      )
    );
  };

  /**
   * Mark admin client unbound so reconnect works as expected and re-emit the error
   *
   * @private
   * @param {Ldap.Error} error The error to be logged and emitted
   * @returns {void}
   */
  private handleErrorAdmin(error: Ldap.Error): void {
    if (`${error.code}` !== 'ECONNRESET') {
      this.logger.error({
        message: `${this.domainName}: admin emitted error: [${error.code}]`,
        error,
        context: LdapDomain.name,
        function: 'handleErrorAdmin',
      });
    }
    this.adminBound = false;
  }

  /**
   * Mark user client unbound so reconnect works as expected and re-emit the error
   *
   * @private
   * @param {Ldap.Error} error The error to be logged and emitted
   * @returns {void}
   */
  private handleErrorUser(error: Ldap.Error): void {
    if (`${error.code}` !== 'ECONNRESET') {
      this.logger.error({
        message: `${this.domainName}: user emitted error: [${error.code}]`,
        error,
        context: LdapDomain.name,
        function: 'handleErrorUser',
      });
    }
    // this.adminBound = false;
  }

  /**
   * Connect error handler
   *
   * @private
   * @param {Ldap.Error} error The error to be logged and emitted
   * @returns {void}
   */
  private handleConnectError(error: Ldap.Error): void {
    this.logger.error({
      message: `${this.domainName}: emitted error: [${error.code}]`,
      error,
      context: LdapDomain.name,
      function: 'handleConnectError',
    });
  }

  /**
   * Bind adminClient to the admin user on connect
   *
   * @private
   * @async
   * @returns {boolean | Error}
   */
  private async onConnectAdmin({ loggerContext }: { loggerContext?: LoggerContext }): Promise<boolean> {
    // Anonymous binding
    if (typeof this.bindDN === 'undefined' || this.bindDN === null) {
      this.adminBound = false;

      throw new Error(`${this.domainName}: bindDN is undefined`);
    }

    return new Promise<boolean>((resolve, reject) =>
      this.adminClient.bind(this.bindDN, this.bindCredentials, (error) => {
        if (error) {
          this.logger.error({
            message: `${this.domainName}: bind error: ${error.toString()}`,
            error,
            context: LdapDomain.name,
            function: 'onConnectAdmin',
            ...loggerContext,
          });
          this.adminBound = false;

          return reject(error);
        }

        this.adminBound = true;
        if (this.options.reconnect) {
          this.emit('installReconnectListener');
        }

        return resolve(true);
      }),
    );
  }

  /**
   * Ensure that `this.adminClient` is bound.
   *
   * @private
   * @async
   * @returns {boolean | Error}
   */
  private adminBind = async ({ loggerContext }: { loggerContext?: LoggerContext }): Promise<boolean> =>
    this.adminBound ? true : this.onConnectAdmin({ loggerContext });

  /**
   * Conduct a search using the admin client. Used for fetching both
   * user and group information.
   *
   * @private
   * @async
   * @param {string} searchBase LDAP search base
   * @param {Object} options LDAP search options
   * @param {string} options.filter LDAP search filter
   * @param {string} options.scope LDAP search scope
   * @param {(string[]|undefined)} options.attributes Attributes to fetch
   * @returns {undefined | Ldap.SearchEntryObject[]}
   * @throws {Error}
   */
  private async search({
    searchBase,
    options,
    loggerContext,
  }: {
    searchBase: string;
    options: Ldap.SearchOptions;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseObject[]> {
    return this.adminBind({ loggerContext }).then(
      () =>
        new Promise<LdapResponseObject[]>((resolve, reject) =>
          this.adminClient.search(searchBase, options, (searchError: Ldap.Error | null, searchResult: Ldap.SearchCallbackResponse) => {
            if (searchError !== null) {
              return reject(searchError);
            }
            if (typeof searchResult !== 'object') {
              return reject(new Error(`The LDAP server has empty search: ${searchBase}, options=${JSON.stringify(options)}`));
            }

            const items: LdapResponseObject[] = [];
            searchResult.on('searchEntry', (entry: Ldap.SearchEntry) => {
              const object = Object.keys(entry.object).reduce((accumulator, key) => {
                let k = key;
                if (key.endsWith(';binary')) {
                  k = key.replace(/;binary$/, '');
                }
                switch (k) {
                  case 'objectGUID':
                    return {
                      ...accumulator,
                      objectGUID: this.GUIDtoString(entry.object[key] as string),
                    } as LdapResponseObject;
                  case 'dn':
                    return {
                      ...accumulator,
                      dn: (entry.object[key] as string).toLowerCase(),
                    } as LdapResponseObject;
                  case 'sAMAccountName':
                    return {
                      ...accumulator,
                      sAMAccountName: (entry.object[key] as string).toLowerCase(),
                    } as LdapResponseObject;
                  case 'whenCreated':
                  case 'whenChanged':
                    return {
                      ...accumulator,
                      [k]: this.dateFromString(entry.object[key] as string),
                    } as LdapResponseObject;
                  default:
                }

                // 'thumbnailPhoto' and 'jpegPhoto' is falling there
                return { ...accumulator, [k]: entry.object[key] } as LdapResponseObject;
              }, {} as LdapResponseObject);

              items.push({ ...object, loginDomain: this.domainName } as LdapResponseObject);

              // if (this.options.includeRaw === true) {
              //   items[items.length - 1].raw = (entry.raw as unknown) as string;
              // }
            });

            searchResult.on('error', (error: Ldap.Error) => {
              reject(error);
            });

            searchResult.on('end', (result: Ldap.LDAPResult) => {
              if (result.status !== 0) {
                return reject(new Error(`non-zero status from LDAP search: ${result.status}`));
              }

              return resolve(items);
            });

            return undefined;
          }),
        ),
    );
  }

  /**
   * Sanitize LDAP special characters from input
   *
   * {@link https://tools.ietf.org/search/rfc4515#section-3}
   *
   * @private
   * @param {string} input String to sanitize
   * @returns {string} Sanitized string
   */
  private sanitizeInput(input: string): string {
    return input
      .replace(/\*/g, '\\2a')
      .replace(/\(/g, '\\28')
      .replace(/\)/g, '\\29')
      .replace(/\\/g, '\\5c')
      .replace(/\0/g, '\\00')
      .replace(/\//g, '\\2f');
  }

  /**
   * Find the user record for the given username.
   *
   * @private
   * @async
   * @param {string} username Username to search for
   * @returns {undefined} If user is not found but no error happened, result is undefined.
   * @throws {Error}
   */
  private async findUser({ username, loggerContext }: { username: string; loggerContext?: LoggerContext }): Promise<LdapResponseUser> {
    if (!username) {
      throw new Error('empty username');
    }

    const searchFilter = this.options.searchFilter.replace(/{{username}}/g, this.sanitizeInput(username));
    const options: Ldap.SearchOptions = {
      filter: searchFilter,
      scope: this.options.searchScope,
      attributes: ldapADattributes,
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: false,
    };
    if (this.options.searchAttributes) {
      options.attributes = this.options.searchAttributes;
    }

    return this.search({
      searchBase: this.options.searchBase,
      options,
      loggerContext,
    })
      .then(
        (result) =>
          new Promise<LdapResponseUser>((resolve, reject) => {
            if (!result) {
              return reject(new Ldap.NoSuchObjectError());
            }

            switch (result.length) {
              case 0:
                return reject(new Ldap.NoSuchObjectError());
              case 1:
                return resolve(result[0] as LdapResponseUser);
              default:
                return reject(new Error(`unexpected number of matches (${result.length}) for "${username}" username`));
            }
          }),
      )
      .catch((error: Error) => {
        this.logger.error({
          message: `${this.domainName}: user search error: ${error.toString()}`,
          error,
          context: LdapDomain.name,
          function: 'findUser',
          ...loggerContext,
        });

        throw error;
      });
  }

  /**
   * Find groups for given user
   *
   * @private
   * @param {Ldap.SearchEntryObject} user The LDAP user object
   * @returns {Promise<Ldap.SearchEntryObject>} Result handling callback
   */
  private async findGroups({
    user,
    loggerContext,
  }: {
    user: LdapResponseUser;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseGroup[]> {
    if (!user) {
      throw new Error('no user');
    }

    const searchFilter = typeof this.options.groupSearchFilter === 'function' ? this.options.groupSearchFilter(user) : undefined;

    const options: Ldap.SearchOptions = {
      filter: searchFilter,
      scope: this.options.groupSearchScope,
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: false,
    };
    if (this.options.groupSearchAttributes) {
      options.attributes = this.options.groupSearchAttributes;
    } else {
      options.attributes = ldapADattributes;
    }

    return this.search({
      searchBase: this.options.groupSearchBase || this.options.searchBase,
      options,
      loggerContext,
    }).catch((error: Error) => {
      this.logger.error({
        message: `${this.domainName}: group search error: ${error.toString()}`,
        error,
        context: LdapDomain.name,
        function: 'findGroups',
        ...loggerContext,
      });

      return [];
    });
  }

  /**
   * Search user by Username
   *
   * @async
   * @param {string} userByUsername user name
   * @returns {Promise<LdapResponseUser>} User in LDAP
   */
  public async searchByUsername({
    username,
    loggerContext,
  }: {
    username: string;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser | undefined> {
    return this.findUser({ username, loggerContext }).catch((error: Error) => {
      this.logger.error({
        message: `${this.domainName}: Search by Username error: ${error.toString()}`,
        error,
        context: LdapDomain.name,
        function: 'searchByUsername',
        ...loggerContext,
      });

      throw error;
    });
  }

  /**
   * Search user by DN
   *
   * @async
   * @param {string} userByDN user distinguished name
   * @returns {Promise<LdapResponseUser>} User in LDAP
   */
  public async searchByDN({ dn, loggerContext }: { dn: string; loggerContext?: LoggerContext }): Promise<LdapResponseUser> {
    const options: Ldap.SearchOptions = {
      scope: this.options.searchScope,
      attributes: ['*'],
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: false,
    };
    if (this.options.searchAttributes) {
      options.attributes = this.options.searchAttributes;
    }

    return this.search({ searchBase: dn, options, loggerContext })
      .then(
        (result) =>
          new Promise<LdapResponseUser>((resolve, reject) => {
            if (!result) {
              return reject(new Error('No result from search'));
            }

            switch (result.length) {
              case 0:
                return reject(new Ldap.NoSuchObjectError());
              case 1:
                return resolve(result[0] as LdapResponseUser);
              default:
                return reject(new Error(`unexpected number of matches (${result.length}) for "${dn}" user DN`));
            }
          }),
      )
      .catch((error: Error | Ldap.NoSuchObjectError) => {
        if (error instanceof Ldap.NoSuchObjectError) {
          this.logger.error({
            message: `${this.domainName}: Not found error: ${error.toString()}`,
            error,
            context: LdapDomain.name,
            function: 'searchByDN',
            ...loggerContext,
          });
        } else {
          this.logger.error({
            message: `${this.domainName}: Search by DN error: ${error.toString()}`,
            error,
            context: LdapDomain.name,
            function: 'searchByDN',
            ...loggerContext,
          });
        }

        throw error;
      });
  }

  /**
   * Synchronize users
   *
   * @async
   * @returns {Record<string, LdapResponseUser[]>} User in LDAP
   * @throws {Error}
   */
  public async synchronization({ loggerContext }: { loggerContext?: LoggerContext }): Promise<Record<string, Error | LdapResponseUser[]>> {
    if (this.hideSynchronization) {
      return {};
    }

    const options: Ldap.SearchOptions = {
      filter: this.options.searchFilterAllUsers,
      scope: this.options.searchScopeAllUsers,
      attributes: ldapADattributes,
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: true,
    };
    if (this.options.searchAttributesAllUsers) {
      options.attributes = this.options.searchAttributesAllUsers;
    }

    return this.search({
      searchBase: this.options.searchBase,
      options,
      loggerContext,
    })
      .then(async (sync) => {
        if (sync) {
          const usersWithGroups = await Promise.all(
            sync.map(async (user) => ({
              ...user,
              groups: await this.getGroups({ user: user as LdapResponseUser, loggerContext }),
            })),
          );

          return { [this.domainName]: usersWithGroups as LdapResponseUser[] };
        }

        this.logger.error({
          message: `${this.domainName}: Synchronize unknown error`,
          error: 'Unknown',
          context: LdapDomain.name,
          function: 'synchronization',
          ...loggerContext,
        });

        return { [this.domainName]: new Error(`${this.domainName}: Synchronize unknown error`) };
      })
      .catch((error: Error | Ldap.Error) => {
        this.logger.error({
          message: `${this.domainName}: Synchronize error: ${error.toString()}`,
          error,
          context: LdapDomain.name,
          function: 'synchronization',
          ...loggerContext,
        });

        return { [this.domainName]: error };
      });
  }

  /**
   * Synchronize groups
   *
   * @async
   * @returns {Record<string, LdapResponseGroup[]>} Group in LDAP
   * @throws {Error}
   */
  public async synchronizationGroups({
    loggerContext,
  }: {
    loggerContext?: LoggerContext;
  }): Promise<Record<string, Error | LdapResponseGroup[]>> {
    const options: Ldap.SearchOptions = {
      filter: this.options.searchFilterAllGroups,
      scope: this.options.groupSearchScope,
      attributes: ldapADattributes,
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: true,
    };
    if (this.options.groupSearchAttributes) {
      options.attributes = this.options.groupSearchAttributes;
    }

    return this.search({
      searchBase: this.options.groupSearchBase || this.options.searchBase,
      options,
      loggerContext,
    })
      .then((sync) => {
        if (sync) {
          return { [this.domainName]: sync as LdapResponseGroup[] };
        }

        this.logger.error({
          message: `${this.domainName}: Synchronization groups: unknown error`,
          error: 'Unknown',
          context: LdapDomain.name,
          function: 'synchronizationGroups',
          ...loggerContext,
        });

        return { [this.domainName]: new Error(`${this.domainName}: Synchronization groups: unknown error`) };
      })
      .catch((error: Error) => {
        this.logger.error({
          message: `${this.domainName}: Synchronization groups: ${error.toString()}`,
          error,
          context: LdapDomain.name,
          function: 'synchronizationGroups',
          ...loggerContext,
        });

        return { [this.domainName]: error };
      });
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
    username,
    password,
    loggerContext,
  }: {
    dn: string;
    data: Change[];
    username?: string;
    password?: string;
    loggerContext?: LoggerContext;
  }): Promise<boolean> {
    return this.adminBind({ loggerContext }).then(
      () =>
        new Promise<boolean>((resolve, reject) => {
          if (password) {
            // If a password, then we try to connect with user's login and password, and try to modify
            this.userClient.bind(dn, password, (error): any => {
              data.forEach((d, i, a) => {
                if (d.modification.type === 'thumbnailPhoto' || d.modification.type === 'jpegPhoto') {
                  // eslint-disable-next-line no-param-reassign
                  a[i].modification.vals = '...skipped...';
                }
              });

              if (error) {
                this.logger.error({
                  message: `${this.domainName}: bind error: ${error.toString()}`,
                  error,
                  context: LdapDomain.name,
                  function: 'modify',
                  ...loggerContext,
                });

                return reject(error);
              }

              return this.userClient.modify(dn, data, async (searchError: Ldap.Error | null): Promise<void> => {
                if (searchError) {
                  this.logger.error({
                    message: `${this.domainName}: Modify error "${dn}": ${searchError.toString()}`,
                    error: searchError,
                    context: LdapDomain.name,
                    function: 'modify',
                    ...loggerContext,
                  });

                  reject(searchError);
                }

                this.logger.debug!({
                  message: `${this.domainName}: Modify success "${dn}"`,
                  context: LdapDomain.name,
                  function: 'modify',
                  ...loggerContext,
                });

                resolve(true);
              });
            });
          } else {
            this.adminClient.modify(dn, data, async (searchError: Ldap.Error | null): Promise<void> => {
              data.forEach((d, i, a) => {
                if (d.modification.type === 'thumbnailPhoto' || d.modification.type === 'jpegPhoto') {
                  // eslint-disable-next-line no-param-reassign
                  a[i].modification.vals = '...skipped...';
                }
              });

              if (searchError) {
                this.logger.error({
                  message: `${this.domainName}: Modify error "${dn}": ${searchError.toString()}`,
                  error: searchError,
                  context: LdapDomain.name,
                  function: 'modify',
                  ...loggerContext,
                });

                reject(searchError);
                return;
              }

              this.logger.debug!({
                message: `${this.domainName}: Modify success "${dn}": ${JSON.stringify(data)}`,
                context: LdapDomain.name,
                function: 'modify',
                ...loggerContext,
              });

              resolve(true);
            });
          }
        }),
    );
  }

  /**
   * Authenticate given credentials against LDAP server (Internal)
   *
   * @async
   * @param {string} username The username to authenticate
   * @param {string} password The password to verify
   * @returns {LdapResponseUser} User in LDAP
   * @throws {Error}
   */
  public async authenticate({
    username,
    password,
    loggerContext,
  }: {
    username: string;
    password: string;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    if (!password) {
      this.logger.error({
        message: `${this.domainName}: No password given`,
        error: 'No password given',
        context: LdapDomain.name,
        function: 'authenticate',
        ...loggerContext,
      });
      throw new Error(`${this.domainName}: No password given`);
    }

    try {
      // 1. Find the user DN in question.
      const foundUser = await this.findUser({ username, loggerContext }).catch((error: Error) => {
        this.logger.error({
          message: `${this.domainName}: Not found user: "${username}"`,
          error,
          context: LdapDomain.name,
          function: 'authenticate',
          ...loggerContext,
        });

        throw error;
      });
      if (!foundUser) {
        this.logger.error({
          message: `${this.domainName}: Not found user: "${username}"`,
          error: 'Not found user',
          context: LdapDomain.name,
          function: 'authenticate',
          ...loggerContext,
        });

        throw new Error(`Not found user: "${username}"`);
      }

      // 2. Attempt to bind as that user to check password.
      return new Promise<LdapResponseUser>((resolve, reject) => {
        this.userClient.bind(
          foundUser[this.options.bindProperty || 'dn'],
          password,
          async (bindError): Promise<unknown | LdapResponseUser> => {
            if (bindError) {
              this.logger.error({
                message: `${this.domainName}: bind error: ${bindError.toString()}`,
                error: bindError,
                context: LdapDomain.name,
                function: 'authenticate',
                ...loggerContext,
              });

              return reject(bindError);
            }

            // 3. If requested, fetch user groups
            try {
              foundUser.groups = await this.getGroups({ user: foundUser, loggerContext });

              return resolve(foundUser);
            } catch (error: unknown) {
              const errorMessage = error instanceof Error ? error.toString() : JSON.stringify(error);
              this.logger.error({
                message: `${this.domainName}: Authenticate error: ${errorMessage}`,
                error,
                context: LdapDomain.name,
                function: 'authenticate',
                ...loggerContext,
              });

              return reject(error);
            }
          },
        );
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.toString() : JSON.stringify(error);
      this.logger.error({
        message: `${this.domainName}: LDAP auth error: ${errorMessage}`,
        error,
        context: LdapDomain.name,
        function: 'authenticate',
        ...loggerContext,
      });

      throw error;
    }
  }

  /**
   * Trusted domain
   *
   * @async
   * @returns {LdapTrustedDomain} ?
   * @throws {Error}
   */
  public async trustedDomain({ searchBase, loggerContext }: { searchBase: string; loggerContext?: LoggerContext }): Promise<any> {
    const options: Ldap.SearchOptions = {
      filter: '(&(objectClass=trustedDomain))',
      scope: this.options.searchScope,
      attributes: ldapADattributes,
      timeLimit: this.options.timeLimit || 10,
      sizeLimit: this.options.sizeLimit || 0,
      paged: false,
    };

    const trustedDomain = await this.search({
      searchBase,
      options,
      loggerContext,
    });

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
  public async add({ entry, loggerContext }: { entry: LdapAddEntry; loggerContext?: LoggerContext }): Promise<LdapResponseUser> {
    return this.adminBind({ loggerContext }).then(
      () =>
        new Promise<LdapResponseUser>((resolve, reject) => {
          if (!this.options.newObject) {
            throw new Error('ADD operation not available');
          }

          const dn = `CN=${this.sanitizeInput(entry.cn as string)},${this.sanitizeInput(this.options.newObject)}`;
          this.adminClient.add(dn, entry, (error: Error) => {
            if (error) {
              return reject(error);
            }

            return resolve(this.searchByDN({ dn, loggerContext }));
          });
        }),
    );
  }

  /**
   * Unbind connections
   *
   * @async
   * @returns {Promise<boolean>}
   */
  public async close(): Promise<boolean> {
    // It seems to be OK just to call unbind regardless of if the
    // client has been bound (e.g. how ldapjs pool destroy does)
    return new Promise<boolean>((resolve) => {
      this.adminClient.unbind(() => {
        this.logger.debug!({
          message: `${this.domainName}: adminClient: close`,
          context: LdapDomain.name,
          function: 'close',
        });

        this.userClient.unbind(() => {
          this.logger.debug!({
            message: `${this.domainName}: userClient: close`,
            context: LdapDomain.name,
            function: 'close',
          });

          resolve(true);
        });
      });
    });
  }
}
