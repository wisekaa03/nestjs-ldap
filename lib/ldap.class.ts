/** @format */
import { EventEmitter } from 'events';
import Ldap from 'ldapjs';
import { Logger } from 'winston';
import type { LdapResponseUser, LdapDomainsConfig, LoggerContext } from './ldap.interface';
import { ldapADattributes, LdapResponseGroup, LDAPAddEntry } from './ldap.interface';
import { Change } from './ldap/change';

export class LdapDomain extends EventEmitter {
  public domainName: string;

  private clientOpts: Ldap.ClientOptions;

  private bindDN: string;

  private bindCredentials: string;

  private adminClient: Ldap.Client;

  private adminBound: boolean;

  private userClient: Ldap.Client;

  private getGroups: ({
    user,
    loggerContext,
  }: {
    user: Ldap.SearchEntryObject;
    loggerContext?: LoggerContext;
  }) => Promise<Ldap.SearchEntryObject>;

  /**
   * Create an LDAP class.
   *
   * @param {LdapModuleOptions} opts Config options
   * @param {LogService} logger Logger service
   * @param {ConfigService} configService Config service
   * @constructor
   */
  constructor(private readonly options: LdapDomainsConfig, private readonly logger: Logger) {
    super();
    this.domainName = options.name;

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
        this.logger.debug(`${options.name}: install reconnect listener`, {
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
        options.groupSearchFilter = (user: Ldap.SearchEntryObject): string =>
          groupSearchFilter
            .replace(
              /{{dn}}/g,
              (options.groupDnProperty && (user[options.groupDnProperty] as string))?.replace(/\(/, '\\(')?.replace(/\)/, '\\)') ||
                'undefined',
            )
            .replace(/{{username}}/g, user.sAMAccountName as string);
      }

      this.getGroups = this.findGroups;
    } else {
      // Assign an async identity function so there is no need to branch
      // the authenticate function to have cache set up.
      this.getGroups = async ({ user }) => user;
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
  fromLDAPString = (string: string): Date | null => {
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
      this.logger.error(`${this.domainName}: admin emitted error: [${error.code}]`, {
        error,
        context: LdapDomain.name,
        function: this.handleErrorAdmin.name,
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
      this.logger.error(`${this.domainName}: user emitted error: [${error.code}]`, {
        error,
        context: LdapDomain.name,
        function: this.handleErrorUser.name,
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
    this.logger.error(`${this.domainName}: emitted error: [${error.code}]`, {
      error,
      context: LdapDomain.name,
      function: this.handleConnectError.name,
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

    this.logger.debug(`${this.domainName}: bind: ${this.bindDN} ...`, {
      context: LdapDomain.name,
      function: this.onConnectAdmin.name,
      ...loggerContext,
    });

    return new Promise<boolean>((resolve, reject) =>
      this.adminClient.bind(this.bindDN, this.bindCredentials, (error) => {
        if (error) {
          this.logger.error(`${this.domainName}: bind error: ${error.toString()}`, {
            error,
            context: LdapDomain.name,
            function: this.onConnectAdmin.name,
            ...loggerContext,
          });
          this.adminBound = false;

          return reject(error);
        }

        this.logger.debug(`${this.domainName}: bind ok`, {
          context: LdapDomain.name,
          function: this.onConnectAdmin.name,
          ...loggerContext,
        });
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
  }): Promise<undefined | Ldap.SearchEntryObject[]> {
    return this.adminBind({ loggerContext }).then(
      () =>
        new Promise<undefined | Ldap.SearchEntryObject[]>((resolve, reject) =>
          this.adminClient.search(searchBase, options, (searchError: Ldap.Error | null, searchResult: Ldap.SearchCallbackResponse) => {
            if (searchError !== null) {
              return reject(searchError);
            }
            if (typeof searchResult !== 'object') {
              return reject(new Error(`The LDAP server has empty search: ${searchBase}, options=${JSON.stringify(options)}`));
            }

            const items: Ldap.SearchEntryObject[] = [];
            searchResult.on('searchEntry', (entry: Ldap.SearchEntry) => {
              const object: Ldap.SearchEntryObject = Object.keys(entry.object).reduce((o, k: string) => {
                let key = k;
                if (k.endsWith(';binary')) {
                  key = k.replace(/;binary$/, '');
                }
                switch (key) {
                  case 'objectGUID':
                    return {
                      ...o,
                      [key]: this.GUIDtoString(entry.object[k] as string),
                    };
                  case 'dn':
                    return {
                      ...o,
                      [key]: (entry.object[k] as string).toLowerCase(),
                    };
                  case 'sAMAccountName':
                    return {
                      ...o,
                      [key]: (entry.object[k] as string).toLowerCase(),
                    };
                  case 'whenCreated':
                  case 'whenChanged':
                    return {
                      ...o,
                      [key]: this.fromLDAPString(entry.object[k] as string),
                    };
                  default:
                }
                // 'thumbnailPhoto' and 'jpegPhoto' is falling there
                return { ...o, [key]: entry.object[k] };
              }, {} as Ldap.SearchEntryObject);

              items.push({ loginDomain: this.domainName, ...object });

              if (this.options.includeRaw === true) {
                items[items.length - 1].raw = (entry.raw as unknown) as string;
              }
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
  private async findUser({
    username,
    loggerContext,
  }: {
    username: string;
    loggerContext?: LoggerContext;
  }): Promise<undefined | Ldap.SearchEntryObject> {
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
          new Promise<undefined | Ldap.SearchEntryObject>((resolve, reject) => {
            if (!result) {
              return reject(new Ldap.NoSuchObjectError());
            }

            switch (result.length) {
              case 0:
                return reject(new Ldap.NoSuchObjectError());
              case 1:
                return resolve(result[0]);
              default:
                return reject(new Error(`unexpected number of matches (${result.length}) for "${username}" username`));
            }
          }),
      )
      .catch((error: Error) => {
        this.logger.error(`${this.domainName}: user search error: ${error.toString()}`, {
          error,
          context: LdapDomain.name,
          function: this.findUser.name,
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
    user: Ldap.SearchEntryObject;
    loggerContext?: LoggerContext;
  }): Promise<Ldap.SearchEntryObject> {
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
    })
      .then((result) => {
        // eslint-disable-next-line no-param-reassign
        (user.groups as unknown) = result;

        return user;
      })
      .catch((error: Error) => {
        this.logger.error(`${this.domainName}: group search error: ${error.toString()}`, {
          error,
          context: LdapDomain.name,
          function: this.findGroups.name,
          ...loggerContext,
        });

        throw error;
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
    userByUsername,
    loggerContext,
  }: {
    userByUsername: string;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    return this.findUser({ username: userByUsername, loggerContext })
      .then((search) => ({ loginDomain: this.domainName, ...((search as unknown) as LdapResponseUser) }))
      .catch((error: Error) => {
        this.logger.error(`${this.domainName}: Search by Username error: ${error.toString()}`, {
          error,
          context: LdapDomain.name,
          function: this.searchByUsername.name,
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
  public async searchByDN({ userByDN, loggerContext }: { userByDN: string; loggerContext?: LoggerContext }): Promise<LdapResponseUser> {
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

    return this.search({ searchBase: userByDN, options, loggerContext })
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
                return resolve({ loginDomain: this.domainName, ...((result[0] as unknown) as LdapResponseUser) });
              default:
                return reject(new Error(`unexpected number of matches (${result.length}) for "${userByDN}" user DN`));
            }
          }),
      )
      .catch((error: Error | Ldap.NoSuchObjectError) => {
        if (error instanceof Ldap.NoSuchObjectError) {
          this.logger.error(`${this.domainName}: Not found error: ${error.toString()}`, {
            error,
            context: LdapDomain.name,
            function: this.searchByDN.name,
            ...loggerContext,
          });
        } else {
          this.logger.error(`${this.domainName}: Search by DN error: ${error.toString()}`, {
            error,
            context: LdapDomain.name,
            function: this.searchByDN.name,
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
  public async synchronization({ loggerContext }: { loggerContext?: LoggerContext }): Promise<Record<string, LdapResponseUser[]>> {
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
          await Promise.allSettled(sync.map(async (u) => this.getGroups({ user: u, loggerContext })));

          return { [this.domainName]: (sync as unknown) as LdapResponseUser[] };
        }

        this.logger.error(`${this.domainName}: Synchronize unknown error.`, {
          error: 'Unknown',
          context: LdapDomain.name,
          function: this.synchronization.name,
          ...loggerContext,
        });
        throw new Error('Synchronize unknown error.');
      })
      .catch((error: Error | Ldap.Error) => {
        this.logger.error(`${this.domainName}: Synchronize error: ${error.toString()}`, {
          error,
          context: LdapDomain.name,
          function: this.synchronization.name,
          ...loggerContext,
        });

        throw error;
      });
  }

  /**
   * Synchronize users
   *
   * @async
   * @returns {Record<string, LdapResponseGroup[]>} Group in LDAP
   * @throws {Error}
   */
  public async synchronizationGroups({ loggerContext }: { loggerContext?: LoggerContext }): Promise<Record<string, LdapResponseGroup[]>> {
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
      searchBase: this.options.searchBase,
      options,
      loggerContext,
    })
      .then((sync) => {
        if (sync) {
          return { [this.domainName]: (sync as unknown) as LdapResponseGroup[] };
        }

        this.logger.error(`${this.domainName}: synchronizationGroups: unknown error.`, {
          error: 'Unknown',
          context: LdapDomain.name,
          function: this.synchronizationGroups.name,
          ...loggerContext,
        });
        throw new Error(`${this.domainName}: synchronizationGroups: unknown error.`);
      })
      .catch((error: Error) => {
        this.logger.error(`${this.domainName}: synchronizationGroups error: ${error.toString()}`, {
          error,
          context: LdapDomain.name,
          function: this.synchronizationGroups.name,
          ...loggerContext,
        });

        throw error;
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
                this.logger.error(`${this.domainName}: bind error: ${error.toString()}`, {
                  error,
                  context: LdapDomain.name,
                  function: this.modify.name,
                  ...loggerContext,
                });

                return reject(error);
              }

              return this.userClient.modify(
                dn,
                data,
                async (searchError: Ldap.Error | null): Promise<void> => {
                  if (searchError) {
                    this.logger.error(`${this.domainName}: Modify error "${dn}": ${searchError.toString()}`, {
                      error: searchError,
                      context: LdapDomain.name,
                      function: this.modify.name,
                      ...loggerContext,
                    });

                    reject(searchError);
                  }

                  this.logger.debug(`${this.domainName}: Modify success "${dn}"`, {
                    context: LdapDomain.name,
                    function: this.modify.name,
                    ...loggerContext,
                  });

                  resolve(true);
                },
              );
            });
          } else {
            this.adminClient.modify(
              dn,
              data,
              async (searchError: Ldap.Error | null): Promise<void> => {
                data.forEach((d, i, a) => {
                  if (d.modification.type === 'thumbnailPhoto' || d.modification.type === 'jpegPhoto') {
                    // eslint-disable-next-line no-param-reassign
                    a[i].modification.vals = '...skipped...';
                  }
                });

                if (searchError) {
                  this.logger.error(`${this.domainName}: Modify error "${dn}": ${searchError.toString()}`, {
                    error: searchError,
                    context: LdapDomain.name,
                    function: this.modify.name,
                    ...loggerContext,
                  });

                  reject(searchError);
                  return;
                }

                this.logger.debug(`${this.domainName}: Modify success "${dn}": ${JSON.stringify(data)}`, {
                  context: LdapDomain.name,
                  function: this.modify.name,
                  ...loggerContext,
                });

                resolve(true);
              },
            );
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
  private async authenticateInternal({
    username,
    password,
    loggerContext,
  }: {
    username: string;
    password: string;
    loggerContext?: LoggerContext;
  }): Promise<LdapResponseUser> {
    // 1. Find the user DN in question.
    const foundUser = await this.findUser({ username, loggerContext }).catch((error: Error) => {
      this.logger.error(`${this.domainName}: Not found user: "${username}"`, {
        error,
        context: LdapDomain.name,
        function: this.authenticateInternal.name,
        ...loggerContext,
      });

      throw error;
    });
    if (!foundUser) {
      this.logger.error(`${this.domainName}: Not found user: "${username}"`, {
        error: 'Not found user',
        context: LdapDomain.name,
        function: this.authenticateInternal.name,
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
            this.logger.error(`${this.domainName}: bind error: ${bindError.toString()}`, {
              error: bindError,
              context: LdapDomain.name,
              function: this.authenticateInternal.name,
              ...loggerContext,
            });

            return reject(bindError);
          }

          // 3. If requested, fetch user groups
          try {
            return resolve(
              ((await this.getGroups({
                user: foundUser,
                loggerContext,
              })) as unknown) as LdapResponseUser,
            );
          } catch (error) {
            this.logger.error(`${this.domainName}: Authenticate error: ${error.toString()}`, {
              error,
              context: LdapDomain.name,
              function: this.authenticateInternal.name,
              ...loggerContext,
            });

            return reject(error);
          }
        },
      );
    });
  }

  /**
   * Authenticate given credentials against LDAP server
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
      this.logger.error(`${this.domainName}: No password given`, {
        error: 'No password given',
        context: LdapDomain.name,
        function: this.authenticate.name,
        ...loggerContext,
      });
      throw new Error(`${this.domainName}: No password given`);
    }

    try {
      return this.authenticateInternal({
        username,
        password,
        loggerContext,
      });
    } catch (error) {
      this.logger.error(`${this.domainName}: LDAP auth error: ${error.toString()}`, {
        error,
        context: LdapDomain.name,
        function: this.authenticate.name,
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
  public async add({ entry, loggerContext }: { entry: LDAPAddEntry; loggerContext?: LoggerContext }): Promise<LdapResponseUser> {
    return this.adminBind({ loggerContext }).then(
      () =>
        new Promise<LdapResponseUser>((resolve, reject) => {
          if (!this.options.newObject) {
            throw new Error('ADD operation not available');
          }

          const userByDN = `CN=${this.sanitizeInput(entry.cn as string)},${this.sanitizeInput(this.options.newObject)}`;
          this.adminClient.add(userByDN, entry, (error: Error) => {
            if (error) {
              return reject(error);
            }

            return resolve(this.searchByDN({ userByDN, loggerContext }));
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
        this.logger.debug(`${this.domainName}: adminClient: close`, {
          context: LdapDomain.name,
          function: this.close.name,
        });

        this.userClient.unbind(() => {
          this.logger.debug(`${this.domainName}: userClient: close`, {
            context: LdapDomain.name,
            function: this.close.name,
          });

          resolve(true);
        });
      });
    });
  }
}
