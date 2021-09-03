/** @format */

import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LdapModule } from '../lib/ldap.module';
import { ldapADattributes, Scope } from '../lib/ldap.interface';

@Module({
  imports: [
    ConfigModule.forRoot(),

    LdapModule.registerAsync({
      inject: [ConfigService /* , RedisService */],
      useFactory: async (configService: ConfigService /* , redisService: RedisService */) => {
        const logger = new Logger('LDAP');
        // let cache: /* Redis | */ undefined;
        // try {
        //    cache = redisService.getClient('LDAP');
        // } catch {
        //    cache = undefined;
        // }

        const domainString = configService.get<string>('LDAP');
        let domainsConfig: Record<string, any>;
        try {
          domainsConfig = JSON.parse(domainString);
        } catch {
          throw new Error('Not available authentication profiles.');
        }

        const domains = Object.keys(domainsConfig).map((name) => ({
          name,
          url: domainsConfig[name].url,
          bindDN: domainsConfig[name].bindDn,
          bindCredentials: domainsConfig[name].bindPw,
          searchBase: domainsConfig[name].searchBase,
          searchFilter: domainsConfig[name].searchUser,
          searchScope: 'sub' as Scope,
          groupSearchBase: domainsConfig[name].searchBase,
          groupSearchFilter: domainsConfig[name].searchGroup,
          groupSearchScope: 'sub' as Scope,
          groupDnProperty: 'dn',
          groupSearchAttributes: ldapADattributes,
          searchAttributes: ldapADattributes,
          hideSynchronization: domainsConfig[name].hideSynchronization === 'true' ?? false,
          searchBaseAllUsers: domainsConfig[name].searchBase,
          searchFilterAllUsers: domainsConfig[name].searchAllUsers,
          searchFilterAllGroups: domainsConfig[name].searchAllGroups,
          searchScopeAllUsers: 'sub' as Scope,
          searchAttributesAllUsers: ldapADattributes,
          reconnect: true,
          newObject: domainsConfig[name].newBase,
        }));

        return {
          // cache,
          // cacheTtl: configService.get<number>('LDAP_REDIS_TTL'),
          domains,
          logger,
        };
      },
    }),
  ],
})
export class AppModule {}
