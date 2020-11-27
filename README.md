# NestJS LDAP

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo_text.svg" width="320" alt="Nest Logo" /></a>
</p>

## Description

A NestJS library for LDAP (ActiveDirectory)

## Installation

```bash
$ yarn add nestjs-ldap
```

## Usage

```typescript
  import { LdapModule, ldapADattributes } from 'nestjs-ldap';

  @Module({
    imports: [
      ...
      LdapModule.registerAsync({
        inject: [ConfigService],
        useFactory: async (configService: ConfigService) => (
          {
            cache: new Redis(), /* optional */
            cacheUrl: 'redis://username:password@example.com:6379/0', /* optional */
            cacheTtl: 600, /* optional */
            domains: [
              'example.com' => {
                url: 'ldaps://pdc.example.local:389',
                bindDN: 'CN=Administrator,DC=example,DC=local',
                bindCredentials: 'PaSsWoRd123',
                searchBase: 'DC=example,DC=local',
                searchFilter: '(&(&(|(&(objectClass=user)(objectCategory=person))(&(objectClass=contact)(objectCategory=person)))))',
                searchScope: 'sub' as Scope,
                groupSearchBase: 'DC=example,DC=local',
                groupSearchFilter: '(&(objectClass=group)(member={{dn}}))',
                groupSearchScope: 'sub' as Scope,
                groupDnProperty: 'dn',
                hideSynchronization: false,
                searchBaseAllUsers: 'DC=example,DC=local',
                searchFilterAllUsers: '(&(&(|(&(objectClass=user)(objectCategory=person))(&(objectClass=contact)(objectCategory=person)))))',
                searchFilterAllGroups: 'objectClass=group',
                searchScopeAllUsers: 'sub' as Scope,
                newObject: 'OU=User,DC=example,DC=local',
                reconnect: true,
                groupSearchAttributes: ldapADattributes,
                searchAttributes: ldapADattributes,
                searchAttributesAllUsers: ldapADattributes,
              },
            ]
          }),
      }),
      ...
    ]
  })
  export class AppModule {}
```

## License

NestJS-ldap is [MIT licensed](LICENSE).
